import http.client
import io
import ipaddress
import json
import logging
import os
import shutil
import signal
import socket
import ssl
import stat
import subprocess
import sys
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace
from typing import NamedTuple, override

import pytest
from zeroconf import Error as ZeroconfError

from se import se2hass

REPO_ROOT = Path(__file__).resolve().parent.parent
HOOK = "hook1"
ABSENT = object()  # Leaves a key out of a request.
GOOD_CODE = "ABCDEFGHJK"
OTHER_CODE = "KJHGFEDCBA"
LOCKOUT = se2hass.LOCKOUT_SECONDS
RETRY = se2hass.RETRY_SECONDS
HTTP_AND_HTTPS = pytest.mark.parametrize(
    "tls", [False, True], ids=["http", "https"]
)


def fields(**changes):
    return {k: v for k, v in changes.items() if v is not ABSENT}


def wait_for(condition, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not condition():
        time.sleep(0.01)
    return bool(condition())


def line(**sections):
    data = {"events": {}, "inverters": {}, "optimizers": {}, **sections}
    return json.dumps(data) + "\n"


def one_line(power, serial="7F104920"):
    return line(inverters={serial: {"Time": "12:00:00", "Pac": power}})


def txt(info):
    return {k.decode(): v.decode() for k, v in info.properties.items()}


def messages(caplog, level=logging.NOTSET):
    return [r.getMessage() for r in caplog.records if r.levelno >= level]


def warnings(caplog):
    return messages(caplog, logging.WARNING)


# --- fakes ----------------------------------------------------------------


class FakeClock:
    def __init__(self, now=1000.0):
        self.now = now

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


class FakeZeroconf:
    def __init__(self, register_error=None):
        self.registered, self.updated, self.closed = [], [], 0
        self.register_error = register_error
        self.update_error = None

    def register_service(self, info):
        if self.register_error is not None:
            raise self.register_error
        self.registered.append(info)

    def update_service(self, info):
        if self.update_error is not None:
            raise self.update_error
        self.updated.append(info)

    def close(self):
        self.closed += 1


# Replaces se.se2hass.Zeroconf: records the objects made, or fails.
class ZeroconfFactory:
    def __init__(self):
        self.instances = []
        self.create_error = self.register_error = None

    def __call__(self):
        if self.create_error is not None:
            raise self.create_error
        self.instances.append(FakeZeroconf(self.register_error))
        return self.instances[-1]


class Pushed(NamedTuple):
    method: str
    path: str
    content_type: str
    body: bytes


class HassHandler(BaseHTTPRequestHandler):
    @override
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        content_type = self.headers.get("Content-Type")
        self.server.requests.append(
            Pushed(self.command, self.path, content_type, body)
        )
        self.send_response(self.server.status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    @override
    def log_message(self, _fmt, *_args):
        pass


# A fake Home Assistant: records what it is sent, answers with `status`.
class FakeHass(ThreadingHTTPServer):
    def __init__(self, tls_context=None):
        super().__init__(("127.0.0.1", 0), HassHandler)
        if tls_context is not None:
            self.socket = tls_context.wrap_socket(self.socket, server_side=True)
        self.requests = []
        self.status = HTTPStatus.OK
        self.scheme = "https" if tls_context is not None else "http"
        self._thread = threading.Thread(target=self.serve_forever, daemon=True)
        self._thread.start()

    @property
    def pairing(self):
        url = f"{self.scheme}://127.0.0.1:{self.server_address[1]}"
        return se2hass.Pairing(url, HOOK)

    @property
    def bodies(self):
        return [request.body.decode() for request in self.requests]

    @override
    def handle_error(self, _request, _client_address):
        pass

    def stop(self):
        self.shutdown()
        self.server_close()
        self._thread.join()


class Reply(NamedTuple):
    status: int
    headers: dict
    body: bytes

    @property
    def json(self):
        return json.loads(self.body)


# A client of the pairing server, which it finds by its port.
class Api:
    def __init__(self, server, state, clock=None, client_context=None):
        self.server, self.state, self.clock = server, state, clock
        self.client_context = client_context
        self.code = f"{state.pairing_code[:5]}-{state.pairing_code[5:]}"

    @property
    def port(self):
        return self.server.server_address[1]

    # The headers are lines like "Content-Length: 5", by default just that of
    # the body. http.client does not let request() send anything else.
    def request(self, method, path, body=None, headers=None):
        if self.client_context is None:
            connection = http.client.HTTPConnection(
                "127.0.0.1", self.port, timeout=5
            )
        else:
            connection = http.client.HTTPSConnection(
                "127.0.0.1", self.port, timeout=5, context=self.client_context
            )
        if headers is None:
            headers = [] if body is None else [f"Content-Length: {len(body)}"]
        try:
            connection.putrequest(method, path)
            for header in headers:
                connection.putheader(*header.split(": ", 1))
            connection.endheaders(body)
            response = connection.getresponse()
            headers = {k.lower(): v for k, v in response.getheaders()}
            return Reply(response.status, headers, response.read())
        finally:
            connection.close()

    def post(self, payload, path="/pair"):
        if not isinstance(payload, bytes):
            payload = json.dumps(payload).encode()
        return self.request("POST", path, payload)

    def payload(self, **changes):
        defaults = {"hass_url": "http://ha:8123", "webhook_id": HOOK}
        return fields(**{**defaults, "code": self.code, **changes})

    def pair(self, **changes):
        return self.post(self.payload(**changes))

    def raw(self, *headers):
        return self.request("POST", "/pair", headers=list(headers))


# --- fixtures -------------------------------------------------------------


# no mDNS, Zeroconf is replaced by a fake
pytestmark = pytest.mark.usefixtures("zc_factory", "log_everything")


@pytest.fixture
def zc_factory(monkeypatch):
    factory = ZeroconfFactory()
    monkeypatch.setattr(se2hass, "Zeroconf", factory)
    return factory


@pytest.fixture
def log_everything(caplog):
    caplog.set_level(logging.DEBUG, logger="se.se2hass")


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def state(workdir, clock):
    return se2hass.State.load(workdir / "state.json", clock=clock)


@pytest.fixture
def paired_state(state):
    state.pair(se2hass.Pairing("http://ha:8123", HOOK))
    return state


# A state that is never saved, to test the lockout of the code.
@pytest.fixture
def unsaved_state(clock):
    return se2hass.State(Path("unused.json"), "id1", GOOD_CODE, clock=clock)


# A state that cannot be written: the directory of its file is a file.
@pytest.fixture
def blocked_state(workdir):
    (workdir / "blocked").write_text("a file, not a directory")
    return se2hass.State(workdir / "blocked" / "state.json", "id1", GOOD_CODE)


@pytest.fixture
def fake_zc():
    return FakeZeroconf()


@pytest.fixture
def advertiser(fake_zc, state):
    return se2hass.Advertiser(fake_zc, state, "solar")


@pytest.fixture
def started(advertiser):
    advertiser.start(22222, "http", ["127.0.0.1"])
    return advertiser


class TlsFiles(NamedTuple):
    cert: Path
    key: Path


@pytest.fixture(scope="module")
def tls_files(tmp_path_factory):
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl is not on PATH")
    directory = tmp_path_factory.mktemp("tls")
    files = TlsFiles(directory / "cert.pem", directory / "key.pem")
    command = [
        openssl,
        *("req", "-x509", "-newkey", "ec", "-nodes", "-days", "2"),
        *("-pkeyopt", "ec_paramgen_curve:prime256v1"),
        *("-keyout", str(files.key), "-out", str(files.cert)),
        *("-subj", "/CN=localhost"),
        *("-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"),
    ]
    try:
        subprocess.run(command, check=True, capture_output=True)
    except subprocess.CalledProcessError as ex:
        pytest.skip(f"openssl cannot make a certificate: {ex.stderr!r}")
    return files


def server_context(files):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(files.cert, files.key)
    return context


@pytest.fixture
def make_hass(request):
    servers = []

    def make(*, tls=False):
        files = request.getfixturevalue("tls_files") if tls else None
        servers.append(FakeHass(server_context(files) if tls else None))
        return servers[-1]

    yield make

    for server in servers:
        server.stop()


@pytest.fixture
def hass(make_hass):
    return make_hass()


# Make a started pairing server and its client, which trusts the server cert.
@pytest.fixture
def make_api(request, state, clock):
    servers = []

    def make(*, tls=False, start=True, state=state):
        files = request.getfixturevalue("tls_files") if tls else None
        context = server_context(files) if tls else None
        servers.append(se2hass.PairingServer("127.0.0.1", 0, state, context))
        if start:
            servers[-1].start()
        client = ssl.create_default_context(cafile=files.cert) if tls else None
        return Api(servers[-1], state, clock, client)

    yield make

    for server in servers:
        server.stop()


@pytest.fixture
def api(make_api):
    return make_api()


# Return a function that runs se2hass.main() with the given arguments, as if
# the program was called "se2hass". main() adds a handler to the root logger
# and sets its level, which is undone here, but only for the handlers added
# here: the root logger also holds the handlers of pytest itself.
@pytest.fixture
def run_se2hass(monkeypatch, capsys):
    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level

    def run(*args, stdin=""):
        monkeypatch.setattr(sys, "argv", ["se2hass"])
        monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
        code, message = 0, ""
        try:
            se2hass.main([str(arg) for arg in args])
        except SystemExit as exit_:
            # sys.exit(text) writes the text to stderr when the process exits
            if isinstance(exit_.code, str):
                code, message = 1, exit_.code
            else:
                code = exit_.code or 0
        captured = capsys.readouterr()
        return code, captured.out, captured.err + message

    yield run

    for handler in root.handlers[:]:
        if handler not in handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(level)


@pytest.fixture
def server_args(workdir):
    return ["-i", "127.0.0.1", "-p", "0", "-S", str(workdir / "state.json")]


# --- options --------------------------------------------------------------

ARGS = {
    "infile": "in.json",
    "interface": "::1",
    "port": 1234,
    "state_file": "s.json",
    "cert": "c.pem",
    "key": "k.pem",
    "insecure": True,
    "hostname": "solar",
    "verbose": 2,
}


def test_the_defaults():
    args = se2hass.build_parser().parse_args([])

    assert vars(args) == {
        **dict.fromkeys(ARGS),
        "port": 22222,
        "state_file": "/var/lib/semonitor/se2hass.json",
        "insecure": False,
        "verbose": 0,
    }


@pytest.mark.parametrize(
    "argv",
    [
        "-i ::1 -p 1234 -S s.json -C c.pem -k k.pem -I -H solar -vv in.json",
        (
            "--interface ::1 --port 1234 --state-file s.json --cert c.pem "
            "--key k.pem --insecure --hostname solar -v -v in.json"
        ),
    ],
    ids=["short", "long"],
)
def test_every_option_has_a_short_and_a_long_form(argv):
    args = se2hass.build_parser().parse_args(argv.split())

    assert vars(args) == ARGS


@pytest.mark.parametrize(
    ("argv", "text"),
    [
        ("--cafile ca.pem", "unrecognized arguments"),
        ("--bind 127.0.0.1", "unrecognized arguments"),
        ("--key key.pem", "--key needs --cert"),
        *(("-p " + p, "invalid") for p in ["x", "1.5", "-1", "65536"]),
        *(
            ("--hostname=" + n, "invalid host name")
            for n in ["a.b", "-a", "a-", "a_b"]
        ),
        ("--hostname=solar.example.org", "use the name only"),
    ],
)
def test_bad_options_are_a_usage_error(run_se2hass, argv, text):
    code, _out, err = run_se2hass(*argv.split())

    assert code == 2
    assert "usage: " in err
    assert text in err


def test_a_host_name_that_is_not_a_label_is_a_usage_error(run_se2hass):
    for name in ["", "a b", "x" * 64]:
        assert run_se2hass("-H", name)[0] == 2


def test_help_describes_the_tool(run_se2hass):
    code, out, _err = run_se2hass("-h")

    assert code == 0
    assert "--state-file" in out
    assert "22222" in out
    assert "/var/lib/semonitor/se2hass.json" in out
    assert "None" not in out


# main() exits with 1 and a message with the name of the program when it
# cannot start.
def fails(run_se2hass, *args, message):
    code, _out, err = run_se2hass(*args)

    assert code == 1
    assert f"se2hass: {message}" in err


@pytest.mark.parametrize("cert", [None, "not a certificate\n"])
def test_a_cert_that_cannot_be_loaded_exits_with_1(
    workdir, run_se2hass, server_args, cert
):
    if cert is not None:
        (workdir / "cert.pem").write_text(cert)

    fails(
        run_se2hass,
        *("-C", workdir / "cert.pem", *server_args),
        message="cannot load the certificate or key",
    )


def test_a_key_that_cannot_be_loaded_exits_with_1(
    workdir, run_se2hass, server_args, tls_files
):
    fails(
        run_se2hass,
        *("-C", tls_files.cert, "-k", workdir / "missing.pem", *server_args),
        message="cannot load the certificate or key",
    )


@pytest.mark.parametrize("content", [b"{oops", b"\xff\xfe\x00\x80"])
def test_a_corrupt_state_file_exits_with_1(
    workdir, run_se2hass, server_args, content
):
    (workdir / "state.json").write_bytes(content)

    fails(run_se2hass, *server_args, message="corrupt state file")

    assert (workdir / "state.json").read_bytes() == content


def test_an_input_file_that_does_not_exist_exits_with_1(
    workdir, run_se2hass, server_args
):
    code, _out, err = run_se2hass(workdir / "missing.json", *server_args)

    assert code == 1
    assert "se2hass: " in err
    assert "missing.json" in err


def test_a_port_that_is_taken_exits_with_1(workdir, run_se2hass):
    with socket.socket() as taken:
        taken.bind(("127.0.0.1", 0))
        taken.listen()
        args = ["-i", "127.0.0.1", "-p", taken.getsockname()[1]]

        fails(
            run_se2hass,
            *args,
            *("-S", workdir / "state.json"),
            message="cannot listen on 127.0.0.1",
        )


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        ("create_error", "cannot start mDNS"),
        ("register_error", "cannot announce the service"),
    ],
)
def test_multicast_dns_that_fails_exits_with_1(
    run_se2hass, server_args, zc_factory, failure, message
):
    setattr(zc_factory, failure, OSError("no multicast"))

    fails(run_se2hass, *server_args, message=message)

    assert all(zc.closed == 1 for zc in zc_factory.instances)


# --- the state ------------------------------------------------------------


def test_a_missing_state_file_is_created_private(workdir):
    path = workdir / "sub" / "dir" / "state.json"

    state = se2hass.State.load(path)

    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text()) == {
        "id": state.id,
        "pairing_code": state.pairing_code,
        "pairing": None,
    }
    assert state.id
    assert len(state.pairing_code) == se2hass.CODE_LENGTH
    assert set(state.pairing_code) <= set(se2hass.CODE_ALPHABET)
    assert set("01ILO").isdisjoint(se2hass.CODE_ALPHABET)
    assert not state.paired
    assert [p.name for p in path.parent.iterdir()] == ["state.json"]


def test_the_id_and_the_code_are_kept_until_the_file_is_deleted(workdir):
    path = workdir / "state.json"
    first = se2hass.State.load(path)

    second = se2hass.State.load(str(path))
    assert (second.id, second.pairing_code) == (first.id, first.pairing_code)

    path.unlink()
    third = se2hass.State.load(path)
    assert (third.id, third.pairing_code) != (first.id, first.pairing_code)


def test_pairing_is_saved_private_and_survives_a_restart(workdir, state):
    path = workdir / "state.json"
    first = se2hass.Pairing("http://one:8123", "one")
    second = se2hass.Pairing("http://two:8123", "two")

    state.pair(first)
    state.pair(second)

    assert state.pairing == second
    assert state.paired
    assert se2hass.State.load(path).pairing == second
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert json.loads(path.read_text())["pairing"] == {
        "hass_url": "http://two:8123",
        "webhook_id": "two",
    }
    assert [p.name for p in workdir.iterdir()] == ["state.json"]


def test_a_failed_write_leaves_the_pairing_as_it_was(blocked_state):
    blocked_state.pairing = old = se2hass.Pairing("http://old:8123", "old")

    with pytest.raises(se2hass.Se2HassError, match="cannot write state file"):
        blocked_state.pair(se2hass.Pairing("http://new:8123", "new"))

    assert blocked_state.pairing == old


def test_a_failed_write_leaves_the_file_and_no_temp_file(
    workdir, state, monkeypatch
):
    before = (workdir / "state.json").read_text()

    def failing_fsync(_descriptor):
        msg = "disk full"
        raise OSError(msg)

    monkeypatch.setattr(os, "fsync", failing_fsync)

    with pytest.raises(se2hass.Se2HassError, match="disk full"):
        state.pair(se2hass.Pairing("http://new:8123", "new"))

    assert not state.paired
    assert (workdir / "state.json").read_text() == before
    assert [p.name for p in workdir.iterdir()] == ["state.json"]


def test_a_state_file_that_cannot_be_used_is_an_error(workdir):
    (workdir / "blocked").write_text("a file, not a directory")
    (workdir / "dir.json").mkdir()

    for name in ["blocked/state.json", "dir.json"]:
        with pytest.raises(se2hass.Se2HassError, match=r"cannot (read|write)"):
            se2hass.State.load(workdir / name)


def state_document(**changes):
    document = {"id": "x", "pairing_code": GOOD_CODE, "pairing": None}
    return json.dumps(fields(**{**document, **changes}))


BAD_PAIRING = {"hass_url": "ftp://x", "webhook_id": "a"}


@pytest.mark.parametrize(
    "document",
    [
        *("{oops", "", "[]", "42", "null", "{}", b"\xff\xfe\x00\x80"),
        *(state_document(id=value) for value in [ABSENT, "", 5]),
        *(
            state_document(pairing_code=c)
            for c in [ABSENT, "abc", 5, GOOD_CODE.lower()]
        ),
        *(state_document(pairing=p) for p in ["x", [], {}, BAD_PAIRING]),
    ],
)
def test_a_corrupt_state_file_is_an_error(workdir, document):
    path = workdir / "state.json"
    content = document if isinstance(document, bytes) else document.encode()
    path.write_bytes(content)

    with pytest.raises(se2hass.Se2HassError, match="corrupt state file"):
        se2hass.State.load(path)

    assert path.read_bytes() == content


# --- the pairing code -----------------------------------------------------


def wrong_codes(state, count):
    for _ in range(count):
        assert not state.check_code(OTHER_CODE)


@pytest.mark.parametrize(
    "candidate",
    [
        "ABCDE-FGHJK",
        GOOD_CODE.lower(),
        "ABCDE FGHJK".lower(),
        " A-B C D-E F G-H J K ".lower(),
    ],
)
def test_a_code_is_right_however_it_is_written(unsaved_state, candidate):
    assert unsaved_state.check_code(candidate)
    assert unsaved_state.retry_after() == 0


@pytest.mark.parametrize(
    "candidate",
    [
        *("", "ABCDE-FGHJ", "ABCDE-FGHJKM", OTHER_CODE, "ÄBCDE-FGHJK"),
        *("\ud800", None, 12345, [GOOD_CODE], {}, True),
    ],
)
def test_a_wrong_code_is_wrong(unsaved_state, candidate):
    assert not unsaved_state.check_code(candidate)


def test_five_wrong_codes_in_a_row_lock_out_until_the_time_is_up(
    unsaved_state, clock, caplog
):
    wrong_codes(unsaved_state, 4)
    assert unsaved_state.retry_after() == 0

    wrong_codes(unsaved_state, 1)

    assert unsaved_state.retry_after() == LOCKOUT == 60
    assert any("5 wrong pairing codes" in m for m in warnings(caplog))
    clock.advance(10.2)
    assert unsaved_state.retry_after() == 50
    assert not unsaved_state.check_code(GOOD_CODE)
    clock.advance(LOCKOUT - 11)
    assert not unsaved_state.check_code(GOOD_CODE)
    clock.advance(1)
    assert unsaved_state.retry_after() == 0
    # The count started again.
    wrong_codes(unsaved_state, 4)
    assert unsaved_state.retry_after() == 0


def test_the_right_code_resets_the_count(unsaved_state):
    wrong_codes(unsaved_state, 4)
    assert unsaved_state.check_code(GOOD_CODE)

    wrong_codes(unsaved_state, 4)

    assert unsaved_state.retry_after() == 0
    assert unsaved_state.check_code(GOOD_CODE)


# --- the pairing ----------------------------------------------------------


def from_request(**changes):
    return se2hass.Pairing.from_request(
        fields(**{"hass_url": "http://ha", "webhook_id": HOOK, **changes})
    )


def test_a_valid_request_is_a_pairing():
    pairing = from_request(hass_url="https://ha:8123", code="x", extra=1)

    assert pairing == se2hass.Pairing("https://ha:8123", HOOK)
    assert len(from_request(webhook_id="A-b_9" * 51 + "x").webhook_id) == 256


@pytest.mark.parametrize(
    "url",
    [
        *("file:///etc/passwd", "ftp://ha/x", "javascript:alert(1)"),
        *("http://", "http:///path", "//ha", "ha:8123", "ha"),
        *("http://ha:99999", "http://ha:abc", "", None, 5, ["http://ha"]),
        ABSENT,
    ],
)
def test_a_bad_url_is_rejected(url):
    with pytest.raises(ValueError, match="hass_url"):
        from_request(hass_url=url)


@pytest.mark.parametrize(
    "webhook_id",
    ["", "a/b", "a b", "a\n", "../x", "é", "a" * 257, 123, None, ["a"], ABSENT],
)
def test_a_bad_webhook_id_is_rejected(webhook_id):
    with pytest.raises(ValueError, match="webhook_id"):
        from_request(webhook_id=webhook_id)


@pytest.mark.parametrize(
    ("hass_url", "webhook_id", "expected"),
    [
        ("http://ha:8123", "hook", "http://ha:8123/api/webhook/hook"),
        ("http://ha:8123/", "hook", "http://ha:8123/api/webhook/hook"),
        ("https://ha.org/ha", "hook", "https://ha.org/ha/api/webhook/hook"),
        ("https://ha.org/ha/", "hook", "https://ha.org/ha/api/webhook/hook"),
        ("http://ha:8123/?x=1#f", "hook", "http://ha:8123/api/webhook/hook"),
        ("http://ha", "a b/c?d", "http://ha/api/webhook/a%20b%2Fc%3Fd"),
    ],
)
def test_the_webhook_url_joins_the_base_path_and_quotes_the_id(
    hass_url, webhook_id, expected
):
    assert se2hass.Pairing(hass_url, webhook_id).webhook_url() == expected


# --- the pairing API ------------------------------------------------------


def test_pairing_answers_200_and_writes_the_file(api, workdir):
    reply = api.pair(code=api.code.lower().replace("-", " "))

    assert reply.status == 200
    assert reply.json == {"status": "paired"}
    assert reply.headers["content-type"] == "application/json"
    assert int(reply.headers["content-length"]) == len(reply.body)
    expected = se2hass.Pairing("http://ha:8123", HOOK)
    assert api.state.pairing == expected
    assert se2hass.State.load(workdir / "state.json").pairing == expected


@pytest.mark.parametrize(
    ("changes", "status", "error"),
    [
        *(
            ({"hass_url": u}, 400, "hass_url")
            for u in ["ftp://ha", "nonsense", 5]
        ),
        *(({"webhook_id": w}, 400, "webhook_id") for w in ["", "a/b", ABSENT]),
        *(({"code": c}, 401, "required") for c in [ABSENT, None]),
        *(
            ({"code": c}, 403, "wrong")
            for c in ["WRONG", OTHER_CODE, "", 12345, [1], {}, "\ud800"]
        ),
        # The code is checked before the rest of the request.
        ({"code": ABSENT, "hass_url": "ftp://ha"}, 401, "required"),
        ({"code": "WRONG", "hass_url": "ftp://ha"}, 403, "wrong"),
    ],
)
def test_a_bad_request_is_refused_and_not_paired(api, changes, status, error):
    reply = api.pair(**changes)

    assert reply.status == status
    assert error in reply.json["error"]
    assert not api.state.paired


@pytest.mark.parametrize(
    "body", [b"not json", b"", b"\xff\xfe", b"{", b"[1, 2]", b'"x"', b"null"]
)
def test_a_body_that_is_not_a_json_object_is_a_400(api, body):
    reply = api.post(body)

    assert reply.status == 400
    assert "JSON" in reply.json["error"]


@pytest.mark.parametrize(
    ("headers", "status", "error"),
    [
        *(
            ([f"Content-Length: {n}"], 400, "not a number")
            for n in ["abc", "-5", "+5", "1.5", ""]
        ),
        ([], 411, "required"),
        (["Content-Length: 4097"], 413, "larger than 4096"),
    ],
)
def test_a_bad_content_length_is_refused(api, headers, status, error):
    reply = api.raw(*headers)

    assert reply.status == status
    assert error in reply.json["error"]


def test_a_body_of_the_largest_size_is_read(api):
    body = json.dumps(api.payload()).encode()

    assert api.post(body.ljust(se2hass.MAX_BODY_BYTES)).status == 200


@pytest.mark.parametrize(
    ("method", "path"),
    [("POST", p) for p in ["/", "/other", "/pair/", "/pair?x=1"]]
    + [(m, "/pair") for m in ["GET", "PUT", "DELETE", "HEAD"]],
)
def test_anything_but_a_post_to_pair_is_a_404(api, method, path):
    reply = api.request(method, path, b"{}" if method == "POST" else None)

    assert reply.status == 404
    assert not api.state.paired
    if method != "HEAD":
        assert reply.json == {"error": "not found"}


def test_a_malformed_request_line_is_a_400(api):
    with socket.create_connection(("127.0.0.1", api.port), timeout=5) as sock:
        sock.sendall(b"BOGUS\r\n\r\n")
        chunks = iter(lambda: sock.recv(4096), b"")  # until the server closes
        reply = b"".join(chunks)

    assert b"Error code: 400" in reply


def test_pairing_is_refused_after_five_wrong_codes_until_the_lockout_ends(api):
    for _ in range(5):
        assert api.pair(code="WRONG").status == 403

    reply = api.pair(code="WRONG")
    assert reply.status == 429
    assert reply.headers["retry-after"] == "60"
    assert "error" in reply.json
    # The order of the API: the right code is refused, a bad body is a 400.
    assert api.pair().status == 429
    assert api.post(b"not json").status == 400
    assert not api.state.paired

    api.clock.advance(15)
    assert api.pair().headers["retry-after"] == "45"
    api.clock.advance(LOCKOUT)
    assert api.pair().status == 200


def test_the_right_code_resets_and_a_missing_code_does_not_count(api):
    for _ in range(8):
        assert api.pair(code=ABSENT).status == 401
    for _ in range(4):
        api.pair(code="WRONG")
    assert api.pair().status == 200
    for _ in range(4):
        assert api.pair(code="WRONG").status == 403

    assert api.pair().status == 200


def test_pairing_again_with_the_code_replaces_the_pairing(api, workdir):
    api.pair()

    assert api.pair(hass_url="https://o:8443/ha", webhook_id="2").status == 200
    assert api.pair(code="WRONG", webhook_id="3").status == 403

    new = se2hass.Pairing("https://o:8443/ha", "2")
    assert api.state.pairing == new
    assert se2hass.State.load(workdir / "state.json").pairing == new


def test_the_code_is_in_no_reply(api):
    replies = [
        api.pair(),
        api.pair(hass_url="x"),
        api.pair(code=ABSENT),
        api.post(b"not json"),
        api.request("GET", "/pair"),
        api.post({}, "/other"),
        api.raw(),
        api.raw("Content-Length: 5000"),
        *(api.pair(code="WRONG") for _ in range(5)),
        api.pair(),
    ]

    assert replies[-1].status == 429
    for reply in replies:
        text = repr(reply.headers) + reply.body.decode()
        assert api.code not in text
        assert api.state.pairing_code not in text


def test_on_paired_is_called_without_arguments_after_a_pairing(api):
    called = threading.Event()
    api.server.on_paired = called.set
    api.pair(code="WRONG")
    api.pair(hass_url="x")
    assert not called.is_set()

    assert api.pair().status == 200

    assert called.wait(5)


def test_a_failed_save_is_a_500(make_api, blocked_state):
    api = make_api(state=blocked_state)
    called = threading.Event()
    api.server.on_paired = called.set

    reply = api.pair()

    assert reply.status == 500
    assert reply.json == {"error": "cannot save the pairing"}
    assert api.code not in repr(reply.headers) + reply.body.decode()
    assert not blocked_state.paired
    assert not called.is_set()


@HTTP_AND_HTTPS
def test_idle_clients_do_not_block_another(make_api, tls):
    api = make_api(tls=tls)
    idle = [socket.create_connection(("127.0.0.1", api.port), 5) for _ in "abc"]
    try:
        reply = api.pair()
    finally:
        for sock in idle:
            sock.close()

    assert reply.status == 200


def test_the_server_listens_on_all_interfaces_without_one(state):
    server = se2hass.PairingServer(None, 0, state)
    server.start()
    try:
        reply = Api(server, state).pair()
    finally:
        server.stop()

    assert reply.status == 200
    assert ipaddress.ip_address(server.server_address[0]).is_unspecified
    dual_stack = socket.has_ipv6 and socket.has_dualstack_ipv6()
    assert server.address_family == (
        socket.AF_INET6 if dual_stack else socket.AF_INET
    )


def test_without_dual_stack_the_ipv4_address_is_used(state, monkeypatch):
    monkeypatch.setattr(socket, "has_dualstack_ipv6", lambda: False)
    server = se2hass.PairingServer(None, 0, state)
    server.start()
    try:
        reply = Api(server, state).pair()
    finally:
        server.stop()

    assert reply.status == 200
    assert server.address_family == socket.AF_INET


@pytest.mark.parametrize(
    ("interface", "message"),
    [
        ("no-such-host.invalid", "cannot resolve"),
        ("192.0.2.1", "cannot listen"),
    ],
)
def test_an_interface_that_cannot_be_used_is_an_error(
    state, interface, message
):
    with pytest.raises(se2hass.Se2HassError, match=message):
        se2hass.PairingServer(interface, 0, state)


# --- TLS ------------------------------------------------------------------


def test_pairing_over_https(make_api, workdir):
    api = make_api(tls=True)

    assert api.pair().status == 200
    assert se2hass.State.load(workdir / "state.json").paired


def test_a_client_that_does_not_trust_the_cert_fails(make_api):
    api = make_api(tls=True)
    api.client_context = ssl.create_default_context()

    with pytest.raises(ssl.SSLCertVerificationError):
        api.pair()

    assert not api.state.paired


def test_plain_http_to_the_tls_port_fails_and_the_server_goes_on(make_api):
    api = make_api(tls=True)
    trusting, api.client_context = api.client_context, None
    with pytest.raises((http.client.HTTPException, OSError)):
        api.pair()
    assert not api.state.paired

    api.client_context = trusting

    assert api.pair().status == 200


# --- the webhook ----------------------------------------------------------


def client_context(kind, tls_files):
    if kind == "trusting":
        return ssl.create_default_context(cafile=tls_files.cert)
    context = ssl.create_default_context()
    if kind == "insecure":
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


@pytest.mark.parametrize(
    ("base", "path"),
    [
        ("", "/api/webhook/hook1"),
        ("/ha", "/ha/api/webhook/hook1"),
        ("/ha/", "/ha/api/webhook/hook1"),
    ],
)
def test_a_line_is_posted_to_the_webhook(hass, clock, base, path):
    pairing = se2hass.Pairing(hass.pairing.hass_url + base, HOOK)

    assert se2hass.WebhookPusher(clock=clock).push(pairing, '{"a": 1}')

    assert hass.requests == [
        Pushed("POST", path, "application/json", b'{"a": 1}')
    ]


def test_a_2xx_answer_is_a_success(hass, clock):
    pusher = se2hass.WebhookPusher(clock=clock)

    for status in [200, 201, 204, 299]:
        hass.status = status
        assert pusher.push(hass.pairing, "{}")


@pytest.mark.parametrize("status", [199, 301, 400, 404, 500, 503])
def test_another_answer_backs_off_and_resumes(hass, clock, caplog, status):
    hass.status = status
    pusher = se2hass.WebhookPusher(clock=clock)

    assert not pusher.push(hass.pairing, "1")
    assert any(f"HTTP status {status}" in m for m in warnings(caplog))
    clock.advance(RETRY - 1)
    assert not pusher.push(hass.pairing, "2")
    clock.advance(1)
    assert not pusher.push(hass.pairing, "3")
    hass.status = 200
    clock.advance(RETRY - 1)
    assert not pusher.push(hass.pairing, "4")
    clock.advance(1)
    assert pusher.push(hass.pairing, "5")

    assert hass.bodies == ["1", "3", "5"]


def test_a_host_that_is_not_reachable_backs_off(clock, caplog):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        url = f"http://127.0.0.1:{sock.getsockname()[1]}"
    pairing = se2hass.Pairing(url, HOOK)
    pusher = se2hass.WebhookPusher(clock=clock)

    assert not pusher.push(pairing, "{}")
    assert not pusher.push(pairing, "{}")
    clock.advance(RETRY)
    assert not pusher.push(pairing, "{}")

    log = messages(caplog)
    assert sum("webhook push failed" in m for m in log) == 2
    assert any("ConnectionRefusedError" in m for m in log)
    assert sum("dropped a line" in m for m in log) == 1


@pytest.mark.parametrize(
    ("kind", "pushed"),
    [("insecure", True), ("trusting", True), ("verifying", False)],
)
def test_an_https_webhook_with_a_self_signed_cert(
    make_hass, clock, tls_files, caplog, kind, pushed
):
    hass = make_hass(tls=True)
    pusher = se2hass.WebhookPusher(client_context(kind, tls_files), clock)

    assert pusher.push(hass.pairing, '{"a": 1}') is pushed

    assert len(hass.requests) == pushed
    refused = any("CERTIFICATE_VERIFY_FAILED" in m for m in warnings(caplog))
    assert refused is (not pushed)


# --- run ------------------------------------------------------------------


class RecordingPusher:
    def __init__(self):
        self.pushed = []

    def push(self, pairing, text):
        self.pushed.append((pairing, text))

    @property
    def lines(self):
        return [text for _pairing, text in self.pushed]


@pytest.fixture
def pusher():
    return RecordingPusher()


def test_unpaired_lines_are_not_pushed(state, advertiser, pusher):
    se2hass.run([one_line(1), one_line(2)], state, advertiser, pusher)

    assert pusher.pushed == []


def test_paired_lines_are_pushed_in_order_with_the_pairing_of_the_moment(
    state, advertiser, pusher
):
    first = se2hass.Pairing("http://one:8123", "one")
    second = se2hass.Pairing("http://two:8123", "two")

    def lines():
        yield one_line(1)
        state.pair(first)
        yield one_line(2)
        yield one_line(3)
        state.pair(second)
        yield one_line(4)

    se2hass.run(lines(), state, advertiser, pusher)

    assert [p for p, _ in pusher.pushed] == [first, first, second]
    assert pusher.lines == [one_line(n).rstrip("\n") for n in (2, 3, 4)]


def test_nan_becomes_null_and_events_are_forwarded_unchanged(
    paired_state, advertiser, pusher
):
    nan = '{"inverters": {"I1": {"Pmax": NaN, "Pac": 1.5, "Z": -Infinity}}}\n'
    events = line(
        inverters={"7F104920": {"Pac": 1234.5, "Eday": 10}},
        optimizers={"1": {"Voltage": 30.0}},
        events={"7F104920": {"Event1": "Fri Jan  1 12:38:09 2016", "Code": 3}},
    )

    se2hass.run([nan, events], paired_state, advertiser, pusher)

    assert pusher.lines == [
        '{"inverters": {"I1": {"Pmax": null, "Pac": 1.5, "Z": null}}}',
        events.rstrip("\n"),
    ]


@pytest.mark.parametrize(
    ("bad", "reason"),
    [
        ("{oops\n", "Expecting"),
        *((text, "not a JSON object") for text in ["[1]\n", "42\n", "null\n"]),
        ('{"a": 1e999}\n', "JSON"),
    ],
)
def test_a_bad_line_is_skipped_with_a_warning_with_its_number(
    paired_state, advertiser, pusher, caplog, bad, reason
):
    lines = ["\n", one_line(1), "  \n", bad, "", one_line(2)]

    se2hass.run(lines, paired_state, advertiser, pusher)

    assert len(pusher.pushed) == 2
    (warning,) = warnings(caplog)
    assert warning.startswith("line 4: ")
    assert reason in warning


@pytest.mark.parametrize("inverters", [{}, None, [], "x", 5], ids=repr)
def test_inverters_that_are_empty_or_odd_do_not_crash(
    paired_state, started, pusher, fake_zc, inverters
):
    se2hass.run(
        [line(inverters=inverters), "{}\n"], paired_state, started, pusher
    )

    assert len(pusher.pushed) == 2
    assert fake_zc.updated == []


def test_the_serials_reach_the_announcement(state, started, pusher, fake_zc):
    two = line(inverters={"B2": {}, "A1": {}})

    se2hass.run(
        [one_line(1, "B2"), two, one_line(2, "A1")], state, started, pusher
    )

    assert [txt(i)["serials"] for i in fake_zc.updated] == ["B2", "A1,B2"]


def test_the_golden_data_announces_both_serials(
    golden, paired_state, started, pusher, fake_zc
):
    lines = golden("json", "7f104920").read_text().splitlines()

    se2hass.run(lines, paired_state, started, pusher)

    assert txt(fake_zc.updated[-1])["serials"] == "7F104920,7F104A16"
    assert len(pusher.pushed) == len(lines)


# --- the advertiser -------------------------------------------------------


def test_the_service_is_registered_at_start_before_any_data(
    fake_zc, state, monkeypatch
):
    monkeypatch.setattr(
        se2hass.importlib.metadata, "version", lambda _n: "1.2.3"
    )
    advertiser = se2hass.Advertiser(fake_zc, state, "solar")
    assert fake_zc.registered == []

    advertiser.start(1234, "https", ["10.0.0.2", "2001:db8::1"])

    (info,) = fake_zc.registered
    assert fake_zc.updated == []
    assert info.type == "_semonitor._tcp.local."
    assert info.name == f"se2hass-{state.id}._semonitor._tcp.local."
    assert (info.port, info.server) == (1234, "solar.local.")
    assert info.parsed_addresses() == ["10.0.0.2", "2001:db8::1"]
    assert txt(info) == {
        "id": state.id,
        "version": "1.2.3",
        "scheme": "https",
        "paired": "false",
        "serials": "",
    }


def test_the_version_is_unknown_without_the_package(
    fake_zc, state, monkeypatch
):
    def not_found(_name):
        raise se2hass.importlib.metadata.PackageNotFoundError

    monkeypatch.setattr(se2hass.importlib.metadata, "version", not_found)

    se2hass.Advertiser(fake_zc, state, "solar").start(1, "http", ["::1"])

    assert txt(fake_zc.registered[0])["version"] == "unknown"


def test_paired_flips_after_a_refresh_and_the_code_is_never_sent(
    started, fake_zc, state
):
    state.pair(se2hass.Pairing("http://ha:8123", HOOK))
    assert txt(fake_zc.registered[0])["paired"] == "false"

    started.add_serials(["A1"])
    started.refresh()

    assert txt(fake_zc.updated[-1])["paired"] == "true"
    for info in [*fake_zc.registered, *fake_zc.updated]:
        assert state.pairing_code not in repr(info.properties)
        assert HOOK not in repr(info.properties)


def test_a_new_serial_updates_the_announcement_once(started, fake_zc):
    for serials in (["B2", "A1"], ["A1"], [], ["B2", "C3"]):
        started.add_serials(serials)

    assert [txt(i)["serials"] for i in fake_zc.updated] == ["A1,B2", "A1,B2,C3"]


def test_nothing_is_updated_before_start_and_after_close(advertiser, fake_zc):
    advertiser.add_serials(["A1"])
    advertiser.refresh()
    assert fake_zc.updated == []

    advertiser.start(1234, "http", ["127.0.0.1"])
    assert txt(fake_zc.registered[0])["serials"] == "A1"
    advertiser.close()
    advertiser.refresh()
    advertiser.add_serials(["B2"])

    assert fake_zc.closed == 1
    assert fake_zc.updated == []


def test_a_failing_update_is_only_a_warning(started, fake_zc, caplog):
    fake_zc.update_error = OSError("network is down")

    started.add_serials(["A1"])
    started.refresh()
    fake_zc.update_error = None
    started.refresh()

    log = warnings(caplog)
    assert len(log) == 2
    assert "cannot update the mDNS announcement: network is down" in log[0]
    assert len(fake_zc.updated) == 1


@pytest.mark.parametrize(
    "error", [OSError("no multicast"), ZeroconfError("bad name")]
)
def test_a_failing_registration_is_an_error(advertiser, fake_zc, error):
    fake_zc.register_error = error

    with pytest.raises(se2hass.Se2HassError, match="cannot announce"):
        advertiser.start(1234, "http", ["127.0.0.1"])

    advertiser.refresh()
    assert fake_zc.updated == []


# --- the addresses --------------------------------------------------------


def fake_adapter(*addresses):
    return SimpleNamespace(
        ips=[
            SimpleNamespace(ip=address, is_IPv6=isinstance(address, tuple))
            for address in addresses
        ]
    )


@pytest.fixture
def adapters(monkeypatch):
    found = [
        fake_adapter("127.0.0.1", ("::1", 0, 1)),
        fake_adapter("192.168.1.5", ("fe80::1", 0, 2), ("2001:db8::1", 0, 0)),
        fake_adapter("169.254.3.4", "10.0.0.2", "192.168.1.5"),
    ]
    monkeypatch.setattr(se2hass.ifaddr, "get_adapters", lambda: found)


@pytest.mark.usefixtures("adapters")
@pytest.mark.parametrize(
    ("ipv6", "expected"),
    [
        (False, ["192.168.1.5", "10.0.0.2"]),
        (True, ["192.168.1.5", "2001:db8::1", "10.0.0.2"]),
    ],
)
def test_the_local_addresses_are_the_usable_ones(ipv6, expected):
    assert se2hass.local_addresses(include_ipv6=ipv6) == expected


# --- main end to end ------------------------------------------------------


def test_main_pushes_every_line_to_home_assistant(
    golden, workdir, hass, run_se2hass, server_args, zc_factory, caplog
):
    state = se2hass.State.load(workdir / "state.json")
    state.pair(hass.pairing)
    path = workdir / "in.json"
    path.write_bytes(golden("json", "7f104920").read_bytes())
    expected = [text for text in path.read_text().splitlines() if text.strip()]

    code, out, _err = run_se2hass(path, *server_args)

    assert code == 0
    assert out == ""
    assert len(hass.requests) == len(expected) == 339
    assert hass.bodies == [text.replace("NaN", "null") for text in expected]
    for pushed in hass.requests:
        assert pushed.path == "/api/webhook/hook1"
        assert pushed.content_type == "application/json"
        json.loads(pushed.body, parse_constant=pytest.fail)
    (zc,) = zc_factory.instances
    assert txt(zc.registered[0])["paired"] == "true"
    assert txt(zc.updated[-1])["serials"] == "7F104920,7F104A16"
    assert zc.registered[0].parsed_addresses() == ["127.0.0.1"]
    assert zc.closed == 1
    shown = f"{state.pairing_code[:5]}-{state.pairing_code[5:]}"
    assert f"pairing code: {shown}" in messages(caplog)


def test_main_does_not_push_when_not_paired_and_reads_stdin(
    hass, run_se2hass, server_args, zc_factory
):
    code, _out, _err = run_se2hass(*server_args, stdin=one_line(1))

    assert code == 0
    assert hass.requests == []
    assert txt(zc_factory.instances[0].registered[0])["paired"] == "false"


def test_main_logs_the_code_the_address_and_the_plain_http_warning(
    workdir, run_se2hass, server_args, caplog
):
    run_se2hass(*server_args)
    assert not any("not verifying" in m for m in warnings(caplog))
    run_se2hass("-I", *server_args)

    state = se2hass.State.load(workdir / "state.json")
    log = messages(caplog)
    shown = f"{state.pairing_code[:5]}-{state.pairing_code[5:]}"
    assert log.count(f"pairing code: {shown}") == 2
    assert sum("not verifying" in m for m in warnings(caplog)) == 1
    assert "not paired yet" in log
    assert any("plain HTTP" in m for m in log)
    assert any(m.startswith("listening on 127.0.0.1 port ") for m in log)
    assert any(m.endswith("(http)") for m in log)


def test_main_serves_https_with_a_cert(
    run_se2hass, server_args, tls_files, caplog, zc_factory
):
    code, _out, _err = run_se2hass(
        *("-C", tls_files.cert, "-k", tls_files.key), *server_args
    )

    log = messages(caplog)
    assert code == 0
    assert any(m.endswith("(https)") for m in log)
    assert not any("plain HTTP" in m for m in log)
    assert txt(zc_factory.instances[0].registered[0])["scheme"] == "https"


@pytest.mark.parametrize(
    ("argv", "name", "server"),
    [
        (["-H", "solar"], "box.example.org", "solar.local."),
        (["--hostname", "Solar-1"], "box", "Solar-1.local."),
        ([], "box.example.org", "box.local."),
        ([], "box", "box.local."),
    ],
)
def test_main_announces_the_host_name(
    run_se2hass, server_args, zc_factory, monkeypatch, argv, name, server
):
    monkeypatch.setattr(socket, "gethostname", lambda: name)

    run_se2hass(*argv, *server_args)

    assert zc_factory.instances[0].registered[0].server == server


@pytest.mark.usefixtures("adapters")
def test_main_announces_the_local_addresses_without_an_interface(
    run_se2hass, workdir, zc_factory
):
    run_se2hass("-p", 0, "-S", workdir / "state.json")

    (info,) = zc_factory.instances[0].registered
    addresses = set(info.parsed_addresses())
    assert {"192.168.1.5", "10.0.0.2"} <= addresses
    assert not {"127.0.0.1", "169.254.3.4", "::1", "fe80::1"} & addresses


def test_pairing_while_the_lines_flow(workdir, hass, caplog, zc_factory):
    args = se2hass.build_parser().parse_args(
        ["-i", "127.0.0.1", "-p", "0", "-S", str(workdir / "state.json")]
    )
    outcome = {}

    def lines():
        yield one_line(1)
        port = next(
            int(m.split()[-2])
            for m in messages(caplog)
            if m.startswith("listening on ")
        )
        state = se2hass.State.load(workdir / "state.json")
        api = Api(SimpleNamespace(server_address=("", port)), state)
        outcome["reply"] = api.pair(hass_url=hass.pairing.hass_url)
        outcome["updated"] = wait_for(lambda: zc_factory.instances[0].updated)
        yield one_line(2)

    se2hass.run_service(args, lines())

    (zc,) = zc_factory.instances
    assert outcome["reply"].status == 200
    assert outcome["updated"]
    assert hass.bodies == [one_line(2).rstrip("\n")]
    assert txt(zc.registered[0])["paired"] == "false"
    assert txt(zc.updated[-1])["paired"] == "true"
    assert zc.closed == 1


# --- SIGTERM --------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="needs SIGTERM")
def test_sigterm_stops_se2hass_cleanly(workdir):
    env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
    command = [
        *(sys.executable, "-m", "se.se2hass", "-i", "127.0.0.1", "-p", "0"),
        *("-S", str(workdir / "state.json")),
    ]
    with subprocess.Popen(
        command,
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
    ) as process:
        # A hung process ends the loop below when it is killed.
        watchdog = threading.Timer(30, process.kill)
        watchdog.start()
        log = ""
        try:
            for text in process.stderr:
                log += text
                if "announced" in text:
                    break
            else:
                if "mDNS" in log:
                    pytest.skip(f"mDNS does not start in this sandbox: {log}")
                pytest.fail(f"se2hass did not start: {log}")
            assert "pairing code: " in log
            process.send_signal(signal.SIGTERM)
            assert process.wait(timeout=10) == 0
        finally:
            watchdog.cancel()
            process.kill()


def test_sigterm_is_not_changed_outside_the_main_thread():
    # signal handlers can only be set in the main thread, the block still runs
    ran = []

    def run():
        with se2hass.sigterm_exits():
            ran.append(True)

    thread = threading.Thread(target=run)
    thread.start()
    thread.join()

    assert ran == [True]
