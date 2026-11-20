"""
Push the semonitor output to Home Assistant.

Reads the JSON Lines of semonitor and does two things:

1. Pushes every line to a Home Assistant webhook, once paired.
2. Runs a small HTTP API (``POST /pair``) and an mDNS advertisement
   (``_semonitor._tcp.local.``) so that Home Assistant can discover se2hass
   and hand over the webhook, protected by a pairing code.
"""

import argparse
import hmac
import http.client
import importlib.metadata
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import signal
import socket
import ssl
import string
import sys
import tempfile
import threading
import time
from contextlib import closing, contextmanager
from dataclasses import asdict, dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import override
from urllib.parse import quote, urlsplit, urlunsplit

import ifaddr
from zeroconf import Error as ZeroconfError, ServiceInfo, Zeroconf

from se.metrics import open_input
from se.se2json import convert

DEFAULT_PORT = 22222
MAX_PORT = 65535
DEFAULT_STATE_FILE = "/var/lib/semonitor/se2hass.json"
SERVICE_TYPE = "_semonitor._tcp.local."
SERVICE_NAME_PREFIX = "se2hass"

PAIR_PATH = "/pair"
WEBHOOK_PATH = "/api/webhook/"
URL_SCHEMES = ("http", "https")
WEBHOOK_ID_PATTERN = re.compile(r"[A-Za-z0-9_-]{1,256}")

# Without the look-alike characters 0, O, 1, I and L: 31 symbols, ~49.5 bits.
CODE_ALPHABET = "23456789" + "".join(
    letter for letter in string.ascii_uppercase if letter not in "ILO"
)
CODE_LENGTH = 10
CODE_GROUP_LENGTH = 5
CODE_SEPARATORS = "- "
MAX_WRONG_CODES = 5
LOCKOUT_SECONDS = 60

MAX_BODY_BYTES = 4096
CONNECTION_TIMEOUT = 10
PUSH_TIMEOUT = 5
RETRY_SECONDS = 60

LOG = logging.getLogger(__name__)


class Se2HassError(Exception):
    """An error to report to the user, without a traceback."""


class RequestError(Exception):
    """A request that is answered with an HTTP error status."""

    def __init__(self, status, message, retry_after=None):
        """
        Remember how the request is answered.

        Args:
            status: The HTTP status to answer with.
            message: The text for the "error" key of the JSON answer.
            retry_after: Seconds for the Retry-After header, or None.
        """
        super().__init__(message)
        self.status = status
        self.message = message
        self.retry_after = retry_after


# Pairing code


def generate_code():
    """Return a new random pairing code of CODE_LENGTH unambiguous symbols."""
    return "".join(secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH))


def is_valid_code(code):
    """Tell whether the text is a normalized pairing code."""
    return (
        isinstance(code, str)
        and len(code) == CODE_LENGTH
        and all(symbol in CODE_ALPHABET for symbol in code)
    )


def display_code(code):
    """Return the code the way it is shown to the user: XXXXX-XXXXX."""
    return f"{code[:CODE_GROUP_LENGTH]}-{code[CODE_GROUP_LENGTH:]}"


def normalize_code(text):
    """Return the text in upper case, without dashes and spaces."""
    for separator in CODE_SEPARATORS:
        text = text.replace(separator, "")
    return text.upper()


def codes_match(expected, candidate):
    """
    Compare a code given by a client with the real one, in constant time.

    Args:
        expected: The normalized pairing code.
        candidate: What the client sent, anything that was in the JSON.

    Returns:
        True if the candidate is the code, however it is written.
    """
    if not isinstance(candidate, str):
        return False
    return hmac.compare_digest(
        normalize_code(candidate).encode(), expected.encode()
    )


class CodeGuard:
    """Check pairing codes, and lock out a client that guesses."""

    def __init__(self, code, clock=time.monotonic):
        """
        Guard a pairing code.

        Args:
            code: The normalized pairing code.
            clock: A function returning the time in seconds, for the lockout.
        """
        self._code = code
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._locked_until = None

    def retry_after(self):
        """Return the seconds left of a lockout, 0 when not locked out."""
        with self._lock:
            return self._seconds_locked()

    def verify(self, candidate):
        """
        Check a code, counting the wrong ones.

        A correct code resets the count of wrong codes. A wrong code counts
        and, after MAX_WRONG_CODES in a row, locks out for LOCKOUT_SECONDS.
        While locked out every code is refused, even the right one.

        Args:
            candidate: What the client sent.

        Returns:
            True if the code is right and the guard is not locked out.
        """
        with self._lock:
            if self._seconds_locked():
                return False
            if codes_match(self._code, candidate):
                self._failures = 0
                return True
            self._record_failure()
            return False

    def _seconds_locked(self):
        if self._locked_until is None:
            return 0
        remaining = self._locked_until - self._clock()
        if remaining > 0:
            return math.ceil(remaining)
        self._locked_until = None
        self._failures = 0
        return 0

    def _record_failure(self):
        self._failures += 1
        if self._failures >= MAX_WRONG_CODES:
            self._locked_until = self._clock() + LOCKOUT_SECONDS
            LOG.warning(
                "%d wrong pairing codes in a row, refusing pairing for %d s",
                self._failures,
                LOCKOUT_SECONDS,
            )


# Pairing


def is_valid_hass_url(url):
    """Tell whether the text is an http or https URL with a host."""
    if not isinstance(url, str):
        return False
    try:
        parts = urlsplit(url)
        _ = parts.port
    except ValueError:
        return False
    return parts.scheme in URL_SCHEMES and bool(parts.hostname)


def is_valid_webhook_id(webhook_id):
    """Tell whether the text is usable as the last part of a webhook URL."""
    return isinstance(webhook_id, str) and bool(
        WEBHOOK_ID_PATTERN.fullmatch(webhook_id)
    )


@dataclass(frozen=True)
class Pairing:
    """Where to push the data: the Home Assistant URL and the webhook id."""

    hass_url: str
    webhook_id: str

    @classmethod
    def from_request(cls, payload):
        """
        Build a pairing from the JSON object a client sent.

        Args:
            payload: A dict with "hass_url" and "webhook_id".

        Returns:
            The validated pairing.

        Raises:
            ValueError: If the URL is not http or https with a host, or the
                webhook id has characters that do not belong in a URL path.
        """
        hass_url = payload.get("hass_url")
        webhook_id = payload.get("webhook_id")
        if not is_valid_hass_url(hass_url):
            msg = "hass_url must be an http or https URL"
            raise ValueError(msg)
        if not is_valid_webhook_id(webhook_id):
            msg = "webhook_id must be 1 to 256 of A-Z, a-z, 0-9, _ and -"
            raise ValueError(msg)
        return cls(hass_url, webhook_id)

    def webhook_url(self):
        """Return the URL of the webhook, the id quoted."""
        parts = urlsplit(self.hass_url)
        path = parts.path.rstrip("/") + WEBHOOK_PATH
        path += quote(self.webhook_id, safe="")
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


# State


def write_private_file(path, text):
    """
    Write a file that only the owner can read, all or nothing.

    The text goes to a temporary file in the same directory (created with mode
    0600) that then replaces the target, so a crash never leaves half a file.
    Missing parent directories are created.

    Args:
        path: A Path, the file to write.
        text: The content.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(
        dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
    )
    temp = Path(temp_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        temp.replace(path)
    except BaseException:
        temp.unlink(missing_ok=True)
        raise


def parse_state(data):
    """
    Pick the parts out of the content of a state file.

    Args:
        data: The parsed JSON of the file.

    Returns:
        A tuple of the id, the pairing code and the Pairing or None.

    Raises:
        TypeError: If the data or the pairing in it is not a JSON object.
        ValueError: If anything is missing or malformed.
    """
    if not isinstance(data, dict):
        msg = "not a JSON object"
        raise TypeError(msg)
    state_id = data.get("id")
    if not isinstance(state_id, str) or not state_id:
        msg = "no valid id"
        raise ValueError(msg)
    code = data.get("pairing_code")
    if not is_valid_code(code):
        msg = "no valid pairing_code"
        raise ValueError(msg)
    stored = data.get("pairing")
    if stored is None:
        return state_id, code, None
    if not isinstance(stored, dict):
        msg = "pairing is not a JSON object"
        raise TypeError(msg)
    return state_id, code, Pairing.from_request(stored)


class State:
    """The persistent state: the id, the pairing code and the pairing."""

    def __init__(self, path, state_id, pairing_code, pairing=None):
        """
        Hold the state of a file, without reading or writing it.

        Args:
            path: A Path, the state file.
            state_id: The random id that names this installation in mDNS.
            pairing_code: The normalized pairing code.
            pairing: The Pairing, or None when not paired.
        """
        self._path = path
        self._id = state_id
        self._pairing_code = pairing_code
        self._pairing = pairing
        self._lock = threading.Lock()

    @classmethod
    def load(cls, path):
        """
        Load the state file, or create it with a new id and pairing code.

        Args:
            path: The state file, a str or Path.

        Returns:
            The State.

        Raises:
            Se2HassError: If the file is unreadable, corrupt, or a new file
                cannot be written.
        """
        path = Path(path)
        try:
            text = path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return cls.create(path)
        except OSError as ex:
            msg = f"cannot read state file {path}: {ex}"
            raise Se2HassError(msg) from ex
        return cls.parse(path, text)

    @classmethod
    def create(cls, path):
        """Create and save a state with a new id and a new pairing code."""
        state = cls(path, secrets.token_hex(8), generate_code())
        state.save()
        return state

    @classmethod
    def parse(cls, path, text):
        """Return the state held by the text of a state file."""
        try:
            return cls(path, *parse_state(json.loads(text)))
        except (TypeError, ValueError) as ex:
            msg = f"corrupt state file {path}: {ex}"
            raise Se2HassError(msg) from ex

    @property
    def id(self):
        """The random id of this installation."""
        return self._id

    @property
    def pairing_code(self):
        """The normalized pairing code."""
        return self._pairing_code

    @property
    def pairing(self):
        """The Pairing, or None when not paired."""
        with self._lock:
            return self._pairing

    @property
    def paired(self):
        """True when there is a pairing."""
        return self.pairing is not None

    def pair(self, pairing):
        """
        Save a new pairing, replacing the one there is.

        The pairing only changes in memory when it was written to the file.

        Args:
            pairing: The new Pairing.

        Raises:
            Se2HassError: If the state file cannot be written.
        """
        with self._lock:
            self._write(pairing)
            self._pairing = pairing

    def save(self):
        """Write the state file."""
        with self._lock:
            self._write(self._pairing)

    def _write(self, pairing):
        document = {
            "id": self._id,
            "pairing_code": self._pairing_code,
            "pairing": None if pairing is None else asdict(pairing),
        }
        try:
            write_private_file(
                self._path, json.dumps(document, indent=2) + "\n"
            )
        except OSError as ex:
            msg = f"cannot write state file {self._path}: {ex}"
            raise Se2HassError(msg) from ex


# Pairing API


class PairingHandler(BaseHTTPRequestHandler):
    """Answer POST /pair, and 404 for everything else."""

    timeout = CONNECTION_TIMEOUT
    server_version = "se2hass"

    @override
    def do_POST(self):
        """Pair when the request is a good POST to /pair."""
        if self.path != PAIR_PATH:
            self.answer_not_found()
            return
        try:
            pairing = self._pairing_from_request()
        except RequestError as ex:
            self._reply(ex.status, {"error": ex.message}, ex.retry_after)
            return
        self._save_pairing(pairing)

    def answer_not_found(self):
        """Answer 404, whatever was asked."""
        self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})

    @override
    def send_error(self, code, message=None, explain=None):
        """Answer 404 to a method that is not supported, not 501."""
        if code == HTTPStatus.NOT_IMPLEMENTED:
            self.answer_not_found()
        else:
            super().send_error(code, message, explain)

    @override
    def log_message(self, fmt, *args):
        """Send the request log to logging, at DEBUG."""
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    def _pairing_from_request(self):
        payload = self._read_payload()
        self._check_code(payload.get("code"))
        try:
            return Pairing.from_request(payload)
        except ValueError as ex:
            raise RequestError(HTTPStatus.BAD_REQUEST, str(ex)) from ex

    def _read_payload(self):
        body = self.rfile.read(self._content_length())
        try:
            payload = json.loads(body)
        except (ValueError, RecursionError) as ex:
            msg = "the body is not JSON"
            raise RequestError(HTTPStatus.BAD_REQUEST, msg) from ex
        if not isinstance(payload, dict):
            msg = "the body is not a JSON object"
            raise RequestError(HTTPStatus.BAD_REQUEST, msg)
        return payload

    def _content_length(self):
        header = self.headers.get("Content-Length")
        if header is None:
            msg = "Content-Length is required"
            raise RequestError(HTTPStatus.LENGTH_REQUIRED, msg)
        if not (header.isascii() and header.isdigit()):
            msg = "Content-Length is not a number"
            raise RequestError(HTTPStatus.BAD_REQUEST, msg)
        if int(header) > MAX_BODY_BYTES:
            msg = f"the body is larger than {MAX_BODY_BYTES} bytes"
            raise RequestError(HTTPStatus.CONTENT_TOO_LARGE, msg)
        return int(header)

    def _check_code(self, code):
        guard = self.server.guard
        retry_after = guard.retry_after()
        if retry_after:
            msg = "too many wrong pairing codes, try again later"
            raise RequestError(HTTPStatus.TOO_MANY_REQUESTS, msg, retry_after)
        if code is None:
            msg = "the pairing code is required"
            raise RequestError(HTTPStatus.UNAUTHORIZED, msg)
        if not guard.verify(code):
            LOG.warning("wrong pairing code from %s", self.client_address[0])
            msg = "the pairing code is wrong"
            raise RequestError(HTTPStatus.FORBIDDEN, msg)

    def _save_pairing(self, pairing):
        try:
            self.server.state.pair(pairing)
        except Se2HassError:
            LOG.exception("cannot save the pairing")
            self._reply(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                {"error": "cannot save the pairing"},
            )
            return
        LOG.info("paired with %s", pairing.hass_url)
        self._reply(HTTPStatus.OK, {"status": "paired"})
        self.server.on_paired()

    def _reply(self, status, payload, retry_after=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        self.wfile.write(body)


def do_nothing():
    """Do nothing, the default for what happens after pairing."""


class PairingServer(ThreadingHTTPServer):
    """The HTTP(S) server of the pairing API, a thread per connection."""

    def __init__(self, listen, state, guard, tls_context=None):
        """
        Bind the listening socket.

        With a TLS context the listening socket is wrapped with the handshake
        deferred, so it runs in the thread of the connection, after the
        timeout is set, and an idle client cannot block the others.

        Args:
            listen: The Listen address to bind.
            state: The State, to save the pairing in.
            guard: The CodeGuard, to check the pairing code with.
            tls_context: A server ssl.SSLContext, or None for plain HTTP.
        """
        self.state = state
        self.guard = guard
        self.on_paired = do_nothing
        self._wildcard_v6 = listen.wildcard and listen.family == socket.AF_INET6
        self._thread = None
        self.address_family = listen.family
        super().__init__(listen.sockaddr, PairingHandler)
        if tls_context is not None:
            self.socket = tls_context.wrap_socket(
                self.socket, server_side=True, do_handshake_on_connect=False
            )

    def server_bind(self):
        """Bind, taking IPv4 too when listening on every IPv6 address."""
        if self._wildcard_v6:
            self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()

    def handle_error(self, _request, client_address):
        """Log a failed connection, quietly when it is only the network."""
        error = sys.exception()
        level = logging.DEBUG if isinstance(error, OSError) else logging.ERROR
        LOG.log(
            level,
            "connection from %s failed",
            client_address[0],
            exc_info=error,
        )

    def start(self):
        """Serve in a background thread."""
        self._thread = threading.Thread(
            target=self.serve_forever, name="pairing-server", daemon=True
        )
        self._thread.start()

    def stop(self):
        """Stop serving, if serving, and close the socket."""
        if self._thread is not None:
            self.shutdown()
            self._thread.join()
            self._thread = None
        self.server_close()


# Addresses


@dataclass(frozen=True)
class Listen:
    """Where the pairing server listens."""

    family: int
    sockaddr: tuple
    wildcard: bool

    @property
    def host(self):
        """The address, as text."""
        return self.sockaddr[0]

    @property
    def port(self):
        """The port."""
        return self.sockaddr[1]


def choose_wildcard(infos):
    """Pick the dual-stack IPv6 entry if the host has it, else IPv4."""
    by_family = {info[0]: info for info in infos}
    if socket.AF_INET6 in by_family and socket.has_dualstack_ipv6():
        return by_family[socket.AF_INET6]
    return by_family.get(socket.AF_INET, infos[0])


def resolve_bind(bind, port):
    """
    Resolve the address to listen on.

    Args:
        bind: An address or host name, or None for all interfaces.
        port: The port number.

    Returns:
        The Listen. For all interfaces it is the IPv6 wildcard, taking IPv4
        as well, if the host can do that, else the IPv4 wildcard.

    Raises:
        Se2HassError: If the address cannot be resolved.
    """
    wildcard = not bind
    try:
        infos = socket.getaddrinfo(
            bind or None,
            port,
            type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        )
    except OSError as ex:
        msg = f"cannot resolve {bind}: {ex}"
        raise Se2HassError(msg) from ex
    family, _type, _proto, _canon, sockaddr = (
        choose_wildcard(infos) if wildcard else infos[0]
    )
    return Listen(family, sockaddr, wildcard)


def is_advertisable(address, include_ipv6):
    """Tell whether an address is one to announce: not loopback or link-local."""
    parsed = ipaddress.ip_address(address)
    if isinstance(parsed, ipaddress.IPv6Address) and not include_ipv6:
        return False
    return not (parsed.is_loopback or parsed.is_link_local)


def local_addresses(include_ipv6):
    """
    Find the addresses of this host that a client can use.

    Args:
        include_ipv6: Whether to list the IPv6 addresses.

    Returns:
        A list of addresses as text, without loopback and link-local ones.
    """
    found = []
    for adapter in ifaddr.get_adapters():
        for entry in adapter.ips:
            address = entry.ip[0] if entry.is_IPv6 else entry.ip
            if address not in found and is_advertisable(address, include_ipv6):
                found.append(address)
    return found


# mDNS


@dataclass(frozen=True)
class Endpoint:
    """What is announced about the pairing server."""

    scheme: str
    port: int
    addresses: list
    hostname: str
    version: str


def local_hostname():
    """Return the host name for mDNS: the name of this host in .local."""
    return socket.gethostname().split(".")[0] + ".local."


def package_version():
    """Return the installed version of semonitor, or "unknown"."""
    try:
        return importlib.metadata.version("semonitor")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


class Advertiser:
    """Announce the pairing server with mDNS, and keep the TXT record true."""

    def __init__(self, zeroconf, state, endpoint):
        """
        Prepare the announcement, without sending it.

        Args:
            zeroconf: The Zeroconf object. The advertiser owns it from now on
                and closes it in close().
            state: The State, for the id and whether it is paired.
            endpoint: The Endpoint to announce.
        """
        self._zeroconf = zeroconf
        self._state = state
        self._endpoint = endpoint
        self._serials = set()
        self._registered = False
        self._lock = threading.Lock()

    def start(self):
        """
        Announce the service.

        Raises:
            Se2HassError: If the announcement fails.
        """
        with self._lock:
            try:
                self._zeroconf.register_service(self._service_info())
            except (OSError, ZeroconfError) as ex:
                msg = f"cannot announce the service with mDNS: {ex}"
                raise Se2HassError(msg) from ex
            self._registered = True
        LOG.info("announced %s as %s", SERVICE_TYPE, self._endpoint.hostname)

    def add_serials(self, serials):
        """Add inverter serials to the announcement, updating it if new."""
        with self._lock:
            new = set(serials) - self._serials
            if new:
                self._serials |= new
                self._update()

    def refresh(self):
        """Update the announcement, for instance after pairing."""
        with self._lock:
            self._update()

    def close(self):
        """Send the goodbye and close the Zeroconf object."""
        with self._lock:
            self._registered = False
            self._zeroconf.close()

    def _update(self):
        if not self._registered:
            return
        try:
            self._zeroconf.update_service(self._service_info())
        except (OSError, ZeroconfError) as ex:
            # The announcement is not worth stopping the data for.
            LOG.warning("cannot update the mDNS announcement: %s", ex)

    def _service_info(self):
        endpoint = self._endpoint
        name = f"{SERVICE_NAME_PREFIX}-{self._state.id}.{SERVICE_TYPE}"
        return ServiceInfo(
            SERVICE_TYPE,
            name,
            port=endpoint.port,
            properties=self._properties(),
            server=endpoint.hostname,
            parsed_addresses=endpoint.addresses,
        )

    def _properties(self):
        return {
            "id": self._state.id,
            "version": self._endpoint.version,
            "scheme": self._endpoint.scheme,
            "paired": "true" if self._state.paired else "false",
            "serials": ",".join(sorted(self._serials)),
        }


# Webhook


class WebhookPusher:
    """Push lines to the webhook, and back off while it does not answer."""

    def __init__(self, tls_context=None, clock=time.monotonic):
        """
        Prepare to push.

        Args:
            tls_context: The client ssl.SSLContext for an https webhook.
            clock: A function returning the time in seconds, for the back-off.
        """
        self._tls_context = tls_context
        self._clock = clock
        self._retry_at = None

    def push(self, pairing, line):
        """
        Post one line to the webhook, unless backing off.

        A failure, or an answer that is not 2xx, is logged and starts a
        back-off of RETRY_SECONDS in which the lines are dropped, so that the
        input keeps draining and semonitor never blocks.

        Args:
            pairing: The Pairing, where to push.
            line: The JSON line to send, without newline.

        Returns:
            True if the webhook accepted the line.
        """
        if self._backing_off():
            LOG.debug("dropped a line, the webhook is backing off")
            return False
        try:
            status = self._post(pairing.webhook_url(), line)
        except (OSError, http.client.HTTPException) as ex:
            return self._fail(f"{type(ex).__name__}: {ex}")
        if not HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES:
            return self._fail(f"HTTP status {status}")
        return True

    def _backing_off(self):
        return self._retry_at is not None and self._clock() < self._retry_at

    def _fail(self, reason):
        self._retry_at = self._clock() + RETRY_SECONDS
        LOG.warning(
            "webhook push failed (%s), dropping lines for %d s",
            reason,
            RETRY_SECONDS,
        )
        return False

    def _post(self, url, line):
        parts = urlsplit(url)
        connection = self._connect(parts)
        try:
            connection.request(
                "POST",
                parts.path,
                body=line.encode(),
                headers={"Content-Type": "application/json"},
            )
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def _connect(self, parts):
        if parts.scheme == "https":
            return http.client.HTTPSConnection(
                parts.hostname,
                parts.port,
                timeout=PUSH_TIMEOUT,
                context=self._tls_context,
            )
        return http.client.HTTPConnection(
            parts.hostname, parts.port, timeout=PUSH_TIMEOUT
        )


# Reading semonitor


def read_telegram(line):
    """
    Parse a line of semonitor output.

    Args:
        line: One line of the output of semonitor.

    Returns:
        A tuple of the line as valid JSON and the parsed dict.

    Raises:
        TypeError: If the line is JSON, but not an object.
        ValueError: If the line is not valid, see se.se2json.convert.
    """
    converted = convert(line)
    data = json.loads(converted)
    if not isinstance(data, dict):
        msg = "not a JSON object"
        raise TypeError(msg)
    return converted, data


def inverter_serials(data):
    """Return the serials of the inverters in a parsed line, maybe none."""
    inverters = data.get("inverters")
    return list(inverters) if isinstance(inverters, dict) else []


def run(lines, state, advertiser, pusher):
    """
    Handle the lines of semonitor until the input ends.

    Each line is checked, its inverter serials are added to the announcement,
    and it is pushed to the webhook when paired. A bad line is a warning and is
    skipped. The events are forwarded as they are.

    Args:
        lines: An iterable of lines, like an open file.
        state: The State, to see whether and where to push.
        advertiser: The Advertiser, told of the serials.
        pusher: The WebhookPusher.
    """
    for line_no, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            telegram, data = read_telegram(line)
        except (TypeError, ValueError) as ex:
            LOG.warning("line %d: %s", line_no, ex)
            continue
        advertiser.add_serials(inverter_serials(data))
        pairing = state.pairing
        if pairing is not None:
            pusher.push(pairing, telegram)


# Start up


def make_server_context(cert, key):
    """
    Load the certificate of the pairing server.

    Args:
        cert: The certificate file, or None for plain HTTP.
        key: The private key file, or None when it is in the cert file.

    Returns:
        A server ssl.SSLContext, or None when there is no cert.

    Raises:
        Se2HassError: If the certificate or key cannot be loaded.
    """
    if cert is None:
        return None
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(cert, key)
    except OSError as ex:
        msg = f"cannot load the certificate or key: {ex}"
        raise Se2HassError(msg) from ex
    return context


def make_client_context(cafile, insecure):
    """
    Make the TLS settings for pushing to Home Assistant.

    Args:
        cafile: A file with CA certificates to trust, or None for the system's.
        insecure: Do not verify the certificate of Home Assistant.

    Returns:
        A client ssl.SSLContext.

    Raises:
        Se2HassError: If the CA file cannot be loaded.
    """
    try:
        context = ssl.create_default_context(cafile=cafile)
    except OSError as ex:
        msg = f"cannot load the CA file: {ex}"
        raise Se2HassError(msg) from ex
    if insecure:
        LOG.warning("not verifying the certificate of Home Assistant")
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    return context


def open_server(listen, state, guard, tls_context):
    """Bind the pairing server, turning a bind error into Se2HassError."""
    try:
        return PairingServer(listen, state, guard, tls_context)
    except OSError as ex:
        msg = f"cannot listen on {listen.host} port {listen.port}: {ex}"
        raise Se2HassError(msg) from ex


def create_zeroconf():
    """Create the Zeroconf object, turning an error into Se2HassError."""
    try:
        return Zeroconf()
    except OSError as ex:
        msg = f"cannot start mDNS: {ex}"
        raise Se2HassError(msg) from ex


def log_startup(state, scheme, server):
    """Log where se2hass listens, and the pairing code."""
    LOG.info(
        "listening on %s port %d (%s)",
        server.server_address[0],
        server.server_address[1],
        scheme,
    )
    LOG.info("pairing code: %s", display_code(state.pairing_code))
    if scheme == "http":
        LOG.warning(
            "plain HTTP: the pairing code travels in the clear, "
            "use --cert and --key"
        )
    LOG.info("%s", "paired" if state.paired else "not paired yet")


def make_endpoint(listen, scheme, server):
    """Describe what to announce for a bound server."""
    addresses = (
        local_addresses(include_ipv6=listen.family == socket.AF_INET6)
        if listen.wildcard
        else [listen.host]
    )
    return Endpoint(
        scheme=scheme,
        port=server.server_address[1],
        addresses=addresses,
        hostname=local_hostname(),
        version=package_version(),
    )


def serve(server, state, endpoint, lines, pusher):
    """
    Announce, serve and handle the lines, until the input ends.

    Args:
        server: The bound PairingServer.
        state: The State.
        endpoint: The Endpoint to announce.
        lines: The lines of semonitor.
        pusher: The WebhookPusher.
    """
    with closing(Advertiser(create_zeroconf(), state, endpoint)) as advertiser:
        server.on_paired = advertiser.refresh
        server.start()
        advertiser.start()
        run(lines, state, advertiser, pusher)


def run_service(args, lines):
    """
    Set everything up from the command line and serve.

    Args:
        args: The parsed command line.
        lines: The lines of semonitor.

    Raises:
        Se2HassError: If the setup fails.
    """
    state = State.load(args.state_file)
    server_context = make_server_context(args.cert, args.key)
    pusher = WebhookPusher(make_client_context(args.cafile, args.insecure))
    listen = resolve_bind(args.bind, args.port)
    server = open_server(
        listen, state, CodeGuard(state.pairing_code), server_context
    )
    try:
        scheme = "https" if server_context else "http"
        log_startup(state, scheme, server)
        endpoint = make_endpoint(listen, scheme, server)
        serve(server, state, endpoint, lines, pusher)
    finally:
        server.stop()


def _exit_on_sigterm(_signal_number, _frame):
    raise SystemExit(0)


@contextmanager
def sigterm_exits():
    """Make SIGTERM raise SystemExit, so that the finally blocks run."""
    try:
        previous = signal.signal(signal.SIGTERM, _exit_on_sigterm)
    except ValueError:
        # Not the main thread, where signal handlers cannot be set.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


# Command line


def port_number(text):
    """Parse a TCP port number for argparse."""
    try:
        port = int(text)
    except ValueError:
        port = -1
    if not 0 <= port <= MAX_PORT:
        msg = f"invalid port: {text!r}"
        raise argparse.ArgumentTypeError(msg)
    return port


def build_parser():
    """Return the command line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Read a file containing JSON performance data, one object per "
            "line, push it to a Home Assistant webhook and run the API and "
            "the mDNS announcement to pair with Home Assistant. The pairing "
            "code is in the log."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "infile",
        nargs="?",
        help="file containing performance data in JSON format, stdin if none",
    )
    parser.add_argument(
        "-b",
        "--bind",
        help="address to listen on, all interfaces if none",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=port_number,
        default=DEFAULT_PORT,
        help="port of the pairing API",
    )
    parser.add_argument(
        "-f",
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help="file for the pairing code and the pairing, kept private",
    )
    parser.add_argument(
        "--cert",
        help="certificate (and key) file to serve the pairing API with HTTPS",
    )
    parser.add_argument("--key", help="private key file for --cert")
    parser.add_argument(
        "--cafile",
        help="CA certificates to verify Home Assistant with, instead of the "
        "system's",
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="do not verify the certificate of Home Assistant",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="log at DEBUG instead of INFO",
    )
    return parser


def main(argv=None):
    """
    Push the semonitor output to Home Assistant.

    Args:
        argv: The command line arguments to use, or None for those of the
            process.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.key and not args.cert:
        parser.error("--key needs --cert")
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        level=logging.DEBUG if args.verbose else logging.INFO,
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    try:
        with (
            open_input([args.infile] if args.infile else []) as in_file,
            sigterm_exits(),
        ):
            run_service(args, in_file)
    except Se2HassError as ex:
        sys.exit(f"{parser.prog}: {ex}")


if __name__ == "__main__":
    main()
