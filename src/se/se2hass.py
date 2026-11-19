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

DEFAULT_INTERFACE = None  # All interfaces.
DEFAULT_PORT = 22222
MIN_PORT = 1025
MAX_PORT = 65535
DEFAULT_STATE_FILE = "/var/lib/semonitor/se2hass.json"
SERVICE_TYPE = "_semonitor._tcp.local."
SERVICE_NAME_PREFIX = "se2hass"
HOSTNAME_PATTERN = re.compile(r"[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?")

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
        try:
            parts = urlsplit(hass_url if isinstance(hass_url, str) else "")
            _ = parts.port
        except ValueError:
            parts = None
        if (
            parts is None
            or parts.scheme not in URL_SCHEMES
            or not parts.hostname
        ):
            msg = "hass_url must be an http or https URL"
            raise ValueError(msg)
        if not isinstance(webhook_id, str) or not WEBHOOK_ID_PATTERN.fullmatch(
            webhook_id
        ):
            msg = "webhook_id must be 1 to 256 of A-Z, a-z, 0-9, _ and -"
            raise ValueError(msg)
        return cls(hass_url, webhook_id)

    def webhook_url(self):
        """Return the URL of the webhook, the id quoted."""
        parts = urlsplit(self.hass_url)
        path = parts.path.rstrip("/") + WEBHOOK_PATH
        path += quote(self.webhook_id, safe="")
        return urlunsplit((parts.scheme, parts.netloc, path, "", ""))


def _parse_state(data):
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
    code = data.get("pairing_code")
    stored = data.get("pairing")
    if not (isinstance(state_id, str) and state_id):
        msg = "no valid id"
        raise ValueError(msg)
    if not (
        isinstance(code, str)
        and len(code) == CODE_LENGTH
        and set(code) <= set(CODE_ALPHABET)
    ):
        msg = "no valid pairing_code"
        raise ValueError(msg)
    if stored is not None and not isinstance(stored, dict):
        msg = "pairing is not a JSON object"
        raise TypeError(msg)
    pairing = None if stored is None else Pairing.from_request(stored)
    return state_id, code, pairing


class State:
    """The state: id, pairing code and pairing, and the code's lockout."""

    def __init__(
        self, path, state_id, pairing_code, pairing=None, clock=time.monotonic
    ):
        """
        Hold the state of a file, without reading or writing it.

        Args:
            path: A Path, the state file.
            state_id: The random id that names this installation in mDNS.
            pairing_code: The normalized pairing code.
            pairing: The Pairing, or None when not paired.
            clock: A function returning the time in seconds, for the lockout.
        """
        self.id = state_id
        self.pairing_code = pairing_code
        self.pairing = pairing  # None when not paired.
        self._path = path
        self._clock = clock
        self._lock = threading.Lock()
        self._failures = 0
        self._locked_until = None

    @classmethod
    def load(cls, path, clock=time.monotonic):
        """
        Load the state file, or create it with a new id and pairing code.

        Args:
            path: The state file, a str or Path.
            clock: A function returning the time in seconds, for the lockout.

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
            code = "".join(
                secrets.choice(CODE_ALPHABET) for _ in range(CODE_LENGTH)
            )
            state = cls(path, secrets.token_hex(8), code, clock=clock)
            state.save()
            return state
        except UnicodeDecodeError as ex:
            msg = f"corrupt state file {path}: {ex}"
            raise Se2HassError(msg) from ex
        except OSError as ex:
            msg = f"cannot read state file {path}: {ex}"
            raise Se2HassError(msg) from ex
        try:
            return cls(path, *_parse_state(json.loads(text)), clock=clock)
        except (TypeError, ValueError) as ex:
            msg = f"corrupt state file {path}: {ex}"
            raise Se2HassError(msg) from ex

    @property
    def paired(self):
        """True when there is a pairing."""
        return self.pairing is not None

    def pair(self, pairing):
        """
        Save a new pairing, replacing the one there is.

        The pairing only changes in memory when it was written to the file.
        If the file cannot be written, the Se2HassError of that propagates.

        Args:
            pairing: The new Pairing.
        """
        with self._lock:
            self._write(pairing)
            self.pairing = pairing

    def save(self):
        """Write the state file."""
        with self._lock:
            self._write(self.pairing)

    def check_code(self, candidate):
        """
        Check a pairing code, counting the wrong ones.

        A correct code resets the count of wrong codes. A wrong code counts
        and, after MAX_WRONG_CODES in a row, locks out for LOCKOUT_SECONDS.
        While locked out every code is refused, even the right one.

        Args:
            candidate: What the client sent, anything that was in the JSON.

        Returns:
            True if the code is right and there is no lockout.
        """
        with self._lock:
            if self._seconds_locked():
                return False
            right = False
            if isinstance(candidate, str):
                for separator in CODE_SEPARATORS:
                    candidate = candidate.replace(separator, "")
                # JSON can carry a lone surrogate, which encode() refuses.
                right = hmac.compare_digest(
                    candidate.upper().encode("utf-8", "surrogatepass"),
                    self.pairing_code.encode(),
                )
            if right:
                self._failures = 0
                return True
            self._failures += 1
            if self._failures >= MAX_WRONG_CODES:
                self._locked_until = self._clock() + LOCKOUT_SECONDS
                LOG.warning(
                    "%d wrong pairing codes in a row, refusing pairing "
                    "for %d s",
                    self._failures,
                    LOCKOUT_SECONDS,
                )
            return False

    def retry_after(self):
        """Return the seconds left of a lockout, 0 when not locked out."""
        with self._lock:
            return self._seconds_locked()

    def _seconds_locked(self):
        """Return the seconds left of a lockout, 0 when not locked out."""
        if self._locked_until is None:
            return 0
        remaining = self._locked_until - self._clock()
        if remaining > 0:
            return math.ceil(remaining)
        self._locked_until = None
        self._failures = 0
        return 0

    def _write(self, pairing):
        """
        Write the file all or nothing, readable by the owner only.

        Args:
            pairing: The Pairing to write, or None when not paired.

        Raises:
            Se2HassError: If the file cannot be written.
        """
        document = {
            "id": self.id,
            "pairing_code": self.pairing_code,
            "pairing": None if pairing is None else asdict(pairing),
        }
        path = self._path
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            # The temporary file has mode 0600 and replaces the target, so a
            # crash never leaves half a file.
            descriptor, temp_name = tempfile.mkstemp(
                dir=path.parent, prefix=f".{path.name}.", suffix=".tmp"
            )
            temp = Path(temp_name)
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    handle.write(json.dumps(document, indent=2) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
                temp.replace(path)
            finally:
                temp.unlink(missing_ok=True)
        except OSError as ex:
            msg = f"cannot write state file {path}: {ex}"
            raise Se2HassError(msg) from ex


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
        if self.server.on_paired is not None:
            self.server.on_paired()

    def answer_not_found(self):
        """Answer 404, whatever was asked."""
        self._reply(HTTPStatus.NOT_FOUND, {"error": "not found"})

    @override
    def send_error(self, code, message=None, explain=None):
        """
        Answer 404 to a method that is not supported, not 501.

        Args:
            code: The HTTP status code of the error.
            message: A short message for the status line, or None.
            explain: A long explanation for the body, or None.
        """
        if code == HTTPStatus.NOT_IMPLEMENTED:
            self.answer_not_found()
        else:
            super().send_error(code, message, explain)

    @override
    def log_message(self, fmt, *args):
        """
        Send the request log to logging, at DEBUG.

        Args:
            fmt: The %-format of the message.
            *args: The values for the format.
        """
        LOG.debug("%s - %s", self.address_string(), fmt % args)

    def _pairing_from_request(self):
        """
        Check the request in the order of the API.

        Returns:
            The Pairing the client sent.

        Raises:
            RequestError: If the request is not good, with the HTTP status to
                answer it with.
        """
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
        try:
            payload = json.loads(self.rfile.read(int(header)))
        except (ValueError, RecursionError) as ex:
            msg = "the body is not JSON"
            raise RequestError(HTTPStatus.BAD_REQUEST, msg) from ex
        if not isinstance(payload, dict):
            msg = "the body is not a JSON object"
            raise RequestError(HTTPStatus.BAD_REQUEST, msg)

        state = self.server.state
        retry_after = state.retry_after()
        if retry_after:
            msg = "too many wrong pairing codes, try again later"
            raise RequestError(HTTPStatus.TOO_MANY_REQUESTS, msg, retry_after)
        code = payload.get("code")
        if code is None:
            msg = "the pairing code is required"
            raise RequestError(HTTPStatus.UNAUTHORIZED, msg)
        if not state.check_code(code):
            LOG.warning("wrong pairing code from %s", self.client_address[0])
            msg = "the pairing code is wrong"
            raise RequestError(HTTPStatus.FORBIDDEN, msg)
        try:
            return Pairing.from_request(payload)
        except ValueError as ex:
            raise RequestError(HTTPStatus.BAD_REQUEST, str(ex)) from ex

    def _reply(self, status, payload, retry_after=None):
        """
        Answer with a JSON object.

        Args:
            status: The HTTP status to answer with.
            payload: The object to send as JSON.
            retry_after: Seconds for the Retry-After header, or None.
        """
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        if retry_after:
            self.send_header("Retry-After", str(retry_after))
        self.end_headers()
        self.wfile.write(body)


class PairingServer(ThreadingHTTPServer):
    """The HTTP(S) server of the pairing API, a thread per connection."""

    def __init__(self, interface, port, state, tls_context=None):
        """
        Resolve the address and bind the listening socket.

        Without an interface (None) this listens on all of them: on the IPv6
        wildcard, taking IPv4 as well, if the host can do that, else on the
        IPv4 wildcard. With a TLS context the listening socket is wrapped
        with the handshake deferred, so it runs in the thread of the
        connection, after the timeout is set, and an idle client cannot
        block the others.

        Args:
            interface: The address to listen on, or None for all of them.
            port: The port to listen on, 0 for any free one.
            state: The State, to save the pairing in.
            tls_context: A server ssl.SSLContext, or None for plain HTTP.

        Raises:
            Se2HassError: If the address cannot be resolved or bound.
        """
        self.state = state
        self.on_paired = None  # Called, without arguments, after pairing.
        self._thread = None
        try:
            infos = socket.getaddrinfo(
                interface,
                port,
                type=socket.SOCK_STREAM,
                flags=socket.AI_PASSIVE,
            )
        except OSError as ex:
            msg = f"cannot resolve {interface}: {ex}"
            raise Se2HassError(msg) from ex
        chosen = infos[0]
        if interface is None:
            by_family = {info[0]: info for info in infos}
            if socket.AF_INET6 in by_family and socket.has_dualstack_ipv6():
                chosen = by_family[socket.AF_INET6]
            else:
                chosen = by_family.get(socket.AF_INET, chosen)
        self.address_family, _type, _proto, _canon, sockaddr = chosen
        self._wildcard_v6 = (
            interface is None and self.address_family == socket.AF_INET6
        )
        try:
            super().__init__(sockaddr, PairingHandler)
        except OSError as ex:
            msg = f"cannot listen on {interface or 'all interfaces'}"
            msg += f" port {port}: {ex}"
            raise Se2HassError(msg) from ex
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
        """
        Log a failed connection, quietly when it is only the network.

        Args:
            _request: The socket of the connection, not used.
            client_address: The address of the client, a (host, port) tuple.
        """
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
            parsed = ipaddress.ip_address(address)
            if (
                address not in found
                and (include_ipv6 or isinstance(parsed, ipaddress.IPv4Address))
                and not (parsed.is_loopback or parsed.is_link_local)
            ):
                found.append(address)
    return found


class Advertiser:
    """Announce the pairing server with mDNS, and keep the TXT record true."""

    def __init__(self, zeroconf, state, hostname):
        """
        Prepare the announcement, without sending it.

        Args:
            zeroconf: The Zeroconf object. The advertiser owns it from now on
                and closes it in close().
            state: The State, for the id and whether it is paired.
            hostname: The name of this host, one label, without ".local".
        """
        self._zeroconf = zeroconf
        self._state = state
        self._server = f"{hostname}.local."
        self._port = None
        self._scheme = None
        self._addresses = []
        try:
            self._version = importlib.metadata.version("semonitor")
        except importlib.metadata.PackageNotFoundError:
            self._version = "unknown"
        self._serials = set()
        self._registered = False
        self._lock = threading.Lock()

    def start(self, port, scheme, addresses):
        """
        Announce the service of the pairing server.

        Args:
            port: The port of the pairing server.
            scheme: "http" or "https".
            addresses: The addresses of the pairing server, as text.

        Raises:
            Se2HassError: If the announcement fails.
        """
        with self._lock:
            self._port = port
            self._scheme = scheme
            self._addresses = addresses
            try:
                self._zeroconf.register_service(self._service_info())
            except (OSError, ZeroconfError) as ex:
                msg = f"cannot announce the service with mDNS: {ex}"
                raise Se2HassError(msg) from ex
            self._registered = True
        LOG.info("announced %s as %s", SERVICE_TYPE, self._server)

    def add_serials(self, serials):
        """
        Add inverter serials to the announcement, updating it if new.

        Args:
            serials: An iterable of inverter serial numbers, as text.
        """
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
        """Send the announcement again, when it was sent before."""
        if not self._registered:
            return
        try:
            self._zeroconf.update_service(self._service_info())
        except (OSError, ZeroconfError) as ex:
            # The announcement is not worth stopping the data for.
            LOG.warning("cannot update the mDNS announcement: %s", ex)

    def _service_info(self):
        """Return the ServiceInfo with the current state and serials."""
        return ServiceInfo(
            SERVICE_TYPE,
            f"{SERVICE_NAME_PREFIX}-{self._state.id}.{SERVICE_TYPE}",
            port=self._port,
            properties={
                "id": self._state.id,
                "version": self._version,
                "scheme": self._scheme,
                "paired": "true" if self._state.paired else "false",
                "serials": ",".join(sorted(self._serials)),
            },
            server=self._server,
            parsed_addresses=self._addresses,
        )


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
        if self._retry_at is not None and self._clock() < self._retry_at:
            LOG.debug("dropped a line, the webhook is backing off")
            return False
        parts = urlsplit(pairing.webhook_url())
        reason = None
        try:
            if parts.scheme == "https":
                connection = http.client.HTTPSConnection(
                    parts.hostname,
                    parts.port,
                    timeout=PUSH_TIMEOUT,
                    context=self._tls_context,
                )
            else:
                connection = http.client.HTTPConnection(
                    parts.hostname, parts.port, timeout=PUSH_TIMEOUT
                )
            with closing(connection):
                connection.request(
                    "POST",
                    parts.path,
                    body=line.encode(),
                    headers={"Content-Type": "application/json"},
                )
                response = connection.getresponse()
                response.read()
            status = response.status
            if not HTTPStatus.OK <= status < HTTPStatus.MULTIPLE_CHOICES:
                reason = f"HTTP status {status}"
        except (OSError, http.client.HTTPException) as ex:
            reason = f"{type(ex).__name__}: {ex}"
        if reason is None:
            return True
        self._retry_at = self._clock() + RETRY_SECONDS
        LOG.warning(
            "webhook push failed (%s), dropping lines for %d s",
            reason,
            RETRY_SECONDS,
        )
        return False


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
            telegram = convert(line)
            data = json.loads(telegram)
        except (TypeError, ValueError) as ex:
            LOG.warning("line %d: %s", line_no, ex)
            continue
        if not isinstance(data, dict):
            LOG.warning("line %d: not a JSON object", line_no)
            continue
        inverters = data.get("inverters")
        if isinstance(inverters, dict):
            advertiser.add_serials(list(inverters))
        pairing = state.pairing
        if pairing is not None:
            pusher.push(pairing, telegram)


def run_service(args, lines):
    """
    Set everything up from the parsed command line and serve the lines.

    Args:
        args: The argparse.Namespace of the command line.
        lines: An iterable of lines of semonitor, like an open file.

    Raises:
        Se2HassError: If the setup fails.
    """
    state = State.load(args.state_file)
    server_context = None
    if args.cert:
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            server_context.load_cert_chain(args.cert, args.key)
        except OSError as ex:
            msg = f"cannot load the certificate or key: {ex}"
            raise Se2HassError(msg) from ex
    client_context = ssl.create_default_context()
    if args.insecure:
        LOG.warning("not verifying the certificate of Home Assistant")
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE

    server = PairingServer(args.interface, args.port, state, server_context)
    try:
        scheme = "https" if server_context else "http"
        host, port = server.server_address[:2]
        LOG.info("listening on %s port %d (%s)", host, port, scheme)
        LOG.info(
            "pairing code: %s-%s",
            state.pairing_code[:CODE_GROUP_LENGTH],
            state.pairing_code[CODE_GROUP_LENGTH:],
        )
        if scheme == "http":
            LOG.warning(
                "plain HTTP: the pairing code travels in the clear, "
                "use --cert and --key"
            )
        LOG.info("%s", "paired" if state.paired else "not paired yet")

        addresses = [host]
        if args.interface is None:
            addresses = local_addresses(
                server.address_family == socket.AF_INET6
            )
        try:
            zeroconf = Zeroconf()
        except OSError as ex:
            msg = f"cannot start mDNS: {ex}"
            raise Se2HassError(msg) from ex
        hostname = args.hostname or socket.gethostname().split(".")[0]
        with closing(Advertiser(zeroconf, state, hostname)) as advertiser:
            server.on_paired = advertiser.refresh
            server.start()
            advertiser.start(port, scheme, addresses)
            run(lines, state, advertiser, WebhookPusher(client_context))
    finally:
        server.stop()


@contextmanager
def sigterm_exits():
    """Make SIGTERM raise SystemExit, so that the finally blocks run."""

    def handler(_signal_number, _frame):
        """
        Exit, as the handler of SIGTERM.

        Args:
            _signal_number: The number of the signal, not used.
            _frame: The interrupted stack frame, not used.

        Raises:
            SystemExit: Always, with status 0.
        """
        raise SystemExit(0)

    try:
        previous = signal.signal(signal.SIGTERM, handler)
    except ValueError:
        # Not the main thread, where signal handlers cannot be set.
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


class HelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    """Show the defaults in the help, except None, which says nothing."""

    @override
    def _get_help_string(self, action):
        """
        Return the help of an argument, with the default if it has one.

        Args:
            action: The argparse.Action to show the help of.

        Returns:
            The help text, with the default added unless it is None.
        """
        if action.default is None:
            return action.help
        return super()._get_help_string(action)


def build_parser():
    """Return the command line parser."""
    parser = argparse.ArgumentParser(
        description=(
            "Read a file containing JSON performance data, one object per "
            "line, push it to a Home Assistant webhook and run the API and "
            "the mDNS announcement to pair with Home Assistant. The pairing "
            "code is in the log."
        ),
        formatter_class=HelpFormatter,
    )
    parser.add_argument(
        "infile",
        nargs="?",
        help="file containing performance data in JSON format, stdin if none",
    )
    parser.add_argument(
        "-i",
        "--interface",
        metavar="ADDRESS",
        default=DEFAULT_INTERFACE,
        help="address to listen on, all interfaces if none",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help="port of the pairing API, 0 for any free one",
    )
    parser.add_argument(
        "-S",
        "--state-file",
        default=DEFAULT_STATE_FILE,
        help="file for the pairing code and the pairing, kept private",
    )
    parser.add_argument(
        "-C",
        "--cert",
        help="certificate (and key) file to serve the pairing API with HTTPS",
    )
    parser.add_argument(
        "-k",
        "--key",
        help="private key file for --cert",
    )
    parser.add_argument(
        "-I",
        "--insecure",
        action="store_true",
        help="do not verify the certificate of Home Assistant",
    )
    parser.add_argument(
        "-H",
        "--hostname",
        metavar="NAME",
        help="name of this host in mDNS, one name like 'solar', as printed "
        "by hostname if none; the '.local' is added",
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
    Run se2hass with argv, or the command line of the process if None.

    Args:
        argv: The list of arguments without the program name, or None.
    """
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.key and not args.cert:
        parser.error("--key needs --cert")
    # 0 asks the system for any free port, the bound port is then announced.
    if args.port != 0 and not MIN_PORT <= args.port <= MAX_PORT:
        parser.error(f"invalid port: {args.port}")
    if args.hostname is not None and not HOSTNAME_PATTERN.fullmatch(
        args.hostname
    ):
        parser.error(
            f"invalid host name {args.hostname!r}: use the name only, "
            "like 'solar', not 'solar.example.org'"
        )
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
