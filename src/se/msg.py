"""
SolarEdge message protocol.

Reads, parses, formats, validates and sends the framed messages exchanged
with SolarEdge inverters, including their CRC-16 checksums.
"""

import functools
import logging
import select
import struct
import sys
import threading
import time
import weakref
from collections import deque
from typing import NamedTuple

import se.logutils

logger = logging.getLogger(__name__)

SLEEP_INTERVAL = 0.1

# message constants
magic = b"\x12\x34\x56\x79"
MAGIC_LEN = len(magic)
MSG_HDR_LEN = 16
CHECKSUM_LEN = 2
# CRC repairs that can be enabled: "crc" repairs a bit of the checksum, "data" a
# bit of the header or data, and implies "crc"
REPAIR_LEVELS = ("crc", "data")
REPAIR_MAX_BITS = 32767  # CRC-16 0x8005 has distance 4 only up to this length


class MsgHdr(NamedTuple):
    """The header of a message."""

    data_len: int
    data_len_inv: int
    msg_seq: int
    from_addr: int
    to_addr: int
    function: int


class Seq:
    """Debugging sequence numbers of the messages read and written."""

    data_in = 0
    data_out = 0


def read_msg(in_file, rec_file, mode, state):
    """
    Read the next message from the input file.

    An RS232 frame is read as the magic number, header, data and checksum in
    turn. Any other input is read one byte at a time until the next magic
    number is found.

    Returns:
        A tuple (msg, eof), where msg is the message without its magic number
        and eof is True when the end of the input was reached.
    """
    se.logutils.set_state(state, "passiveMode", mode.passive_mode)
    se.logutils.set_state(state, "serialType", mode.serial_type)
    Seq.data_in += 1
    if mode.serial_type == "2":
        (msg, eof) = read_rs232_frame(in_file, rec_file, mode, state)
    else:
        (msg, eof) = scan_msg(in_file, rec_file, mode, state)
    if len(msg) > 0:  # don't log zero length messages
        logger.message("-->", Seq.data_in, magic + msg, in_file.name)
    return (msg, eof)


def read_rs232_frame(in_file, rec_file, mode, state):
    """
    Read an RS232 frame: the magic number, header, data and checksum.

    The bytes before the magic number are skipped, which also resyncs after
    a damaged frame. The data is only read once its length is confirmed by
    its inverse length.

    A frame that directly follows a valid frame needs no magic number, so it
    is taken without one, when its bytes are already waiting.

    Returns:
        A tuple (msg, eof), as for read_msg.
    """
    if _after_valid.pop(in_file, False):  # the frame before was valid
        frame = read_frame_without_magic(in_file, rec_file, mode, state)
        if frame is not None:
            _after_valid[in_file] = True
            return (frame, False)
    (skipped, eof) = skip_to_magic(in_file, rec_file, mode, state)
    if skipped:
        logger.data("Discarding %s bytes before the magic number", len(skipped))
        for line in se.logutils.format_data(skipped):
            logger.data(line)
    if eof:  # end of file before a magic number
        return (b"", True)
    # read the header
    msg = read_input(in_file, rec_file, MSG_HDR_LEN, mode, state)
    # a repeated magic number (M M X) is skipped, a header can't start with it
    while len(msg) == MSG_HDR_LEN and msg[:MAGIC_LEN] == magic:
        logger.data("Skipping a repeated magic number")
        msg = msg[MAGIC_LEN:] + read_input(
            in_file, rec_file, MAGIC_LEN, mode, state
        )
    if len(msg) < MSG_HDR_LEN:  # end of file in the header
        return (b"", True)
    (data_len, data_len_inv, _msg_seq, _from_addr, _to_addr, _function) = (
        struct.unpack("<HHHLLH", msg)
    )
    # the data length is only trusted when its inverse agrees with it
    if data_len != ~data_len_inv & 0xFFFF:
        reject_inverse(msg, data_len, data_len_inv)
        return (b"", False)
    # read the data and checksum
    length = data_len + CHECKSUM_LEN
    msg += read_input(in_file, rec_file, length, mode, state)
    if len(msg) == MSG_HDR_LEN + length and frame_length(msg) is None:
        # The length is confirmed by its inverse, but the checksum is wrong.
        # A lost or added byte in the data shifts the frame, so the frame that
        # follows may be in the bytes read. They are pushed back, so that the
        # magic number search finds it.
        _pushback[in_file] = msg + _pushback.get(in_file, b"")
    _after_valid[in_file] = frame_length(msg) is not None
    return (msg, False)


# input files whose last RS232 frame was valid, by input file
_after_valid = weakref.WeakKeyDictionary()


def read_frame_without_magic(in_file, rec_file, mode, state):
    """
    Read a frame that follows a valid frame, without a magic number before it.

    Only when bytes are already waiting on the input, so this never waits for
    data. The bytes are pushed back unless they are a valid frame, so the
    magic number search still finds what follows.

    Returns:
        The frame, or None if there is no valid frame at once.
    """
    if not input_ready(in_file):
        return None
    read = read_input(in_file, rec_file, MSG_HDR_LEN, mode, state)
    length = header_length(read) if len(read) == MSG_HDR_LEN else None
    frame = None
    if length is not None:
        read += read_input(in_file, rec_file, length - MSG_HDR_LEN, mode, state)
        if frame_length(read) is not None:
            frame = read
    if frame is None:  # not a frame: all the bytes read are read again
        _pushback[in_file] = read + _pushback.get(in_file, b"")
    return frame


def input_ready(in_file):
    """
    Return True if a read from the input does not wait for data.

    Pushed back bytes and in-memory inputs are always ready. A serial port
    reports the bytes waiting. A file descriptor is checked with select and a
    zero timeout, which does not work on Windows, so there the frame is not
    taken without a magic number.

    Returns:
        True if the read is ready, False if it would wait or is not known.
    """
    if _pushback.get(in_file):
        return True
    if hasattr(in_file, "in_waiting"):  # a serial port
        return in_file.in_waiting > 0
    try:
        fd = in_file.fileno()
    except AttributeError, OSError, ValueError:  # in memory, never waits
        return True
    if sys.platform == "win32":  # select does not take files there
        return False
    try:
        (ready, _, _) = select.select([fd], [], [], 0)
    except OSError, ValueError:
        return False
    return bool(ready)


# bytes read ahead of the input, by input file, to be read again first
_pushback = weakref.WeakKeyDictionary()


def read_input(in_file, rec_file, length, mode, state):
    """
    Read the specified number of bytes, the pushed back bytes first.

    The pushed back bytes were recorded when they were first read, so they
    are not recorded again.

    Returns:
        The bytes read, which are fewer at the end of the input.
    """
    pushed = _pushback.get(in_file, b"")
    head = pushed[:length]
    _pushback[in_file] = pushed[len(head) :]
    if len(head) < length:
        head += read_bytes(in_file, rec_file, length - len(head), mode, state)
    return head


def scan_msg(in_file, rec_file, mode, state):
    """
    Read the next message for RS485, a file or stdin.

    The input is split at the magic numbers. When the header of a message
    gives a longer frame, the magic numbers in its data are joined again,
    and the frame is only kept when its length and checksum confirm it. A
    message that is not confirmed is split as it is.

    Returns:
        A tuple (msg, eof), as for read_msg.
    """
    queue = _pending.pop(in_file, deque())  # segments read ahead
    if not queue:
        queue.append(scan_segment(in_file, rec_file, mode, state))

    def read_next():
        return scan_segment(in_file, rec_file, mode, state)

    (msg, eof) = queue[0]
    length = header_length(msg)
    frame = None
    if length is not None and len(msg) < length and not eof:
        frame = join_frame(queue, length, read_next)
    if frame is not None:
        (msg, eof) = frame
    else:
        queue.popleft()
        (msg, rest) = split_frame(msg)
        if rest:  # keep the frame that follows, it is returned next
            queue.appendleft((rest, eof))
            eof = False
    if queue:
        _pending[in_file] = queue
    return (msg, eof)


def join_frame(queue, length, read_next):
    """
    Join segments of the input into one frame of the given length.

    The segments are taken from the queue, and read when it runs out, until
    their joined length reaches the length of the frame. The frame is kept
    only if its checksum is correct at that length. Otherwise the segments
    stay in the queue. Bytes after the frame stay in the queue, as the start
    of the next message.

    Returns:
        A tuple (frame, eof), as for read_msg, or None if no frame was found.
    """
    taken = [queue.popleft()]
    joined = taken[0][0]
    while len(joined) < length and not taken[-1][1]:
        taken.append(queue.popleft() if queue else read_next())
        joined += magic + taken[-1][0]
    extra = len(joined) - length
    if frame_length(joined) != length or extra > len(taken[-1][0]):
        queue.extendleft(reversed(taken))
        return None
    last_eof = taken[-1][1]
    if extra:  # bytes after the frame, the start of the next message
        queue.appendleft((taken[-1][0][len(taken[-1][0]) - extra :], last_eof))
        return (joined[:length], False)
    return (joined[:length], last_eof)


def scan_segment(in_file, rec_file, mode, state):
    """
    Read the bytes up to the next magic number, or the end of the input.

    Returns:
        A tuple (segment, eof), where segment is without the magic number.
    """
    msg = b""
    eof = False
    # read 1 byte at a time until the next magic number
    while msg[-MAGIC_LEN:] != magic:
        next_byte = read_bytes(in_file, rec_file, 1, mode, state)
        if not next_byte:  # end of file
            eof = True
            msg += magic  # append a magic number to end the loop
        else:
            msg += next_byte
    return (msg[:-MAGIC_LEN], eof)


# segments that were read ahead, by input file, each as (bytes, eof)
_pending = weakref.WeakKeyDictionary()


def header_length(msg):
    """
    Return the length of the frame that the header of msg gives.

    Returns:
        The length including the checksum, or None if the header is too short
        or its inverse length does not agree with its length.
    """
    if len(msg) < MSG_HDR_LEN:
        return None
    (data_len, data_len_inv) = struct.unpack("<HH", msg[:4])
    if data_len != ~data_len_inv & 0xFFFF:
        return None
    return MSG_HDR_LEN + data_len + CHECKSUM_LEN


def split_frame(msg):
    """
    Split a message that holds a second frame after the first one.

    The second frame must follow the first at once, and both must be valid
    frames. Anything else is left as it is, for validate_msg to discard.

    Returns:
        A tuple (first, rest), where rest is b"" when there is no second frame.
    """
    length = frame_length(msg)
    if length is None or length >= len(msg):
        return (msg, b"")
    rest = msg[length:]
    if frame_length(rest) is None:
        return (msg, b"")
    return (msg[:length], rest)


def frame_length(msg):
    """
    Return the length of the frame at the start of msg, if it is valid.

    The frame is valid when its inverse length agrees, the data fits in msg,
    and the checksum is correct.

    Returns:
        The length of the frame including its checksum, or None if the frame
        is not valid.
    """
    if len(msg) < MSG_HDR_LEN + CHECKSUM_LEN:
        return None
    (data_len, data_len_inv, msg_seq, from_addr, to_addr, function) = (
        struct.unpack("<HHHLLH", msg[0:MSG_HDR_LEN])
    )
    length = MSG_HDR_LEN + data_len + CHECKSUM_LEN
    if data_len != ~data_len_inv & 0xFFFF or length > len(msg):
        return None
    data = msg[MSG_HDR_LEN : MSG_HDR_LEN + data_len]
    checksum = struct.unpack("<H", msg[length - CHECKSUM_LEN : length])[0]
    calcsum = calc_crc(
        struct.pack(">HLLH", msg_seq, from_addr, to_addr, function) + data
    )
    if calcsum != checksum:
        return None
    return length


def skip_to_magic(in_file, rec_file, mode, state):
    """
    Read the input up to and including the next magic number.

    Returns:
        A tuple (skipped, eof), where skipped holds the bytes read before the
        magic number. At the end of the input, eof is True and skipped holds
        all the bytes read.
    """
    skipped = bytearray()
    window = b""  # the last bytes read, at most a magic number long
    while window != magic:
        next_byte = read_input(in_file, rec_file, 1, mode, state)
        if not next_byte:  # end of file
            return (bytes(skipped) + window, True)
        window += next_byte
        if len(window) > MAGIC_LEN:
            skipped += window[:1]
            window = window[1:]
    return (bytes(skipped), False)


def read_bytes(in_file, rec_file, length, mode, state):
    """
    Read the specified number of bytes from the input file.

    When following a growing file, waits for more data at the end of the
    file. The bytes read are also written to the record file. Read and write
    errors are raised, as they are not the end of the data.

    Returns:
        The bytes read, or b"" at end of file.
    """
    se.logutils.set_state(state, "readLength", length)
    in_buf = bytes(in_file.read(length))
    # at the end of file, wait for more data when following
    if not in_buf and mode.following:
        while not in_buf:
            time.sleep(SLEEP_INTERVAL)
            in_buf = in_file.read(length)
    record_msg(in_buf, rec_file)
    if in_buf:  # keep the last byte read at the end of file
        se.logutils.set_state(
            state, "lastByteRead", f"{bytearray(in_buf)[-1]:02x}"
        )
    return in_buf


class Tally:
    """
    Count the messages rejected and repaired, for the summary of a run.

    The reader can run in a thread, so the counts are kept under a lock.
    """

    def __init__(self):
        """Start the counts at zero."""
        self._lock = threading.Lock()
        self._clear()

    def _clear(self):
        self.rejected = 0
        self.looks = dict.fromkeys(REPAIR_LEVELS, 0)
        self.repaired = dict.fromkeys(REPAIR_LEVELS, 0)

    def add_rejected(self):
        """Count a rejected message."""
        with self._lock:
            self.rejected += 1

    def add_looks(self, level):
        """Count a rejected message that looks repairable at the level."""
        with self._lock:
            self.looks[level] += 1

    def add_repaired(self, level):
        """Count a message that is repaired at the level."""
        with self._lock:
            self.repaired[level] += 1

    def take_summary(self):
        """
        Return the summary of the counts, and clear them.

        Returns:
            A tuple (level, text) for the log, or None if nothing was counted.
        """
        with self._lock:
            rejected, looks, repaired = (
                self.rejected,
                dict(self.looks),
                dict(self.repaired),
            )
            self._clear()
        if not rejected and not any(repaired.values()):
            return None
        text = (
            f"{rejected} messages rejected ({looks['crc']} look repairable "
            f"with -R crc, {looks['data']} with -R data), "
            f"{repaired['crc']} repaired at level crc, "
            f"{repaired['data']} at level data"
        )
        return (logging.ERROR if rejected else logging.WARNING, text)


TALLY = Tally()


def parse_msg(msg, repair=()):
    """
    Parse a message into its sequence, addresses, function and data.

    Messages shorter than a header plus checksum are thrown out.

    Args:
        msg: The message, without its magic number.
        repair: The CRC repair levels that are enabled, see validate_msg.

    Returns:
        A tuple (msgSeq, fromAddr, toAddr, function, data). All fields are
        zero and data is empty if the message is rejected.
    """
    if (
        len(msg) < MSG_HDR_LEN + CHECKSUM_LEN
    ):  # throw out messages that are too short
        logger.data("Threw out a message that was too short")
        TALLY.add_rejected()
        return (0, 0, 0, 0, b"")
    (msg_seq, from_addr, to_addr, function, data) = validate_msg(msg, repair)
    return (msg_seq, from_addr, to_addr, function, data)


def reject_msg(msg, reason, *args):
    """
    Log why a message is rejected and dump the message data.

    Returns:
        The empty message tuple (0, 0, 0, 0, b"").
    """
    TALLY.add_rejected()
    logger.error(reason, *args)
    for line in se.logutils.format_data(msg):
        logger.data(line)
    return (0, 0, 0, 0, b"")


def reject_inverse(msg, data_len, data_len_inv):
    """
    Reject a message whose data length does not match its inverse length.

    Returns:
        The empty message tuple (0, 0, 0, 0, b"").
    """
    return reject_msg(
        msg,
        "Data length 0x%04x doesn't match inverse length 0x%04x, "
        "expected 0x%04x",
        data_len,
        data_len_inv,
        ~data_len & 0xFFFF,
    )


class Fault(NamedTuple):
    """A bit that is wrong in a frame, and the level that repairs it."""

    level: str  # "crc" for a bit of the checksum, "data" for a covered bit
    frame_byte: object  # the byte of the frame, None for a bit of the checksum
    mask: int  # the bit of the checksum, or of the frame byte
    direction: str  # "1->0" or "0->1" for a bit of the checksum, else ""


def find_fault(checksum, calcsum, data_len, frame_len):
    """
    Find the one bit that is wrong in a frame of exactly its declared length.

    The syndrome, the XOR of the received and the calculated checksum, is one
    bit for a bit of the checksum that is wrong. A bit of the sequence,
    addresses, function or data has a syndrome of its own, see data_syndromes.
    A frame longer than REPAIR_MAX_BITS is not looked at.

    Returns:
        A Fault, or None if no single bit explains the checksum.
    """
    if 8 * frame_len > REPAIR_MAX_BITS:
        return None
    diff = checksum ^ calcsum
    if diff == 0:
        return None
    if (diff & (diff - 1)) == 0:  # one bit: the checksum
        direction = "1->0" if checksum & diff else "0->1"
        return Fault("crc", None, diff, direction)
    found = data_syndromes(data_len).get(diff)
    if found is None:
        return None
    return Fault("data", found[0], found[1], "")


def describe(fault):
    """
    Return where the wrong bit is, in the words of the log.

    Returns:
        The bit of the checksum or of the frame byte, with its bit number.
    """
    bit = fault.mask.bit_length() - 1
    if fault.frame_byte is None:
        return f"checksum bit {bit} {fault.direction}"
    return f"frame byte {fault.frame_byte} bit {bit}"


def hint(fault):
    """
    Return what the reject reason says when a frame is repairable, but off.

    Returns:
        The hint to add to the checksum error, naming the level to repair it.
    """
    return f", looks repairable with -R {fault.level}: {describe(fault)}"


def _enabled(levels, level):
    """
    Return whether a repair level is enabled, data implies the crc level.

    Returns:
        True if the level is enabled.
    """
    return level in levels or (level == "crc" and "data" in levels)


# the covered header fields as (frame offset, size), in the order of the CRC
CRC_FIELDS = ((4, 2), (6, 4), (10, 4), (14, 2))  # sequence, from, to, function
CRC_HDR_LEN = 12  # the covered header fields, before the data


def crc_frame_byte(index):
    """
    Return the frame byte of a byte of the CRC input.

    The header fields are big endian in the CRC input, and little endian in
    the frame, so their bytes are in reverse order.

    Returns:
        The index of the byte in the frame.

    Raises:
        ValueError: If the index is not a covered byte of the header.
    """
    if index >= CRC_HDR_LEN:  # data
        return index + MSG_HDR_LEN - CRC_HDR_LEN
    start = 0
    for offset, size in CRC_FIELDS:
        if index < start + size:
            return offset + size - 1 - (index - start)
        start += size
    msg = f"no CRC field at {index}"
    raise ValueError(msg)


@functools.cache
def data_syndromes(data_len):
    """
    Map the syndrome of each covered bit to its frame byte and mask.

    The covered bytes are the sequence, addresses, function and data, as the
    CRC takes them. The syndrome of a bit only depends on its position, so the
    table is made once per data length. A table with a repeated syndrome, or
    with a syndrome of an even number of bits or of one bit, is empty.

    Returns:
        A dict {syndrome: (frame_byte, mask)}.
    """
    entries = []
    column = [CRC_TABLE[1 << bit] for bit in range(8)]
    for index in range(CRC_HDR_LEN + data_len - 1, -1, -1):
        for bit, syndrome in enumerate(column):
            entries.append((syndrome, crc_frame_byte(index), 1 << bit))
        column = [CRC_TABLE[s & 0xFF] ^ (s >> 8) for s in column]
    syndromes = [entry[0] for entry in entries]
    if len(set(syndromes)) != len(syndromes) or any(
        s.bit_count() % 2 == 0 or s & (s - 1) == 0 for s in syndromes
    ):
        return {}
    return {syndrome: (byte, mask) for syndrome, byte, mask in entries}


def repair_frame(msg, fault, checksum, calcsum):
    """
    Repair the bit of a fault, and log the repair at WARNING.

    A bit of the checksum is repaired by the checksum alone, the data is not
    changed. A covered bit is flipped back, and then the checksum must match.

    Returns:
        The repaired message, or None if the flip does not give the checksum.
    """
    fixed = bytearray(msg)
    if fault.frame_byte is not None:
        fixed[fault.frame_byte] ^= fault.mask
    (data_len,) = struct.unpack_from("<H", msg, 0)
    (msg_seq, from_addr, to_addr, function) = struct.unpack(
        "<HLLH", fixed[4:MSG_HDR_LEN]
    )
    data = bytes(fixed[MSG_HDR_LEN : MSG_HDR_LEN + data_len])
    if (
        fault.frame_byte is not None
        and calc_crc(
            struct.pack(">HLLH", msg_seq, from_addr, to_addr, function) + data
        )
        != checksum
    ):
        return None
    logger.warning(
        "Repaired frame seq %d from 0x%08x to 0x%08x function 0x%04x: %s, "
        "checksum 0x%04x -> 0x%04x",
        msg_seq,
        from_addr,
        to_addr,
        function,
        describe(fault),
        checksum,
        calcsum,
    )
    TALLY.add_repaired(fault.level)
    return bytes(fixed)


def validate_msg(msg, repair=()):
    """
    Parse the header of a message and check its lengths and checksum.

    Extra bytes after the message are logged and discarded. A checksum that
    does not match is looked at for one bit that is wrong, see find_fault. The
    frame is repaired when that bit's level is in repair, and is rejected
    otherwise. A frame that looks repairable is logged as such, either way.

    Args:
        msg: The message, without its magic number.
        repair: The CRC repair levels that are enabled, see REPAIR_LEVELS.

    Returns:
        A tuple (msgSeq, fromAddr, toAddr, function, data), or the rejected
        message tuple from reject_msg if the message is invalid.
    """
    # message must be at least a header and checksum
    if len(msg) < MSG_HDR_LEN + CHECKSUM_LEN:
        return reject_msg(
            msg,
            "Message of %d bytes is too short, at least %d bytes needed",
            len(msg),
            MSG_HDR_LEN + CHECKSUM_LEN,
        )
    # parse the message header
    (data_len, data_len_inv, msg_seq, from_addr, to_addr, function) = (
        struct.unpack("<HHHLLH", msg[0:MSG_HDR_LEN])
    )
    log_msg_hdr(
        MsgHdr(data_len, data_len_inv, msg_seq, from_addr, to_addr, function)
    )
    # data length must match inverse length, before the length is used
    if data_len != ~data_len_inv & 0xFFFF:
        return reject_inverse(msg, data_len, data_len_inv)
    # header + data + checksum can't be longer than the message
    if MSG_HDR_LEN + data_len + CHECKSUM_LEN > len(msg):
        return reject_msg(
            msg,
            "Data length %d is too big for a message of %d bytes",
            data_len,
            len(msg),
        )
    data = msg[MSG_HDR_LEN : MSG_HDR_LEN + data_len]
    # discard extra bytes after the message
    extra_len = len(msg) - (MSG_HDR_LEN + data_len + CHECKSUM_LEN)
    if extra_len != 0:
        logger.data("Discarding %s extra bytes", extra_len)
        for line in se.logutils.format_data(msg[-extra_len:]):
            logger.data(line)
    # validate the checksum
    checksum = struct.unpack(
        "<H",
        msg[MSG_HDR_LEN + data_len : MSG_HDR_LEN + data_len + CHECKSUM_LEN],
    )[0]
    calcsum = calc_crc(
        struct.pack(">HLLH", msg_seq, from_addr, to_addr, function) + data
    )
    if calcsum != checksum:
        fault = None
        if extra_len == 0:  # the length of the message is confirmed
            fault = find_fault(checksum, calcsum, data_len, len(msg))
        enabled = fault is not None and _enabled(repair, fault.level)
        repaired = (
            repair_frame(msg, fault, checksum, calcsum) if enabled else None
        )
        if repaired is None:
            reason = "Checksum error. Expected 0x%04x, got 0x%04x"
            if fault is not None and not enabled:
                TALLY.add_looks(fault.level)
                reason += hint(fault)
            return reject_msg(msg, reason, calcsum, checksum)
        msg = repaired
        (msg_seq, from_addr, to_addr, function) = struct.unpack(
            "<HLLH", msg[4:MSG_HDR_LEN]
        )
        data = msg[MSG_HDR_LEN : MSG_HDR_LEN + data_len]
    return (msg_seq, from_addr, to_addr, function, data)


def format_msg(msg_seq, from_addr, to_addr, function, data=b""):
    """
    Build a complete message, with its length fields and checksum.

    Returns:
        The message as a bytearray, without the magic number.
    """
    checksum = calc_crc(
        bytearray(struct.pack(">HLLH", msg_seq, from_addr, to_addr, function))
        + data
    )
    msg = bytearray(
        struct.pack(
            "<HHHLLH",
            len(data),
            ~len(data) & 0xFFFF,
            msg_seq,
            from_addr,
            to_addr,
            function,
        )
        + data
        + struct.pack("<H", checksum)
    )
    log_msg_hdr(
        MsgHdr(
            len(data),
            ~len(data) & 0xFFFF,
            msg_seq,
            from_addr,
            to_addr,
            function,
        )
    )
    return msg


def send_msg(data_file, msg, rec_file):
    """Write a message, prefixed with the magic number, to the data file."""
    Seq.data_out += 1
    logger.message("<--", Seq.data_out, magic + msg, data_file.name)
    data_file.write(magic + msg)
    data_file.flush()
    record_msg(magic + msg, rec_file)


def record_msg(msg, rec_file):
    """Write a message to the record file, if one is open."""
    if rec_file:
        rec_file.write(msg)
        rec_file.flush()


# CRC calculation
#
# CRC-16 with the following parameters:
#
# width=16 poly=0x8005 init=0x5a5a refin=true refout=true xorout=0x0000

# fmt: off
CRC_TABLE = [
    0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241,
    0xC601, 0x06C0, 0x0780, 0xC741, 0x0500, 0xC5C1, 0xC481, 0x0440,
    0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40,
    0x0A00, 0xCAC1, 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841,
    0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81, 0x1A40,
    0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41,
    0x1400, 0xD4C1, 0xD581, 0x1540, 0xD701, 0x17C0, 0x1680, 0xD641,
    0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040,
    0xF001, 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240,
    0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0, 0x3480, 0xF441,
    0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41,
    0xFA01, 0x3AC0, 0x3B80, 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840,
    0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
    0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40,
    0xE401, 0x24C0, 0x2580, 0xE541, 0x2700, 0xE7C1, 0xE681, 0x2640,
    0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041,
    0xA001, 0x60C0, 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240,
    0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480, 0xA441,
    0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41,
    0xAA01, 0x6AC0, 0x6B80, 0xAB41, 0x6900, 0xA9C1, 0xA881, 0x6840,
    0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41,
    0xBE01, 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40,
    0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1, 0xB681, 0x7640,
    0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041,
    0x5000, 0x90C1, 0x9181, 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241,
    0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
    0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40,
    0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901, 0x59C0, 0x5880, 0x9841,
    0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40,
    0x4E00, 0x8EC1, 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41,
    0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680, 0x8641,
    0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040,
]
# fmt: on


def calc_crc(data):
    """Return the CRC-16 checksum of data, using the table above."""
    crc = 0x5A5A  # initial value
    for d in data:
        crc = CRC_TABLE[(crc ^ d) & 0xFF] ^ (crc >> 8)
    return crc


def log_msg_hdr(hdr):
    """Log each field of a message header at the data log level."""
    logger.data("dataLen:    %04x", hdr.data_len)
    logger.data("dataLenInv: %04x", hdr.data_len_inv)
    logger.data("sequence:   %04x", hdr.msg_seq)
    logger.data("source:     %08x", hdr.from_addr)
    logger.data("dest:       %08x", hdr.to_addr)
    logger.data("function:   %04x", hdr.function)
