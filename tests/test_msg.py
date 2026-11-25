import io
import logging
import os
import struct
import sys
import time
import types

import pytest

import se.env
import se.logutils
import se.msg
from tests.conftest import is_whole

SRC = 0xFFFFFFFE
DST = 0x7F104920
FUNCTION = 0x0501
NOTHING = (0, 0, 0, 0, b"")

DATA_LEVEL = se.logutils.LOG_LEVEL_DATA
RAW_LEVEL = se.logutils.LOG_LEVEL_RAW


def make_file(data=b""):
    file = io.BytesIO(data)
    file.name = "<test>"
    return file


def frame(seq=1, data=b"", function=FUNCTION):
    return bytes(se.msg.format_msg(seq, SRC, DST, function, data))


def corrupt(msg, index, mask):
    broken = bytearray(msg)
    broken[index] ^= mask
    return bytes(broken)


def too_big(msg):
    (data_len,) = struct.unpack("<H", msg[:2])
    return (
        f"Data length {data_len} is too big for a message of {len(msg)} bytes"
    )


def inverse_mismatch(msg):
    (data_len, inverse) = struct.unpack("<HH", msg[:4])
    return (
        f"Data length 0x{data_len:04x} doesn't match inverse length "
        f"0x{inverse:04x}, expected 0x{~data_len & 0xFFFF:04x}"
    )


def run_mode(*, passive, serial_type=None, following=False):
    return se.env.RunMode(
        serial_device=True,
        serial_type=serial_type,
        passive_mode=passive,
        master_mode=not passive,
        following=following,
    )


def reference_crc(data):
    crc = 0x5A5A
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def messages(caplog, level):
    return [r.getMessage() for r in caplog.records if r.levelno == level]


def log_all(caplog, level=RAW_LEVEL):
    caplog.set_level(level, logger="se.msg")


def read_all(infile, recfile, mode):
    results = []
    eof = False
    while not eof:
        result = se.msg.read_msg(infile, recfile, mode, {})
        results.append(result)
        eof = result[1]
    return results


MAGIC = se.msg.magic
GOOD = frame(1, b"\x01\x02\x03")
EMPTY = frame(2)

SCANNING_MODES = [
    pytest.param(run_mode(passive=True), id="passive"),
    pytest.param(run_mode(passive=False, serial_type="4"), id="rs485-active"),
    pytest.param(run_mode(passive=True, serial_type="4"), id="rs485-passive"),
]
HEADER_MODES = [
    pytest.param(run_mode(passive=False, serial_type="2"), id="active-rs232"),
]


# --- CRC and formatting ------------------------------------------------------


def test_crc_of_nothing_is_the_initial_value():
    assert se.msg.calc_crc(b"") == 0x5A5A


@pytest.mark.parametrize(
    "data",
    [b"\x00", b"\xff", b"123456789", bytes(range(256)), bytearray(b"abc")],
)
def test_crc_matches_the_bitwise_definition(data):
    assert se.msg.calc_crc(data) == reference_crc(data)


@pytest.mark.parametrize("data", [b"", b"\x01", b"hello world", bytes(300)])
def test_format_msg_layout(data):
    msg = se.msg.format_msg(0x1234, SRC, DST, FUNCTION, data)

    header = struct.pack(
        "<HHHLLH", len(data), ~len(data) & 0xFFFF, 0x1234, SRC, DST, FUNCTION
    )
    crc = reference_crc(struct.pack(">HLLH", 0x1234, SRC, DST, FUNCTION) + data)
    assert isinstance(msg, bytearray)
    assert msg == header + data + struct.pack("<H", crc)


def test_format_msg_takes_bytearray_data():
    msg = se.msg.format_msg(7, SRC, DST, FUNCTION, bytearray(b"ab"))

    assert msg == se.msg.format_msg(7, SRC, DST, FUNCTION, b"ab")


def test_format_msg_logs_the_header(caplog):
    log_all(caplog, DATA_LEVEL)

    se.msg.format_msg(0x1234, SRC, DST, FUNCTION, b"ab")

    assert messages(caplog, DATA_LEVEL) == [
        "dataLen:    0002",
        f"dataLenInv: {0xFFFD:04x}",
        "sequence:   1234",
        f"source:     {SRC:08x}",
        f"dest:       {DST:08x}",
        "function:   0501",
    ]


# --- parsing and validating --------------------------------------------------


@pytest.mark.parametrize("data", [b"", b"\x01", b"x" * 100])
@pytest.mark.parametrize("parse", [se.msg.parse_msg, se.msg.validate_msg])
def test_valid_message_is_parsed(parse, data):
    msg = frame(4660, data, function=0x0080)

    assert parse(msg) == (4660, SRC, DST, 0x0080, data)


def test_message_as_bytearray_is_parsed():
    msg = se.msg.format_msg(5, SRC, DST, FUNCTION, b"\x09")

    assert se.msg.parse_msg(msg) == (5, SRC, DST, FUNCTION, b"\x09")


def test_parse_msg_throws_out_a_message_that_is_too_short(caplog):
    log_all(caplog, DATA_LEVEL)

    assert se.msg.parse_msg(EMPTY[:-1]) == NOTHING

    assert messages(caplog, DATA_LEVEL) == [
        "Threw out a message that was too short"
    ]
    assert not messages(caplog, logging.ERROR)


@pytest.mark.parametrize("length", [0, 1, 17])
def test_validate_msg_rejects_a_message_that_is_too_short(caplog, length):
    log_all(caplog, DATA_LEVEL)
    msg = EMPTY[:length]

    assert se.msg.validate_msg(msg) == NOTHING

    needed = se.msg.MSG_HDR_LEN + se.msg.CHECKSUM_LEN
    too_short = f"Message of {length} bytes is too short, at least {needed}"
    assert messages(caplog, logging.ERROR) == [f"{too_short} bytes needed"]
    assert messages(caplog, DATA_LEVEL) == list(se.logutils.format_data(msg))


@pytest.mark.parametrize(
    ("msg", "error"),
    [
        pytest.param(GOOD[:-1], too_big(GOOD[:-1]), id="too-big"),
        pytest.param(
            corrupt(GOOD, 0, 0x10),
            inverse_mismatch(corrupt(GOOD, 0, 0x10)),
            id="length-byte-only",
        ),
        pytest.param(
            corrupt(GOOD, 2, 0x01),
            inverse_mismatch(corrupt(GOOD, 2, 0x01)),
            id="inverse-low-byte",
        ),
        pytest.param(
            corrupt(GOOD, 3, 0x80),
            inverse_mismatch(corrupt(GOOD, 3, 0x80)),
            id="inverse-high-byte",
        ),
        pytest.param(
            corrupt(GOOD, -1, 0x01), "Checksum error.", id="checksum-low-byte"
        ),
        pytest.param(
            corrupt(GOOD, -2, 0x80), "Checksum error.", id="checksum-high-byte"
        ),
        pytest.param(
            corrupt(GOOD, 17, 0x04), "Checksum error.", id="corrupt-data"
        ),
        pytest.param(
            corrupt(GOOD, 4, 0x04), "Checksum error.", id="corrupt-sequence"
        ),
        pytest.param(
            corrupt(GOOD, 8, 0x04), "Checksum error.", id="corrupt-source"
        ),
        pytest.param(
            corrupt(GOOD, 14, 0x04), "Checksum error.", id="corrupt-function"
        ),
    ],
)
@pytest.mark.parametrize("parse", [se.msg.parse_msg, se.msg.validate_msg])
def test_broken_message_is_rejected_and_dumped(caplog, parse, msg, error):
    log_all(caplog, DATA_LEVEL)

    assert parse(msg) == NOTHING

    (logged,) = messages(caplog, logging.ERROR)
    assert logged.startswith(error)
    dump = list(se.logutils.format_data(msg))
    assert messages(caplog, DATA_LEVEL)[-len(dump) :] == dump


def test_extra_bytes_after_the_message_are_discarded(caplog):
    log_all(caplog, DATA_LEVEL)

    result = se.msg.parse_msg(GOOD + b"\xaa\xbb")

    assert result == (1, SRC, DST, FUNCTION, b"\x01\x02\x03")
    logged = messages(caplog, DATA_LEVEL)
    assert "Discarding 2 extra bytes" in logged
    assert logged[-1] == "data:       aa bb"
    assert not messages(caplog, logging.ERROR)


def test_extra_bytes_are_dumped_in_lines_of_16(caplog):
    log_all(caplog, DATA_LEVEL)
    extra = bytes(range(20))

    assert se.msg.parse_msg(EMPTY + extra) == (2, SRC, DST, FUNCTION, b"")

    assert "Discarding 20 extra bytes" in messages(caplog, DATA_LEVEL)
    assert messages(caplog, DATA_LEVEL)[-2:] == [
        "data:       " + " ".join(f"{x:02x}" for x in range(16)),
        "data:       10 11 12 13",
    ]


def test_message_without_extra_bytes_does_not_log_any(caplog):
    log_all(caplog, DATA_LEVEL)

    se.msg.parse_msg(GOOD)

    assert not [m for m in messages(caplog, DATA_LEVEL) if "extra" in m]


def test_checksum_error_reports_the_calculated_sum_as_expected(caplog):
    log_all(caplog, DATA_LEVEL)
    (msg_seq, from_addr, to_addr, function, data) = se.msg.parse_msg(GOOD)
    calculated = se.msg.calc_crc(
        struct.pack(">HLLH", msg_seq, from_addr, to_addr, function) + data
    )
    received = calculated ^ 0x0101

    se.msg.parse_msg(GOOD[:-2] + struct.pack("<H", received))

    (logged,) = messages(caplog, logging.ERROR)
    sums = f"Expected 0x{calculated:04x}, got 0x{received:04x}"
    assert logged == f"Checksum error. {sums}"


# --- repairing the checksum --------------------------------------------------

# the checksum repairs, the data level is tested on its own
CRC_ONLY = ("crc",)


# Frames of no data from a recording, whose checksum has one bit wrong. index
# and mask give the byte of the checksum and the bit, as passed to corrupt.
# direction is the repair: a bit received as 1 is cleared, and a bit received
# as 0 is set.
FAMILY_FROM = 0x73124CBA
FAMILY_TO = 0xFFFFFFFE
FAMILY_FUNCTION = 0x039A
WRONG_BIT = [
    pytest.param(
        bytes.fromhex("0000ffffef01ba4c1273feffffff9a038adb"),
        -1,
        0x80,
        "1->0",
        id="hi-7",
    ),
    pytest.param(
        bytes.fromhex("0000ffff1400ba4c1273feffffff9a0351ff"),
        -1,
        0x40,
        "1->0",
        id="hi-6",
    ),
    pytest.param(
        bytes.fromhex("0000ffff4b86ba4c1273feffffff9a036afc"),
        -1,
        0x20,
        "1->0",
        id="hi-5",
    ),
    pytest.param(
        bytes.fromhex("0000ffff4803ba4c1273feffffff9a036bfa"),
        -1,
        0x10,
        "1->0",
        id="hi-4",
    ),
    pytest.param(
        bytes.fromhex("0000ffffd54aba4c1273feffffff9a03b06f"),
        -1,
        0x08,
        "1->0",
        id="hi-3",
    ),
    pytest.param(
        bytes.fromhex("0000ffffb101ba4c1273feffffff9a03bfb6"),
        -1,
        0x04,
        "1->0",
        id="hi-2",
    ),
    pytest.param(
        bytes.fromhex("0000ffff5f07ba4c1273feffffff9a03d493"),
        -1,
        0x02,
        "1->0",
        id="hi-1",
    ),
    pytest.param(
        bytes.fromhex("0000ffff18ccba4c1273feffffff9a037dbf"),
        -1,
        0x01,
        "1->0",
        id="hi-0",
    ),
    pytest.param(
        bytes.fromhex("0000ffff7febba4c1273feffffff9a03fdbf"),
        -2,
        0x10,
        "1->0",
        id="lo-4",
    ),
    pytest.param(
        bytes.fromhex("0000ffffa06eba4c1273feffffff9a037b12"),
        -1,
        0x08,
        "0->1",
        id="set-hi-3",
    ),
]
FRAMES_WITH_ONE_BIT_WRONG = [
    pytest.param(p.values[0], id=p.id) for p in WRONG_BIT
]
# A frame of the family with more than one bit wrong, not repaired.
UNREPAIRABLE = bytes.fromhex("0000ffffa200ba4c1273feffffff9a037df7")


def repaired_seq(frame_bytes):
    return struct.unpack_from("<H", frame_bytes, 4)[0]


def checksum_bit(index, mask):
    # the checksum is little endian, so the last byte is its high byte
    return (8 if index == -1 else 0) + mask.bit_length() - 1


@pytest.mark.parametrize("parse", [se.msg.parse_msg, se.msg.validate_msg])
@pytest.mark.parametrize(("rx", "index", "mask", "direction"), WRONG_BIT)
def test_a_checksum_with_one_bit_wrong_is_repaired(
    caplog, parse, rx, index, mask, direction
):
    seq = repaired_seq(rx)
    expected = corrupt(rx, index, mask)  # the frame as it was sent

    assert parse(rx, CRC_ONLY) == (
        seq,
        FAMILY_FROM,
        FAMILY_TO,
        FAMILY_FUNCTION,
        b"",
    )

    assert (
        se.msg.format_msg(seq, FAMILY_FROM, FAMILY_TO, FAMILY_FUNCTION)
        == expected
    )
    (logged,) = messages(caplog, logging.WARNING)
    assert logged.startswith(f"Repaired frame seq {seq} ")
    assert f"checksum bit {checksum_bit(index, mask)} {direction}, " in logged


@pytest.mark.parametrize("rx", FRAMES_WITH_ONE_BIT_WRONG)
def test_a_checksum_is_not_repaired_unless_the_repair_is_enabled(caplog, rx):
    assert se.msg.parse_msg(rx) == NOTHING

    assert not messages(caplog, logging.WARNING)
    (logged,) = messages(caplog, logging.ERROR)
    assert logged.startswith("Checksum error.")


@pytest.mark.parametrize(
    ("checksum", "calcsum"),
    [
        pytest.param(0x1234, 0x1234, id="no-bit"),
        pytest.param(0x0003, 0x0000, id="two-bits"),
    ],
)
def test_a_checksum_without_one_bit_wrong_has_no_fault(checksum, calcsum):
    assert se.msg.find_fault(checksum, calcsum, 0, len(GOOD)) is None


@pytest.mark.parametrize(
    ("checksum", "calcsum", "fault"),
    [
        pytest.param(0x0001, 0x0000, ("crc", None, 0x0001, "1->0"), id="lost"),
        pytest.param(
            0x0000, 0x8000, ("crc", None, 0x8000, "0->1"), id="gained"
        ),
    ],
)
def test_find_fault_gives_the_checksum_bit_and_its_direction(
    checksum, calcsum, fault
):
    found = se.msg.find_fault(checksum, calcsum, 0, len(GOOD))

    assert found == se.msg.Fault(*fault)


# frames of 4095 bytes are within REPAIR_MAX_BITS, 4096 bytes are not
@pytest.mark.parametrize(
    ("data_len", "repaired"),
    [
        pytest.param(4095 - 18, True, id="at-the-limit"),
        pytest.param(4096 - 18, False, id="above"),
    ],
)
def test_a_frame_is_repaired_only_within_the_limit(data_len, repaired):
    rx = bytes(
        corrupt(
            se.msg.format_msg(
                1, FAMILY_FROM, FAMILY_TO, FAMILY_FUNCTION, bytes(data_len)
            ),
            -1,
            0x01,
        )
    )

    assert (se.msg.parse_msg(rx, CRC_ONLY) != NOTHING) == repaired


@pytest.mark.parametrize(
    "flips",
    [
        pytest.param([(-1, 0x03)], id="two-bits-high"),
        pytest.param([(-2, 0x81)], id="two-bits-low"),
        pytest.param([(-1, 0x01), (-2, 0x01)], id="one-bit-in-each-byte"),
    ],
)
def test_a_checksum_with_more_than_one_bit_wrong_is_not_repaired(caplog, flips):
    rx = bytes(se.msg.format_msg(1, FAMILY_FROM, FAMILY_TO, FAMILY_FUNCTION))
    for index, mask in flips:
        rx = corrupt(rx, index, mask)

    assert se.msg.parse_msg(rx, CRC_ONLY) == NOTHING

    assert not messages(caplog, logging.WARNING)


def test_a_frame_with_unexplained_bits_is_not_repaired(caplog):
    assert se.msg.parse_msg(UNREPAIRABLE, CRC_ONLY) == NOTHING

    assert not messages(caplog, logging.WARNING)
    (logged,) = messages(caplog, logging.ERROR)
    assert logged.startswith("Checksum error.")


@pytest.mark.parametrize(
    ("msg", "index", "mask"),
    [
        pytest.param(GOOD, 17, 0x04, id="data"),
        pytest.param(GOOD, 4, 0x04, id="sequence"),
        pytest.param(GOOD, 8, 0x04, id="source"),
    ],
)
def test_a_damaged_frame_other_than_its_checksum_is_not_repaired(
    caplog, msg, index, mask
):
    rx = corrupt(msg, index, mask)

    assert se.msg.parse_msg(rx, CRC_ONLY) == NOTHING

    assert not messages(caplog, logging.WARNING)


@pytest.mark.parametrize("rx", FRAMES_WITH_ONE_BIT_WRONG[:1])
def test_a_checksum_is_not_repaired_when_the_message_is_longer(caplog, rx):
    longer = rx + b"\x00"

    assert se.msg.parse_msg(longer, CRC_ONLY) == NOTHING

    assert not messages(caplog, logging.WARNING)


def test_payload_bit_flips_are_never_repaired():
    msg = frame(1, bytes(range(1, 65)))
    payload = [(16 + i // 8, 1 << i % 8) for i in range(8 * 64)]
    checksum = [(-2, 1 << k) for k in range(8)] + [
        (-1, 1 << k) for k in range(8)
    ]
    # every single payload bit, pairs of them, and a payload bit with a CRC bit
    flips = [[flip] for flip in payload]
    flips += [
        [payload[i], payload[j]]
        for i in range(len(payload))
        for j in (i + 1, i + 2, i + 3, i + 97)
        if j < len(payload)
    ]
    flips += [[flip, bit] for flip in payload for bit in checksum]

    for flip in flips:
        rx = msg
        for index, mask in flip:
            rx = corrupt(rx, index, mask)
        assert se.msg.validate_msg(rx, CRC_ONLY) == NOTHING


# --- repairing a bit of the header or data -----------------------------------

# A bit of the sequence, addresses, function or data. The data level implies
# the checksum level, so it is tested on its own too.
DATA_ONLY = ("data",)
DATA_FRAMES = [
    pytest.param(frame(1, bytes(range(64))), id="data"),
    pytest.param(frame(3), id="no-data"),
]


def covered_bits(msg):
    """Return the bits of the sequence, addresses, function and data of msg."""
    return [
        (index, 1 << bit)
        for index in range(4, len(msg) - 2)
        for bit in range(8)
    ]


@pytest.mark.parametrize("levels", [se.msg.REPAIR_LEVELS, DATA_ONLY])
@pytest.mark.parametrize("msg", DATA_FRAMES)
def test_a_bit_of_the_header_or_data_is_repaired(caplog, msg, levels):
    caplog.set_level(logging.WARNING, logger="se.msg")
    expected = se.msg.validate_msg(msg)
    assert expected != NOTHING

    for index, mask in covered_bits(msg):
        caplog.clear()
        rx = corrupt(msg, index, mask)

        assert se.msg.parse_msg(rx, levels) == expected
        (logged,) = messages(caplog, logging.WARNING)
        assert f"frame byte {index} bit {mask.bit_length() - 1}," in logged


@pytest.mark.parametrize("levels", [CRC_ONLY, DATA_ONLY])
@pytest.mark.parametrize("msg", DATA_FRAMES)
def test_a_checksum_bit_is_repaired_by_the_data_level_too(msg, levels):
    expected = se.msg.validate_msg(msg)

    for index in (-2, -1):
        for bit in range(8):
            rx = corrupt(msg, index, 1 << bit)
            assert se.msg.parse_msg(rx, levels) == expected


@pytest.mark.parametrize("levels", [CRC_ONLY, ()])
@pytest.mark.parametrize("msg", DATA_FRAMES)
def test_a_bit_of_the_header_or_data_is_not_repaired_without_its_level(
    msg, levels
):
    for index, mask in covered_bits(msg):
        assert se.msg.parse_msg(corrupt(msg, index, mask), levels) == NOTHING


def test_a_pair_of_bits_of_the_header_or_data_is_not_repaired(caplog):
    caplog.set_level(logging.WARNING, logger="se.msg")
    msg = frame(1, bytes(range(4)))
    bits = covered_bits(msg)

    for pos, (index, mask) in enumerate(bits):
        for other, other_mask in bits[pos + 1 :]:
            rx = corrupt(corrupt(msg, index, mask), other, other_mask)
            assert se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) == NOTHING

    assert not messages(caplog, logging.WARNING)


@pytest.mark.parametrize("stride", [1, 8, 63])
def test_a_pair_of_bits_of_a_long_frame_is_not_repaired(caplog, stride):
    caplog.set_level(logging.WARNING, logger="se.msg")
    msg = frame(1, bytes(range(64)))
    bits = covered_bits(msg)

    for pos in range(len(bits) - stride):
        (index, mask) = bits[pos]
        (other, other_mask) = bits[pos + stride]
        rx = corrupt(corrupt(msg, index, mask), other, other_mask)
        assert se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) == NOTHING

    assert not messages(caplog, logging.WARNING)


@pytest.mark.parametrize(
    ("data_len", "repaired"),
    [
        pytest.param(4077, True, id="at-the-limit"),
        pytest.param(4078, False, id="above"),
    ],
)
def test_a_data_frame_is_repaired_only_within_the_limit(data_len, repaired):
    rx = corrupt(frame(1, bytes(data_len)), 20, 0x01)

    assert (se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) != NOTHING) == repaired


def test_a_frame_with_trailing_bytes_is_not_repaired_in_its_data():
    rx = corrupt(frame(1, bytes(range(4))), 20, 0x01) + b"\x00"

    assert se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) == NOTHING


@pytest.mark.parametrize("msg", DATA_FRAMES)
def test_a_length_field_is_not_repaired(msg):
    for index in range(4):
        for bit in range(8):
            rx = corrupt(msg, index, 1 << bit)
            assert se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) == NOTHING


# --- saying when a frame looks repairable ------------------------------------


def test_a_checksum_bit_that_looks_repairable_is_named_with_its_level(caplog):
    caplog.set_level(logging.ERROR, logger="se.msg")
    rx = corrupt(GOOD, -1, 0x80)
    direction = "1->0" if rx[-1] & 0x80 else "0->1"

    assert se.msg.parse_msg(rx) == NOTHING

    (logged,) = messages(caplog, logging.ERROR)
    assert logged.startswith("Checksum error.")
    assert logged.endswith(
        f", looks repairable with -R crc: checksum bit 15 {direction}"
    )


@pytest.mark.parametrize("levels", [(), CRC_ONLY])
def test_a_covered_bit_that_looks_repairable_is_named_with_the_data_level(
    caplog, levels
):
    caplog.set_level(logging.ERROR, logger="se.msg")

    assert se.msg.parse_msg(corrupt(GOOD, 17, 0x04), levels) == NOTHING

    (logged,) = messages(caplog, logging.ERROR)
    assert logged.endswith(
        ", looks repairable with -R data: frame byte 17 bit 2"
    )


@pytest.mark.parametrize(
    "rx",
    [
        pytest.param(corrupt(corrupt(GOOD, 17, 1), 18, 1), id="two-bits"),
        pytest.param(corrupt(GOOD, 17, 4) + b"\x00", id="trailing-byte"),
        pytest.param(
            corrupt(frame(1, bytes(4078)), 20, 1), id="over-the-limit"
        ),
        pytest.param(corrupt(GOOD, 0, 0x01), id="length-field"),
    ],
)
def test_a_frame_that_is_not_repairable_has_no_hint(caplog, rx):
    caplog.set_level(logging.ERROR, logger="se.msg")

    assert se.msg.parse_msg(rx, se.msg.REPAIR_LEVELS) == NOTHING

    assert not [m for m in messages(caplog, logging.ERROR) if "looks" in m]


def test_a_repairable_frame_is_repaired_without_an_error(caplog):
    caplog.set_level(logging.WARNING, logger="se.msg")

    assert se.msg.parse_msg(
        corrupt(GOOD, 17, 0x04), DATA_ONLY
    ) == se.msg.parse_msg(GOOD)

    assert not messages(caplog, logging.ERROR)
    (logged,) = messages(caplog, logging.WARNING)
    assert "frame byte 17 bit 2, checksum" in logged


# --- reading messages --------------------------------------------------------


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_scans_for_the_magic_number(mode):
    infile = make_file(MAGIC + GOOD + MAGIC + EMPTY)
    state = {}

    results = [se.msg.read_msg(infile, None, mode, state) for _ in range(4)]

    # The first magic number has nothing in front of it, and the last message
    # is ended by the end of the file.
    assert results == [(b"", False), (GOOD, False), (EMPTY, True), (b"", True)]


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_keeps_garbage_in_front_of_a_message(mode):
    infile = make_file(b"junk" + MAGIC + GOOD)

    assert se.msg.read_msg(infile, None, mode, {}) == (b"junk", False)
    assert se.msg.read_msg(infile, None, mode, {}) == (GOOD, True)


# Two acknowledgments as the inverter sends them, one after the other with
# no magic number between them (from a recording, 20220725.rec).
ACK_PAIR = bytes.fromhex(
    "0000ffff6705feffffffba4c12738000b5610000ffff680bba4c1273feffffff9a0321f5"
)
ACK_FIRST, ACK_SECOND = ACK_PAIR[:18], ACK_PAIR[18:]


# A frame from a recording (20220725.rec) with 224 bytes of data, of which
# the magic number is part of the data.
MAGIC_IN_DATA = bytes.fromhex(
    "e0001fff7303ba4c1273feffffff00050003ba4c12731c0018813b6376000000b34b"
    "0000ffffa0b12a000000ba4c0000000000001000ba4c9273b40018813b63904f0000"
    "00000000e06ae7410000ffff00000000cdbb68430000000030074842ffff7fffffff"
    "7fffffff7fffffff7fff0844c24ba96b873fc8601234ffff7fff0100000012345679"
    "dc1e9d3bf83f293fffff7fffffff7fff0000000000000000ba4c12730000807f0000"
    "807f7d4dcbf010888401000000009bb1ba4c6a4bc04cb69503060000000001001088"
    "84010000000000000000000000000000000000000000000000000100000000000000"
    "0000ea5e"
)


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_keeps_a_frame_whose_data_has_the_magic_number(mode):
    infile = make_file(MAGIC + MAGIC_IN_DATA + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]

    assert results == [(b"", False), (MAGIC_IN_DATA, False), (EMPTY, True)]


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_keeps_the_bytes_after_a_joined_frame(mode):
    # the bytes after the frame are in the same segment as its end
    junk = b"\x55\xaa\x01"
    infile = make_file(MAGIC + MAGIC_IN_DATA + junk + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(4)]

    assert results == [
        (b"", False),
        (MAGIC_IN_DATA, False),
        (junk, False),
        (EMPTY, True),
    ]


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_splits_at_a_magic_number_that_confirms_no_frame(mode):
    # the magic number in the data is only split at when the frame is damaged
    data = bytes(range(20)) + MAGIC + bytes(range(20))
    damaged = corrupt(frame(3, data), -1, 0x01)
    infile = make_file(MAGIC + damaged + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(4)]

    first = damaged[: se.msg.MSG_HDR_LEN + 20]
    rest = damaged[se.msg.MSG_HDR_LEN + 24 :]
    assert results == [
        (b"", False),
        (first, False),
        (rest, False),
        (EMPTY, True),
    ]


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_returns_the_frame_that_follows_without_a_magic_number(
    mode,
):
    infile = make_file(MAGIC + ACK_PAIR + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(4)]

    assert results == [
        (b"", False),
        (ACK_FIRST, False),
        (ACK_SECOND, False),
        (EMPTY, True),
    ]


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_keeps_the_bytes_after_a_message_that_are_not_a_frame(
    caplog, mode
):
    log_all(caplog, DATA_LEVEL)
    infile = make_file(MAGIC + GOOD + b"\xaa\xbb")

    assert se.msg.read_msg(infile, None, mode, {}) == (b"", False)
    assert se.msg.read_msg(infile, None, mode, {}) == (GOOD + b"\xaa\xbb", True)

    # the bytes are not a second frame, so validate_msg discards them
    assert se.msg.parse_msg(GOOD + b"\xaa\xbb") == (
        1,
        SRC,
        DST,
        FUNCTION,
        b"\x01\x02\x03",
    )
    assert "Discarding 2 extra bytes" in messages(caplog, DATA_LEVEL)


@pytest.mark.parametrize("mode", SCANNING_MODES)
def test_read_msg_without_any_magic_number_returns_the_rest(mode):
    assert se.msg.read_msg(make_file(b"abc"), None, mode, {}) == (b"abc", True)


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_uses_the_length_in_the_header(mode):
    infile = make_file(MAGIC + GOOD + MAGIC + EMPTY)
    state = {}

    results = [se.msg.read_msg(infile, None, mode, state) for _ in range(3)]

    assert results == [(GOOD, False), (EMPTY, False), (b"", True)]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_leaves_the_bytes_after_a_message_unread(mode):
    infile = make_file(MAGIC + GOOD + b"rest")

    assert se.msg.read_msg(infile, None, mode, {}) == (GOOD, False)
    assert infile.read() == b"rest"


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_returns_what_is_left_of_a_truncated_message(mode):
    infile = make_file(MAGIC + GOOD[:-3])

    assert se.msg.read_msg(infile, None, mode, {}) == (GOOD[:-3], False)
    assert se.msg.read_msg(infile, None, mode, {}) == (b"", True)


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_does_not_read_the_data_of_a_bad_inverse_length(caplog, mode):
    log_all(caplog, logging.ERROR)
    damaged = corrupt(GOOD, 2, 0x01)
    infile = make_file(MAGIC + damaged + b"rest")

    assert se.msg.read_msg(infile, None, mode, {}) == (b"", False)

    # only the header was read, the data and what follows are still unread
    assert infile.read() == damaged[se.msg.MSG_HDR_LEN :] + b"rest"
    (logged,) = messages(caplog, logging.ERROR)
    assert logged == inverse_mismatch(damaged)


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_skips_the_bytes_before_the_magic_number(caplog, mode):
    log_all(caplog, DATA_LEVEL)
    infile = make_file(b"junk" + MAGIC + GOOD)

    assert se.msg.read_msg(infile, None, mode, {}) == (GOOD, False)

    assert "Discarding 4 bytes before the magic number" in messages(
        caplog, DATA_LEVEL
    )


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_resyncs_on_the_magic_number_after_a_damaged_frame(mode):
    # the damaged header is rejected, and the rest of its frame is skipped
    infile = make_file(MAGIC + corrupt(GOOD, 2, 0x01) + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]

    assert results == [(b"", False), (EMPTY, False), (b"", True)]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_finds_the_frame_after_a_frame_that_lost_a_byte(mode):
    # the length of the damaged frame is still read, so its end is taken from
    # the length, and the magic number of the next frame is read as data
    infile = make_file(MAGIC + GOOD[:17] + GOOD[18:] + MAGIC + EMPTY)

    results = read_all(infile, None, mode)

    assert EMPTY in [msg for msg, _ in results]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_does_not_take_a_frame_without_the_magic_number(mode):
    infile = make_file(corrupt(MAGIC, 0, 0x01) + GOOD + MAGIC + EMPTY)

    assert se.msg.read_msg(infile, None, mode, {}) == (EMPTY, False)


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_skips_a_repeated_magic_number(mode):
    infile = make_file(MAGIC + MAGIC + GOOD + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(2)]

    assert results == [(GOOD, False), (EMPTY, False)]


# frames from a recording of an inverter, 20230621.rec: the first is preceded
# by a doubled magic number, the second follows the first without one
REAL_FIRST = bytes.fromhex("0000ffff5e01feffffffba4c127380009532")
REAL_SECOND = bytes.fromhex("0000ffff0200ba4c1273feffffff9a031bf7")


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_takes_the_frames_of_a_doubled_magic_number(mode):
    infile = make_file(MAGIC + MAGIC + REAL_FIRST + REAL_SECOND)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]

    assert results == [(REAL_FIRST, False), (REAL_SECOND, False), (b"", True)]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_returns_the_frame_that_follows_a_frame_on_rs232(mode):
    infile = make_file(MAGIC + ACK_PAIR + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]

    assert results == [
        (ACK_FIRST, False),
        (ACK_SECOND, False),
        (EMPTY, False),
    ]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_pushes_back_the_bytes_after_a_frame_that_are_not_a_frame(
    mode,
):
    infile = make_file(MAGIC + GOOD + bytes(20) + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(2)]

    assert results == [(GOOD, False), (EMPTY, False)]


def test_read_frame_without_magic_does_not_wait_for_data():
    read_fd, write_fd = os.pipe()
    infile = os.fdopen(read_fd, "rb", buffering=0)
    mode = run_mode(passive=False, serial_type="2")
    try:
        os.write(write_fd, MAGIC + GOOD)
        assert se.msg.read_msg(infile, None, mode, {}) == (GOOD, False)
        # nothing is waiting: returns at once, the writer is still open
        assert se.msg.read_frame_without_magic(infile, None, mode, {}) is None
    finally:
        infile.close()
        os.close(write_fd)


@pytest.mark.skipif(sys.platform == "win32", reason="select needs POSIX")
def test_read_msg_takes_a_frame_without_magic_when_it_is_waiting_on_a_pipe():
    read_fd, write_fd = os.pipe()
    infile = os.fdopen(read_fd, "rb", buffering=0)
    try:
        os.write(write_fd, MAGIC + REAL_FIRST + REAL_SECOND)
        os.close(write_fd)
        write_fd = None
        mode = run_mode(passive=False, serial_type="2")
        results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]
    finally:
        infile.close()
        if write_fd is not None:
            os.close(write_fd)

    assert results == [(REAL_FIRST, False), (REAL_SECOND, False), (b"", True)]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_pushes_back_a_frame_with_a_bad_checksum_after_a_frame(mode):
    broken = corrupt(GOOD, -1, 0x01)
    infile = make_file(MAGIC + GOOD + broken + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(2)]

    assert results == [(GOOD, False), (EMPTY, False)]


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_reads_the_bytes_pushed_back_before_a_following_frame(mode):
    # A damaged frame whose data holds a frame. The bytes after that frame in
    # the data are pushed back, and a frame may follow them without a magic.
    inner = MAGIC + GOOD + b"\x00" * 4
    damaged = corrupt(frame(1, inner), -1, 0x01)
    infile = make_file(MAGIC + damaged + MAGIC + EMPTY)

    results = [se.msg.read_msg(infile, None, mode, {}) for _ in range(3)]

    assert results == [(damaged, False), (GOOD, False), (EMPTY, False)]


def test_input_ready_is_true_for_an_in_memory_input():
    assert se.msg.input_ready(make_file(b""))


@pytest.mark.skipif(sys.platform == "win32", reason="select needs POSIX")
def test_input_ready_waits_for_a_pipe_only_when_it_has_no_data():
    read_fd, write_fd = os.pipe()
    infile = os.fdopen(read_fd, "rb", buffering=0)
    try:
        assert not se.msg.input_ready(infile)
        os.write(write_fd, b"x")
        assert se.msg.input_ready(infile)
    finally:
        infile.close()
        os.close(write_fd)


def test_input_ready_does_not_use_select_on_windows(monkeypatch):
    read_fd, write_fd = os.pipe()
    infile = os.fdopen(read_fd, "rb", buffering=0)
    try:
        os.write(write_fd, b"x")
        monkeypatch.setattr(sys, "platform", "win32")
        assert not se.msg.input_ready(infile)
    finally:
        infile.close()
        os.close(write_fd)


def test_input_ready_is_false_when_select_fails(monkeypatch):
    read_fd, write_fd = os.pipe()
    infile = os.fdopen(read_fd, "rb", buffering=0)

    def select(*_args):
        msg = "no select"
        raise OSError(msg)

    try:
        monkeypatch.setattr(se.msg.select, "select", select)
        assert not se.msg.input_ready(infile)
    finally:
        infile.close()
        os.close(write_fd)


class SerialFake:
    """A serial port that reports the bytes waiting, as pyserial does."""

    def __init__(self, data):
        self.data = data
        self.reads = 0

    @property
    def in_waiting(self):
        return len(self.data)

    def read(self, length):
        self.reads += 1
        (head, self.data) = (self.data[:length], self.data[length:])
        return head


def test_read_frame_without_magic_uses_the_bytes_a_serial_port_reports():
    mode = run_mode(passive=False, serial_type="2")
    serial = SerialFake(b"")

    assert se.msg.read_frame_without_magic(serial, None, mode, {}) is None
    assert serial.reads == 0

    serial = SerialFake(REAL_SECOND)
    assert se.msg.read_frame_without_magic(serial, None, mode, {}) == (
        REAL_SECOND
    )


@pytest.mark.parametrize("mode", HEADER_MODES)
def test_read_msg_reports_the_end_of_a_file_inside_the_header(mode):
    infile = make_file(MAGIC + GOOD[:6])

    assert se.msg.read_msg(infile, None, mode, {}) == (b"", True)


@pytest.mark.parametrize("mode", SCANNING_MODES + HEADER_MODES)
def test_read_msg_records_everything_it_reads(mode):
    stream = MAGIC + GOOD + MAGIC + EMPTY
    infile = make_file(stream)
    recfile = io.BytesIO()

    read_all(infile, recfile, mode)

    assert recfile.getvalue() == stream


@pytest.mark.parametrize("mode", SCANNING_MODES + HEADER_MODES)
def test_read_msg_counts_the_messages_it_reads(mode):
    infile = make_file(MAGIC + GOOD)
    before = se.msg.Seq.data_in

    se.msg.read_msg(infile, None, mode, {})
    se.msg.read_msg(infile, None, mode, {})

    assert se.msg.Seq.data_in == before + 2


@pytest.mark.parametrize(
    ("mode", "last_byte", "length"),
    [
        pytest.param(SCANNING_MODES[0].values[0], "79", 1, id="scanning"),
        pytest.param(
            HEADER_MODES[0].values[0], f"{GOOD[-1]:02x}", 5, id="header"
        ),
    ],
)
def test_read_msg_keeps_track_of_its_state(mode, last_byte, length):
    state = {}

    se.msg.read_msg(make_file(MAGIC + GOOD), None, mode, state)

    assert state["passiveMode"][1] is mode.passive_mode
    assert state["serialType"][1] == mode.serial_type
    assert state["readLength"][1] == length
    assert state["lastByteRead"][1] == last_byte


@pytest.mark.parametrize("mode", SCANNING_MODES + HEADER_MODES)
def test_read_msg_logs_the_message_but_not_empty_ones(caplog, mode):
    log_all(caplog)
    infile = make_file(MAGIC + GOOD)

    se.msg.read_msg(infile, None, mode, {})  # zero length for scanning
    if mode.passive_mode or mode.serial_type == "4":
        assert not caplog.records
        se.msg.read_msg(infile, None, mode, {})

    seq = se.msg.Seq.data_in
    length = len(MAGIC + GOOD)
    assert messages(caplog, logging.DEBUG) == [
        f"<test> --> message: {seq} length: {length}"
    ]
    assert messages(caplog, RAW_LEVEL) == list(
        se.logutils.format_data(MAGIC + GOOD)
    )


# --- reading recordings ------------------------------------------------------


def test_read_msg_splits_a_recording_at_the_magic_numbers(golden, sample):
    data = golden("rec", sample).read_bytes()
    recfile = io.BytesIO()

    results = read_all(
        make_file(data), recfile, run_mode(passive=True, serial_type="4")
    )

    msgs, eofs = zip(*results, strict=True)
    assert list(msgs) == data.split(MAGIC)
    assert list(eofs) == ([False] * (len(results) - 1)) + [True]
    assert recfile.getvalue() == data


def test_recorded_messages_are_accepted_only_when_whole(golden, sample):
    data = golden("rec", sample).read_bytes()
    results = read_all(make_file(data), None, run_mode(passive=True))

    # The recording starts with a magic number, and the prefix may end inside
    # the last message.
    whole = [result[0] for result in results[1:-1]]

    assert whole
    for msg in whole:
        assert (se.msg.validate_msg(msg) != NOTHING) == is_whole(msg)


# --- reading bytes -----------------------------------------------------------


def test_read_bytes_reads_and_records(caplog):
    infile = make_file(b"abcdef")
    recfile = io.BytesIO()
    state = {}

    data = se.msg.read_bytes(infile, recfile, 4, run_mode(passive=True), state)

    assert data == b"abcd"
    assert recfile.getvalue() == b"abcd"
    assert infile.read() == b"ef"
    assert state["readLength"][1] == 4
    assert state["lastByteRead"][1] == "64"
    assert not caplog.records


def test_read_bytes_works_without_a_record_file():
    infile = make_file(b"\x0a\xff")

    data = se.msg.read_bytes(infile, None, 2, run_mode(passive=True), {})

    assert data == b"\x0a\xff"


def test_read_bytes_returns_bytes_for_any_buffer():
    infile = types.SimpleNamespace(read=lambda _size: bytearray(b"xy"))

    data = se.msg.read_bytes(infile, None, 2, run_mode(passive=True), {})

    assert data == b"xy"
    assert type(data) is bytes


@pytest.mark.parametrize("record", [True, False])
def test_read_bytes_treats_the_end_of_file_as_empty(caplog, record):
    caplog.set_level(logging.INFO, logger="se.msg")
    recfile = io.BytesIO() if record else None

    data = se.msg.read_bytes(
        make_file(), recfile, 3, run_mode(passive=True), {}
    )

    assert data == b""
    assert not messages(caplog, logging.INFO)
    if record:
        assert recfile.getvalue() == b""


def test_read_bytes_keeps_the_last_byte_read_at_the_end_of_file():
    state = {}
    infile = make_file(b"\x12\x34")

    se.msg.read_bytes(infile, None, 2, run_mode(passive=True), state)
    data = se.msg.read_bytes(infile, None, 2, run_mode(passive=True), state)

    assert data == b""
    assert state["lastByteRead"][1] == "34"


def test_read_bytes_raises_a_read_error_instead_of_ending_the_data():
    def read(_size):
        msg = "disk on fire"
        raise OSError(msg)

    infile = types.SimpleNamespace(read=read)

    with pytest.raises(OSError, match="disk on fire"):
        se.msg.read_bytes(infile, None, 3, run_mode(passive=True), {})


def test_read_bytes_raises_a_failing_record_file_instead_of_ending_the_data():
    class Failing(io.BytesIO):
        def write(self, _data):
            msg = "no space left"
            raise OSError(msg)

    with pytest.raises(OSError, match="no space left"):
        se.msg.read_bytes(
            make_file(b"abc"), Failing(), 3, run_mode(passive=True), {}
        )


def test_read_bytes_waits_for_the_file_to_grow_when_following(monkeypatch):
    infile = make_file()
    recfile = io.BytesIO()
    sleeps = []

    def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 3:  # somebody appends to the file
            position = infile.tell()
            infile.write(b"\x01\x02")
            infile.seek(position)

    monkeypatch.setattr(time, "sleep", sleep)
    state = {}

    data = se.msg.read_bytes(
        infile, recfile, 2, run_mode(passive=True, following=True), state
    )

    assert data == b"\x01\x02"
    assert sleeps == [se.msg.SLEEP_INTERVAL] * 3
    assert recfile.getvalue() == b"\x01\x02"
    assert state["lastByteRead"][1] == "02"


def test_read_bytes_does_not_wait_when_following_and_data_is_there(
    monkeypatch,
):
    def sleep(_seconds):
        pytest.fail("should not sleep")

    monkeypatch.setattr(time, "sleep", sleep)

    data = se.msg.read_bytes(
        make_file(b"\x05"), None, 1, run_mode(passive=True, following=True), {}
    )

    assert data == b"\x05"


def test_read_bytes_does_not_wait_when_not_following(monkeypatch):
    def sleep(_seconds):
        pytest.fail("should not sleep")

    monkeypatch.setattr(time, "sleep", sleep)

    assert (
        se.msg.read_bytes(make_file(), None, 1, run_mode(passive=True), {})
        == b""
    )


# --- sending and recording ---------------------------------------------------


@pytest.mark.parametrize("record", [True, False])
def test_send_msg_writes_the_magic_number_and_the_message(record):
    outfile = make_file()
    recfile = io.BytesIO() if record else None
    msg = se.msg.format_msg(3, SRC, DST, FUNCTION, b"\x01")

    se.msg.send_msg(outfile, msg, recfile)

    assert outfile.getvalue() == MAGIC + msg
    if record:
        assert recfile.getvalue() == MAGIC + msg


def test_send_msg_counts_and_logs_the_messages(caplog):
    log_all(caplog, logging.DEBUG)
    outfile = make_file()
    msg = se.msg.format_msg(3, SRC, DST, FUNCTION)
    before = se.msg.Seq.data_out

    se.msg.send_msg(outfile, msg, None)
    se.msg.send_msg(outfile, msg, None)

    assert se.msg.Seq.data_out == before + 2
    assert messages(caplog, logging.DEBUG) == [
        f"<test> <-- message: {before + 1} length: {len(MAGIC + msg)}",
        f"<test> <-- message: {before + 2} length: {len(MAGIC + msg)}",
    ]


def test_sent_message_can_be_read_again():
    outfile = make_file()
    se.msg.send_msg(
        outfile, se.msg.format_msg(9, DST, SRC, 0x0080, b"ok"), None
    )
    outfile.seek(0)

    msg, eof = se.msg.read_msg(
        outfile, None, run_mode(passive=False, serial_type="2"), {}
    )

    assert not eof
    assert se.msg.parse_msg(msg) == (9, DST, SRC, 0x0080, b"ok")


def test_record_msg_appends_to_the_file():
    recfile = io.BytesIO()

    se.msg.record_msg(b"ab", recfile)
    se.msg.record_msg(b"cd", recfile)

    assert recfile.getvalue() == b"abcd"


def test_record_msg_without_a_file_does_nothing():
    assert se.msg.record_msg(b"ab", None) is None
