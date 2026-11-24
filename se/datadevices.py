"""
The seDataDevices module defines the ParseDevice class and its subclasses.

ParseDevice and it's subclasses are intended to be a reasonably straightforward
way of adding new (se_type) devices to the list that the semonitor suite can
recognize and can parse.

ParseDevice is a subclass of a dictionary, with a tailored __new__ method. Given
a block of seData from a pcap file, the __new__ method will parse it, and
populate the ParseDevice instance with entries mapping items to their parsed
value, as found in the data block.

The top level ParseDevice only performs a rudimentary parse of the data, and
returns almost all of it as a hex string.

Subclasses of ParseDevice (e.g. ParseDevice0x0030) contain more extensive item
definitions (stored in the field_defs list) and populate the dictionary in a
more sensible and useful way. Each subclass is tuned to a specific se_type.
se_type defines the value the subclass is designed to parse, and field_defs
lists the definitions for blocks of data of that se_type.

Thanks to some fancy footwork in the __new__ method of ParseDevice itself, it is
only ever necessary to try to create an instance of ParseDevice (i.e. to code
`ParseDevice(data)`). ParseDevice.__new__ determines the se_type of the block of
data, by examining the standard header block in the data. Then it searches
through all the subclasses of ParseDevice that have been defined, and if one
'tuned' to the se_type of the block of data being parsed is found, creates an
instance of that specialized subclass.

There is one extra special subclass of ParseDevice, namely ParseDeviceExplorer.
It is *not* intended for production use. It operates without any item
definitions at all. Instead it works its way through the block of seData, in
2-byte increments, parsing the next 4 bytes in almost every way they could be
parsed. Almost all of the parsed data items will be nonsense, but perusing the
parsed device - for example by using se2csv and then opening the csv file - may
help with the deciphering of new se_type devices. It is an alternative, of
sorts, to examining the relevant part of the pcap file using a hex editor.
"""

import binascii
import logging
import struct
import time
from typing import TYPE_CHECKING, Any, ClassVar

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Spacer field for documenting field definitions more neatly, for convenience
sp = "\n\t\t\t\t\t\t: "
# Create a "utility" constant, to use later to make code less verbose
nan = float("nan")


def is_zero(name):
    """
    Build the hypothesis that the item `name` is always zero.

    Args:
        name: The name of the item.

    Returns:
        The text of the hypothesis, and a function that tests it on a device.
    """
    return (f"self['{name}'] == 0", lambda dev: dev[name] == 0)


def is_small(name):
    """
    Build the hypothesis that the float item `name` is below 10**25.

    Args:
        name: The name of the item.

    Returns:
        The text of the hypothesis, and a function that tests it on a device.
    """
    return (
        f"abs(self['{name}']) < 10**25",
        lambda dev: abs(dev[name]) < 10**25,
    )


class ParseDevice(dict):
    """
    ParseDevice itself can only do a very basic parse of a seData block.

    The block of seData is from a pcap file.

    Its main purposes are:

        to provide a suite of standard methods shared by all the subclasses (and
        in particular the parse_dev_table method which given a field_defs list,
        will parse the seData block accordingly); and to have a 'clever' __new__
        method, which redirects the creation of a ParseDevice to the creation of
        a subclass of a ParseDevice which specializes in the particular se_type
        encountered in the current block of seData (provided of course that a
        specialized subclass for that se_type has been defined).
    """

    se_type = (
        0xFFFF  # dummy value, I hope. Should be overwritten in subclasses.
    )
    _dev_name = "Unknown_device"
    dev_type = f"{_dev_name}_{se_type:#06x}"

    # DEFINITIONS for items in new devices, filled in for subclasses.
    #
    # The definition has to be a list not a mapping because field order matters!
    # Each field definition is (also) a list, with 6 members, namely
    # [paramLen, paramInFmt, paramName, outFormatFn (can be None),
    # out (to CSV) True or False, comment]

    field_defs: ClassVar[list[list[Any]]] = [
        # The following standard device header fields are automatically parsed
        # for all device types.
        # These items do *not* need to be defined! They are:
        # - se_type: 2 bytes ('H'), identifies the type of this SolarEdge data
        #   block, shown as a 4 digit hex number
        # - se_id: 4 bytes ('L'), identifies the SolarEdge device, formatted by
        #   parse_id
        # - dev_len: 2 bytes ('H'), the length in bytes of the data block
    ]

    # DERIVATIONS, optional, can be left empty if not required.
    #
    # List of names of derived items.
    # Useful for documenting the interpretation of the derived values, and is
    # also used to set the default values (in case the condition which triggers
    # the derivation does not occur at a particular timeStamp) - see the
    # set_derivation_defaults method.

    # Each "definition" is itself a list, comprising:
    # [paramName, paramDefault, out (to CSV) True or False, comment]
    # paramDefault is the value itself, e.g. 0, 0.0, "" or nan.
    #
    # NB *** It is (much) simpler to describe the actual derivation for a
    # particular item in Python code (within the subclass that needs it) than to
    # develop a completely new "syntax" for describing derivations! see the
    # code_derivations method in the subclasses of ParseDevice for examples.

    _derivn: ClassVar[list[list[Any]]] = [
        # [paramName, paramDefault, out (to CSV) True or False, comment]
    ]

    # HYPOTHESES, optional, list of (text, predicate) pairs for conditions which
    # I expect to be always true. The predicate takes the parsed device, the
    # text is what gets logged when it is false. Useful for generating debug
    # alerts in the event of "new" unexpected values appearing in data items.
    # See ParseDevice0x0030 for an example, and is_zero and is_small
    # for the common cases.
    _hypotheses: ClassVar[list[tuple[str, Callable[[Any], bool]]]] = []

    def __new__(cls, data, *, explorer=False):
        """Return the subclass instance that matches the se_type of the data."""
        # Some fancy footwork so that I can always start to create a
        # ParseDevice, but actually get a subclass which is appropriate for the
        # se_type encountered in the data block (provided a subclass specific to
        # the se_type has been defined, of course).
        dev_hdr_len = 8
        (se_type, _se_id, _dev_len) = struct.unpack("<HLH", data[0:dev_hdr_len])

        # Search for a subclass which can handle this seType
        device_class = cls
        for subclass in cls.__subclasses__():
            if subclass.se_type == se_type:
                device_class = subclass
                break
        else:
            # Otherwise either use a ParseDeviceExplorer (explorer=True), which
            # is a special subclass which will parse almost anything, albeit
            # with quite a number of nonsense parsings interspersed with
            # occasional correctly parsed fields, or just a bare minimum
            # instance of a dictionary (explorer=False).
            if explorer:
                # a special ParseDevice which tries almost every field parsing
                # it knows about
                device_class = ParseDeviceExplorer

        # Create the dictionary of the chosen class directly (and not with
        # super().__new__ or the class itself, which would redirect to this
        # method again), and parse the data block right here: __init__ is
        # called again by Python for the returned instance, so parsing there
        # would parse every data block twice.
        new_instance = super().__new__(device_class)
        if device_class is ParseDevice:
            # (Re)setting a basically empty (unknown) definition for this
            # instance is crucial because you may have already encountered
            # another unknown device with a *different* length and field_defs,
            # and the parse_dev_table method updates the *class* definition
            # dynamically if it encounters more data than it expects.
            new_instance.field_defs = [
                [
                    4,
                    "L",
                    "dateTime",
                    "dateTime",
                    False,
                    "seconds, time since the epoch",
                ]
            ]
        new_instance.parse_dev_table(data)
        new_instance.set_derivation_defaults()
        new_instance.code_derivations()
        new_instance.check_hypotheses()
        return new_instance

    @staticmethod
    def parse_id(se_id):
        """
        Return the device id as an upper-case hex string, bit 23 cleared.

        Args:
            se_id: The device id from the header of a data block.

        Returns:
            The device id as a string.
        """
        return ("%x" % (se_id & 0xFF7FFFFF)).upper()

    @staticmethod
    def format_date_stamp(time_stamp):
        """
        Return the local date of a Unix timestamp, or "invalid".

        Args:
            time_stamp: The Unix timestamp.

        Returns:
            The date as a string, or "invalid" if the timestamp is not valid.
        """
        try:
            return time.strftime("%Y-%m-%d", time.localtime(time_stamp))
        except (OverflowError, OSError, TypeError, ValueError) as ex:
            logger.info("Invalid timestamp: %s %s", time_stamp, ex)
            return "invalid"

    @staticmethod
    def format_time_stamp(time_stamp):
        """
        Format a Unix timestamp as a local time, HH:MM:SS.

        Args:
            time_stamp: The Unix timestamp.

        Returns:
            The time as a string, or "invalid" if the timestamp is not valid.
        """
        try:
            return time.strftime("%H:%M:%S", time.localtime(time_stamp))
        except (OverflowError, OSError, TypeError, ValueError) as ex:
            logger.info("Invalid timestamp: %s %s", time_stamp, ex)
            return "invalid"

    @staticmethod
    def hex_data(data):
        """
        Convert a string of bytes into a nicely formatted hex string.

        Args:
            data: A string of bytes.

        Returns:
            A longer string, containing a hex representation of the data
            bytes, formatted for easier reading.
        """
        line_size = 16

        def hex_line(data):
            return " ".join(f"{x:02x}" for x in data)

        hex_lines = []
        if data:
            print_ptr = 0
            while len(data) - print_ptr >= line_size:
                hex_lines.append(
                    hex_line(data[print_ptr : print_ptr + line_size])
                )
                print_ptr += line_size
            if print_ptr < len(data):
                hex_lines.append(hex_line(data[print_ptr:]))
        return " | ".join(hex_lines)

    @staticmethod
    def unhex_data(hex_data):
        """
        Convert a hex representation into bytes, the inverse of hex_data.

        Args:
            hex_data: String, containing a (must be valid) hex representation
                of some bytes.

        Returns:
            The string of bytes corresponding to hex_data.
        """
        return binascii.unhexlify(hex_data.replace("|", "").replace(" ", ""))

    def __eq__(self, other):
        """
        Compare the items, and the device type and id kept outside of them.

        Args:
            other: The object to compare with.

        Returns:
            True if the items are equal and, when other is a ParseDevice, so
            are the device type and id. NotImplemented is what dict returns
            for an object it cannot compare with.
        """
        if isinstance(other, ParseDevice):
            return (
                dict.__eq__(self, other)
                and self.dev_type == other.dev_type
                and self._seId == other._seId
            )
        return dict.__eq__(self, other)

    def __ne__(self, other):
        """Return the opposite of __eq__ (dict defines its own __ne__)."""
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    __hash__ = None

    def __init__(self, _data, **_kwargs):
        """
        Do nothing: __new__ has parsed the data block already.

        Args:
            data: The data block to parse.
            **_kwargs: Ignored. ParseDevice(data, explorer=...) passes the
                keywords of __new__ to __init__ too.
        """
        super().__init__()

    def parse_dev_table(self, data):
        """
        Parse the header and every field of the data block into self.

        Args:
            data: The data block to parse.

        Raises:
            ValueError: If field_defs describe more bytes than the data block
                contains.
        """
        data_ptr = 0
        dev_hdr_len = 8
        # device header
        (se_type, se_id, dev_len) = struct.unpack(
            "<HLH", data[data_ptr : data_ptr + dev_hdr_len]
        )
        data_ptr += dev_hdr_len

        # For (almost) all subclasses, dev_type will already have this value.
        # This is necessary only when a default catchall parse is happening,
        # because a specific parser for se_type has not been defined.
        self.dev_type = f"{self._dev_name}_{se_type:#06x}"
        # Store _seId as an attribute for later use as part of the standard
        # "dictionary of dictionaries" wrapper when a parsed instance is
        # converted to json.
        self._seId = self.parse_id(se_id)

        self.update(
            {
                "seType": f"{se_type:#06x}",
                "seId": self._seId,
                "devLen": dev_len,
                "devType": self.dev_type,
            }
        )

        if self.field_defs_len > dev_len:
            msg = f"You have defined more bytes, {self.field_defs_len}, than the message contains, {dev_len}"
            raise ValueError(msg)
        if self.field_defs_len < dev_len:
            # By default, convert any remaining undefined bytes to their
            # representation as a hexadecimal string.
            self.field_defs.append(
                [
                    dev_len - self.field_defs_len,
                    "hex",
                    "Undeciphered_data",
                    self.hex_data,
                    True,
                    "unknown as yet",
                ]
            )

        for (
            param_len,
            param_in_fmt,
            param_name,
            out_format_fn,
            _out,
            _comment,
        ) in self.field_defs:
            raw = data[data_ptr : data_ptr + param_len]
            self._unpack_field(param_name, param_in_fmt, raw)
            self._format_field(param_name, out_format_fn)
            data_ptr += param_len

    def _unpack_field(self, param_name, param_fmt, raw):
        """Unpack the raw bytes of a field into self."""
        # Extract the field
        if param_fmt == "hex":
            self[param_name] = raw
        # Check for a specific value I believe should be read as NaN
        # In little endian format '\xff\xff\x7f\xff' unpacks as
        # -3.402...*10**38.
        # But the SolarEdge messages seem to use it to signify "not reported".
        # In all the cases I have encountered it makes more sense to interpret
        # this particular float value as NaN rather than as a very large
        # negative number, so that is what I do below.
        # Note that if unpacked in **big** endian format, this special value
        # actually unpacks as NaN.
        # I suspect a legacy "bug" somewhere in the SolarEdge messages, but in
        # the meantime just check the bytes and fix it.
        elif param_fmt == "f" and (raw == b"\xff\xff\x7f\xff"):
            self[param_name] = float("nan")
        else:
            self[param_name] = struct.unpack("<" + param_fmt, raw)[0]
            if "s" in param_fmt:
                # Python 3.x requires that we convert byte string to Unicode
                # string if the value is to be used (later on) as a dictionary
                # key for nested fields
                # Required for e.g. battery IDs
                # Remove trailing 'null' character (i.e. 0x00) at the same time
                self[param_name] = (
                    self[param_name].decode("utf-8").strip("\x00")
                )

    def _format_field(self, param_name, out_format_fn):
        """Format the value of a field in self, if it has a format."""
        # Optionally format the field
        if out_format_fn == "dateTime":
            try:
                self["Date"] = self.format_date_stamp(self[param_name])
            except ValueError:
                logger.debug(
                    "'%s' is not a valid date, changed to '1970-01-01'",
                    format(self[param_name]),
                )
                self["Date"] = "1970-01-01"
            try:
                self["Time"] = self.format_time_stamp(self[param_name])
            except ValueError:
                logger.debug(
                    "'%s' is not a valid time, changed to '00:00:01'",
                    format(self[param_name]),
                )
                self["Time"] = "00:00:01"
        elif out_format_fn is not None:
            self[param_name] = out_format_fn(self[param_name])

    def set_derivation_defaults(self):
        """Set every derived item to its default value."""
        for param_name, param_default, _out, _comment in self._derivn:
            self[param_name] = param_default

    def code_derivations(self):
        """Calculate derived items. Nothing here; subclasses override it."""

    def check_hypotheses(self):
        """Log a warning for each hypothesis that does not hold."""
        for hypothesis, holds in self._hypotheses:
            if not holds(self):
                msg = [
                    "Failed hypothesis",
                    self.__class__.__name__,
                    self["Date"],
                    self["Time"],
                    ":",
                    hypothesis,
                    "is not True",
                ]
                logger.warning(" ".join(msg))

    def wrap_in_ids(self):
        """
        Wrap the parsed items in a dict of dicts keyed by device identifiers.

        "Wrap" the dictionary of parsed data items inside a "dictionary of
        dictionary" structure (like invDict etc) based on the device type and
        device id(s), to uniquely identify each device instance. The standard
        identifiers are dev_type and _seId, but some device types (e.g.
        batteries and optimizers) may have alternative and/or additional
        identifiers following the dev_type (in which case the subclass parsers
        for those devices should override this method with their own
        identifiers).

        The full name structure of the metric is embedded in the "dict of dict"
        structure, and so the data items (aka metrics) from this device can be
        distinguished from any data items reported by other devices.

        Returns:
            The (parsed) device attributes, "wrapped" in dictionary of
            dictionaries based on device type and device identifiers.
        """
        return {self.dev_type: {self._seId: self}}

    @classmethod
    def item_names(cls):
        """
        Return the names of the items written to CSV and Graphite.

        Extract some item name and definition length information that se2csv
        needs.

        Returns:
            The list of item names, with Date and Time in place of dateTime.
        """
        # devItemNames = ["seType", "seId", "devLen", "devType"] These are
        # "uninteresting" and will not be output to CSV
        # Extract a list of the names of "interesting" items, that will
        # routinely be sent to CSV and Graphite.
        dev_item_names = [
            name
            for itemLen, fmt, name, outFmt, out, comment in cls.field_defs
            if out
        ]
        dev_item_names.extend(
            [
                paramName
                for paramName, paramDefault, out, comment in cls._derivn
                if out
            ]
        )
        # Find the dateTime output format entry (if it exists) and insert
        # additional separate Date and Time items
        try:
            i_date_time = [
                outFmt
                for itemLen, fmt, name, outFmt, out, comment in cls.field_defs
            ].index("dateTime")  # + 3
            dev_item_names.insert(i_date_time, "Time")
            dev_item_names.insert(i_date_time, "Date")
        except ValueError:
            pass  # The dateTime field has not been identified/defined yet
        return dev_item_names

    @property
    def field_defs_len(self):
        """The total number of bytes described by field_defs."""
        return sum(
            itemLen
            for itemLen, fmt, name, outFmt, out, comment in self.field_defs
        )

    @classmethod
    def item_defs(cls):
        """
        Produce a pretty report on the item definitions parsed by this class.

        The report also covers its subclasses.

        Returns:
            A formatted string, (usually) extracted from field_defs and
            _derivn.
        """
        msg = [
            "\n\n{} / {} parses data blocks with seType = {:#06x}.\n{}".format(
                cls.__name__, cls.dev_type, cls.se_type, "=" * 80
            )
        ]
        msg.append("Items are:")
        item_line = "{:<4} ({:^6})   {:<6} | {:<25} \n\t\t\t\t\t\t: {:<0}\n"
        msg.append(
            item_line.format("Byte", "Length", "Word", "Item Name", "Meaning")
        )
        msg.append(
            item_line.format("_" * 4, "_" * 6, "_" * 6, "_" * 25, "_" * 40)
        )
        byte = 0
        word = byte / 4.0
        if len(cls.field_defs) > 0:
            for (
                param_len,
                _param_in_fmt,
                param_name,
                _out_format_fn,
                _out,
                comment,
            ) in cls.field_defs:
                msg.append(
                    item_line.format(byte, param_len, word, param_name, comment)
                )
                byte += param_len
                word = byte / 4.0
        if len(cls._derivn) > 0:
            msg.append("Derived items\n")
            for param_name, param_default, _out, comment in cls._derivn:
                msg.append(
                    item_line.format(
                        "----",
                        "------",
                        "----",
                        param_name,
                        f"(default={param_default}) {comment}",
                    )
                )
        msg.extend(subclass.item_defs() for subclass in cls.__subclasses__())
        return "\n".join(msg)


class ParseDevice0x0030(ParseDevice):
    """Parser for battery (se_type 0x0030) data blocks."""

    se_type = 0x0030
    _dev_name = "batteries"
    dev_type = f"{_dev_name}_{se_type:#06x}"
    field_defs: ClassVar[list[list[Any]]] = [
        # device specific fields
        #  [paramLen, paramInFmt, paramName, outFormatFn (can be None),
        #   out (to CSV or Graphite) True or False, comment]
        [
            4,
            "L",
            "dateTime",
            "dateTime",
            False,
            "seconds, time since the epoch",
        ],
        [12, "12s", "batteryId", None, True, "identifier for this battery"],
        [4, "f", "Vdc", None, True, "V, DC voltage"],
        [4, "f", "Idc", None, True, "A, DC current"],
        [
            4,
            "f",
            "BattCapacityNom",
            None,
            True,
            "Wh, nameplate energy capacity",
        ],
        [
            4,
            "f",
            "BattCapacityActual",
            None,
            True,
            "Wh, actual battery capacity now",
        ],
        [4, "f", "BattCharge", None, True, "Wh, energy stored now"],
        [
            4,
            "L",
            "TotalEnergyIn",
            None,
            True,
            "Wh, lifetime energy input to battery",
        ],
        [4, "f", "AlwaysZero_40_float", None, False, "unused"],
        [
            4,
            "L",
            "TotalEnergyOut",
            None,
            True,
            "Wh, lifetime energy output by battery",
        ],
        [4, "f", "AlwaysZero_48_float", None, False, "unused"],
        [
            4,
            "hex",
            "HexConst_52",
            ParseDevice.hex_data,
            False,
            "unknown, constant value",
        ],
        [
            4,
            "hex",
            "HexConst_56",
            ParseDevice.hex_data,
            False,
            "unknown, constant value",
        ],
        [4, "f", "Temp", None, True, "°C, battery temperature"],
        [
            2,
            "H",
            "BattChargingStatus",
            None,
            True,
            "3=>Charging, 4=>Discharging, 6=>Holding",
        ],
        [4, "f", "AlwaysZero_66_float", None, False, "unused"],
        [4, "f", "AlwaysZero_70_float", None, False, "unused"],
        [4, "L", "Interval", None, False, "seconds, time interval"],
        [4, "L", "EIn", None, True, "Wh, energy into battery during interval"],
        [
            4,
            "L",
            "EOut",
            None,
            True,
            "Wh, energy out of battery during interval",
        ],
    ]

    _hypotheses: ClassVar[list[tuple[str, Callable[[Any], bool]]]] = [
        is_small("AlwaysZero_40_float"),
        is_small("AlwaysZero_48_float"),
        is_small("AlwaysZero_66_float"),
        is_small("AlwaysZero_70_float"),
    ]

    def wrap_in_ids(self):
        """
        Wrap the parsed items in a dict of dicts keyed by device identifiers.

        "Wrap" the dictionary of parsed data items inside a "dictionary of
        dictionary" structure (like invDict etc) based on the device type and
        device id(s), to uniquely identify each device instance. The standard
        identifiers are dev_type and _seId, but some device types (e.g.
        batteries and optimizers) may have alternative and/or additional
        identifiers following the dev_type (in which case the subclass parsers
        for those devices should override this method with their own
        identifiers).

        The full name structure of the metric is embedded in this "dict of dict"
        structure, and so the data items (aka metrics) from this device can be
        distinguished from any data items reported by other devices.

        Returns:
            The (parsed) device attributes, "wrapped" in dictionary of
            dictionaries based on device type and device identifiers.
        """
        return {self.dev_type: {self._seId: {self["batteryId"]: self}}}


class ParseDevice0x0022(ParseDevice):
    """Parser for meter (se_type 0x0022) data blocks, one record per recType."""

    se_type = 0x0022
    _dev_name = "meters"
    dev_type = f"{_dev_name}_{se_type:#06x}"
    field_defs: ClassVar[list[list[Any]]] = [
        # device specific fields
        #  [paramLen, paramInFmt, paramName, outFormatFn (can be None),
        #   out (to CSV or Graphite) True or False, comment]
        [
            4,
            "L",
            "dateTime",
            "dateTime",
            False,
            "seconds, time since the epoch",
        ],
        [
            1,
            "b",
            "recType",
            None,
            True,
            "record type, determines the interpretation of later fields"
            + sp
            + "3=Consumption,"
            + sp
            + "5=Grid Import/Export,"
            + sp
            + "7=Battery,"
            + sp
            + "8=Unknown, almost all 0,or very very small,"
            + sp
            + "9=PV production",
        ],
        [
            1,
            "b",
            "onlyIntervalData",
            None,
            True,
            "1=only interval data has been reported, 0=lifetime data reported as well",
        ],
        [
            4,
            "L",
            "TotalE2Grid",
            None,
            True,
            "Wh, lifetime energy exported to grid (*provided* onlyIntervalData flag is not set)"
            + sp
            + "Wh, total lifetime energy exported to grid when recType=5 (matches SE LCD panel value)"
            + sp
            + "always 0, when recType=3, or 7, or 8, or 9 because onlyIntervalData=1 (True)",
        ],
        [2, "H", "AlwaysZero_off10_int2", None, False, "padding"],
        [
            2,
            "hex",
            "Flag_off12_hex",
            ParseDevice.hex_data,
            True,
            "flag"
            + sp
            + "0x0000->TotalE2Grid reported"
            + sp
            + "0x0080->TotalE2Grid not reported",
        ],
        [
            4,
            "L",
            "TotalEfromGrid",
            None,
            True,
            "Wh, lifetime energy imported from grid (*provided* onlyIntervalData flag is not set)"
            + sp
            + "Wh, total lifetime energy imported from grid when recType=5 (matches SE LCD panel value)"
            + sp
            + "always 0, when recType=3, or 7, or 8, or 9 because onlyIntervalData=1 (True)",
        ],
        [2, "H", "AlwaysZero_off18_int2", None, False, "padding"],
        [
            2,
            "hex",
            "Flag_off20_hex",
            ParseDevice.hex_data,
            True,
            "flag"
            + sp
            + "0x0000->TotalEfromGrid reported"
            + sp
            + "0x0080->TotalEfromGrid not reported",
        ],
        [
            4,
            "L",
            "Totaloff22_int4",
            None,
            True,
            "unknown, probably an energy field (*provided* lifetime flag is set)"
            + sp
            + "maybe a cumulative net value, it appears to decrease overnight when importing power"
            + sp
            + "Wh, unknown when recType=5 (generally increasing trend, but falls overnight)"
            + sp
            + "always 0, when recType=3, or 7, or 8, or 9 because onlyIntervalData=1 (True)",
        ],
        [2, "H", "AlwaysZero_off26_int2", None, False, "padding"],
        [
            2,
            "hex",
            "Flag_off28_hex",
            ParseDevice.hex_data,
            True,
            "flag"
            + sp
            + "0x0000->Totaloff22_int4 reported"
            + sp
            + "0x0080->Totaloff22_int4 not reported",
        ],
        [
            4,
            "L",
            "Totaloff30_int4",
            None,
            True,
            "unknown total energy field (*provided* lifetime flag is set)"
            + sp
            + "monotonically increasing so far including overnight."
            + sp
            + "maybe something like cumulative total consumption scaled by about 60%?"
            + sp
            + "Wh, unknown when recType=5 (steadily increasing trend)"
            + sp
            + "always 0, when recType=3, or 7, or 8, or 9 because onlyIntervalData=1 (True)",
        ],
        [2, "H", "AlwaysZero_off34_int2", None, False, "padding"],
        [
            2,
            "hex",
            "Flag_off36_hex",
            ParseDevice.hex_data,
            True,
            "flag"
            + sp
            + "0x0000->Totaloff30_int4 reported"
            + sp
            + "0x0080->Totaloff30_int4 not reported",
        ],
        [4, "L", "Interval", None, True, "seconds, time interval"],
        [
            4,
            "L",
            "E2X",
            None,
            True,
            "Wh, energy to X during the interval"
            + sp
            + "always 0 when recType=3"
            + sp
            + "Wh, energy exported to grid during interval when recType=5 (whenever TotalE2Grid is static, E2X=0)"
            + sp
            + "Wh, energy into battery when recType=7 (matches battery(0x0030).EIn)"
            + sp
            + "unknown, when recType=8 (almost always 0, very occasionally has small positive value)"
            + sp
            + "Wh, PV energy production during interval when recType=9",
        ],
        [
            4,
            "L",
            "EfromX",
            None,
            True,
            "Wh, energy in from X during interval"
            + sp
            + "Wh, consumption when recType=3"
            + sp
            + "Wh, energy imported from grid during interval when recType=5 "
            + "(whenever TotalEfromGrid is static, EfromX=0)"
            + sp
            + "always 0 when recType=7 (I expected E from battery but it does not match battery(0x0030).EOut)"
            + sp
            + "always 0 when recType=8"
            + sp
            + "always 0 when recType=9",
        ],
        [
            4,
            "f",
            "P2X",
            None,
            True,
            "W, power output to X"
            + sp
            + "always NaN when recType=3"
            + sp
            + "W, power to grid at end of interval when recType=5 (whenever TotalE2Grid is static, P2X=0)"
            + sp
            + "W, power into battery when recType=7 (is nonzero when E2X is nonzero)"
            + sp
            + "almost always 0 when recType=8"
            + sp
            + "W, PV power when recType=9",
        ],
        [
            4,
            "f",
            "PfromX",
            None,
            True,
            "W, power input from X"
            + sp
            + "W, consumption when recType=3"
            + sp
            + "W, power from grid at end of interval when recType=5 (whenever TotalEfromGrid is static, PfromX=0)"
            + sp
            + "always NaN when recType=7"
            + sp
            + "always NaN when recType=8"
            + sp
            + "always NaN when recType=9",
        ],
    ]

    _derivn: ClassVar[list[list[Any]]] = [
        # [paramName, paramDefault, out (to CSV) True or False, comment]
    ]

    _hypotheses: ClassVar[list[tuple[str, Callable[[Any], bool]]]] = [
        is_zero("AlwaysZero_off10_int2"),
        is_zero("AlwaysZero_off18_int2"),
        is_zero("AlwaysZero_off26_int2"),
        is_zero("AlwaysZero_off34_int2"),
    ]

    def code_derivations(self):
        """Replace the bogus large negative P2X values with NaN."""
        # Filter out some sporadic 'NaN'-like values which appear in P2X.  The
        # hex value is the BIG endian version of a Python NaN. Read as LITTLE
        # endian it becomes "-3.2... 10^38" which is unlikely to be meant as a
        # real value!
        # Most of these are filtered out later, but occasionally if the interval
        # is short one slips through anyway.
        # Short intervals appear to happen about once a day, perhaps when the
        # inverter is going to sleep for the night.
        if self["P2X"] < -3 * 10**38:
            self["P2X"] = nan

    def wrap_in_ids(self):
        """
        Wrap the parsed items in a dict of dicts keyed by device identifiers.

        "Wrap" the dictionary of parsed data items inside a "dictionary of
        dictionary" structure (like invDict etc) based on the device type and
        device id(s), to uniquely identify each device instance. The standard
        identifiers are dev_type and _seId, but some device types (e.g.
        batteries and optimizers) may have alternative and/or additional
        identifiers following the dev_type (in which case the subclass parsers
        for those devices should override this method with their own
        identifiers).

        The full name structure of the metric is embedded in this "dict of dict"
        structure, and so the data items (aka metrics) from this device can be
        distinguished from any data items reported by other devices.

        Because there are multiple reported 0x0022 entries in a typical pcap
        file, all with the same timestamp, it is *essential* to distinguish them
        by means of the recType, otherwise almost all the reported metrics end
        up being overwritten by the next 0x0022 entry!

        Returns:
            The (parsed) device attributes, "wrapped" in dictionary of
            dictionaries based on device type and device identifiers.
        """
        rec_type_labels = {
            3: "3_Consumption",
            5: "5_GridImportExport",
            7: "7_Battery",
            8: "8_MostlyZeroes",
            9: "9_PVProduction",
        }
        rec_type_label = rec_type_labels.get(
            self["recType"], "{}_UnrecognizedRecType".format(self["recType"])
        )
        return {self.dev_type: {self._seId: {rec_type_label: self}}}


class ParseDeviceExplorer(ParseDevice):
    """
    A special parser which tries several ways of interpreting each data item.

    It reports *ALL* of them.

    Most of the parsed values will be wrong, but hopefully by inspection you can
    find the parsings which make sense.

    Intended for exploring new device types by either looking at the raw json
    file, or by using se2csv and looking at the csv file. Once the correct
    interpretations for each item have been determined, a new subclass of
    ParseDevice tailored to those items should be constructed.
    """

    se_type = 0xFFFF  # dummy value since ParseDeviceExplorer will "parse" any se_type (albeit overly enthusiastically!)
    _dev_name = "explore"
    dev_type = f"{_dev_name}_{se_type:#06x}"
    field_defs: ClassVar[list[list[Any]]] = []
    _item_names: ClassVar[list[str]] = ["seType", "seId", "devLen", "devType"]
    _field_defs_len = 0

    def __eq__(self, other):
        """
        Compare the explorer attributes, as well as those of ParseDevice.

        Args:
            other: The object to compare with.

        Returns:
            True if ParseDevice.__eq__ holds and, when other is a
            ParseDeviceExplorer, so do the se_type and the length of the
            field definitions.
        """
        if isinstance(other, ParseDeviceExplorer):
            return (
                ParseDevice.__eq__(self, other)
                and self.se_type == other.se_type
                and self._field_defs_len == other._field_defs_len
            )
        return ParseDevice.__eq__(self, other)

    def __ne__(self, other):
        """Return the opposite of __eq__ (dict defines its own __ne__)."""
        result = self.__eq__(other)
        return result if result is NotImplemented else not result

    __hash__ = None

    def parse_dev_table(self, data):
        """
        Parse the data block in as many ways as possible.

        It needs no predefined item definitions. Somewhere among the plethora of
        parsed values it produces, there will be the correct interpretation of
        each item. I hope!

        It does presume all devices begin with a standard "seType, seId, devLen"
        header, which may not be correct.

        The parsed values are added into self, as itemName to parsedValue.

        Args:
            data: The data to be parsed, in as many ways as possible.
        """
        data_ptr = 0
        dev_hdr_len = 8
        # device header
        (se_type, se_id, dev_len) = struct.unpack(
            "<HLH", data[data_ptr : data_ptr + dev_hdr_len]
        )

        self.se_type = se_type
        self._field_defs_len = dev_len
        # For standard subclasses, dev_type will already have this value.
        # However ParseDeviceExplorer can be used as a default parser, when a
        # new device is encountered, in which case the actual instance value of
        # se_type would be unknown when the seDataDevices module was imported
        # (or in other words, ParseDeviceExplorer.se_type will contain a
        # nonsense value which must be corrected when real data is read)
        self.dev_type = f"{self._dev_name}_{se_type:#06x}"
        self._seId = self.parse_id(se_id)

        data_ptr += dev_hdr_len
        self.update(
            {
                "seType": f"{se_type:#06x}",
                "seId": self.parse_id(se_id),
                "devLen": dev_len,
                "devType": self.dev_type,
            }
        )

        # First, dump a hex version of the whole block into one field
        self["AllAsHex"] = self.hex_data(data[data_ptr:])
        # Next work through the block, 2 bytes at a time, trying as many
        # potential parsings as will fit.
        # I am assuming items will be at least 2 bytes long. Easy enough to
        # change if you need to try different offsets.
        for offset in range(0, dev_len, 2):
            # Parse a range of possible interpretations of the (4) bytes
            # beginning at offset.
            self.parse_at_offset(data[data_ptr:], offset, dev_len)

    def parse_at_offset(self, data, offset, devlen):
        """
        Parse (up to) 4 bytes of data at offset, in as many ways as it can.

        The parsed values are added into self, as itemName to parsedValue.

        Args:
            data: The complete data message.
            offset: The beginning point for the 4 bytes to be parsed.
            devlen: The length of the data message (we cannot parse beyond
                this!).
        """
        if offset <= (devlen - 1):
            # Parse items which may be 1 byte long
            item_name = f"offset{offset:03}_1_hex1"
            self[item_name] = self.hex_data(data[offset : offset + 1])
            self._item_names.append(item_name)

        if offset <= (devlen - 2):
            # Parse items which may be 2 bytes long
            item_name = f"offset{offset:03}_1_hex2"
            self[item_name] = self.hex_data(data[offset : offset + 2])
            self._item_names.append(item_name)
            item_name = f"offset{offset:03}_4_int2"
            self[item_name] = struct.unpack("<H", data[offset : offset + 2])[0]
            self._item_names.append(item_name)

        if offset <= (devlen - 4):
            # Parse items which may be 4 bytes long
            item_name = f"offset{offset:03}_1_hex4"
            self[item_name] = self.hex_data(data[offset : offset + 4])
            self._item_names.append(item_name)
            item_name = f"offset{offset:03}_3_float_LE"
            self[item_name] = struct.unpack("<f", data[offset : offset + 4])[0]
            self._item_names.append(item_name)
            item_name = f"offset{offset:03}_3_float_BE"
            self[item_name] = struct.unpack(">f", data[offset : offset + 4])[0]
            self._item_names.append(item_name)
            item_name = f"offset{offset:03}_4_int4"
            self[item_name] = struct.unpack("<L", data[offset : offset + 4])[0]
            self._item_names.append(item_name)
            # Maybe it is a date?
            try:
                self[f"Date_offset{offset:03}"] = self.format_date_stamp(
                    self[item_name]
                )
                self[f"Time_offset{offset:03}"] = self.format_time_stamp(
                    self[item_name]
                )
                # Other modules (e.g. se2graphite) become upset if Date and Time
                # are not supplied, so take the 1st valid Date we find.
                # Implicitly I'm guessing offset zero is the "real" date.
                if "Date" not in self.keys():
                    self["Date"] = self.format_date_stamp(self[item_name])
                    self["Time"] = self.format_time_stamp(self[item_name])
            except ValueError:
                # Apparently it is not a date!
                self[f"Date_offset{offset:03}"] = (
                    f"{self[item_name]} is not a Date"
                )
                self[f"Time_offset{offset:03}"] = (
                    f"{self[item_name]} is not a Time"
                )
            self._item_names.append(f"Date_offset{offset:03}")
            self._item_names.append(f"Time_offset{offset:03}")

    @classmethod
    def item_names(cls):
        """
        Return the item names collected by the exploratory parser.

        Returns:
            The list of item names, generated from the offsets of the bytes.
        """
        # Warning. If ParseDevice_Explorer is used on more than 1 se_type data
        # block in a single run, this will *NOT* return sensible values!
        return cls._item_names

    @property
    def field_defs_len(self):
        """The byte length of the data block, from its header."""
        return self._field_defs_len

    @classmethod
    def item_defs(cls):
        """
        Return a report describing the exploratory parser's items.

        Returns:
            A formatted string, explaining how the items are generated.
        """
        msg = [
            "\n\n{} / {} parses data blocks with any unrecognized seType.\n{}".format(
                cls.__name__, cls.dev_type, "=" * 80
            ),
            """\
Each pair/quadruple of bytes is parsed multiple times, using a number of different field types.
Item names are generated automatically, signaling the offset where the bytes began
and the Python field type they have been parsed as.
Inspecting the parsed fields (e.g. using se2csv) and identifying sensible and/or recognized values is
a step towards deciphering a new se_type block, and creating a more sensible parser for it.""",
        ]
        return "\n".join(msg)


def merge_update(dict1, dict2):
    """
    Merge only the new elements of a nested dict2 into the master dict1.

    This recursive function updates a master nested dictionary (dict1) with
    **only the new** elements of a smaller contributor nested dictionary
    (dict2).

    Args:
        dict1: The master nested dictionary, updated in place with **only** the
            new parts of dict2.
        dict2: A new subsidiary nested dictionary, to be merged into dict1.
    """
    for k2, v2 in dict2.items():
        if k2 not in dict1:
            dict1.update({k2: v2})
        elif isinstance(v2, dict):
            merge_update(dict1[k2], v2)
        elif dict1[k2] == v2:
            # We have a duplicated value being reported by se. I presume it is
            # an updated value.
            pass
        else:
            # We have reached the bottom of the dictionary of dictionaries
            # structure and still have no NEW identifier keys. So it looks like
            # the inverter has reported new attributes for an existing instance
            # identifier in the same message
            message = (
                f"WARNING: For {k2} about to overwrite {dict1[k2]} with {v2}"
            )
            logger.debug(message)
            dict1[k2] = v2
