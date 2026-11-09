# SolarEdge command line argument parsing and validation

import sys
import serial.tools.list_ports
import re
import argparse
import datetime
from collections import namedtuple
import logging
import logging.handlers
import se.logutils

logger = logging.getLogger(__name__)

# local time of day for the daily exit when -n is given 'default'
NADIR_DEFAULT = datetime.time(1, 40)

# run environment that is derived from the arguments that defines how the program will behave
RunMode = namedtuple("RunMode", ("serialDevice",  # boolean, data comes from a RS485 serial device
                                 "passiveMode",   # boolean, only listen
                                 "masterMode",    # boolean, function as RS485 master
                                 "following",     # boolean
                                 ))

# argument parser class
class SeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage()
        sys.stderr.write(message+"\n")
        sys.exit(2)

# get arguments from the command line and validate them
def getArgs():

    # argument validation functions
    def validated_commands(command_str):
        commands = []
        for c in command_str.split("/"):
            if not re.match(r"^[0-9a-fA-F]+(,[bhlBHL][0-9a-fA-F]+)*$", c):
                raise argparse.ArgumentTypeError("Invalid command: {}".format(c))
            commands.append(c.split(","))
        return commands

    def validated_slaves(slave_str):
        slaves = []
        for s in slave_str.split(","):
            if not re.match(r"^[0-9a-fA-F]+$", s):
                raise argparse.ArgumentTypeError("Invalid slave ID: {}".format(s))
            slaves.append(s)
        return slaves

    def validated_nadir(time_str):
        if time_str.lower() == "default":
            return NADIR_DEFAULT
        m = re.match(r"^([01]?[0-9]|2[0-3]):([0-5][0-9])$", time_str)
        if not m:
            raise argparse.ArgumentTypeError("Invalid nadir, expected 24h HH:MM or 'default': {}".format(time_str))
        return datetime.time(int(m.group(1)), int(m.group(2)))

    parser = SeArgumentParser(description='Parse Solaredge data to extract inverter and optimizer telemetry',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-a", dest="append", action="store_true", default=False, help="append to output file if the file exists")
    parser.add_argument("-b", dest="baudrate", type=int, default=115200, help="baud rate for serial data source")
    parser.add_argument("-c", dest="commands", type=validated_commands, default=[], help="send the specified command functions")
    parser.add_argument("-d", dest="logfile", default="stderr", help="where to write log messages.  either a file name or one of ['stderr', 'syslog']")
    parser.add_argument("-f", dest="follow", action="store_true", default=False, help="wait for appended data as the input file grows (as in tail -f)")
    parser.add_argument("-m", dest="master", action="store_true", default=False, help="function as a RS485 master")
    parser.add_argument("-n", dest="nadir", type=validated_nadir, default=None, metavar="HH:MM|default", help="exit cleanly (status 0) once a day at the nadir, the local 24h HH:MM time the sun is lowest, so a container restart starts new output files. 'default' is 01:40. not set means never exit")
    parser.add_argument("-o", dest="outfile", default="stdout", help="write performance data to the specified file in JSON format (default: stdout)")
    parser.add_argument("-r", dest="record", help="file to record all incoming and outgoing messages to")
    parser.add_argument("-s", dest="slaves", type=validated_slaves, default=[], help="comma delimited list of SolarEdge slave inverter IDs")
    parser.add_argument("-v", dest="verbose", action="count", default=0, help="verbose output")
    parser.add_argument("-x", dest="xerror", action="store_true", default=False, help="halt on data exception")
    parser.add_argument("datasource", default="stdin", nargs='?', help="Input filename or serial port")

    args = parser.parse_args()

    # configure logging
    stream_formatter = logging.Formatter("%(message)s")
    file_formatter = logging.Formatter("%(asctime)s %(message)s", datefmt="%b %d %H:%M:%S")

    if args.logfile == "syslog":
        handler = logging.handlers.SysLogHandler(address="/dev/log")
        handler.setFormatter(stream_formatter)
    elif args.logfile == "stderr":
        handler = logging.StreamHandler(stream=sys.stderr)
        handler.setFormatter(stream_formatter)
    elif args.logfile == "stdout":
        handler = logging.StreamHandler(stream=sys.stdout)
        handler.setFormatter(stream_formatter)
    elif args.logfile:
        handler = logging.FileHandler(args.logfile, mode="a" if args.append else "w")
        handler.setFormatter(file_formatter)

    level = {                               # previously:
            1: logging.INFO,                # -v    debugFiles
            2: logging.DEBUG,               # -vv   debugMsgs
            3: se.logutils.LOG_LEVEL_DATA,  # -vvv  debugData
            4: se.logutils.LOG_LEVEL_RAW,   # -vvvv debugRaw
            }.get(min(args.verbose, 4), logging.ERROR)

    # configure the root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    root_logger.addHandler(handler)

    serialDevice = False

    # data source validation (a RS485 serial device, a file or stdin)
    if args.datasource == "-":
        args.datasource = "stdin"
    elif args.datasource != "stdin":
        # figure out the list of valid serial ports on this server
        # this is either a list of tuples or ListPortInfo objects
        serial_ports = serial.tools.list_ports.comports()
        serial_port_names = map(lambda p: p.device if isinstance(p,
                                serial.tools.list_ports_common.ListPortInfo) else p[0], serial_ports)
        serialDevice = args.datasource in serial_port_names

    if serialDevice:
        args.following = True

    # master mode validation
    passiveMode = not args.master
    if args.master:
        if not serialDevice:
            parser.error("Master mode only allowed with RS485 serial device")
        if len(args.slaves) < 1:
            parser.error("At least one slave address must be specified for master mode")

    # command mode validation
    if args.commands:
        passiveMode = False
        if len(args.slaves) != 1:
            parser.error("Exactly one slave address must be specified for command mode")

    # print out the arguments and option
    for k,v in sorted(vars(args).items()):
        if k == "commands":
            v = " ".join(",".join(cpart for cpart in command) for command in v)
        if k == "slaves":
            v = ",".join(slave for slave in v)
        logger.info("%s: %s", k, v)

    return (args, RunMode(serialDevice, passiveMode, args.master, args.follow))
