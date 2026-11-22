"""
Maintain a file containing the current state and selected statistics.

The state covers SolarEdge inverters and optimizers.
"""

import argparse
import json
import time
from pathlib import Path

from se.metrics import open_input


def inverter_list(value):
    """
    Split a comma separated list of inverter IDs.

    Args:
        value: The command line value, such as "7F104920,7F104921".

    Returns:
        The list of inverter IDs.
    """
    return value.split(",")


def parse_args(argv):
    """
    Parse the command line arguments.

    Args:
        argv: The command line arguments, without the name of the program, or
            None for those of the process.

    Returns:
        The parsed arguments, with the input file in infile (None for stdin).
    """
    parser = argparse.ArgumentParser(
        description=(
            "Maintain a JSON file with the current state of SolarEdge "
            "inverters and optimizers."
        ),
    )
    parser.add_argument(
        "-i",
        dest="inverters",
        type=inverter_list,
        metavar="INVERTER[,INVERTER...]",
        help=(
            "initialize the state file with these inverter IDs, rather than "
            "using an existing one"
        ),
    )
    parser.add_argument(
        "-o",
        dest="out_file_name",
        required=True,
        metavar="STATEFILE",
        help="state file, overwritten every time that new data is read",
    )
    parser.add_argument(
        "infile",
        nargs="?",
        help="file containing performance data in JSON format (default: stdin)",
    )
    return parser.parse_args(argv)


def sum_items(item_dict, item_attr):
    """
    Return the sum of an attribute over the items in a dictionary.

    The stats item is ignored.

    Args:
        item_dict: The dictionary of items.
        item_attr: The name of the attribute to sum.

    Returns:
        The sum of the attribute.
    """
    item_sum = 0
    for item in item_dict:
        if item != "stats":
            item_sum += item_dict[item][item_attr]
    return item_sum


def avg_items(item_dict, item_attr):
    """
    Return the average of an attribute over the items in a dictionary.

    The stats item is ignored.

    Args:
        item_dict: The dictionary of items.
        item_attr: The name of the attribute to average.

    Returns:
        The average of the attribute, 0 when there are no items.
    """
    try:
        return sum_items(item_dict, item_attr) / (len(item_dict) - 1)
    except ZeroDivisionError:
        return 0


def write_state(state_dict, out_file_name):
    """Write the state dictionary to the state file as JSON."""
    with Path(out_file_name).open("w") as out_file:
        json.dump(state_dict, out_file)


def zero_stats():
    """Return the stats of an item with all values zeroed."""
    return {
        "Vac": 0.0,
        "Pac": 0.0,
        "Eac": 0.0,
        "Eday": 0.0,
        "Etot": 0.0,
        "Temp": 0.0,
    }


def initial_state(inverters):
    """
    Return a state dictionary with all statistics zeroed.

    Args:
        inverters: The names of the inverters to add to the state.

    Returns:
        The new state dictionary.
    """
    state_dict = {
        "inverters": {"stats": zero_stats()},
        "optimizers": {"stats": {"Temp": 0.0}},
    }
    for inverter in inverters:
        state_dict["inverters"][inverter] = zero_stats()
    return state_dict


def update_state(state_dict, in_dict):
    """
    Update the state dictionary in place with one line of input.

    Args:
        state_dict: The state dictionary to update.
        in_dict: The input data, with the inverters, optimizers and events.
    """
    state_dict["inverters"].update(in_dict["inverters"])
    state_dict["optimizers"].update(in_dict["optimizers"])
    # compute optimizer power
    for optimizer in state_dict["optimizers"]:
        if optimizer != "stats":
            state_dict["optimizers"][optimizer]["Pdc"] = (
                state_dict["optimizers"][optimizer]["Vmod"]
                * state_dict["optimizers"][optimizer]["Imod"]
            )
    # compute the stats
    state_dict["inverters"]["stats"]["Vac"] = avg_items(
        state_dict["inverters"], "Vac"
    )
    state_dict["inverters"]["stats"]["Pac"] = sum_items(
        state_dict["inverters"], "Pac"
    )
    state_dict["inverters"]["stats"]["Eac"] = sum_items(
        state_dict["inverters"], "Eac"
    )
    e_day = sum_items(state_dict["inverters"], "Eday")
    # only update Eday if it increases
    state_dict["inverters"]["stats"]["Eday"] = max(
        state_dict["inverters"]["stats"]["Eday"], e_day
    )
    state_dict["inverters"]["stats"]["Etot"] = sum_items(
        state_dict["inverters"], "Etot"
    )
    state_dict["inverters"]["stats"]["Temp"] = avg_items(
        state_dict["inverters"], "Temp"
    )
    state_dict["optimizers"]["stats"]["Temp"] = avg_items(
        state_dict["optimizers"], "Temp"
    )
    # zero current energy and power for devices when an event occurs
    if len(in_dict["events"]) != 0:
        for inverter in state_dict["inverters"]:
            state_dict["inverters"][inverter]["Eac"] = 0.0
            state_dict["inverters"][inverter]["Pac"] = 0.0
        for optimizer in state_dict["optimizers"]:
            state_dict["optimizers"][optimizer]["Vmod"] = 0.0
            state_dict["optimizers"][optimizer]["Vopt"] = 0.0
            state_dict["optimizers"][optimizer]["Imod"] = 0.0


def main(argv=None):
    """
    Maintain the state file with the given arguments.

    Args:
        argv: The command line arguments, without the program name. The
            arguments of the process are used when this is None.
    """
    # get program arguments and options
    args = parse_args(argv)
    in_file = open_input([] if args.infile is None else [args.infile])
    out_file_name = args.out_file_name

    # initialize the state dictionary
    if args.inverters is not None:
        # zero the statistics
        state_dict = initial_state(args.inverters)
        write_state(state_dict, out_file_name)
    else:
        # start with values from the file if it exists
        try:
            with Path(out_file_name).open() as state_file:
                state_dict = json.load(state_file)
        except OSError:
            # Without a state file, start from zeroed statistics
            state_dict = initial_state([])

    # read the input forever
    with in_file:
        while True:
            json_str = ""
            # wait for data
            while json_str == "":
                time.sleep(0.1)
                json_str = in_file.readline()
            update_state(state_dict, json.loads(json_str))
            write_state(state_dict, out_file_name)


if __name__ == "__main__":
    main()
