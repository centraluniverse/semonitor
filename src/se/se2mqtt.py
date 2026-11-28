r"""
Send JSON performance data to Mosquitto MQTT broker.

Options:
    -j, --client-id   Mosquitto client ID
    -u, --username    Mosquitto client user ID
    -W, --password    Mosquitto client password
    -H, --host        Mosquitto server (DNS or IP address)
    -T, --topic       Mosquitto MQTT topic to publish to

Example:
    Follow /root/solaredge/performance.json and publish to topic
    "/ha/value/solaredge" on server "mosquitto.domain.local" with client ID
    "solaredge" and user "solaredge" and password "s0lar3dg3"::

        python3 se2MQTT.py --client-id solaredge --username solaredge \
            --password s0lar3dg3 --host mosquitto.domain.local \
            --topic /ha/value/solaredge /root/solaredge/performance.json

    Or pipe the output of semonitor directly into se2MQTT.py::

        python3 semonitor.py -t 4 -d /root/solaredge/selog.txt -s 7f123456 \
            -vvvv /dev/ttyUSB0 | \
            python3 se2MQTT.py -j solaredge -u solaredge -W s0lar3dg3 \
            -H mosquitto.domain.local -T /ha/value/solaredge
"""

import argparse
import json
import sys
import time

import paho.mqtt.client as mqtt

from se.metrics import open_input


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
        description="Publish SolarEdge performance data to a Mosquitto broker.",
    )
    parser.add_argument(
        "-j",
        "--client-id",
        dest="clientid",
        required=True,
        help="Mosquitto client ID",
    )
    parser.add_argument(
        "-u",
        "--username",
        dest="user",
        required=True,
        help="Mosquitto client user ID",
    )
    parser.add_argument(
        "-W",
        "--password",
        dest="passwd",
        required=True,
        help="Mosquitto client password",
    )
    parser.add_argument(
        "-H",
        "--host",
        dest="server",
        required=True,
        help="Mosquitto server (DNS or IP address)",
    )
    parser.add_argument(
        "-T",
        "--topic",
        dest="topic",
        required=True,
        help="Mosquitto MQTT topic to publish to",
    )
    parser.add_argument(
        "infile",
        nargs="?",
        help="file containing performance data in JSON format (default: stdin)",
    )
    return parser.parse_args(argv)


def update_state(state_dict, in_dict):
    """
    Update the state with the inverters and optimizers of a message.

    The energy and power of all inverters are zeroed when the message has an
    event, such as the inverters going to sleep.
    """
    state_dict["inverters"].update(in_dict["inverters"])
    state_dict["optimizers"].update(in_dict["optimizers"])
    if len(in_dict["events"]) != 0:
        for inverter in state_dict["inverters"]:
            state_dict["inverters"][inverter]["Eac"] = 0.0
            state_dict["inverters"][inverter]["Pac"] = 0.0


def main(argv=None):
    """
    Publish the performance data read from the input to MQTT, forever.

    Args:
        argv: The command line arguments to use, or None for those of the
            process.
    """
    # state values
    state_dict = {"inverters": {}, "optimizers": {}}

    # get program arguments and options
    args = parse_args(argv)
    in_file = open_input([] if args.infile is None else [args.infile])

    # read the input forever
    with in_file:
        while True:
            json_str = ""
            # wait for data
            while json_str == "":
                time.sleep(0.1)
                json_str = in_file.readline()
            in_dict = json.loads(json_str)
            update_state(state_dict, in_dict)
            # send to MQTT
            try:
                mqttc = mqtt.Client(client_id=args.clientid)
                mqttc.username_pw_set(args.user, args.passwd)
                mqttc.connect(args.server)
                mqttc.publish(args.topic, json.dumps(state_dict))
                mqttc.disconnect()
            except (OSError, ValueError) as ex:
                sys.stderr.write(f"MQTT Exception: {ex}\n")


if __name__ == "__main__":
    main()
