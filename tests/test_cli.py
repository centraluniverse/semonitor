import json
import runpy
import sys
from pathlib import Path

import pytest

from se import env, se2csv, se2file, se2graphite, se2state, seprint

DEVICE = {
    "Date": "2020-01-01",
    "Time": "10:00:00",
    "Eday": 1.0,
    "Pac": 2.0,
    "Vac": 3.0,
}
DATA = {"inverters": {"I1": DEVICE}, "optimizers": {}, "events": {}}


# The entry points call main() without arguments, so main() has to take the
# arguments of the process then. Giving it arguments has to work as well, and
# has to ignore those of the process.
def test_seprint_main_reads_the_file_it_is_given(tmp_path, capsys):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(DATA) + "\n")

    seprint.main([str(path)])

    assert capsys.readouterr().out.splitlines()[0] == "Inverters"


def test_seprint_main_defaults_to_the_arguments_of_the_process(
    tmp_path, capsys, monkeypatch
):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(DATA) + "\n")
    monkeypatch.setattr("sys.argv", ["seprint", str(path)])

    seprint.main()

    assert capsys.readouterr().out.splitlines()[0] == "Inverters"


def test_se2csv_main_uses_the_arguments_it_is_given(tmp_path, monkeypatch):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(DATA) + "\n")
    monkeypatch.setattr("sys.argv", ["se2csv", "--no-such-option"])

    se2csv.main(["-P", str(tmp_path / "out"), str(path)])

    assert (tmp_path / "out.inverters.csv").exists()


# Every tool parses its options with argparse, so -h and --help describe the
# tool and a stray option is a usage error, not a file name.
SRC = Path(__file__).resolve().parent.parent / "src" / "se"
TOOLS = ["se2mqtt", "se2state", "se2graphite", "seprint", "se2hex"]


def run_tool(monkeypatch, tool, *args):
    monkeypatch.setattr(sys, "argv", [tool, *args])
    with pytest.raises(SystemExit) as exit_:
        runpy.run_path(str(SRC / f"{tool}.py"), run_name="__main__")
    return exit_.value.code


@pytest.mark.parametrize("flag", ["-h", "--help"])
@pytest.mark.parametrize("tool", TOOLS)
def test_every_tool_answers_help(monkeypatch, capsys, tool, flag):
    assert run_tool(monkeypatch, tool, flag) == 0
    assert capsys.readouterr().out.startswith("usage: ")


@pytest.mark.parametrize(
    ("tool", "args"),
    [
        ("seprint", ("-x",)),
        ("se2hex", ("log.txt", "-x")),
        (
            "se2mqtt",
            ("-j", "c", "-u", "u", "-W", "p", "-H", "s", "-T", "t", "-x"),
        ),
        ("se2state", ("-S", "state.json", "-x")),
        ("se2graphite", ("-x",)),
    ],
)
def test_a_stray_option_is_a_usage_error(monkeypatch, capsys, tool, args):
    assert run_tool(monkeypatch, tool, *args) == 2
    assert "-x" in capsys.readouterr().err


# Every long option has the same meaning as its short option: both spellings
# must parse to the same values. The parsers are compared, not the output.
def parsed(parse, argv):
    return vars(parse(argv))


@pytest.mark.parametrize(
    ("short", "long"),
    [
        (
            ["-a", "-b", "9600", "-c", "0012", "-d", "x.log", "-f", "-m"],
            [
                "--append",
                "--baudrate",
                "9600",
                "--commands",
                "0012",
                "--logfile",
                "x.log",
                "--follow",
                "--master",
            ],
        ),
        (
            [
                "-n",
                "default",
                "-o",
                "out.json",
                "-r",
                "rec.bin",
                "-s",
                "7f101234",
            ],
            [
                "--nadir",
                "default",
                "--outfile",
                "out.json",
                "--record",
                "rec.bin",
                "--slave",
                "7f101234",
            ],
        ),
        (
            ["-t", "4", "-v", "-x", "in.rec"],
            ["--type", "4", "--verbose", "--xerror", "in.rec"],
        ),
    ],
)
def test_the_long_options_of_semonitor_are_the_short_ones(short, long):
    assert parsed(env._make_parser().parse_args, long) == parsed(
        env._make_parser().parse_args, short
    )


def test_the_long_options_of_se2csv_are_the_short_ones():
    short = ["-a", "-F", ";", "-L", "-P", "out"]
    long = ["--append", "--delimiter", ";", "--headers", "--prefix", "out"]
    assert parsed(se2csv.parse_args, long) == parsed(se2csv.parse_args, short)


def test_the_long_options_of_se2file_are_the_short_ones():
    short = ["-v", "-B", "d", "-P", "p_", "-D", "-l", "5", "-w", "-M"]
    long = [
        "--verbose",
        "--basedir",
        "d",
        "--prefix",
        "p_",
        "--daily",
        "--linger",
        "5",
        "--wait",
        "--make-daily-dir",
    ]
    assert parsed(se2file.getargs, long) == parsed(se2file.getargs, short)


def test_the_long_options_of_se2graphite_are_the_short_ones():
    def values(argv):
        options = se2graphite.parse_options(argv)
        return (
            options.base,
            options.host_name,
            options.port,
            options.following,
            options.text,
        )

    short = ["-P", "p", "-H", "h", "-p", "2203", "-f", "-e"]
    long = [
        "--prefix",
        "p",
        "--host",
        "h",
        "--port",
        "2203",
        "--follow",
        "--text",
    ]
    assert values(long) == values(short)


def test_the_long_options_of_se2mqtt_are_the_short_ones():
    se2mqtt = pytest.importorskip("se.se2mqtt")
    parse_args = se2mqtt.parse_args

    short = ["-j", "c", "-u", "u", "-W", "p", "-H", "h", "-T", "t", "in.json"]
    long = [
        "--client-id",
        "c",
        "--username",
        "u",
        "--password",
        "p",
        "--host",
        "h",
        "--topic",
        "t",
        "in.json",
    ]
    assert parsed(parse_args, long) == parsed(parse_args, short)


def test_the_long_options_of_se2state_are_the_short_ones():
    short = ["-s", "I1,I2", "-S", "state.json", "in.json"]
    long = ["--slave", "I1,I2", "--state-file", "state.json", "in.json"]
    assert parsed(se2state.parse_args, long) == parsed(
        se2state.parse_args, short
    )


def test_the_long_options_of_se2influx_are_the_short_ones():
    se2influx = pytest.importorskip("se.se2influx")
    parse_args = se2influx.parse_args

    short = ["-H", "db.lan", "-p", "9999", "-u", "me", "-W", "pw"]
    long = [
        "--host",
        "db.lan",
        "--port",
        "9999",
        "--username",
        "me",
        "--password",
        "pw",
    ]
    assert parsed(parse_args, long) == parsed(parse_args, short)
    assert parsed(parse_args, short)["port"] == 9999
    assert isinstance(parsed(parse_args, short)["port"], int)
