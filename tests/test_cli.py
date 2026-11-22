import json
import runpy
import sys
from pathlib import Path

import pytest

from se import se2csv, seprint

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

    se2csv.main(["-p", str(tmp_path / "out"), str(path)])

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
            ("-c", "c", "-u", "u", "-p", "p", "-s", "s", "-t", "t", "-x"),
        ),
        ("se2state", ("-o", "state.json", "-x")),
        ("se2graphite", ("-x",)),
    ],
)
def test_a_stray_option_is_a_usage_error(monkeypatch, capsys, tool, args):
    assert run_tool(monkeypatch, tool, *args) == 2
    assert "-x" in capsys.readouterr().err
