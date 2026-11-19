import io
import json
import sys

import pytest

from se import se2json


def reject_constant(constant):
    raise ValueError(constant)


def run_se2json(monkeypatch, capsys, *args, stdin=""):
    monkeypatch.setattr(sys, "stdin", io.StringIO(stdin))
    code = 0
    message = ""
    try:
        se2json.main([str(arg) for arg in args])
    except SystemExit as exit_:
        # sys.exit(text) writes the text to stderr when the interpreter exits
        if isinstance(exit_.code, str):
            code, message = 1, exit_.code
        else:
            code = exit_.code or 0
    captured = capsys.readouterr()
    return code, captured.out, captured.err + message


def line(**sections):
    data = {"events": {}, "inverters": {}, "optimizers": {}}
    data.update(sections)
    return json.dumps(data) + "\n"


def inverter(**extra):
    return {"Date": "2016-01-01", "ID": "I1", "Time": "12:00:00", **extra}


# --- the values ---------------------------------------------------------------


@pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
def test_a_value_that_is_not_valid_json_becomes_null(
    monkeypatch, capsys, constant
):
    text = f'{{"inverters": {{"I1": {{"Pmax": {constant}, "Pac": 1.5}}}}}}\n'

    code, out, err = run_se2json(monkeypatch, capsys, stdin=text)

    assert code == 0
    assert err == ""
    assert out == '{"inverters": {"I1": {"Pmax": null, "Pac": 1.5}}}\n'


def test_the_output_is_valid_json(monkeypatch, capsys):
    text = line(inverters={"I1": inverter(Pmax=float("nan"))})

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=text)

    assert json.loads(out, parse_constant=reject_constant) == {
        "events": {},
        "inverters": {"I1": inverter(Pmax=None)},
        "optimizers": {},
    }


def test_a_value_in_a_list_becomes_null_as_well(monkeypatch, capsys):
    _code, out, _err = run_se2json(monkeypatch, capsys, stdin="[1, NaN]\n")

    assert out == "[1, null]\n"


def test_the_string_nan_is_left_alone(monkeypatch, capsys):
    text = '{"Name": "NaN", "Value": NaN}\n'

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=text)

    assert out == '{"Name": "NaN", "Value": null}\n'


def test_valid_input_comes_out_the_same(monkeypatch, capsys):
    text = line(
        inverters={"I1": inverter(Pac=1.5, Eday=10, Name="x")},
        events={"E1": {"Code": 3}},
    )

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=text)

    assert out == text


def test_the_order_of_the_keys_is_kept(monkeypatch, capsys):
    text = '{"b": 1, "a": NaN, "c": {"z": 1, "y": 2}}\n'

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=text)

    assert out == '{"b": 1, "a": null, "c": {"z": 1, "y": 2}}\n'


# --- the lines ----------------------------------------------------------------


def test_every_line_is_converted_on_its_own(monkeypatch, capsys):
    text = line(inverters={"I1": inverter(Pmax=float("nan"))}) + line()

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=text)

    assert out.splitlines() == [
        json.dumps(
            {
                "events": {},
                "inverters": {"I1": inverter(Pmax=None)},
                "optimizers": {},
            }
        ),
        json.dumps({"events": {}, "inverters": {}, "optimizers": {}}),
    ]


def test_empty_lines_are_skipped(monkeypatch, capsys):
    _code, out, _err = run_se2json(monkeypatch, capsys, stdin="\n{}\n  \n[]\n")

    assert out == "{}\n[]\n"


def test_input_without_a_final_newline_is_converted(monkeypatch, capsys):
    _code, out, _err = run_se2json(monkeypatch, capsys, stdin="[NaN]")

    assert out == "[null]\n"


def test_empty_input_gives_no_output(monkeypatch, capsys):
    code, out, err = run_se2json(monkeypatch, capsys)

    assert (code, out, err) == (0, "", "")


def test_each_line_is_flushed_for_whoever_waits_for_it(monkeypatch):
    class Stdout(io.StringIO):
        def __init__(self):
            super().__init__()
            self.flushed = []

        def flush(self):
            self.flushed.append(self.getvalue())
            super().flush()

    stdout = Stdout()
    monkeypatch.setattr(sys, "stdin", io.StringIO("[1]\n[NaN]\n"))
    monkeypatch.setattr(sys, "stdout", stdout)

    se2json.main([])

    assert stdout.flushed == ["[1]\n", "[1]\n[null]\n"]


# --- failures -----------------------------------------------------------------


def test_a_line_that_is_not_json_is_an_error_with_its_number(
    monkeypatch, capsys
):
    code, out, err = run_se2json(monkeypatch, capsys, stdin="[1]\n{oops\n[2]\n")

    assert code == 1
    assert out == "[1]\n"
    assert ": line 2: " in err


def test_a_number_that_is_too_large_is_an_error(monkeypatch, capsys):
    code, out, err = run_se2json(monkeypatch, capsys, stdin="[1e999]\n")

    assert code == 1
    assert out == ""
    assert ": line 1: " in err


# --- command line -------------------------------------------------------------


def test_the_input_is_read_from_the_file_it_is_given(
    workdir, monkeypatch, capsys
):
    path = workdir / "in.json"
    path.write_text("[NaN]\n")

    code, out, _err = run_se2json(monkeypatch, capsys, path)

    assert code == 0
    assert out == "[null]\n"


def test_a_file_that_does_not_exist_is_an_error(workdir, monkeypatch, capsys):
    code, out, err = run_se2json(monkeypatch, capsys, workdir / "missing.json")

    assert code == 1
    assert out == ""
    assert "missing.json" in err


def test_help_describes_the_tool(monkeypatch, capsys):
    code, out, _err = run_se2json(monkeypatch, capsys, "-h")

    assert code == 0
    assert "null" in out
    assert "infile" in out


# --- the output of semonitor --------------------------------------------------


def test_the_golden_output_comes_out_as_valid_json(
    monkeypatch, capsys, golden, sample
):
    original = golden("json", sample).read_text()

    code, out, _err = run_se2json(monkeypatch, capsys, stdin=original)

    assert code == 0
    assert len(out.splitlines()) == len(original.splitlines())
    for converted in out.splitlines():
        json.loads(converted, parse_constant=reject_constant)


def test_the_golden_output_only_loses_its_nan(
    monkeypatch, capsys, golden, sample
):
    original = golden("json", sample).read_text()

    _code, out, _err = run_se2json(monkeypatch, capsys, stdin=original)

    assert out == original.replace("NaN", "null")
