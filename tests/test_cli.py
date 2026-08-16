import json

from prompt_injection_blocker.cli import main


def join_parts(*parts):
    return "".join(parts)


def test_clean_target_exits_zero(tmp_path, capsys):
    (tmp_path / "README.md").write_text("Normal notes.\n")
    assert main([str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert "No blocking promptware patterns" in out


def test_blocked_target_exits_two(tmp_path, capsys):
    marker = join_parts("ignore ", "previous instructions")
    (tmp_path / "notes.md").write_text(f"{marker}\n")
    assert main([str(tmp_path)]) == 2
    out = capsys.readouterr().out
    assert "STOP" in out


def test_json_output_parses(tmp_path, capsys):
    (tmp_path / "README.md").write_text("Normal notes.\n")
    assert main([str(tmp_path), "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["risk"] == "no-known-indicators"


def test_report_file_written(tmp_path, capsys):
    (tmp_path / "README.md").write_text("Normal notes.\n")
    report_path = tmp_path / "out" / "report.json"
    report_path.parent.mkdir()
    assert main([str(tmp_path), f"--report={report_path}"]) == 0
    report = json.loads(report_path.read_text())
    assert report["tool"] == "prompt-injection-blocker"


def test_unknown_argument_exits_one(capsys):
    assert main(["--bogus"]) == 1
    assert "Unknown argument" in capsys.readouterr().err


def test_report_without_path_exits_one(capsys):
    assert main(["--report"]) == 1
    assert "requires a file path" in capsys.readouterr().err


def test_multiple_targets_exit_one(tmp_path, capsys):
    assert main([str(tmp_path), str(tmp_path)]) == 1
    assert "Only one target" in capsys.readouterr().err


def test_missing_target_exits_one(tmp_path, capsys):
    assert main([str(tmp_path / "missing")]) == 1
    assert "Target does not exist" in capsys.readouterr().err


def test_help_exits_zero(capsys):
    assert main(["--help"]) == 0
    assert "Exit codes" in capsys.readouterr().out
