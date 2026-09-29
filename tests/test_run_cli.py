from pathlib import Path

from sentinel.run import main

ALERT = Path(__file__).parent / "fixtures" / "alerts" / "day2-001.json"


def test_cli_runs_end_to_end_without_tracing(capsys):
    final = main(["--alert", str(ALERT), "--stub", "--no-trace", "--passes", "FFT"])

    assert final["outcome"] == "rule_passed"
    assert len(final["validations"]) == 3
    out = capsys.readouterr().out
    assert "ingest -> enrich -> triage -> route -> rule_gen -> validate -> repair" in out
    assert "off (no LANGFUSE keys" in out


def test_cli_benign_skips_rule_generation(capsys):
    final = main(["--alert", str(ALERT), "--stub", "--no-trace", "--verdict", "benign_noisy"])

    assert final["outcome"] == "benign"
    assert "rule_gen" not in capsys.readouterr().out
