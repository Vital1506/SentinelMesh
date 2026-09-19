from sentinelmesh.deception_ai import AdaptiveDeceptionEngine


def test_predictor_and_shell_responses(tmp_path):
    engine = AdaptiveDeceptionEngine(tmp_path / "sequence_model.json", "lab-host-01")
    engine.train([["whoami", "pwd", "ls -la"], ["uname -a", "id", "ps aux"]])

    response = engine.synthesize_response("session-1", "whoami", ["whoami"])
    assert response == "www-data"

    listing = engine.synthesize_response("session-1", "ls", ["whoami", "ls"])
    assert "config.php" in listing

    prediction = engine.predict_next(["whoami"])
    assert prediction == "pwd"
