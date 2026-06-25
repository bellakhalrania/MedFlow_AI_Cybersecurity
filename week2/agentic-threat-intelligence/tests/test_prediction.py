from intelligence.technique_predictor import predict_next_tactics

def test_predicts_next_tactic_after_execution():
    result = predict_next_tactics(["execution"])
    assert "persistence" in result
