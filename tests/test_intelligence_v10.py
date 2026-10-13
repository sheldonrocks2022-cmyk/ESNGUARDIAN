from esn_guardian.intelligence_v10 import assess_threat


def test_v10_bounds_and_confidence():
    assessment = assess_threat(
        base_score=98, burst_count=100, category_count=20,
        surface_count=20, subject_case_count=100, baseline_samples=1000,
    )
    assert assessment.version == 10
    assert assessment.score == 100
    assert 0 <= assessment.confidence <= 1
    assert assessment.severity == "CRITICAL"


def test_v10_low_evidence_is_explained():
    assessment = assess_threat(base_score=0, rare_action=True)
    assert assessment.score == 0
    assert "limited baseline evidence" in assessment.reasons


def test_v10_correlated_events_increase_risk():
    quiet = assess_threat(base_score=20, baseline_samples=20)
    attack = assess_threat(
        base_score=20, burst_count=9, category_count=4,
        surface_count=5, subject_case_count=8, baseline_samples=20,
    )
    assert attack.score > quiet.score
    assert attack.confidence >= quiet.confidence
    assert len(attack.reasons) >= 3


def test_v10_negative_inputs_are_bounded():
    assessment = assess_threat(base_score=-100, burst_count=-5, baseline_samples=-10)
    assert assessment.score == 0
    assert assessment.confidence >= 0
