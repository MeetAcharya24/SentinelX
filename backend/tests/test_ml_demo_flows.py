import json
from pathlib import Path

import pytest

from app.api.network import MAX_FLOWS_PER_REQUEST, FlowFeatures
from app.ml.demo_flows import (
    MAX_DEMO_FLOWS,
    PROFILES,
    build_demo_document,
    generate_demo_flows,
    main,
)
from app.ml.schema import FEATURE_COLUMNS


def test_generates_the_requested_number_of_flows_with_every_feature() -> None:
    flows = generate_demo_flows(count=12, seed=1)

    assert len(flows) == 12
    assert all(tuple(flow.features) == FEATURE_COLUMNS for flow in flows)


def test_the_same_seed_reproduces_the_same_flows() -> None:
    assert generate_demo_flows(count=10, seed=4) == generate_demo_flows(count=10, seed=4)


def test_a_different_seed_gives_different_flows() -> None:
    assert generate_demo_flows(count=10, seed=4) != generate_demo_flows(count=10, seed=5)


def test_every_profile_appears_once_there_is_room_for_all_of_them() -> None:
    flows = generate_demo_flows(count=len(PROFILES), seed=2)

    assert {flow.profile for flow in flows} == {profile.name for profile in PROFILES}


def test_flows_are_not_grouped_by_profile() -> None:
    names = [flow.profile for flow in generate_demo_flows(count=50, seed=2)]

    assert names != sorted(names)
    assert names[: len(PROFILES)] != [profile.name for profile in PROFILES]


def test_every_flow_is_a_valid_scoring_input() -> None:
    for flow in generate_demo_flows(count=MAX_DEMO_FLOWS, seed=3):
        FlowFeatures.model_validate(flow.features)


def test_derived_fields_agree_with_the_fields_they_come_from() -> None:
    for flow in generate_demo_flows(count=MAX_DEMO_FLOWS, seed=6):
        features = flow.features
        assert features["smean"] == features["sbytes"] // features["spkts"]
        assert features["tcprtt"] == pytest.approx(features["synack"] + features["ackdat"])
        packets = features["spkts"] + features["dpkts"]
        assert features["rate"] == pytest.approx((packets - 1) / features["dur"], rel=1e-3)
        if features["dpkts"] == 0:
            assert features["dbytes"] == features["dload"] == features["dmean"] == 0


def test_only_tcp_flows_carry_tcp_fields() -> None:
    for flow in generate_demo_flows(count=MAX_DEMO_FLOWS, seed=6):
        features = flow.features
        if features["proto"] == "tcp":
            assert features["swin"] == features["dwin"] == 255
            assert features["tcprtt"] > 0
        else:
            assert features["swin"] == features["stcpb"] == features["tcprtt"] == 0


def test_the_flow_limit_matches_one_scoring_request() -> None:
    assert MAX_DEMO_FLOWS == MAX_FLOWS_PER_REQUEST


@pytest.mark.parametrize("count", [0, -1, MAX_DEMO_FLOWS + 1])
def test_a_count_outside_the_limits_is_rejected(count: int) -> None:
    with pytest.raises(ValueError, match="between 1 and"):
        generate_demo_flows(count=count, seed=1)


def test_a_negative_seed_is_rejected() -> None:
    with pytest.raises(ValueError, match="seed"):
        generate_demo_flows(count=5, seed=-1)


def test_the_document_is_labelled_as_synthetic_demo_data() -> None:
    document = build_demo_document(count=8, seed=3)

    assert document["demo"] is True
    assert "synthetic" in document["notice"].lower()
    assert "not captured" in document["notice"].lower()
    assert document["seed"] == 3
    assert len(document["profiles"]) == len(document["flows"]) == 8


def test_main_writes_a_labelled_document_to_the_output_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "flows.json"

    exit_code = main(["--count", "6", "--seed", "3", "--output", str(output)])

    assert exit_code == 0
    assert json.loads(output.read_text(encoding="utf-8")) == build_demo_document(count=6, seed=3)
    assert "synthetic" in capsys.readouterr().out.lower()


def test_main_prints_the_document_when_no_output_file_is_given(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code = main(["--count", "5", "--seed", "9"])

    assert exit_code == 0
    assert json.loads(capsys.readouterr().out) == build_demo_document(count=5, seed=9)


def test_main_fails_with_the_reason_for_an_invalid_count(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output = tmp_path / "flows.json"

    exit_code = main(["--count", "0", "--output", str(output)])

    assert exit_code == 1
    assert "between 1 and" in capsys.readouterr().out
    assert not output.exists()
