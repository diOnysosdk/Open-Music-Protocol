"""Executable decision-table checks for the ADR-013 semantic amendment."""

import json
import pathlib


ROOT = pathlib.Path(__file__).resolve().parents[1]


def evaluate(case):
    value = case["input"]
    result = {"authenticity": value["signature"]}

    if not value["content_exact"]:
        result.update(
            authorization="AUTHORIZATION_UNKNOWN",
            playback="PLAYBACK_DENIED",
            error="OMP_ASSET_BINDING_INVALID",
        )
        return result

    if not value["role_matches"]:
        authorization = "UNAUTHORIZED"
    elif value["current_status"] == "ACTIVE":
        authorization = "AUTHORIZED_CURRENT"
    elif value["historical_evidence"] == "PROVEN_PRE_BOUNDARY":
        authorization = "AUTHORIZED_HISTORICAL"
    else:
        authorization = "AUTHORIZATION_UNKNOWN"
    result["authorization"] = authorization

    status = value["current_status"]
    if status in {"REVOKED", "CONFLICT"}:
        result["current_status"] = status

    if value["historical_evidence"] == "MISSING_TRUSTED_TIME":
        result["error"] = "OMP_TRUSTED_TIME_UNAVAILABLE"
        return result

    if value["operation"] != "playback":
        if value["operation"] != "inspect" and authorization == "AUTHORIZATION_UNKNOWN":
            result.update(operation_result="DENIED", error="OMP_KEY_UNAUTHORIZED")
        return result

    if status == "REVOKED":
        result.update(playback="PLAYBACK_DENIED", error="OMP_KEY_REVOKED")
    elif status == "CONFLICT":
        if authorization == "AUTHORIZED_HISTORICAL" and value["pin"] == "ELIGIBLE":
            result["playback"] = "VALID_CONFLICTED_PINNED"
        else:
            result.update(playback="PLAYBACK_DENIED", error="OMP_TRUST_CONFLICT")
    elif authorization in {"AUTHORIZED_CURRENT", "AUTHORIZED_HISTORICAL"}:
        result["playback"] = "PLAYBACK_ALLOWED"
    elif not value["public_unrestricted"]:
        result.update(playback="PLAYBACK_DENIED", error="OMP_KEY_UNAUTHORIZED")
    elif value["pin"] == "ELIGIBLE":
        result["playback"] = "PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN"
    elif value["pin"] == "TOFU_UNVERIFIED":
        result.update(playback="PLAYBACK_DENIED", error="OMP_IDENTITY_UNVERIFIED")
    elif value["pin"] == "ROLLBACK":
        result.update(playback="PLAYBACK_DENIED", error="OMP_TRUST_ROLLBACK")
    else:
        result.update(playback="PLAYBACK_DENIED", error="OMP_KEY_UNAUTHORIZED")
    return result


def test_all_semantic_fixtures_match_the_normative_decision_table():
    fixture = json.loads(
        (ROOT / "historical-authorization" / "semantic-fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    assert fixture["profile"] == "OMP-v0.2-historical-authorization-amendment-1"
    identifiers = [case["id"] for case in fixture["cases"]]
    assert len(identifiers) == len(set(identifiers))
    for case in fixture["cases"]:
        assert evaluate(case) == case["expected"], case["id"]


def test_exception_is_never_an_authorization_success():
    fixture = json.loads(
        (ROOT / "historical-authorization" / "semantic-fixtures.json").read_text(
            encoding="utf-8"
        )
    )
    exceptions = [
        case for case in fixture["cases"]
        if case["expected"].get("playback") == "PLAYBACK_ALLOWED_PINNED_AUTH_UNKNOWN"
    ]
    assert exceptions
    assert all(
        case["expected"]["authorization"] == "AUTHORIZATION_UNKNOWN"
        for case in exceptions
    )
