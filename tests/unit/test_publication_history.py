"""Publication observations distinguish inclusion, execution and authorization."""

import pytest

from src.storage.publication_history import PublicationObservation


@pytest.fixture
def observation():
    return dict(
        schema_version="clearproof-publication-observation-v1",
        intent_id="ab" * 32,
        transaction_hash="cd" * 32,
        phase="publish",
        anchor_number=10,
        anchor_hash="ef" * 32,
        block_tag="safe",
        minimum_confirmations=2,
        confirmations=2,
        execution="succeeded",
        registry_effect="statement-published-at-inclusion",
        current_authorization="not-evaluated",
        resubmission="not-authorized",
        status="confirmed-success",
        inclusion_number=9,
        inclusion_hash="12" * 32,
    )


@pytest.mark.parametrize(
    "phase,effect", [("publish", "statement-published-at-inclusion"), ("mirror", "receipt-mirrored-at-inclusion")]
)
@pytest.mark.parametrize("status", ["confirmed-success", "confirmed-failure", "awaiting-confirmations"])
def test_included_observations_preserve_execution_without_authorization(observation, phase, effect, status):
    value = {**observation, "phase": phase, "registry_effect": effect, "status": status}
    if status == "confirmed-failure":
        value.update(execution="reverted", registry_effect="not-established")
    elif status == "awaiting-confirmations":
        value.update(minimum_confirmations=3)
    parsed = PublicationObservation.model_validate(value)
    assert parsed.current_authorization == "not-evaluated"
    assert parsed.resubmission == "not-authorized"
    assert parsed.status == status


@pytest.mark.parametrize("status", ["not-found", "pending", "noncanonical"])
def test_unestablished_observations_do_not_claim_execution(observation, status):
    value = {
        **observation,
        "status": status,
        "confirmations": 0,
        "execution": "not-established",
        "registry_effect": "not-established",
    }
    if status != "noncanonical":
        value.update(inclusion_number=None, inclusion_hash=None)
    assert PublicationObservation.model_validate(value).execution == "not-established"


@pytest.mark.parametrize(
    "changes,message",
    [
        ({"status": "pending"}, "inclusion fields"),
        ({"inclusion_number": None, "inclusion_hash": None}, "inclusion fields"),
        ({"inclusion_number": None}, "complete inclusion identity"),
        ({"inclusion_hash": None}, "complete inclusion identity"),
        ({"status": "noncanonical"}, "Unestablished inclusion"),
        ({"confirmations": 1}, "Confirmation count"),
        ({"minimum_confirmations": 3}, "Confirmation policy"),
        ({"status": "awaiting-confirmations"}, "Confirmation policy"),
        ({"execution": "not-established"}, "Observed execution"),
        ({"execution": "reverted"}, "Observed execution"),
        ({"status": "confirmed-failure"}, "Observed execution"),
        ({"registry_effect": "not-established"}, "Registry effect"),
        ({"phase": "mirror"}, "Registry effect"),
    ],
)
def test_incoherent_publication_claims_reject(observation, changes, message):
    with pytest.raises(ValueError, match=message):
        PublicationObservation.model_validate({**observation, **changes})


@pytest.mark.parametrize(
    "field,value",
    [
        ("confirmations", True),
        ("minimum_confirmations", 1.0),
        ("minimum_confirmations", 0),
        ("minimum_confirmations", 10001),
        ("current_authorization", "authorized"),
        ("resubmission", "authorized"),
    ],
)
def test_observations_reject_ambiguous_numbers_and_authority_claims(observation, field, value):
    with pytest.raises(ValueError):
        PublicationObservation.model_validate({**observation, field: value})


@pytest.fixture
def history():
    from types import SimpleNamespace
    from unittest.mock import Mock

    from src.storage.publication_history import PublicationHistory

    store = SimpleNamespace(transaction=Mock(side_effect=AssertionError("Database must not be accessed")))
    return PublicationHistory(SimpleNamespace(_require=Mock(), store=store))


@pytest.mark.parametrize(
    "after,limit", [(-1, 1), (2**53, 1), (True, 1), (1.0, 1), (0, 0), (0, 65), (0, True), (0, 1.0)]
)
async def test_invalid_history_page_rejects_before_storage(history, after, limit):
    with pytest.raises(ValueError, match="^Invalid publication history page$"):
        await history.page("ab" * 32, after=after, limit=limit)
    history.journal._require.assert_called_once()
    history.journal.store.transaction.assert_not_called()


@pytest.mark.parametrize("now", [-1, 2**53, True, 1.0])
async def test_invalid_observation_clock_rejects_before_storage(history, observation, now):
    with pytest.raises(ValueError, match="^Publication history scope or clock is invalid$"):
        await history.append(observation["intent_id"], observation, policy_digest="00" * 32, observed_at=now)
    history.journal.store.transaction.assert_not_called()


async def test_history_cannot_attach_observation_to_different_intent(history, observation):
    with pytest.raises(ValueError, match="^Publication history scope or clock is invalid$"):
        await history.append("00" * 32, observation, policy_digest="00" * 32, observed_at=100)
    history.journal.store.transaction.assert_not_called()


@pytest.mark.parametrize("digest", ["", "AB" * 32, "00" * 31, None])
async def test_history_policy_pin_requires_canonical_digest(history, observation, digest):
    with pytest.raises(ValueError):
        await history.append(observation["intent_id"], observation, policy_digest=digest, observed_at=100)
    history.journal.store.transaction.assert_not_called()
