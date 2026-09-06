"""Read-only summaries of explicitly selected observation cohorts."""

from typing import Literal

from pydantic import Field, model_validator

from src.auth.principal import Principal
from src.policy.evaluator import Outcome
from src.protocol.canonical import record_digest
from src.protocol.transfer import Hex32, OpaqueId, Record
from src.services.proof_observation import ObservationRecord, decode_observation
from src.storage.database import Database
from src.storage.pilot import PilotStore
from src.storage.pilot_cipher import RecordCipher


class ObservationCase(Record):
    case_id: OpaqueId
    observation_id: Hex32 | None
    baseline_outcome: Outcome | None = None


class ObservationCohort(Record):
    cohort_id: OpaqueId
    cases: tuple[ObservationCase, ...] = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def unique_cases(self):
        if len({case.case_id for case in self.cases}) != len(self.cases):
            raise ValueError("Duplicate cohort case")
        references = [case.observation_id for case in self.cases if case.observation_id is not None]
        if len(references) != len(set(references)):
            raise ValueError("Duplicate observation would bias cohort counts")
        return self

    @property
    def digest(self) -> str:
        return record_digest(
            "clearproof/observation-cohort/v1",
            {
                "cohort_id": self.cohort_id,
                "cases": [case.model_dump(mode="json") for case in sorted(self.cases, key=lambda item: item.case_id)],
            },
        )


class CohortCaseResult(Record):
    case_id: OpaqueId
    status: Literal["observed", "not-observed", "unavailable"]
    outcome: Outcome | None
    cryptographic_valid: bool | None
    baseline_outcome: Outcome | None
    agrees_with_baseline: bool | None


def summarize_observations(cohort: ObservationCohort, records: dict[str, ObservationRecord]) -> dict:
    """Records must already be authenticated by the tenant storage boundary.

    Baseline labels are caller assertions, not independently authenticated truth.
    Missing and failed-pairing observations never become a policy outcome.
    """
    cohort = ObservationCohort.model_validate(cohort)
    cases, transfers = [], set()
    counts = {outcome: 0 for outcome in ("ALLOW", "DENY", "REVIEW", "INDETERMINATE")}
    observed = failed = comparable = agreements = labelled = 0
    for case in sorted(cohort.cases, key=lambda item: item.case_id):
        record = records.get(case.observation_id) if case.observation_id is not None else None
        if record is not None:
            record = ObservationRecord.model_validate(record)
            if record.digest != case.observation_id:
                raise ValueError("Observation reference mismatch")
            observed += 1
            transfers.add(record.transfer_digest)
            failed += not record.cryptographic_valid
        outcome = record.policy.outcome if record is not None and record.policy is not None else None
        if outcome is not None:
            counts[outcome] += 1
        labelled += case.baseline_outcome is not None
        agrees = outcome == case.baseline_outcome if outcome is not None and case.baseline_outcome is not None else None
        comparable += agrees is not None
        agreements += agrees is True
        cases.append(
            CohortCaseResult(
                case_id=case.case_id,
                status="observed"
                if record is not None
                else ("not-observed" if case.observation_id is None else "unavailable"),
                outcome=outcome,
                cryptographic_valid=record.cryptographic_valid if record is not None else None,
                baseline_outcome=case.baseline_outcome,
                agrees_with_baseline=agrees,
            ).model_dump(mode="json")
        )
    return {
        "schema_version": "clearproof-observation-cohort-report-v1",
        "mode": "observation",
        "scope": "selected-observation-cases",
        "assurance": "development-unapproved",
        "baseline_authority": "caller-supplied-unverified",
        "cohort_id": cohort.cohort_id,
        "cohort_digest": cohort.digest,
        "case_count": len(cases),
        "observed_count": observed,
        "missing_count": len(cases) - observed,
        "distinct_observed_transfers": len(transfers),
        "failed_pairing_count": failed,
        "policy_count": sum(counts.values()),
        "determinate_count": sum(counts.values()) - counts["INDETERMINATE"],
        "outcome_counts": counts,
        "baseline_label_count": labelled,
        "comparable_count": comparable,
        "agreement_count": agreements,
        "disagreement_count": comparable - agreements,
        "latency_status": "not-recorded",
        "cases": cases,
    }


async def observation_cohort_report(
    db: Database,
    cipher: RecordCipher,
    principal: Principal,
    cohort: ObservationCohort,
) -> dict:
    principal = Principal.model_validate(principal)
    for role in ("policy:read", "evidence:decrypt"):
        principal.require(role)
    cohort = ObservationCohort.model_validate(cohort)
    records = {}
    async with PilotStore(db, cipher, principal).transaction() as tx:
        for case in cohort.cases:
            if case.observation_id is None:
                continue
            value = await tx.get("observation", case.observation_id)
            if value is not None:
                records[case.observation_id] = decode_observation(
                    value, tenant_id=principal.tenant_id, observation_id=case.observation_id
                )
    return summarize_observations(cohort, records)
