import json
from decimal import Decimal
from pathlib import Path

import pytest
from pydantic import ValidationError

from procurement_review.domain.enums import (
    ApplicabilityState,
    HumanDecisionAction,
    ProcurementFamily,
    RedactionMode,
    ResultEnum,
    ReviewState,
    RiskLevel,
    RuleStatus,
    RunState,
    RuntimeMode,
    SourceNature,
    ValidationStatus,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    ALL_DOMAIN_MODELS,
    CaseFacts,
    Finding,
    Review,
    VersionRef,
    export_domain_schemas,
    validate_case,
)


def test_unknown_is_not_false():
    """Verify CaseFacts.remote_access is None is preserved and not coerced to False."""
    facts = CaseFacts(
        review_baseline_date="2026-10-15",
        remote_access=None,
        unknown_fields=["remote_access"],
    )
    assert facts.remote_access is None
    assert "remote_access" in facts.unknown_fields

    case_with_unknown_remote_access = {
        "case_id": "11111111-1111-4111-8111-111111111111",
        "title": "測試案件-遠端存取未明",
        "contract_type": "services",
        "contract_version": "1.0",
        "original_file_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "facts": {
            "review_baseline_date": "2026-10-15",
            "remote_access": None,
            "unknown_fields": ["remote_access"],
        },
        "created_by": "test-user",
        "created_at": "2026-10-15T08:00:00Z",
    }
    validated = validate_case(case_with_unknown_remote_access)
    assert validated.facts.remote_access is None
    assert validated.facts.remote_access is not False


def test_missing_finding_requires_scope():
    """Verify that a finding with result='missing' without clause_ids requires review_scope."""
    finding_without_scope = {
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "run_id": "33333333-3333-4333-8333-333333333333",
        "clause_ids": [],
        "requirement_id": "44444444-4444-4444-8444-444444444444",
        "result": "missing",
        "risk": "high",
        "evidence": [],
        "rule_refs": [],
        "case_refs": [],
        "reason": "契約中完全未提及遠端存取防護義務",
        "unknowns": [],
        "review_scope": None,
    }
    with pytest.raises(ValidationError) as excinfo:
        Finding.model_validate(finding_without_scope)
    assert "review_scope" in str(excinfo.value)

    finding_with_scope = dict(finding_without_scope)
    finding_with_scope["review_scope"] = "全份主約及資安附件"
    valid_finding = Finding.model_validate(finding_with_scope)
    assert valid_finding.result == ResultEnum.MISSING
    assert valid_finding.review_scope == "全份主約及資安附件"


def test_reject_unknown_result():
    """Verify that result='safe' is rejected by validation."""
    finding_with_result_safe = {
        "finding_id": "22222222-2222-4222-8222-222222222222",
        "run_id": "33333333-3333-4333-8333-333333333333",
        "clause_ids": ["clause-1"],
        "requirement_id": "44444444-4444-4444-8444-444444444444",
        "result": "safe",
        "risk": "info",
        "evidence": [],
        "rule_refs": [],
        "case_refs": [],
        "reason": "條款安全",
        "unknowns": [],
    }
    with pytest.raises(ValidationError):
        Finding.model_validate(finding_with_result_safe)


def test_extra_fields_forbidden():
    """Verify extra='forbid' on models."""
    with pytest.raises(ValidationError):
        VersionRef.model_validate(
            {
                "id": "11111111-1111-4111-8111-111111111111",
                "version": "1.0",
                "sha256": "abc",
                "unexpected_field": "disallowed",
            }
        )


def test_money_decimal_and_int_only():
    """Ensure monetary fields reject binary float to avoid precision issues."""
    with pytest.raises(ValidationError):
        CaseFacts.model_validate(
            {
                "review_baseline_date": "2026-10-15",
                "budget_amount": 100000.50,  # float disallowed
            }
        )

    facts_decimal = CaseFacts(
        review_baseline_date="2026-10-15",
        budget_amount=Decimal("100000.50"),
    )
    assert facts_decimal.budget_amount == Decimal("100000.50")

    facts_int = CaseFacts(
        review_baseline_date="2026-10-15",
        budget_amount=Decimal(100000),
    )
    assert facts_int.budget_amount == Decimal(100000)


def test_uuid_validation():
    """Ensure IDs require valid UUID formatting."""
    with pytest.raises(ValidationError):
        VersionRef.model_validate(
            {
                "id": "not-a-uuid",
                "version": "1.0",
                "sha256": "a" * 64,
            }
        )


def test_domain_error():
    """Ensure DomainError retains code and safe_message."""
    err = DomainError(code="INVALID_STATE", safe_message="案件狀態不符合轉移條件")
    assert err.code == "INVALID_STATE"
    assert err.safe_message == "案件狀態不符合轉移條件"
    assert "案件狀態不符合轉移條件" in str(err)
    assert "DomainError" in repr(err)


def test_exported_schema_matches_models():
    """Ensure exported schema file exists and matches fresh schema dump."""
    schema_file = Path(__file__).resolve().parents[2] / "schemas" / "domain.json"
    assert schema_file.exists(), "schemas/domain.json does not exist"
    with open(schema_file, encoding="utf-8") as f:
        saved_schema = json.load(f)
    fresh_schema = export_domain_schemas()
    assert saved_schema == fresh_schema


def test_all_domain_models_registered():
    """Ensure all core types are defined and listed in ALL_DOMAIN_MODELS."""
    assert len(ALL_DOMAIN_MODELS) == 33
    expected_names = {
        "VersionRef",
        "CaseFacts",
        "RuntimePolicy",
        "SourceReference",
        "Rule",
        "Requirement",
        "ApplicabilityDecision",
        "SourceSpan",
        "DocumentSnapshot",
        "Review",
        "ReviewRun",
        "ContextBundle",
        "CoverageEntry",
        "CoverageMatrix",
        "DetectedSpan",
        "MaskingSession",
        "RestorationResult",
        "OutboundDraft",
        "PreparedRequest",
        "EgressApproval",
        "ProviderReply",
        "Finding",
        "ValidationReport",
        "SuggestedChange",
        "HumanDecision",
        "Feedback",
        "ReviewReport",
        "ExportPaths",
        "GateReport",
        "EvaluationReport",
        "PurgePlan",
        "ProviderConfig",
        "AuditEvent",
    }
    actual_names = {m.__name__ for m in ALL_DOMAIN_MODELS}
    assert actual_names == expected_names


def test_enums_and_chinese_labels():
    """Verify all enums have required values and Chinese labels."""
    for result in ResultEnum:
        assert isinstance(result.label_zh, str) and len(result.label_zh) > 0
    for risk in RiskLevel:
        assert isinstance(risk.label_zh, str) and len(risk.label_zh) > 0
    for fam in ProcurementFamily:
        assert isinstance(fam.label_zh, str) and len(fam.label_zh) > 0
    for nature in SourceNature:
        assert isinstance(nature.label_zh, str) and len(nature.label_zh) > 0

    assert ApplicabilityState.APPLICABLE.value == "applicable"
    assert HumanDecisionAction.ADOPT.value == "adopt"
    assert RedactionMode.MASKED.value == "masked"
    assert ReviewState.IMPORTED.value == "imported"
    assert RunState.PLANNED.value == "planned"
    assert RuleStatus.ACTIVE.value == "active"
    assert RuntimeMode.SYNTHETIC.value == "synthetic"
    assert ValidationStatus.PASSED.value == "passed"


def test_synthetic_cases_all_valid(synthetic_cases: dict):
    """Ensure all synthetic cases validate cleanly against Review model."""
    assert "cases" in synthetic_cases
    cases = synthetic_cases["cases"]
    assert len(cases) == 5, f"Expected 5 cases, found {len(cases)}"

    families_represented = set()
    for case_data in cases:
        review = validate_case(case_data)
        assert isinstance(review, Review)
        assert review.facts.review_baseline_date is not None
        families_represented.add(review.contract_type)

    assert ProcurementFamily.SERVICES in families_represented
    assert ProcurementFamily.CLOUD in families_represented
    assert ProcurementFamily.COTS in families_represented
    assert ProcurementFamily.DEVELOPMENT in families_represented
