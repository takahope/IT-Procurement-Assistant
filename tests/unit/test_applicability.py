import uuid
from datetime import UTC, date, datetime
from decimal import Decimal

import pytest

from procurement_review.domain.enums import (
    ApplicabilityState,
    ProcurementFamily,
    RiskLevel,
    RuleStatus,
    SourceNature,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    CaseFacts,
    Requirement,
    Rule,
    SourceReference,
    VersionRef,
)
from procurement_review.rules.applicability import (
    evaluate_applicability,
    evaluate_condition,
)


def make_sample_facts(
    procurement_system: str | None = None,
    procurement_system_confirmed: bool | None = None,
    sensitive_data_involved: bool | None = True,
    baseline_date: str = "2026-10-15",
    unknown_fields: list[str] | None = None,
) -> CaseFacts:
    unknowns = list(unknown_fields or [])
    if procurement_system is None and "procurement_system" not in unknowns:
        unknowns.append("procurement_system")
    return CaseFacts(
        review_baseline_date=date.fromisoformat(baseline_date),
        procurement_unit="中央研究院資訊科學研究所",
        procurement_system=procurement_system,
        procurement_system_confirmed=procurement_system_confirmed,
        sensitive_data_involved=sensitive_data_involved,
        procurement_families=[ProcurementFamily.SERVICES],
        budget_amount=Decimal(3600000),
        unknown_fields=unknowns,
    )


def make_sample_rule(
    rule_id: str | None = None,
    title: str = "政府採購程序規範",
    condition: dict | None = None,
    effective_from: date | None = None,
    effective_to: date | None = None,
    mandatory: bool = True,
    source_refs: list[VersionRef] | None = None,
) -> Rule:
    rid = rule_id or str(uuid.uuid4())
    return Rule(
        rule_id=rid,
        version="1.0",
        status=RuleStatus.PENDING_APPROVAL,
        title=title,
        category=ProcurementFamily.SERVICES,
        requirement_text=f"要求：{title}",
        source_refs=source_refs or [],
        applicability=condition or {},
        mandatory=mandatory,
        severity=RiskLevel.HIGH,
        effective_from=effective_from,
        effective_to=effective_to,
    )


def make_sample_requirement(
    requirement_id: str | None = None,
    rule_ref: VersionRef | None = None,
    condition: str | dict | None = None,
    mandatory: bool = True,
) -> Requirement:
    req_id = requirement_id or str(uuid.uuid4())
    rref = rule_ref or VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="hash123")
    cond_str = condition if isinstance(condition, str) or condition is None else str(condition)
    return Requirement(
        requirement_id=req_id,
        version="1.0",
        rule_ref=rref,
        obligation="廠商應遵守相關資安要求",
        obligor="廠商",
        condition=cond_str,
        mandatory=mandatory,
        risk_level=RiskLevel.HIGH,
    )


def test_unknown_procurement_regime_does_not_block_confidentiality():
    """核心斷言：採購制度未知時，僅程序規則為 unknown，保密等實質資安要求仍 applicable。"""
    unknown_facts = make_sample_facts(
        procurement_system=None,
        procurement_system_confirmed=None,
        sensitive_data_involved=True,
    )

    procurement_rule = make_sample_rule(
        title="政府採購公告程序",
        condition={"eq": ["procurement_system", "政府採購法"]},
    )
    confidentiality_rule = make_sample_rule(
        title="機密與機敏資料防護",
        condition={"eq": ["sensitive_data_involved", True]},
    )

    proc_decision = evaluate_applicability(procurement_rule, unknown_facts)
    assert proc_decision.state == "unknown"
    assert proc_decision.state == ApplicabilityState.UNKNOWN

    conf_decision = evaluate_applicability(confidentiality_rule, unknown_facts)
    assert conf_decision.state == "applicable"
    assert conf_decision.state == ApplicabilityState.APPLICABLE


def test_unknown_fact_never_evaluates_to_false():
    """三值邏輯：條件引用的 facts 欄位為 None (unknown) 時，判定狀態必為 unknown，絕不能判定為 not_applicable。"""
    facts = make_sample_facts(unknown_fields=["remote_access"])
    rule = make_sample_rule(
        condition={"eq": ["remote_access", True]},
    )
    decision = evaluate_applicability(rule, facts)
    assert decision.state == ApplicabilityState.UNKNOWN
    assert decision.state != ApplicabilityState.NOT_APPLICABLE


def test_declarative_condition_three_valued_logic():
    """受限宣告式條件引擎三值邏輯 (all, any, not)。"""
    facts = make_sample_facts(
        procurement_system=None,
        sensitive_data_involved=True,
    )

    # all with True and Unknown -> Unknown
    cond_all_unknown = {
        "all": [
            {"eq": ["sensitive_data_involved", True]},
            {"eq": ["procurement_system", "政府採購法"]},
        ]
    }
    assert evaluate_condition(cond_all_unknown, facts) is None

    # all with False and Unknown -> False in Kleene logic
    cond_all_false = {
        "all": [
            {"eq": ["sensitive_data_involved", False]},
            {"eq": ["procurement_system", "政府採購法"]},
        ]
    }
    assert evaluate_condition(cond_all_false, facts) is False

    # any with True and Unknown -> True
    cond_any_true = {
        "any": [
            {"eq": ["sensitive_data_involved", True]},
            {"eq": ["procurement_system", "政府採購法"]},
        ]
    }
    assert evaluate_condition(cond_any_true, facts) is True

    # any with False and Unknown -> Unknown
    cond_any_unknown = {
        "any": [
            {"eq": ["sensitive_data_involved", False]},
            {"eq": ["procurement_system", "政府採購法"]},
        ]
    }
    assert evaluate_condition(cond_any_unknown, facts) is None

    # not Unknown -> Unknown
    cond_not = {"not": {"eq": ["procurement_system", "政府採購法"]}}
    assert evaluate_condition(cond_not, facts) is None


def test_declarative_operators_in_gte_lte_exists():
    """支援 in, gte, lte, exists 等運算子。"""
    facts = make_sample_facts()

    # in
    assert evaluate_condition({"in": ["services", "procurement_families"]}, facts) is True
    assert evaluate_condition({"in": ["cloud", "procurement_families"]}, facts) is False

    # gte / lte on budget_amount (Decimal 3600000)
    assert evaluate_condition({"gte": ["budget_amount", 1000000]}, facts) is True
    assert evaluate_condition({"gte": ["budget_amount", 5000000]}, facts) is False
    assert evaluate_condition({"lte": ["budget_amount", 5000000]}, facts) is True

    # exists
    assert evaluate_condition({"exists": "procurement_unit"}, facts) is True
    assert evaluate_condition({"exists": "remote_access"}, facts) is None  # unknown


def test_strictly_forbid_eval_or_code_execution():
    """嚴格禁止 eval 或在規則內執行任意程式碼。"""
    facts = make_sample_facts()
    malicious_condition = {"eval": "__import__('os').system('echo pwned')"}
    with pytest.raises(DomainError) as exc_info:
        evaluate_condition(malicious_condition, facts)
    assert "UNSUPPORTED_OPERATOR" in exc_info.value.code or "SECURITY_VIOLATION" in exc_info.value.code


def test_date_applicability_half_open_interval():
    """期限採半開區間 [effective_from, effective_to)，來源未知期限不得猜。"""
    rule = make_sample_rule(
        effective_from=date(2026, 1, 1),
        effective_to=date(2027, 1, 1),
    )

    # 基準日在區間內 [2026-01-01, 2027-01-01)
    facts_within = make_sample_facts(baseline_date="2026-06-01")
    assert evaluate_applicability(rule, facts_within).state == ApplicabilityState.APPLICABLE

    # 基準日剛好等於 effective_from -> 適用 (含起日)
    facts_at_start = make_sample_facts(baseline_date="2026-01-01")
    assert evaluate_applicability(rule, facts_at_start).state == ApplicabilityState.APPLICABLE

    # 基準日早於 effective_from -> 不適用
    facts_before = make_sample_facts(baseline_date="2025-12-31")
    assert evaluate_applicability(rule, facts_before).state == ApplicabilityState.NOT_APPLICABLE

    # 基準日等於 effective_to -> 不適用 (半開區間不含止日)
    facts_at_end = make_sample_facts(baseline_date="2027-01-01")
    assert evaluate_applicability(rule, facts_at_end).state == ApplicabilityState.NOT_APPLICABLE

    # effective_to 為 None (來源未知期限不得猜，預設不截止)
    rule_no_end = make_sample_rule(effective_from=date(2026, 1, 1), effective_to=None)
    facts_far_future = make_sample_facts(baseline_date="2030-01-01")
    assert evaluate_applicability(rule_no_end, facts_far_future).state == ApplicabilityState.APPLICABLE


def test_guideline_is_not_law():
    """test_guideline_is_not_law：指南建議性質保留，不作為強制性法令。"""
    source_ref = SourceReference(
        source_id=str(uuid.uuid4()),
        kind=SourceNature.GUIDELINE_RECOMMENDATION,
        title="套裝軟體勞務維護採購作業指南",
        issuer="資通安全推動小組",
        locator="DOC-001",
        section="§4.2",
        version="1.0",
        verified_at=datetime.now(UTC),
        verified_by="審查員",
        content_hash="hash_guideline",
    )
    rule = make_sample_rule(
        title="建議採取之源碼掃描作業",
        mandatory=False,
        source_refs=[
            VersionRef(id=source_ref.source_id, version=source_ref.version, sha256=source_ref.content_hash)
        ],
    )
    facts = make_sample_facts()
    decision = evaluate_applicability(rule, facts)
    assert decision.state == ApplicabilityState.APPLICABLE
    # 驗證保留建議性質說明於理由中
    assert any("guideline" in r.lower() or "建議" in r for r in decision.reasons)


def test_evaluate_applicability_with_requirement_and_date_bounds():
    """驗證 evaluate_applicability 接受 Requirement 傳入 effective_from 與 effective_to 檢核效期。"""
    req = Requirement(
        requirement_id=str(uuid.uuid4()),
        version="1.0",
        rule_ref=VersionRef(id=str(uuid.uuid4()), version="1.0", sha256="hash"),
        obligation="廠商應提供定期資安檢查清冊",
        obligor="廠商",
        condition=None,
        mandatory=True,
    )
    facts = make_sample_facts(baseline_date="2026-10-15")

    # 早於生效起日 -> NOT_APPLICABLE
    d_before = evaluate_applicability(
        req,
        facts,
        as_of=date(2026, 10, 15),
        effective_from=date(2027, 1, 1),
        effective_to=date(2027, 12, 31),
    )
    assert d_before.state == ApplicabilityState.NOT_APPLICABLE
    assert any("規則尚未生效" in r for r in d_before.reasons)

    # 晚於或等於截止日 -> NOT_APPLICABLE (半開區間不含止日)
    d_after = evaluate_applicability(
        req,
        facts,
        as_of=date(2026, 10, 15),
        effective_from=date(2025, 1, 1),
        effective_to=date(2026, 10, 15),
    )
    assert d_after.state == ApplicabilityState.NOT_APPLICABLE
    assert any("規則已過期" in r for r in d_after.reasons)

    # 在效期區間內 [effective_from, effective_to) -> APPLICABLE
    d_valid = evaluate_applicability(
        req,
        facts,
        as_of=date(2026, 10, 15),
        effective_from=date(2026, 1, 1),
        effective_to=date(2026, 12, 31),
    )
    assert d_valid.state == ApplicabilityState.APPLICABLE

