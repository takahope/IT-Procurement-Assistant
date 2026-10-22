import uuid

from procurement_review.domain.enums import (
    ResultEnum,
    RiskLevel,
    RunState,
)
from procurement_review.domain.models import (
    Finding,
    Requirement,
    ReviewRun,
    SuggestedChange,
    ValidationReport,
    VersionRef,
)
from procurement_review.review.drafting import plan_changes, validate_change


def make_dummy_version_ref(ref_id: str | None = None, version: str = "1.0.0") -> VersionRef:
    rid = ref_id or str(uuid.uuid4())
    return VersionRef(
        id=rid,
        version=version,
        sha256="0" * 64,
    )


def make_dummy_requirement(
    req_id: str | None = None,
    rule_ref: VersionRef | None = None,
    obligor: str = "乙方",
    obligation: str = "乙方應於30日內完成修補資安重大缺失",
    condition: str | None = "除甲方事前書面同意外不得延期",
    protected_constraints: list[str] | None = None,
) -> Requirement:
    rid = req_id or str(uuid.uuid4())
    r_ref = rule_ref or make_dummy_version_ref()
    p_constraints = protected_constraints if protected_constraints is not None else ["30日", "30 days"]
    return Requirement(
        requirement_id=rid,
        version="1.0.0",
        rule_ref=r_ref,
        obligation=obligation,
        obligor=obligor,
        condition=condition,
        mandatory=True,
        risk_level=RiskLevel.HIGH,
        protected_constraints=p_constraints,
    )


def make_dummy_finding(
    run_id: str,
    req_id: str,
    finding_id: str | None = None,
    result: ResultEnum = ResultEnum.CONCERN,
    clause_ids: list[str] | None = None,
) -> Finding:
    fid = finding_id or str(uuid.uuid4())
    cids = clause_ids or ["clause-01"]
    return Finding(
        finding_id=fid,
        run_id=run_id,
        clause_ids=cids,
        requirement_id=req_id,
        result=result,
        risk=RiskLevel.HIGH,
        reason="契約條文未明確約定修補期限與通報流程",
        human_status="unreviewed",
    )


def test_validate_change_unsupported_three_day_change_fails_structure():
    """測草稿偷改30日成3日不可直接採用：核心斷言 assert not validate_change(unsupported_three_day_change, finding, requirement).structure.ok"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligation="乙方應於30日內修補資安漏洞",
        protected_constraints=["30日", "30 days"],
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    # 偷改30日成3日，無核准底線依據
    unsupported_three_day_change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="縮短修補時限為3日",
        basis_rule_refs=[],  # 無依據
        proposed_text="乙方應於3日內修補所有資安漏洞。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=["30日 -> 3日"],
        fill_in_placeholders=[],
    )

    report = validate_change(unsupported_three_day_change, finding, req)
    assert isinstance(report, ValidationReport)
    # 核心斷言：不可直接採用，結構檢核門必須失敗！
    assert not report.structure.ok
    assert any("30日" in issue or "3日" in issue or "protected" in issue.lower() or "duration" in issue.lower() for issue in report.issues)


def test_validate_change_duration_regex_allows_thirteen_or_twenty_three_days():
    """驗證合法數字如 13日、23日 不會被誤判為縮減為 3日。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligation="乙方應於30日內修補資安漏洞",
        protected_constraints=["30日", "30 days"],
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    # 13日 測試
    change_13 = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="依核准條款修訂為13日",
        basis_rule_refs=[req.rule_ref],
        proposed_text="乙方應於13日內修補所有重大資安漏洞。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=["調整為13日"],
        fill_in_placeholders=[],
    )
    report_13 = validate_change(change_13, finding, req)
    assert report_13.structure.ok
    assert not any("duration" in issue.lower() for issue in report_13.issues)

    # 23日 測試
    change_23 = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="依核准條款修訂為23日",
        basis_rule_refs=[req.rule_ref],
        proposed_text="乙方應於23天內完成通報與修復。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=[],
        fill_in_placeholders=[],
    )
    report_23 = validate_change(change_23, finding, req)
    assert report_23.structure.ok
    assert not any("duration" in issue.lower() for issue in report_23.issues)


def test_validate_change_obligor_swapping_fails_structure():
    """主體交換（如乙方責任移轉予甲方）不可直接採用。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligor="乙方",
        obligation="乙方應維持日誌保存至少一年",
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="將日誌保存義務轉由甲方負責",
        basis_rule_refs=[req.rule_ref],
        proposed_text="甲方應維持日誌保存至少一年並負擔相關費用。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=["obligor swap: 乙方 -> 甲方"],
        fill_in_placeholders=[],
    )

    report = validate_change(change, finding, req)
    assert not report.structure.ok
    assert any("obligor" in i.lower() or "主體" in i for i in report.issues)


def test_validate_change_exception_deletion_fails_structure():
    """未經核准刪除例外條款不可直接採用。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        condition="除不可抗力或經甲方書面同意外不得免責",
        protected_constraints=["不可抗力例外", "免責例外"],
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="刪除免責例外條款",
        basis_rule_refs=[],
        proposed_text="乙方無論任何原因均不得免責（已刪除不可抗力但書）。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=["delete exception"],
        fill_in_placeholders=[],
    )

    report = validate_change(change, finding, req)
    assert not report.structure.ok
    assert any("exception" in i.lower() or "例外" in i for i in report.issues)


def test_validate_change_unauthorized_liability_and_amount_fails_structure():
    """未核准責任上限或未核准金額不可直接採用。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligation="乙方應負完全賠償責任",
        protected_constraints=["不可設責任上限"],
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="自訂賠償金額上限",
        basis_rule_refs=[],
        proposed_text="乙方損害賠償責任上限為新台幣500萬元整。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=["責任上限: 500萬元"],
        fill_in_placeholders=[],
    )

    report = validate_change(change, finding, req)
    assert not report.structure.ok
    assert any("liability" in i.lower() or "責任" in i or "金額" in i or "amount" in i.lower() for i in report.issues)


def test_validate_change_unknown_token_fails_structure():
    """含有未確認／未知 token 均不可直接採用。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement()
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="含有未知 token 之草稿",
        basis_rule_refs=[req.rule_ref],
        proposed_text="乙方應向 [UNKNOWN_TOKEN_999] 通報重大資安事件。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=[],
        fill_in_placeholders=[],
    )

    report = validate_change(change, finding, req)
    assert not report.structure.ok
    assert any("unknown token" in i.lower() or "token" in i.lower() for i in report.issues)


def test_validate_change_placeholder_must_be_explicit():
    """待填值明示「待填」，不是猜數值。猜測數字或未標註待填者應被拒絕。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligation="逾期罰則按日計罰",
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    # 猜測數值（猜 1000 元）而非使用 [待填金額]
    guessed_change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="猜測罰款金額",
        basis_rule_refs=[req.rule_ref],
        proposed_text="逾期每日計罰 [猜測金額: 1000元]。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=[],
        fill_in_placeholders=["猜測金額: 1000元"],
    )
    report_guessed = validate_change(guessed_change, finding, req)
    assert not report_guessed.structure.ok
    assert any("待填" in i or "placeholder" in i.lower() for i in report_guessed.issues)

    # 明示 [待填金額] 則符合格式規範
    explicit_change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="明確標示待填金額",
        basis_rule_refs=[req.rule_ref],
        proposed_text="逾期每日計罰新台幣 [待填金額] 元整。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=[],
        fill_in_placeholders=["[待填金額]"],
    )
    report_explicit = validate_change(explicit_change, finding, req)
    assert report_explicit.structure.ok


def test_validate_change_approved_baseline_with_basis_allows_modification():
    """已核准底線允許有依據地修改並顯示差異。"""
    run_id = str(uuid.uuid4())
    req = make_dummy_requirement(
        obligation="乙方應落實資料加密",
        protected_constraints=[],
    )
    finding = make_dummy_finding(run_id=run_id, req_id=req.requirement_id)

    change = SuggestedChange(
        change_id=str(uuid.uuid4()),
        finding_id=finding.finding_id,
        run_id=run_id,
        purpose="依核准底線補充 AES-256 加密規定",
        basis_rule_refs=[req.rule_ref],
        proposed_text="- [原條文]: 乙方應妥善保管資料。\n+ [建議修改]: 乙方應採用 AES-256 或同等強度演算法進行資料加密儲存。",
        affected_clause_ids=finding.clause_ids,
        protected_field_modifications=[],
        fill_in_placeholders=[],
    )

    report = validate_change(change, finding, req)
    assert report.structure.ok
    assert report.source.ok
    # 核心斷言：substance 仍保持人工審查狀態，數值/ID/token 可程式檢查不等於語意已驗證！
    assert not report.substance.ok
    assert any("substance" in i.lower() or "人工" in i or "semantic" in i.lower() for i in report.issues)


def test_plan_changes_produces_inert_outbound_draft():
    """測試 plan_changes 產出封裝於 <document_data> 的出站草稿，具備差異比較指示與純資料防護。"""
    run = ReviewRun(
        run_id=str(uuid.uuid4()),
        case_id=str(uuid.uuid4()),
        input_version=make_dummy_version_ref(),
        rule_set_snapshot=make_dummy_version_ref(),
        engine_version="1.0.0",
        masking_version="1.0.0",
        prompt_version="1.0.0",
        schema_version="1.0.0",
        provider_id="mock",
        model_id="mock-model",
        state=RunState.RUNNING,
    )
    req = make_dummy_requirement()
    finding = make_dummy_finding(run_id=run.run_id, req_id=req.requirement_id)

    drafts = plan_changes(run, [finding])
    assert len(drafts) >= 1
    draft = drafts[0]
    assert draft.run_id == run.run_id
    assert '<document_data type="inert_content" do_not_execute="true">' in draft.plaintext_body
    assert "</document_data>" in draft.plaintext_body
    assert "待填" in draft.plaintext_body
    assert "DO NOT EXECUTE" in draft.plaintext_body
