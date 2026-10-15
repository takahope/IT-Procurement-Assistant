import uuid
from datetime import UTC, date, datetime
from decimal import Decimal
from pathlib import Path

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
    Rule,
    SourceReference,
    VersionRef,
)
from procurement_review.rules.releases import (
    release_rules,
    revoke_rule,
    select_requirements,
)
from procurement_review.storage.repository import Repository
from procurement_review.storage.secrets import FakeSecretStore
from procurement_review.storage.vault import ArtifactStore


@pytest.fixture
def artifact_store(tmp_path: Path) -> ArtifactStore:
    secrets = FakeSecretStore()
    vault_root = tmp_path / "vault"
    return ArtifactStore(root=vault_root, secrets=secrets)


@pytest.fixture
def repo(tmp_path: Path, artifact_store: ArtifactStore) -> Repository:
    db_path = tmp_path / "app.db"
    return Repository(db=db_path, artifacts=artifact_store)


def make_verified_source(
    source_id: str | None = None,
    title: str = "資通安全管理法",
    kind: SourceNature = SourceNature.APPLICABLE_LAW,
) -> SourceReference:
    sid = source_id or str(uuid.uuid4())
    return SourceReference(
        source_id=sid,
        kind=kind,
        title=title,
        issuer="立法院",
        locator="LAW-001",
        section="§12",
        version="1.0",
        verified_at=datetime.now(UTC),
        verified_by="資安查核員A",
        content_hash="hash_law_verified_1234",
    )


def make_test_rule(
    rule_id: str | None = None,
    status: RuleStatus = RuleStatus.PENDING_APPROVAL,
    source_ref: SourceReference | None = None,
    category: ProcurementFamily = ProcurementFamily.SERVICES,
    title: str = "資通安全防護基準遵守",
    condition: dict | None = None,
    effective_from: date | None = None,
    effective_to: date | None = None,
    conflicts_with: list[str] | None = None,
    supersedes: list[str] | None = None,
) -> Rule:
    rid = rule_id or str(uuid.uuid4())
    sources = []
    if source_ref:
        sources.append(
            VersionRef(
                id=source_ref.source_id,
                version=source_ref.version,
                sha256=source_ref.content_hash,
            )
        )
    return Rule(
        rule_id=rid,
        version="1.0",
        status=status,
        title=title,
        category=category,
        requirement_text="廠商應遵循資安防護基準之控制措施",
        source_refs=sources,
        applicability=condition or {},
        mandatory=True,
        severity=RiskLevel.HIGH,
        effective_from=effective_from,
        effective_to=effective_to,
        conflicts_with=conflicts_with or [],
        supersedes=supersedes or [],
    )


def make_sample_case_facts(baseline_date: str = "2026-10-15") -> CaseFacts:
    return CaseFacts(
        review_baseline_date=date.fromisoformat(baseline_date),
        procurement_unit="中央研究院資訊科學研究所",
        procurement_system="政府採購法",
        procurement_system_confirmed=True,
        procurement_families=[ProcurementFamily.SERVICES, ProcurementFamily.CLOUD],
        sensitive_data_involved=True,
        budget_amount=Decimal(3600000),
        unknown_fields=[],
    )


def test_release_rejects_draft_status(repo: Repository):
    """草稿不得直接發布：僅接受 pending_approval 狀態。"""
    source = make_verified_source()
    draft_rule = make_test_rule(status=RuleStatus.DRAFT, source_ref=source)

    with pytest.raises(DomainError) as exc_info:
        release_rules(
            rules=[draft_rule],
            sources=[source],
            approver="資安長",
            at=datetime.now(UTC),
            repo=repo,
        )
    assert exc_info.value.code == "INVALID_RULE_STATUS"


def test_release_rejects_unverified_source(repo: Repository):
    """來源未查核不得 release：source.verified_at 或 verified_by 為空時拒絕發布。"""
    unverified_source = SourceReference(
        source_id=str(uuid.uuid4()),
        kind=SourceNature.APPLICABLE_LAW,
        title="未經查核之外部指引",
        issuer="外部單位",
        locator="DOC-999",
        section="§1",
        version="1.0",
        verified_at=None,
        verified_by=None,
        content_hash="unverified_hash",
    )
    rule = make_test_rule(
        status=RuleStatus.PENDING_APPROVAL,
        source_ref=unverified_source,
    )

    with pytest.raises(DomainError) as exc_info:
        release_rules(
            rules=[rule],
            sources=[unverified_source],
            approver="資安長",
            at=datetime.now(UTC),
            repo=repo,
        )
    assert exc_info.value.code == "UNVERIFIED_SOURCE"


def test_release_rejects_unauthorized_approver(repo: Repository):
    """不允許空白或未經授權之核准者。"""
    source = make_verified_source()
    rule = make_test_rule(status=RuleStatus.PENDING_APPROVAL, source_ref=source)

    with pytest.raises(DomainError) as exc_info:
        release_rules(
            rules=[rule],
            sources=[source],
            approver="   ",  # 空白
            at=datetime.now(UTC),
            repo=repo,
        )
    assert exc_info.value.code == "UNAUTHORIZED_APPROVER"


def test_successful_rule_release_and_storage(repo: Repository):
    """成功發布：將 pending_approval 規則標為 active、保存來源與要求，並回傳 VersionRef 清單。"""
    source = make_verified_source()
    rule = make_test_rule(status=RuleStatus.PENDING_APPROVAL, source_ref=source)
    approver = "院資安長"
    now = datetime.now(UTC)

    refs = release_rules(
        rules=[rule],
        sources=[source],
        approver=approver,
        at=now,
        repo=repo,
    )

    assert len(refs) == 1
    assert refs[0].id == rule.rule_id
    assert refs[0].version == rule.version

    # 驗證已儲存於 repo 且狀態為 active
    stored_rule = repo.get_rule(rule.rule_id, rule.version)
    assert stored_rule.status == RuleStatus.ACTIVE
    assert stored_rule.approved_by == approver
    assert stored_rule.approved_at is not None


def test_select_requirements_deduplication_across_packs(repo: Repository):
    """同規則跨包去重：核心斷言 assert len({d.requirement_ref.id for d in decisions}) == len(decisions)。"""
    source = make_verified_source()
    # 建立一條共通規則（例如機密維護），同時被 services 包與 cloud 包引用
    shared_rule = make_test_rule(
        status=RuleStatus.PENDING_APPROVAL,
        source_ref=source,
        title="通用保密性要求",
    )
    other_rule = make_test_rule(
        status=RuleStatus.PENDING_APPROVAL,
        source_ref=source,
        title="雲端特有稽核要求",
    )

    refs = release_rules(
        rules=[shared_rule, other_rule],
        sources=[source],
        approver="資安長",
        at=datetime.now(UTC),
        repo=repo,
    )

    # 模擬兩包皆傳入 shared_rule 的 ref (重複傳入)
    pack_refs = [refs[0], refs[1], refs[0]]

    facts = make_sample_case_facts()
    decisions = select_requirements(
        refs=pack_refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    # 核心斷言：去重保證每個 requirement 僅出現一次
    assert len({d.requirement_ref.id for d in decisions}) == len(decisions)
    assert len(decisions) == 2


def test_revoke_rule_invalidates_active_runs(repo: Repository):
    """撤銷規則必使 T3 的相關 run 失效。"""
    source = make_verified_source()
    rule = make_test_rule(status=RuleStatus.PENDING_APPROVAL, source_ref=source)
    refs = release_rules(
        rules=[rule],
        sources=[source],
        approver="資安長",
        at=datetime.now(UTC),
        repo=repo,
    )
    rule_ref = refs[0]

    # 建立審查案件並啟動依賴該規則的 run
    review_case = {
        "case_id": str(uuid.uuid4()),
        "title": "測試案件-受撤銷影響",
        "contract_type": "services",
        "contract_version": "1.0",
        "original_file_hash": "hash_sample_contract_123",
        "facts": {
            "review_baseline_date": "2026-10-15",
            "unknown_fields": [],
        },
        "created_by": "tester",
        "created_at": datetime.now(UTC).isoformat(),
    }
    from procurement_review.domain.models import Review
    rev = repo.save_review(Review.model_validate(review_case), expected_revision=None)

    run = repo.create_run(review_id=rev.case_id, rule_refs=[rule_ref])
    assert repo.get_run(run.id).stale is False

    # 撤銷此規則
    invalidated_run_ids = revoke_rule(
        ref=rule_ref,
        reason="法令最新修正，舊條款廢止",
        repo=repo,
    )

    # 核心斷言：該 run 必須被失效 (stale=True)，且回傳清單包含此 run.id
    assert run.id in invalidated_run_ids
    assert repo.get_run(run.id).stale is True

    # 儲存庫中規則狀態應更新為 REVOKED
    revoked_rule = repo.get_rule(rule_ref.id, rule_ref.version)
    assert revoked_rule.status == RuleStatus.REVOKED


def test_source_update_pending_reverification_blocks_only_related_requirements(repo: Repository):
    """回歸案例：法規來源更新待查時，僅阻擋引用該來源之相關要求，不阻擋其他已查核要求。"""
    source_a = make_verified_source(title="資通安全管理法原版")
    source_b = make_verified_source(title="個人資料保護法")

    rule_a = make_test_rule(
        status=RuleStatus.PENDING_APPROVAL,
        source_ref=source_a,
        title="資安法規範要求",
    )
    rule_b = make_test_rule(
        status=RuleStatus.PENDING_APPROVAL,
        source_ref=source_b,
        title="個資法保密要求",
    )

    refs = release_rules(
        rules=[rule_a, rule_b],
        sources=[source_a, source_b],
        approver="資安長",
        at=datetime.now(UTC),
        repo=repo,
    )

    # 模擬 source_a 有新版修正但處於「待查核 (未核准)」狀態
    unverified_source_a = source_a.model_copy(
        update={
            "verified_at": None,
            "verified_by": None,
            "version": "2.0-draft",
        }
    )
    repo.save_source(unverified_source_a)

    facts = make_sample_case_facts()
    decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    dec_map = {d.requirement_ref.id: d for d in decisions}
    # 引用 source_a 的要求因法源更新待查而被阻擋為 unknown
    assert dec_map[rule_a.rule_id].state == ApplicabilityState.UNKNOWN
    assert any("更新待查" in r or "reverification" in r for r in dec_map[rule_a.rule_id].reasons)

    # 引用 source_b 的要求不受影響，依然 applicable
    assert dec_map[rule_b.rule_id].state == ApplicabilityState.APPLICABLE


def test_select_requirements_date_validity_half_open_interval(repo: Repository):
    """日期半開區間檢核：已過期及未來規則判定為 not_applicable 並註明效期原因。"""
    source = make_verified_source()

    # 1. 已過期規則：有效區間 [2026-01-01, 2026-06-01)
    expired_rule = make_test_rule(
        source_ref=source,
        title="已過期資安舊制規則",
        effective_from=date(2026, 1, 1),
        effective_to=date(2026, 6, 1),
    )
    # 2. 未來規則：有效區間 [2027-01-01, 2027-12-31)
    future_rule = make_test_rule(
        source_ref=source,
        title="尚未生效之資安新規",
        effective_from=date(2027, 1, 1),
        effective_to=date(2027, 12, 31),
    )
    # 3. 作用中規則：有效區間 [2026-06-01, 2026-12-31)
    active_rule = make_test_rule(
        source_ref=source,
        title="現行有效資安防護規則",
        effective_from=date(2026, 6, 1),
        effective_to=date(2026, 12, 31),
    )

    refs = release_rules(
        rules=[expired_rule, future_rule, active_rule],
        sources=[source],
        approver="資安法規組長",
        at=datetime.now(UTC),
        repo=repo,
    )

    facts = make_sample_case_facts(baseline_date="2026-10-15")
    decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    dec_map = {d.requirement_ref.id: d for d in decisions}

    # 已過期規則判定為 not_applicable
    assert dec_map[expired_rule.rule_id].state == ApplicabilityState.NOT_APPLICABLE
    assert any("規則已過期" in r or "after effective_to" in r for r in dec_map[expired_rule.rule_id].reasons)

    # 未來規則判定為 not_applicable
    assert dec_map[future_rule.rule_id].state == ApplicabilityState.NOT_APPLICABLE
    assert any("規則尚未生效" in r or "before effective_from" in r for r in dec_map[future_rule.rule_id].reasons)

    # 效期內規則判定為 applicable
    assert dec_map[active_rule.rule_id].state == ApplicabilityState.APPLICABLE

    # 驗證半開區間邊界 [effective_from, effective_to)
    # 基準日設為 2026-06-01：
    # - expired_rule 的 effective_to 為 2026-06-01 (不含截止日 -> not_applicable)
    # - active_rule 的 effective_from 為 2026-06-01 (含起日 -> applicable)
    boundary_decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 6, 1),
        repo=repo,
    )
    b_map = {d.requirement_ref.id: d for d in boundary_decisions}
    assert b_map[expired_rule.rule_id].state == ApplicabilityState.NOT_APPLICABLE
    assert b_map[active_rule.rule_id].state == ApplicabilityState.APPLICABLE


def test_select_requirements_rule_supersedes(repo: Repository):
    """規則取代：被其他選定規則取代之要求標記為 not_applicable，並附明確取代理由。"""
    source = make_verified_source()

    old_rule_id = str(uuid.uuid4())
    new_rule_id = str(uuid.uuid4())

    old_rule = make_test_rule(
        rule_id=old_rule_id,
        source_ref=source,
        title="舊版密碼長度要求 (8碼)",
    )
    new_rule = make_test_rule(
        rule_id=new_rule_id,
        source_ref=source,
        title="新版密碼長度要求 (12碼)",
        supersedes=[old_rule_id],
    )

    refs = release_rules(
        rules=[old_rule, new_rule],
        sources=[source],
        approver="資安法務主任",
        at=datetime.now(UTC),
        repo=repo,
    )

    facts = make_sample_case_facts()
    decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    dec_map = {d.requirement_ref.id: d for d in decisions}

    # 被取代之舊規則判定為 not_applicable，並註明被新規則取代
    assert dec_map[old_rule_id].state == ApplicabilityState.NOT_APPLICABLE
    assert any(f"已被規則 {new_rule_id} 取代" in r for r in dec_map[old_rule_id].reasons)

    # 取代者新規則判定為 applicable
    assert dec_map[new_rule_id].state == ApplicabilityState.APPLICABLE


def test_select_requirements_rule_conflicts_unresolved(repo: Repository):
    """未解決衝突：存在衝突關聯的選定規則必須標記為 unknown，不可靜默均判定為 applicable。"""
    source = make_verified_source()

    rule_a_id = str(uuid.uuid4())
    rule_b_id = str(uuid.uuid4())
    rule_c_id = str(uuid.uuid4())

    rule_a = make_test_rule(
        rule_id=rule_a_id,
        source_ref=source,
        title="專案機房本地部署要求",
        conflicts_with=[rule_b_id],
    )
    rule_b = make_test_rule(
        rule_id=rule_b_id,
        source_ref=source,
        title="政府公有雲優先採用要求",
        conflicts_with=[rule_a_id],
    )
    rule_c = make_test_rule(
        rule_id=rule_c_id,
        source_ref=source,
        title="共通源碼檢測要求",
    )

    refs = release_rules(
        rules=[rule_a, rule_b, rule_c],
        sources=[source],
        approver="架構治理委員會",
        at=datetime.now(UTC),
        repo=repo,
    )

    facts = make_sample_case_facts()
    decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    dec_map = {d.requirement_ref.id: d for d in decisions}

    # 衝突規則 A 與 B 均必須判定為 unknown，且載明衝突對象
    assert dec_map[rule_a_id].state == ApplicabilityState.UNKNOWN
    assert any(f"與規則 {rule_b_id} 存在衝突，待決策確認" in r for r in dec_map[rule_a_id].reasons)

    assert dec_map[rule_b_id].state == ApplicabilityState.UNKNOWN
    assert any(f"與規則 {rule_a_id} 存在衝突，待決策確認" in r for r in dec_map[rule_b_id].reasons)

    # 無衝突的規則 C 正常適用
    assert dec_map[rule_c_id].state == ApplicabilityState.APPLICABLE


def test_select_requirements_conflict_ignored_when_one_side_expired_or_superseded(repo: Repository):
    """當衝突規則因過期或已被取代而不適用時，不應牽連有效規則變為 unknown。"""
    source = make_verified_source()

    rule_live_id = str(uuid.uuid4())
    rule_expired_id = str(uuid.uuid4())

    rule_live = make_test_rule(
        rule_id=rule_live_id,
        source_ref=source,
        title="現行雲端存取控管",
        effective_from=date(2026, 1, 1),
        conflicts_with=[rule_expired_id],
    )
    rule_expired = make_test_rule(
        rule_id=rule_expired_id,
        source_ref=source,
        title="歷史雲端存取控管",
        effective_from=date(2025, 1, 1),
        effective_to=date(2026, 1, 1),  # 已於 2026-01-01 過期
        conflicts_with=[rule_live_id],
    )

    refs = release_rules(
        rules=[rule_live, rule_expired],
        sources=[source],
        approver="合約管理員",
        at=datetime.now(UTC),
        repo=repo,
    )

    facts = make_sample_case_facts(baseline_date="2026-10-15")
    decisions = select_requirements(
        refs=refs,
        facts=facts,
        as_of=date(2026, 10, 15),
        repo=repo,
    )

    dec_map = {d.requirement_ref.id: d for d in decisions}
    # 過期規則為 not_applicable
    assert dec_map[rule_expired_id].state == ApplicabilityState.NOT_APPLICABLE
    # 現行規則不應受到已過期規則衝突影響，應為 applicable
    assert dec_map[rule_live_id].state == ApplicabilityState.APPLICABLE


