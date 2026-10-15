from datetime import date, datetime

from procurement_review.domain.enums import ApplicabilityState, RuleStatus
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    ApplicabilityDecision,
    CaseFacts,
    Rule,
    SourceReference,
    VersionRef,
)
from procurement_review.rules.applicability import evaluate_applicability
from procurement_review.rules.catalog import (
    compute_rule_hash,
    rule_to_requirement,
)
from procurement_review.storage.repository import Repository


def release_rules(
    rules: list[Rule],
    sources: list[SourceReference],
    approver: str,
    at: datetime,
    repo: Repository,
) -> list[VersionRef]:
    """執行規則發布治理。

    規格要求：
    - 僅接受 pending_approval 狀態的規則，草稿 (draft) 拒絕發布。
    - 來源必須已經查核 (verified_at 與 verified_by 不得為空)，未查核來源拒絕發布。
    - 呼叫端必須提供非空白且經認證之核准者 (approver)。
    - 核准後將規則標記為 active，寫入 approved_by 與 approved_at。
    - 安全持久化至 Repository，並回傳發布版本參照 (VersionRef) 清單。
    """
    if not approver or not approver.strip():
        raise DomainError(
            "UNAUTHORIZED_APPROVER",
            "A valid, authenticated approver name is required to release rules",
        )

    # 1. 檢核來源是否已查核
    verified_sources_map: dict[str, SourceReference] = {}
    for source in sources:
        if source.verified_at is None or source.verified_by is None or not source.verified_by.strip():
            raise DomainError(
                "UNVERIFIED_SOURCE",
                f"Source '{source.source_id}' ({source.title}) is unverified and cannot be released",
            )
        verified_sources_map[source.source_id] = source
        repo.save_source(source)

    # 2. 檢核規則狀態與引用法源
    released_refs: list[VersionRef] = []
    for rule in rules:
        if rule.status != RuleStatus.PENDING_APPROVAL:
            raise DomainError(
                "INVALID_RULE_STATUS",
                f"Rule '{rule.rule_id}' is in status '{rule.status.value}', only 'pending_approval' rules can be released",
            )

        # 檢核關聯法源
        for sref in rule.source_refs:
            if sref.id in verified_sources_map:
                continue
            # 嘗試自儲存庫讀取
            try:
                existing_source = repo.get_source(sref.id)
                if existing_source.verified_at is None or existing_source.verified_by is None:
                    raise DomainError(
                        "UNVERIFIED_SOURCE",
                        f"Referenced source '{sref.id}' in repository is unverified",
                    )
            except DomainError as err:
                if err.code == "SOURCE_NOT_FOUND":
                    raise DomainError(
                        "UNVERIFIED_SOURCE",
                        f"Referenced source '{sref.id}' for rule '{rule.rule_id}' not found in release batch or repository",
                    ) from err
                raise

        # 標記為 ACTIVE 並記錄核准人與時間
        active_rule = rule.model_copy(
            update={
                "status": RuleStatus.ACTIVE,
                "approved_by": approver.strip(),
                "approved_at": at,
            }
        )
        repo.save_rule(active_rule)

        # 同步儲存要求契約 Requirement
        req = rule_to_requirement(active_rule)
        repo.save_requirement(req)

        r_hash = compute_rule_hash(active_rule)
        released_refs.append(
            VersionRef(
                id=active_rule.rule_id,
                version=active_rule.version,
                sha256=r_hash,
            )
        )

    return released_refs


def select_requirements(
    refs: list[VersionRef],
    facts: CaseFacts,
    as_of: date,
    repo: Repository,
) -> list[ApplicabilityDecision]:
    """自規則集參照篩選適用要求，並進行跨包去重與適用性判定。

    保證：
    - 同一 requirement_id 在結果中僅出現一次 (去重)。
    - 若法規來源處於「更新待查」狀態，僅阻擋引用該來源之相關要求，不阻擋其他要求。
    - 依據基準日期 as_of 檢核效期 [effective_from, effective_to)。
    """
    seen_req_ids: set[str] = set()
    decisions: list[ApplicabilityDecision] = []

    for ref in refs:
        rule = repo.get_rule(ref.id, ref.version)
        if rule.status != RuleStatus.ACTIVE:
            continue

        # 檢查法源是否發生「更新待查」情境
        source_pending_reverification = False
        for sref in rule.source_refs:
            try:
                src = repo.get_source(sref.id)
                if src.verified_at is None or src.verified_by is None:
                    source_pending_reverification = True
                    break
            except DomainError:
                # 若儲存庫未記錄或來源不存在，視為待查
                source_pending_reverification = True
                break

        requirements = repo.get_requirements_for_rule(rule.rule_id, rule.version)
        if not requirements:
            requirements = [rule_to_requirement(rule)]

        for req in requirements:
            if req.requirement_id in seen_req_ids:
                continue
            seen_req_ids.add(req.requirement_id)

            if source_pending_reverification:
                # 僅阻擋依賴未查核來源的要求
                decision = ApplicabilityDecision(
                    requirement_ref=VersionRef(
                        id=req.requirement_id,
                        version=req.version,
                        sha256=req.rule_ref.sha256,
                    ),
                    state=ApplicabilityState.UNKNOWN,
                    reasons=["來源更新待查 (Source pending reverification)"],
                )
            else:
                decision = evaluate_applicability(req, facts, as_of=as_of)

            decisions.append(decision)

    return decisions


def revoke_rule(
    ref: VersionRef,
    reason: str,
    repo: Repository,
) -> list[str]:
    """撤銷規則，並自動反向使引用該規則之所有作用中執行管線 (active runs) 失效。

    回傳：被標記為 stale 的 run ID 清單。
    """
    rule = repo.get_rule(ref.id, ref.version)
    revoked_rule = rule.model_copy(
        update={
            "status": RuleStatus.REVOKED,
            "change_reason": reason,
        }
    )
    repo.save_rule(revoked_rule)

    # 使所有引用該規則之 active runs 失效
    invalidated_run_ids = repo.invalidate_runs_by_rule(
        rule_id=ref.id,
        reason=f"REVOKED_RULE: {reason}",
    )
    return invalidated_run_ids
