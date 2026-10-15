"""Feedback service for human decisions and audit preservation (Task 11).

提供人工決定之記錄、舊 run 防護、冪等性寫入與狀態更新：
- record_feedback: 驗證 run_id 有效性、拒絕已 stale 之 run、保證單案例外不更動 catalog 基礎規則。
"""

import uuid
from datetime import UTC, datetime

from procurement_review.domain.enums import HumanDecisionAction
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import Feedback, HumanDecision
from procurement_review.storage.repository import Repository


def record_feedback(
    decision: HumanDecision,
    repo: Repository,
    idempotency_key: str,
) -> Feedback:
    """記錄人工決定回饋。

    保證：
    1. 驗證 finding 存在性與所屬 run_id。
    2. 拒絕針對已 stale 的 run 提交回饋 (STALE_RUN_REJECTED)。
    3. 若 decision 帶有 run_id，檢查與 finding.run_id 一致性。
    4. 支援冪等鍵 (idempotency_key)，重複提交不重複寫入。
    5. 單案例外不更動 catalog 中的基礎規則 (Rule)，保留候選案例屬性。
    6. 同步更新 finding 之 human_status。
    """
    now = datetime.now(UTC)

    # 1. 查詢 finding 與對應 run
    finding = repo.get_finding(decision.finding_id)
    finding_run_id = str(finding.run_id)

    # 2. 檢驗 run 狀態
    run = repo.get_run(finding_run_id)
    if run.stale:
        raise DomainError(
            "STALE_RUN_REJECTED",
            f"Cannot submit feedback for stale review run '{run.run_id}'",
        )

    # 3. 檢驗 decision.run_id 一致性
    decision_run_id = decision.run_id
    if decision_run_id is not None and str(decision_run_id) != finding_run_id:
        raise DomainError(
            "RUN_MISMATCH",
            f"Decision run_id '{decision_run_id}' does not match finding run_id '{finding_run_id}'",
        )

    # 設定 decision.run_id
    decision.run_id = finding_run_id

    # 4. 組裝 Feedback
    exception_scope = "case_only" if decision.action == HumanDecisionAction.MODIFY else None
    feedback_id = str(uuid.uuid4())
    feedback = Feedback(
        feedback_id=feedback_id,
        finding_id=finding.finding_id,
        run_id=finding.run_id,
        original_result=finding.result,
        human_decision=decision,
        exception_scope=exception_scope,
        approved_for_case_base=False,  # 單案例外不更動規則庫
        operator=decision.decided_by,
        created_at=now,
        version=1,
    )

    # 5. 透過 repo 以冪等鍵附加
    saved_feedback = repo.append_feedback(feedback, idempotency_key=idempotency_key)

    # 6. 更新 finding 之 human_status
    status_mapping = {
        HumanDecisionAction.ADOPT: "adopted",
        HumanDecisionAction.MODIFY: "modified",
        HumanDecisionAction.REJECT: "rejected",
    }
    new_human_status = status_mapping.get(decision.action, "reviewed")
    updated_finding = finding.model_copy(update={"human_status": new_human_status})
    repo.save_finding(updated_finding)

    return saved_feedback
