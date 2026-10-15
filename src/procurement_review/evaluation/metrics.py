from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from procurement_review.domain.enums import ResultEnum, RiskLevel
from procurement_review.domain.models import Finding


class EvaluationReport(BaseModel):
    """審查評測結果報告（規格 §11）"""

    model_config = ConfigDict(extra="ignore")

    total_expected: int = 0
    total_actual: int = 0
    aligned_pairs: int = 0
    unmatched_expected: int = 0
    unmatched_actual: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    precision: float | None = None
    recall: float | None = None
    f1: float | None = None
    accuracy: float | None = None
    omission_rate: float | None = None
    confusion_matrix: dict[str, dict[str, int]] = Field(default_factory=dict)
    needs_confirmation_rate: float | None = None
    all_abstentions: bool = False
    high_risk_false_compliant_count: int = 0
    per_pack_metrics: dict[str, dict[str, Any]] = Field(default_factory=dict)
    extraction_metrics: dict[str, Any] = Field(default_factory=dict)
    masking_metrics: dict[str, Any] = Field(default_factory=dict)
    roundtrip_metrics: dict[str, Any] = Field(default_factory=dict)
    coverage_metrics: dict[str, Any] = Field(default_factory=dict)
    citation_metrics: dict[str, Any] = Field(default_factory=dict)
    draft_metrics: dict[str, Any] = Field(default_factory=dict)
    human_effort: dict[str, Any] = Field(default_factory=dict)
    safety_violations: dict[str, int] = Field(default_factory=dict)
    metadata: dict[str, Any] = Field(default_factory=dict)


class GateReport(BaseModel):
    """發布門檻判定報告（規格 §11）"""

    model_config = ConfigDict(extra="ignore")

    ok: bool
    status: str  # "passed" | "failed" | "unapproved"
    failures: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    checked_rules: list[str] = Field(default_factory=list)
    details: dict[str, Any] = Field(default_factory=dict)


def _safe_div(n: float, d: float) -> float | None:
    if d == 0:
        return None
    return float(n / d)


def _get_result_val(res: Any) -> str:
    if hasattr(res, "value"):
        return str(res.value)
    return str(res)


def _get_risk_val(r: Any) -> str:
    if hasattr(r, "value"):
        return str(r.value)
    return str(r)


def _normalize_pack_name(scope: str | None) -> str:
    if not scope:
        return "mixed"
    s = scope.lower().strip()
    if s in ("software_maintenance", "maintenance", "cots", "services"):
        return "software_maintenance"
    if s in ("custom_software", "development"):
        return "custom_software"
    if s in ("cloud_service", "cloud"):
        return "cloud_service"
    return "mixed"


def evaluate(
    expected: list[Finding],
    actual: list[Finding],
    artifacts: dict[str, Any] | None = None,
) -> EvaluationReport:
    """執行合約審查多維度評測。

    比對對齊原則：使用 (requirement_id, tuple(sorted(clause_ids))) 嚴格配對，
    絕不使用隨機 finding_id 或列表順序。
    """
    artifacts = artifacts or {}

    # 1. 答案去重與建置 Key 對應
    expected_dict: dict[tuple[str, tuple[str, ...]], Finding] = {}
    for ef in expected:
        key = (ef.requirement_id, tuple(sorted(ef.clause_ids)))
        if key not in expected_dict:
            expected_dict[key] = ef

    actual_dict: dict[tuple[str, tuple[str, ...]], Finding] = {}
    for af in actual:
        key = (af.requirement_id, tuple(sorted(af.clause_ids)))
        if key not in actual_dict:
            actual_dict[key] = af

    total_expected = len(expected_dict)
    total_actual = len(actual_dict)

    # 2. 初始化混淆矩陣
    all_results = [r.value for r in ResultEnum]
    confusion_matrix: dict[str, dict[str, int]] = {
        r1: {r2: 0 for r2 in all_results} for r1 in all_results
    }

    aligned_pairs = 0
    tp = 0
    misclassified = 0
    high_risk_false_compliant_count = 0

    # 3. 比對對齊
    for key, exp_f in expected_dict.items():
        if key in actual_dict:
            act_f = actual_dict[key]
            aligned_pairs += 1
            e_res = _get_result_val(exp_f.result)
            a_res = _get_result_val(act_f.result)

            if e_res in confusion_matrix and a_res in confusion_matrix[e_res]:
                confusion_matrix[e_res][a_res] += 1

            if e_res == a_res:
                tp += 1
            else:
                misclassified += 1

            # 檢測致命之高風險誤判符合 (high-risk false compliant)
            exp_risk = _get_risk_val(exp_f.risk)
            if (
                exp_risk in (RiskLevel.CRITICAL.value, RiskLevel.HIGH.value)
                and e_res in (ResultEnum.CONCERN.value, ResultEnum.MISSING.value)
                and a_res == ResultEnum.COMPLIANT.value
            ):
                high_risk_false_compliant_count += 1

    unmatched_expected = total_expected - aligned_pairs
    unmatched_actual = total_actual - aligned_pairs

    fp = unmatched_actual + misclassified
    fn = unmatched_expected + misclassified

    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * (precision * recall) / (precision + recall)

    accuracy = _safe_div(tp, tp + fp + fn)
    omission_rate = _safe_div(unmatched_expected, total_expected)

    # 4. 全棄答與待確認率
    needs_conf_count = sum(
        1
        for af in actual_dict.values()
        if _get_result_val(af.result) in (ResultEnum.NEEDS_CONFIRMATION.value, "abstain")
    )
    needs_confirmation_rate = _safe_div(needs_conf_count, total_actual)
    all_abstentions = (total_actual > 0 and needs_conf_count == total_actual)

    # 5. 四包各自分母與指標
    known_packs = ["software_maintenance", "custom_software", "cloud_service", "mixed"]
    per_pack_metrics: dict[str, dict[str, Any]] = {}
    for pack in known_packs:
        pack_exp = [
            f for f in expected_dict.values()
            if _normalize_pack_name(getattr(f, "review_scope", None)) == pack
        ]
        pack_act = [
            f for f in actual_dict.values()
            if _normalize_pack_name(getattr(f, "review_scope", None)) == pack
        ]

        p_exp_dict = {(f.requirement_id, tuple(sorted(f.clause_ids))): f for f in pack_exp}
        p_act_dict = {(f.requirement_id, tuple(sorted(f.clause_ids))): f for f in pack_act}
        p_tp = sum(
            1 for k, ef in p_exp_dict.items()
            if k in p_act_dict and _get_result_val(ef.result) == _get_result_val(p_act_dict[k].result)
        )
        p_mis = sum(
            1 for k, ef in p_exp_dict.items()
            if k in p_act_dict and _get_result_val(ef.result) != _get_result_val(p_act_dict[k].result)
        )
        p_unmatched_exp = len(p_exp_dict) - sum(1 for k in p_exp_dict if k in p_act_dict)
        p_unmatched_act = len(p_act_dict) - sum(1 for k in p_act_dict if k in p_exp_dict)
        p_fp = p_unmatched_act + p_mis
        p_fn = p_unmatched_exp + p_mis

        p_prec = _safe_div(p_tp, p_tp + p_fp)
        p_rec = _safe_div(p_tp, p_tp + p_fn)
        p_f1 = None
        if p_prec is not None and p_rec is not None and (p_prec + p_rec) > 0:
            p_f1 = 2 * (p_prec * p_rec) / (p_prec + p_rec)

        per_pack_metrics[pack] = {
            "total_expected": len(p_exp_dict),
            "total_actual": len(p_act_dict),
            "tp": p_tp,
            "fp": p_fp,
            "fn": p_fn,
            "precision": p_prec,
            "recall": p_rec,
            "f1": p_f1,
            "omission_rate": _safe_div(p_unmatched_exp, len(p_exp_dict)),
        }

    # 6. 整合 artifacts 指標
    # 擷取
    ext_data = artifacts.get("extraction", {})
    ext_chars = ext_data.get("total_characters", 0)
    ext_errors = ext_data.get("error_count", 0)
    ext_acc = _safe_div(ext_chars - ext_errors, ext_chars) if ext_chars > 0 else (1.0 if ext_errors == 0 else 0.0)
    extraction_metrics = {
        "total_characters": ext_chars,
        "error_count": ext_errors,
        "accuracy": ext_acc,
    }

    # 遮罩
    mask_data = artifacts.get("masking", {})
    leakage_count = mask_data.get("leakage_count", 0)
    mask_total = mask_data.get("total_entities", 0)
    mask_masked = mask_data.get("masked_entities", 0)
    mask_categories = mask_data.get("categories", {})
    # 計算整體遮罩 precision/recall
    cat_tp = sum(v.get("tp", 0) for v in mask_categories.values())
    cat_fp = sum(v.get("fp", 0) for v in mask_categories.values())
    cat_fn = sum(v.get("fn", 0) for v in mask_categories.values())
    if cat_tp + cat_fp + cat_fn > 0:
        mask_prec = _safe_div(cat_tp, cat_tp + cat_fp)
        mask_rec = _safe_div(cat_tp, cat_tp + cat_fn)
    else:
        mask_prec = _safe_div(mask_masked, mask_total) if mask_total > 0 else (1.0 if leakage_count == 0 else 0.0)
        mask_rec = mask_prec
    mask_f1 = None
    if mask_prec is not None and mask_rec is not None and (mask_prec + mask_rec) > 0:
        mask_f1 = 2 * (mask_prec * mask_rec) / (mask_prec + mask_rec)

    masking_metrics = {
        "total_entities": mask_total,
        "masked_entities": mask_masked,
        "leakage_count": leakage_count,
        "precision": mask_prec,
        "recall": mask_rec,
        "f1": mask_f1,
        "per_category": mask_categories,
    }

    # 還原完整性
    rt_data = artifacts.get("roundtrip", {})
    fidelity_rate = rt_data.get("fidelity_rate", 1.0 if not rt_data.get("mismatches") else 0.0)
    cross_case_swaps = rt_data.get("cross_case_swaps", 0)
    roundtrip_metrics = {
        "fidelity_rate": fidelity_rate,
        "mismatches": rt_data.get("mismatches", 0),
        "cross_case_swaps": cross_case_swaps,
    }

    # 覆蓋率
    cov_data = artifacts.get("coverage", {})
    clause_eval = cov_data.get("evaluated_clauses", 0)
    clause_tot = cov_data.get("total_clauses", 0)
    req_eval = cov_data.get("evaluated_requirements", 0)
    req_tot = cov_data.get("total_requirements", 0)
    coverage_metrics = {
        "clause_coverage_rate": _safe_div(clause_eval, clause_tot) if clause_tot > 0 else 1.0,
        "requirement_coverage_rate": _safe_div(req_eval, req_tot) if req_tot > 0 else 1.0,
        "evaluated_clauses": clause_eval,
        "total_clauses": clause_tot,
        "evaluated_requirements": req_eval,
        "total_requirements": req_tot,
    }

    # 引用與捏造
    cit_data = artifacts.get("citations", {})
    tot_cit = cit_data.get("total_citations", 0)
    val_cit = cit_data.get("valid_citations", 0)
    sup_cit = cit_data.get("supported_citations", 0)
    hallucinated = cit_data.get("hallucinated_citations", [])
    hallucinated_count = len(hallucinated) if isinstance(hallucinated, list) else int(hallucinated)
    citation_metrics = {
        "total_citations": tot_cit,
        "valid_citations": val_cit,
        "supported_citations": sup_cit,
        "validity_rate": _safe_div(val_cit, tot_cit) if tot_cit > 0 else 1.0,
        "support_rate": _safe_div(sup_cit, val_cit) if val_cit > 0 else 1.0,
        "hallucinated_citations_count": hallucinated_count,
        "hallucinated_citations": hallucinated if isinstance(hallucinated, list) else [],
    }

    # 草稿採用
    draft_data = artifacts.get("drafts", {})
    tot_drafts = draft_data.get("total_drafts", 0)
    adopted_drafts = draft_data.get("adopted", 0)
    modified_drafts = draft_data.get("modified", 0)
    rejected_drafts = draft_data.get("rejected", 0)
    draft_metrics = {
        "total_drafts": tot_drafts,
        "adopted_count": adopted_drafts,
        "modified_count": modified_drafts,
        "rejected_count": rejected_drafts,
        "adoption_rate": _safe_div(adopted_drafts, tot_drafts) if tot_drafts > 0 else None,
        "rewrite_rate": _safe_div(modified_drafts, tot_drafts) if tot_drafts > 0 else None,
    }

    # 人工工時與成本
    human_data = artifacts.get("human_effort", {})
    total_minutes = human_data.get("minutes", 0.0)
    total_cost = human_data.get("cost", 0.0)
    cases_eval = human_data.get("cases_evaluated", 1 if (total_minutes > 0 or total_cost > 0) else 0)
    human_effort = {
        "total_minutes": float(total_minutes),
        "total_cost": float(total_cost),
        "cases_evaluated": cases_eval,
        "minutes_per_case": _safe_div(total_minutes, cases_eval) if cases_eval > 0 else None,
        "cost_per_case": _safe_div(total_cost, cases_eval) if cases_eval > 0 else None,
    }

    # 安全紅線總整
    safety_data = artifacts.get("safety", {})
    unauth_egress = safety_data.get("unauthorized_egress_count", 0)
    unauth_alter = safety_data.get("unauthorized_alterations_count", 0)
    safety_violations = {
        "high_risk_false_compliant": high_risk_false_compliant_count,
        "hallucinated_citations": hallucinated_count,
        "masking_leakage": leakage_count,
        "unauthorized_egress": unauth_egress,
        "unauthorized_alterations": unauth_alter,
        "cross_case_swaps": cross_case_swaps,
    }

    return EvaluationReport(
        total_expected=total_expected,
        total_actual=total_actual,
        aligned_pairs=aligned_pairs,
        unmatched_expected=unmatched_expected,
        unmatched_actual=unmatched_actual,
        tp=tp,
        fp=fp,
        fn=fn,
        precision=precision,
        recall=recall,
        f1=f1,
        accuracy=accuracy,
        omission_rate=omission_rate,
        confusion_matrix=confusion_matrix,
        needs_confirmation_rate=needs_confirmation_rate,
        all_abstentions=all_abstentions,
        high_risk_false_compliant_count=high_risk_false_compliant_count,
        per_pack_metrics=per_pack_metrics,
        extraction_metrics=extraction_metrics,
        masking_metrics=masking_metrics,
        roundtrip_metrics=roundtrip_metrics,
        coverage_metrics=coverage_metrics,
        citation_metrics=citation_metrics,
        draft_metrics=draft_metrics,
        human_effort=human_effort,
        safety_violations=safety_violations,
        metadata={"processed_cases": cases_eval},
    )


def check_release(report: EvaluationReport, policy: dict[str, Any]) -> GateReport:
    """執行合約審查發布判定與零容忍安全檢查。

    判定規則：
    1. 政策必須正式核准 (approved == True) 且設定人工接受率與工時門檻；否則為 unapproved。
    2. 零容忍紅線：全棄答、高風險誤判符合、不存在引用、漏遮、未授權出站、受保護改動、跨案混用均不得大於 0。
    3. 各類品質與覆蓋門檻檢核。
    """
    failures: list[str] = []
    warnings: list[str] = []
    checked_rules: list[str] = []

    # 1. 檢核政策是否核准
    checked_rules.append("policy_approval_status")
    if not policy.get("approved"):
        return GateReport(
            ok=False,
            status="unapproved",
            failures=["政策未經正式核准 (approved != True)，禁止默認 PASS。"],
            warnings=[],
            checked_rules=checked_rules,
            details={"policy": policy},
        )

    thresholds = policy.get("thresholds", {})
    checked_rules.append("mandatory_thresholds_defined")
    has_acceptance_threshold = (
        "min_draft_adoption_rate" in thresholds or "min_human_acceptance_rate" in thresholds
    )
    has_time_threshold = (
        "max_human_minutes_per_case" in thresholds or "max_human_time_limit" in thresholds
    )
    if not has_acceptance_threshold or not has_time_threshold:
        return GateReport(
            ok=False,
            status="unapproved",
            failures=["政策缺少必要門檻設定：必須明定人工接受率門檻與工時門檻，禁止默認 PASS。"],
            warnings=[],
            checked_rules=checked_rules,
            details={"thresholds": thresholds},
        )

    # 2. 零容忍違規紅線檢驗 (Zero Tolerance)
    zero_tol = policy.get("zero_tolerance", {})

    # (a) 全棄答檢驗
    checked_rules.append("zero_tolerance_all_abstentions")
    if not zero_tol.get("allow_all_abstentions", False) and report.all_abstentions:
        failures.append("全棄答違規 (All Abstentions)：所有審查結果均為待確認或棄答，無實質分析能力。")

    # (b) 高風險誤判符合 (High-Risk False Compliant)
    checked_rules.append("zero_tolerance_high_risk_false_compliant")
    hr_count = report.safety_violations.get("high_risk_false_compliant", 0)
    max_hr = zero_tol.get("max_high_risk_false_compliant", 0)
    if hr_count > max_hr:
        failures.append(f"高風險誤判符合 (High-Risk False Compliant)：檢測出 {hr_count} 項高風險缺失被誤判為符合。")

    # (c) 捏造／不存在引用 (Hallucinated Citations)
    checked_rules.append("zero_tolerance_hallucinated_citations")
    hall_count = report.safety_violations.get("hallucinated_citations", 0)
    max_hall = zero_tol.get("max_hallucinated_citations", 0)
    if hall_count > max_hall:
        failures.append(f"捏造引用 (Hallucinated Citations)：檢測出 {hall_count} 筆不存在或捏造之條文引用。")

    # (d) 遮罩殘留／機敏外洩 (Masking Leakage)
    checked_rules.append("zero_tolerance_masking_leakage")
    leak_count = report.safety_violations.get("masking_leakage", 0)
    max_leak = zero_tol.get("max_masking_leakage", 0)
    if leak_count > max_leak:
        failures.append(f"機敏遮罩殘留／洩漏 (Masking Leakage)：檢測出 {leak_count} 筆未遮蔽機敏實體。")

    # (e) 未授權出站 (Unauthorized Egress)
    checked_rules.append("zero_tolerance_unauthorized_egress")
    egress_count = report.safety_violations.get("unauthorized_egress", 0)
    max_egress = zero_tol.get("max_unauthorized_egress", 0)
    if egress_count > max_egress:
        failures.append(f"未授權網路出站 (Unauthorized Egress)：檢測出 {egress_count} 次違規出站連線。")

    # (f) 未經授權改動受保護內容 (Unauthorized Alterations)
    checked_rules.append("zero_tolerance_unauthorized_alterations")
    alter_count = report.safety_violations.get("unauthorized_alterations", 0)
    max_alter = zero_tol.get("max_unauthorized_alterations", 0)
    if alter_count > max_alter:
        failures.append(f"無據篡改受保護內容 (Unauthorized Alterations)：檢測出 {alter_count} 筆保護欄位異常變更。")

    # (g) 跨案錯換／混用 (Cross-case Swaps)
    checked_rules.append("zero_tolerance_cross_case_swaps")
    swap_count = report.safety_violations.get("cross_case_swaps", 0)
    max_swap = zero_tol.get("max_cross_case_swaps", 0)
    if swap_count > max_swap:
        failures.append(f"跨案錯換與污染 (Cross-Case Swaps)：檢測出 {swap_count} 筆跨案混用違規。")

    # 3. 品質與效率門檻檢驗 (Quality & Efficiency Thresholds)
    # 擷取正確率
    if "min_extraction_accuracy" in thresholds:
        checked_rules.append("threshold_min_extraction_accuracy")
        ext_acc = report.extraction_metrics.get("accuracy")
        if ext_acc is not None and ext_acc < thresholds["min_extraction_accuracy"]:
            failures.append(f"擷取正確率不足: 實際值 {ext_acc:.3f} < 門檻值 {thresholds['min_extraction_accuracy']}")

    # 遮罩 Precision / Recall
    if "min_masking_precision" in thresholds:
        checked_rules.append("threshold_min_masking_precision")
        m_prec = report.masking_metrics.get("precision")
        if m_prec is not None and m_prec < thresholds["min_masking_precision"]:
            failures.append(f"遮罩精準度不足: 實際值 {m_prec:.3f} < 門檻值 {thresholds['min_masking_precision']}")
    if "min_masking_recall" in thresholds:
        checked_rules.append("threshold_min_masking_recall")
        m_rec = report.masking_metrics.get("recall")
        if m_rec is not None and m_rec < thresholds["min_masking_recall"]:
            failures.append(f"遮罩召回率不足: 實際值 {m_rec:.3f} < 門檻值 {thresholds['min_masking_recall']}")

    # 還原完整度
    if "min_roundtrip_fidelity" in thresholds:
        checked_rules.append("threshold_min_roundtrip_fidelity")
        rt_fid = report.roundtrip_metrics.get("fidelity_rate")
        if rt_fid is not None and rt_fid < thresholds["min_roundtrip_fidelity"]:
            failures.append(f"文字還原完整度不足: 實際值 {rt_fid:.3f} < 門檻值 {thresholds['min_roundtrip_fidelity']}")

    # 條款與要求覆蓋率
    if "min_clause_coverage" in thresholds:
        checked_rules.append("threshold_min_clause_coverage")
        cov_clause = report.coverage_metrics.get("clause_coverage_rate")
        if cov_clause is not None and cov_clause < thresholds["min_clause_coverage"]:
            failures.append(f"條款審查覆蓋率不足: 實際值 {cov_clause:.3f} < 門檻值 {thresholds['min_clause_coverage']}")
    if "min_requirement_coverage" in thresholds:
        checked_rules.append("threshold_min_requirement_coverage")
        cov_req = report.coverage_metrics.get("requirement_coverage_rate")
        if cov_req is not None and cov_req < thresholds["min_requirement_coverage"]:
            failures.append(f"資安要求審查覆蓋率不足: 實際值 {cov_req:.3f} < 門檻值 {thresholds['min_requirement_coverage']}")

    # 草稿採用率
    draft_req = thresholds.get("min_draft_adoption_rate", thresholds.get("min_human_acceptance_rate"))
    if draft_req is not None:
        checked_rules.append("threshold_min_draft_adoption_rate")
        d_adopt = report.draft_metrics.get("adoption_rate")
        if d_adopt is not None and d_adopt < draft_req:
            failures.append(f"草稿人工採用率不足: 實際值 {d_adopt:.3f} < 門檻值 {draft_req}")

    # 待確認率上限
    if "max_needs_confirmation_rate" in thresholds:
        checked_rules.append("threshold_max_needs_confirmation_rate")
        nc_rate = report.needs_confirmation_rate
        if nc_rate is not None and nc_rate > thresholds["max_needs_confirmation_rate"]:
            failures.append(f"待確認比例過高: 實際值 {nc_rate:.3f} > 門檻值 {thresholds['max_needs_confirmation_rate']}")

    # 人工工時與成本上限
    time_req = thresholds.get("max_human_minutes_per_case", thresholds.get("max_human_time_limit"))
    if time_req is not None:
        checked_rules.append("threshold_max_human_minutes_per_case")
        m_case = report.human_effort.get("minutes_per_case")
        if m_case is not None and m_case > time_req:
            failures.append(f"每案人工工時超標: 實際值 {m_case:.1f} 分鐘 > 門檻值 {time_req} 分鐘")

    if "max_human_cost_per_case" in thresholds:
        checked_rules.append("threshold_max_human_cost_per_case")
        c_case = report.human_effort.get("cost_per_case")
        if c_case is not None and c_case > thresholds["max_human_cost_per_case"]:
            failures.append(f"每案人工成本超標: 實際值 {c_case:.1f} 元 > 門檻值 {thresholds['max_human_cost_per_case']} 元")

    # 引用有效性與人工支持度
    if "min_citation_validity_rate" in thresholds:
        checked_rules.append("threshold_min_citation_validity_rate")
        c_val = report.citation_metrics.get("validity_rate")
        if c_val is not None and c_val < thresholds["min_citation_validity_rate"]:
            failures.append(f"引用有效率不足: 實際值 {c_val:.3f} < 門檻值 {thresholds['min_citation_validity_rate']}")
    if "min_citation_support_rate" in thresholds:
        checked_rules.append("threshold_min_citation_support_rate")
        c_sup = report.citation_metrics.get("support_rate")
        if c_sup is not None and c_sup < thresholds["min_citation_support_rate"]:
            failures.append(f"引用支持率不足: 實際值 {c_sup:.3f} < 門檻值 {thresholds['min_citation_support_rate']}")

    # 遺漏率 (Omission Rate)
    if "max_omission_rate" in thresholds:
        checked_rules.append("threshold_max_omission_rate")
        om_rate = report.omission_rate
        if om_rate is not None and om_rate > thresholds["max_omission_rate"]:
            failures.append(f"要求遺漏率過高: 實際值 {om_rate:.3f} > 門檻值 {thresholds['max_omission_rate']}")

    ok = len(failures) == 0
    status = "passed" if ok else "failed"

    return GateReport(
        ok=ok,
        status=status,
        failures=failures,
        warnings=warnings,
        checked_rules=checked_rules,
        details={
            "total_rules_checked": len(checked_rules),
            "failures_count": len(failures),
        },
    )
