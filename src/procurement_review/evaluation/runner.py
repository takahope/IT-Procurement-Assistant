import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from procurement_review.domain.models import Finding
from procurement_review.evaluation.metrics import (
    GateReport,
    _safe_div,
    check_release,
    evaluate,
)


def load_manifest(path: Path | str) -> dict[str, Any]:
    """讀取並驗證評測清單 Manifest 檔案。"""
    p = Path(path).resolve()
    if not p.exists():
        raise FileNotFoundError(f"評測清單檔案不存在: {p}")
    data = json.loads(p.read_text(encoding="utf-8"))
    required_keys = ["manifest_id", "family_id", "split", "mode", "records"]
    for k in required_keys:
        if k not in data:
            raise ValueError(f"評測清單缺少必要欄位: '{k}'")
    return data


def run_evaluation(
    manifest_path: Path | str,
    output_path: Path | str,
    policy_path: Path | str | None = None,
) -> dict[str, Any]:
    """執行評測流程並產製報告檔案。"""
    manifest = load_manifest(manifest_path)
    records = manifest.get("records", [])

    all_expected: list[Finding] = []
    all_actual: list[Finding] = []

    # 累計 artifacts
    total_ext_chars = 0
    total_ext_errors = 0

    total_mask_entities = 0
    total_mask_masked = 0
    total_mask_leakage = 0
    mask_categories: dict[str, dict[str, int]] = {}

    rt_mismatches = 0
    rt_cross_case_swaps = 0

    cov_eval_clauses = 0
    cov_tot_clauses = 0
    cov_eval_reqs = 0
    cov_tot_reqs = 0

    cit_total = 0
    cit_valid = 0
    cit_supported = 0
    cit_hallucinated: list[str] = []

    drafts_total = 0
    drafts_adopted = 0
    drafts_modified = 0
    drafts_rejected = 0

    human_minutes = 0.0
    human_cost = 0.0

    unauth_egress = 0
    unauth_alter = 0

    for rec in records:
        pack = rec.get("pack", rec.get("category", "mixed"))

        for item in rec.get("expected_findings", []):
            item_copy = dict(item)
            if not item_copy.get("review_scope"):
                item_copy["review_scope"] = pack
            all_expected.append(Finding.model_validate(item_copy))

        for item in rec.get("actual_findings", []):
            item_copy = dict(item)
            if not item_copy.get("review_scope"):
                item_copy["review_scope"] = pack
            all_actual.append(Finding.model_validate(item_copy))

        art = rec.get("artifacts", {})

        # extraction
        ext = art.get("extraction", {})
        total_ext_chars += ext.get("total_characters", 0)
        total_ext_errors += ext.get("error_count", 0)

        # masking
        msk = art.get("masking", {})
        total_mask_entities += msk.get("total_entities", 0)
        total_mask_masked += msk.get("masked_entities", 0)
        total_mask_leakage += msk.get("leakage_count", 0)
        for cat, scores in msk.get("categories", {}).items():
            if cat not in mask_categories:
                mask_categories[cat] = {"tp": 0, "fp": 0, "fn": 0}
            mask_categories[cat]["tp"] += scores.get("tp", 0)
            mask_categories[cat]["fp"] += scores.get("fp", 0)
            mask_categories[cat]["fn"] += scores.get("fn", 0)

        # roundtrip
        rt = art.get("roundtrip", {})
        rt_mismatches += rt.get("mismatches", 0)
        rt_cross_case_swaps += rt.get("cross_case_swaps", 0)

        # coverage
        cov = art.get("coverage", {})
        cov_eval_clauses += cov.get("evaluated_clauses", 0)
        cov_tot_clauses += cov.get("total_clauses", 0)
        cov_eval_reqs += cov.get("evaluated_requirements", 0)
        cov_tot_reqs += cov.get("total_requirements", 0)

        # citations
        cit = art.get("citations", {})
        cit_total += cit.get("total_citations", 0)
        cit_valid += cit.get("valid_citations", 0)
        cit_supported += cit.get("supported_citations", 0)
        h_list = cit.get("hallucinated_citations", [])
        if isinstance(h_list, list):
            cit_hallucinated.extend(h_list)

        # drafts
        drf = art.get("drafts", {})
        drafts_total += drf.get("total_drafts", 0)
        drafts_adopted += drf.get("adopted", 0)
        drafts_modified += drf.get("modified", 0)
        drafts_rejected += drf.get("rejected", 0)

        # human
        hum = art.get("human_effort", {})
        human_minutes += hum.get("minutes", 0.0)
        human_cost += hum.get("cost", 0.0)

        # safety
        saf = art.get("safety", {})
        unauth_egress += saf.get("unauthorized_egress_count", 0)
        unauth_alter += saf.get("unauthorized_alterations_count", 0)

    merged_artifacts: dict[str, Any] = {
        "extraction": {
            "total_characters": total_ext_chars,
            "error_count": total_ext_errors,
        },
        "masking": {
            "total_entities": total_mask_entities,
            "masked_entities": total_mask_masked,
            "leakage_count": total_mask_leakage,
            "categories": mask_categories,
        },
        "roundtrip": {
            "fidelity_rate": (
                max(
                    0.0,
                    _safe_div(float((total_mask_entities or total_mask_masked) - rt_mismatches), float(total_mask_entities or total_mask_masked))
                    if (total_mask_entities or total_mask_masked) > 0
                    else (1.0 if rt_mismatches == 0 else max(0.0, 1.0 - (rt_mismatches / max(10, rt_mismatches))))
                )
            ),
            "mismatches": rt_mismatches,
            "cross_case_swaps": rt_cross_case_swaps,
        },
        "coverage": {
            "evaluated_clauses": cov_eval_clauses,
            "total_clauses": cov_tot_clauses,
            "evaluated_requirements": cov_eval_reqs,
            "total_requirements": cov_tot_reqs,
        },
        "citations": {
            "total_citations": cit_total,
            "valid_citations": cit_valid,
            "supported_citations": cit_supported,
            "hallucinated_citations": cit_hallucinated,
        },
        "drafts": {
            "total_drafts": drafts_total,
            "adopted": drafts_adopted,
            "modified": drafts_modified,
            "rejected": drafts_rejected,
        },
        "human_effort": {
            "minutes": human_minutes,
            "cost": human_cost,
            "cases_evaluated": len(records),
        },
        "safety": {
            "unauthorized_egress_count": unauth_egress,
            "unauthorized_alterations_count": unauth_alter,
        },
    }

    report = evaluate(
        expected=all_expected,
        actual=all_actual,
        artifacts=merged_artifacts,
    )

    gate: GateReport | None = None
    if policy_path:
        p_path = Path(policy_path).resolve()
        if not p_path.exists():
            raise FileNotFoundError(f"判定政策檔案不存在: {p_path}")
        policy = json.loads(p_path.read_text(encoding="utf-8"))
        gate = check_release(report, policy)

    out_payload: dict[str, Any] = {
        "manifest_id": manifest.get("manifest_id"),
        "family_id": manifest.get("family_id"),
        "split": manifest.get("split"),
        "mode": manifest.get("mode"),
        "rule_pack_version": manifest.get("rule_pack_version"),
        "model_version": manifest.get("model_version"),
        "evaluated_at": datetime.now(UTC).isoformat(),
        "evaluation_report": report.model_dump(),
    }
    if gate:
        out_payload["gate_report"] = gate.model_dump()

    out_p = Path(output_path).resolve()
    out_p.parent.mkdir(parents=True, exist_ok=True)
    out_p.write_text(json.dumps(out_payload, ensure_ascii=False, indent=2), encoding="utf-8")

    return out_payload
