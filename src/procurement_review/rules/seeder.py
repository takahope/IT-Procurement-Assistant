import json
import logging
from datetime import UTC, datetime
from pathlib import Path

from procurement_review.domain.enums import RuleStatus
from procurement_review.domain.models import Requirement, Rule, SourceReference
from procurement_review.rules.catalog import compute_rule_hash, rule_to_requirement
from procurement_review.storage.repository import Repository

logger = logging.getLogger(__name__)


def seed_rules_and_sources(
    repo: Repository,
    rules_root: Path | None = None,
    active: bool = True,
    approver: str = "資安審查委員會",
) -> dict[str, int]:
    """將檔案系統中的法規來源與規則草稿同步/種子化至 Repository 儲存庫。

    參數：
    - repo: 目標儲存庫實例。
    - rules_root: 規則定義目錄（預設為專案 rules/ 目錄）。
    - active: 是否直接標記為 ACTIVE（synthetic 模式預設為 True）。
    - approver: 核准人名稱（標記 ACTIVE 時填寫）。

    回傳：
    - {"sources": count, "rules": count, "requirements": count}
    """
    if rules_root is None:
        rules_root = Path.cwd() / "rules"
        if not rules_root.exists():
            rules_root = Path(__file__).resolve().parent.parent.parent.parent / "rules"

    counts = {"sources": 0, "rules": 0, "requirements": 0}

    # 1. 匯入法規與內規來源 (manifest.json)
    manifest_file = rules_root / "sources" / "manifest.json"
    if manifest_file.exists():
        with open(manifest_file, "r", encoding="utf-8") as f:
            m_data = json.load(f)
        for s in m_data.get("sources", []):
            s_kwargs = {k: v for k, v in s.items() if k != "retrieval_status"}
            src = SourceReference.model_validate(s_kwargs)
            repo.save_source(src)
            counts["sources"] += 1

    # 2. 匯入各分類規則包 (drafts/*.json)
    drafts_dir = rules_root / "drafts"
    if drafts_dir.exists():
        for df in sorted(drafts_dir.glob("*.json")):
            with open(df, "r", encoding="utf-8") as f:
                content = json.load(f)

            rules_map: dict[tuple[str, str], Rule] = {}
            for r_dict in content.get("rules", []):
                rule = Rule.model_validate(r_dict)
                if active:
                    rule = rule.model_copy(
                        update={
                            "status": RuleStatus.ACTIVE,
                            "approved_by": approver,
                            "approved_at": datetime.now(UTC),
                        }
                    )
                else:
                    rule = rule.model_copy(update={"status": RuleStatus.PENDING_APPROVAL})
                repo.save_rule(rule)
                rules_map[(rule.rule_id, rule.version)] = rule
                counts["rules"] += 1

            req_list = content.get("requirements", [])
            if req_list:
                for req_dict in req_list:
                    req = Requirement.model_validate(req_dict)
                    target_rule = rules_map.get((req.rule_ref.id, req.rule_ref.version))
                    if target_rule:
                        r_hash = compute_rule_hash(target_rule)
                        req = req.model_copy(
                            update={"rule_ref": req.rule_ref.model_copy(update={"sha256": r_hash})}
                        )
                    repo.save_requirement(req)
                    counts["requirements"] += 1
            else:
                for rule in rules_map.values():
                    req = rule_to_requirement(rule)
                    repo.save_requirement(req)
                    counts["requirements"] += 1

    return counts
