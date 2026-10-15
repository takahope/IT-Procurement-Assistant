import hashlib
import json

from procurement_review.domain.enums import ProcurementFamily, RuleStatus
from procurement_review.domain.models import (
    Requirement,
    Rule,
    SourceReference,
    VersionRef,
)


def compute_rule_hash(rule: Rule) -> str:
    """計算 Rule 確定性雜湊值。"""
    raw = (
        f"{rule.rule_id}:{rule.version}:{rule.title}:{rule.category.value}:"
        f"{rule.requirement_text}:{rule.mandatory}:{rule.severity.value}:"
        f"{json.dumps(rule.applicability, sort_keys=True)}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_source_hash(source: SourceReference) -> str:
    """計算 SourceReference 確定性雜湊值。"""
    raw = f"{source.source_id}:{source.version}:{source.title}:{source.content_hash}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_requirement_hash(req: Requirement) -> str:
    """計算 Requirement 確定性雜湊值。"""
    raw = f"{req.requirement_id}:{req.version}:{req.obligation}:{req.obligor}:{req.condition}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def rule_to_requirement(rule: Rule) -> Requirement:
    """將單一 Rule 轉換為單一可判斷資安要求契約 Requirement。"""
    r_hash = compute_rule_hash(rule)
    rule_ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
    condition_str = json.dumps(rule.applicability) if rule.applicability else None

    return Requirement(
        requirement_id=rule.rule_id,
        version=rule.version,
        rule_ref=rule_ref,
        obligation=rule.requirement_text,
        obligor="廠商",
        condition=condition_str,
        mandatory=rule.mandatory,
        evidence_requirements=[],
        deterministic_checks=rule.deterministic_checks,
        risk_level=rule.severity,
        required_documents=[],
        protected_constraints=[],
    )


class RuleCatalog:
    """規則與法源目錄（Registry / Catalog），提供查詢與註冊資料結構。"""

    def __init__(self) -> None:
        self._rules: dict[tuple[str, str], Rule] = {}
        self._sources: dict[str, SourceReference] = {}
        self._requirements: dict[str, Requirement] = {}

    def register_rule(self, rule: Rule) -> None:
        self._rules[(rule.rule_id, rule.version)] = rule
        req = rule_to_requirement(rule)
        self._requirements[req.requirement_id] = req

    def register_source(self, source: SourceReference) -> None:
        self._sources[source.source_id] = source

    def get_rule(self, rule_id: str, version: str | None = None) -> Rule | None:
        if version is not None:
            return self._rules.get((rule_id, version))
        matching = [r for (rid, _), r in self._rules.items() if rid == rule_id]
        if not matching:
            return None
        return matching[-1]

    def get_source(self, source_id: str) -> SourceReference | None:
        return self._sources.get(source_id)

    def get_requirement(self, requirement_id: str) -> Requirement | None:
        return self._requirements.get(requirement_id)

    def list_active_rules(
        self,
        category: ProcurementFamily | None = None,
    ) -> list[Rule]:
        results: list[Rule] = []
        for rule in self._rules.values():
            if rule.status != RuleStatus.ACTIVE:
                continue
            if category is not None and rule.category != category:
                continue
            results.append(rule)
        return results
