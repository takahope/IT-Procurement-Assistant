import json
from datetime import date
from decimal import Decimal
from enum import Enum
from typing import Any

from procurement_review.domain.enums import ApplicabilityState
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import (
    ApplicabilityDecision,
    CaseFacts,
    Requirement,
    Rule,
    VersionRef,
)
from procurement_review.rules.catalog import (
    compute_requirement_hash,
    compute_rule_hash,
)

FORBIDDEN_OPERATORS = {
    "eval",
    "exec",
    "compile",
    "__import__",
    "open",
    "system",
    "subprocess",
    "shutil",
    "os",
    "sys",
}

VALID_OPERATORS = {
    "all",
    "any",
    "not",
    "eq",
    "in",
    "gte",
    "lte",
    "exists",
}


def _resolve_operand(operand: Any, facts: CaseFacts) -> tuple[Any, bool]:
    """解析運算元。若為 CaseFacts 的欄位名稱，則取出其值。

    回傳：(數值, 是否為未知 unknown)
    """
    if isinstance(operand, str) and hasattr(facts, operand):
        if operand in facts.unknown_fields:
            return None, True
        val = getattr(facts, operand)
        if val is None:
            return None, True
        return val, False
    return operand, False


def _normalize_value(val: Any) -> Any:
    """標準化數值以利比較（如 Enum 轉字串，數值轉 Decimal）。"""
    if isinstance(val, Enum):
        return val.value
    return val


def evaluate_condition(cond: Any, facts: CaseFacts) -> bool | None:
    """安全宣告式條件引擎，使用三值邏輯 (True, False, None=Unknown)。

    嚴格禁止 eval 或任意程式碼執行。
    若條件參照之 facts 欄位為 None 或列於 unknown_fields，回傳 None (unknown)。
    """
    if cond is None or cond == {} or cond == "":
        return True

    if isinstance(cond, str):
        try:
            cond = json.loads(cond)
        except Exception as e:
            raise DomainError("MALFORMED_CONDITION", f"Invalid condition string: {cond}") from e

    if not isinstance(cond, dict):
        raise DomainError(
            "MALFORMED_CONDITION",
            f"Condition must be a dictionary or JSON object, got {type(cond).__name__}",
        )

    # 安全檢驗：阻擋可疑操作
    for k in cond:
        if k.lower() in FORBIDDEN_OPERATORS or "__" in k:
            raise DomainError(
                "SECURITY_VIOLATION",
                f"Forbidden operator or code execution attempt detected: {k!r}",
            )

    # 1. 邏輯運算子：all
    if "all" in cond:
        items = cond["all"]
        if not isinstance(items, list):
            raise DomainError("MALFORMED_CONDITION", "'all' operator expects a list")
        has_unknown = False
        for item in items:
            res = evaluate_condition(item, facts)
            if res is False:
                return False  # Kleene logic: False AND anything = False
            if res is None:
                has_unknown = True
        return None if has_unknown else True

    # 2. 邏輯運算子：any
    if "any" in cond:
        items = cond["any"]
        if not isinstance(items, list):
            raise DomainError("MALFORMED_CONDITION", "'any' operator expects a list")
        has_unknown = False
        for item in items:
            res = evaluate_condition(item, facts)
            if res is True:
                return True  # Kleene logic: True OR anything = True
            if res is None:
                has_unknown = True
        return None if has_unknown else False

    # 3. 邏輯運算子：not
    if "not" in cond:
        inner = cond["not"]
        res = evaluate_condition(inner, facts)
        if res is None:
            return None
        return not res

    # 4. 比較運算子：eq
    if "eq" in cond:
        operands = cond["eq"]
        if isinstance(operands, list) and len(operands) == 2:
            left, right = operands
        elif isinstance(operands, dict) and "field" in operands and "value" in operands:
            left, right = operands["field"], operands["value"]
        else:
            raise DomainError("MALFORMED_CONDITION", "'eq' operator expects a 2-element list or {field, value}")

        v1, unk1 = _resolve_operand(left, facts)
        v2, unk2 = _resolve_operand(right, facts)
        if unk1 or unk2:
            return None
        v1_norm = _normalize_value(v1)
        v2_norm = _normalize_value(v2)
        return v1_norm == v2_norm

    # 5. 比較運算子：in
    if "in" in cond:
        operands = cond["in"]
        if isinstance(operands, list) and len(operands) == 2:
            first, second = operands
        else:
            raise DomainError("MALFORMED_CONDITION", "'in' operator expects a 2-element list [item, collection]")

        v1, unk1 = _resolve_operand(first, facts)
        v2, unk2 = _resolve_operand(second, facts)
        if unk1 or unk2:
            return None

        # 支援 [item, collection] 或 [collection, item]
        if isinstance(v2, (list, set, tuple)):
            item, collection = v1, v2
        elif isinstance(v1, (list, set, tuple)):
            item, collection = v2, v1
        else:
            raise DomainError("MALFORMED_CONDITION", "'in' operator requires at least one iterable collection")

        item_norm = _normalize_value(item)
        collection_norms = [_normalize_value(x) for x in collection]
        return item_norm in collection_norms

    # 6. 比較運算子：gte
    if "gte" in cond:
        operands = cond["gte"]
        if isinstance(operands, list) and len(operands) == 2:
            left, right = operands
        else:
            raise DomainError("MALFORMED_CONDITION", "'gte' operator expects a 2-element list")

        v1, unk1 = _resolve_operand(left, facts)
        v2, unk2 = _resolve_operand(right, facts)
        if unk1 or unk2:
            return None

        # 數值型別轉換 (如 Decimal 與 int)
        if isinstance(v1, Decimal) or isinstance(v2, Decimal):
            v1 = Decimal(str(v1))
            v2 = Decimal(str(v2))
        return v1 >= v2

    # 7. 比較運算子：lte
    if "lte" in cond:
        operands = cond["lte"]
        if isinstance(operands, list) and len(operands) == 2:
            left, right = operands
        else:
            raise DomainError("MALFORMED_CONDITION", "'lte' operator expects a 2-element list")

        v1, unk1 = _resolve_operand(left, facts)
        v2, unk2 = _resolve_operand(right, facts)
        if unk1 or unk2:
            return None

        if isinstance(v1, Decimal) or isinstance(v2, Decimal):
            v1 = Decimal(str(v1))
            v2 = Decimal(str(v2))
        return v1 <= v2

    # 8. 存在性運算子：exists
    if "exists" in cond:
        target = cond["exists"]
        if not isinstance(target, str):
            raise DomainError("MALFORMED_CONDITION", "'exists' expects a field name string")
        if target in facts.unknown_fields:
            return None
        if hasattr(facts, target):
            val = getattr(facts, target)
            if val is None:
                return None
            if isinstance(val, (list, set, tuple, dict)):
                return len(val) > 0
            return True
        return False

    # 9. 欄位為鍵的簡易比對：例如 {"procurement_system": "政府採購法"}
    sub_results: list[bool | None] = []
    for k, v in cond.items():
        if k not in VALID_OPERATORS:
            if hasattr(facts, k):
                val, is_unk = _resolve_operand(k, facts)
                if is_unk:
                    sub_results.append(None)
                else:
                    val_norm = _normalize_value(val)
                    expected_norm = _normalize_value(v)
                    sub_results.append(val_norm == expected_norm)
            else:
                raise DomainError(
                    "UNSUPPORTED_OPERATOR",
                    f"Unsupported operator or unknown condition field: {k!r}",
                )

    if not sub_results:
        return True
    if any(r is False for r in sub_results):
        return False
    if any(r is None for r in sub_results):
        return None
    return True


def evaluate_applicability(
    requirement: Requirement | Rule,
    facts: CaseFacts,
    as_of: date | None = None,
) -> ApplicabilityDecision:
    """依據案件事實與基準日期判定單一資安要求／規則之適用性。

    核心規格保證：
    - 半開區間日期效期檢核 [effective_from, effective_to)。
    - 三值宣告式條件邏輯 (applicable, not_applicable, unknown)。
    - 若事實為未知 (None)，絕不推定為 not_applicable，必標示為 unknown。
    - 指南／作業手冊保留建議性質，不作為強制法令。
    """
    ref_date = as_of or facts.review_baseline_date

    if isinstance(requirement, Rule):
        rule = requirement
        r_hash = compute_rule_hash(rule)
        ref = VersionRef(id=rule.rule_id, version=rule.version, sha256=r_hash)
        cond = rule.applicability
        is_guideline = not rule.mandatory
        effective_from = rule.effective_from
        effective_to = rule.effective_to
    else:
        req = requirement
        r_hash = compute_requirement_hash(req)
        ref = VersionRef(id=req.requirement_id, version=req.version, sha256=r_hash)
        cond = req.condition
        is_guideline = not req.mandatory
        effective_from = None
        effective_to = None

    reasons: list[str] = []
    if is_guideline:
        reasons.append("guideline_recommendation: 建議性質，非強制性法定要求")

    # 1. 期限檢驗：採半開區間 [effective_from, effective_to)
    if effective_from is not None and ref_date < effective_from:
        reasons.append(f"Baseline date {ref_date} is before effective_from {effective_from}")
        return ApplicabilityDecision(
            requirement_ref=ref,
            state=ApplicabilityState.NOT_APPLICABLE,
            reasons=reasons,
        )

    if effective_to is not None and ref_date >= effective_to:
        reasons.append(f"Baseline date {ref_date} is on or after effective_to {effective_to}")
        return ApplicabilityDecision(
            requirement_ref=ref,
            state=ApplicabilityState.NOT_APPLICABLE,
            reasons=reasons,
        )

    # 2. 條件檢驗
    eval_result = evaluate_condition(cond, facts)
    if eval_result is True:
        reasons.append("Applicable based on confirmed case facts")
        return ApplicabilityDecision(
            requirement_ref=ref,
            state=ApplicabilityState.APPLICABLE,
            reasons=reasons,
        )
    elif eval_result is False:
        reasons.append("Not applicable based on confirmed case facts")
        return ApplicabilityDecision(
            requirement_ref=ref,
            state=ApplicabilityState.NOT_APPLICABLE,
            reasons=reasons,
        )
    else:
        reasons.append("Fact(s) referenced by condition are unknown or unconfirmed")
        return ApplicabilityDecision(
            requirement_ref=ref,
            state=ApplicabilityState.UNKNOWN,
            reasons=reasons,
        )
