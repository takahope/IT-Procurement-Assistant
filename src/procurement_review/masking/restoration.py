import re

from procurement_review.domain.models import MaskingSession, RestorationResult
from procurement_review.masking.session import get_session_mapping


def restore(text: str, session: MaskingSession) -> RestorationResult:
    """本機安全還原已遮罩文字。

    保證：
    - 僅還原屬於當前會話命名空間（session_id[:8]）的有效 token
    - 跨案／跨會話 token 標註於 wrong_case_tokens 並拒絕採用 (adoptable=False)
    - 模型幻覺或未知 token 標註於 unknown_tokens 並拒絕採用 (adoptable=False)
    - 原文既有之假 token（如 <PERSON_1>）安全保留，絕不替換為實體名稱
    """
    mapping = get_session_mapping(session.session_id)
    token_to_original: dict[str, str] = mapping.token_to_original if mapping else {}
    literal_escapes: set[str] = mapping.literal_escapes if mapping else set()

    unknown_tokens: list[str] = []
    wrong_case_tokens: list[str] = []
    current_prefix = session.session_id[:8]

    # 1. 掃描帶有命名空間的標準 token: [<TYPE>_<tag>_<idx>]
    namespaced_pat = re.compile(r"\[([A-Z_]+)_([a-zA-Z0-9_-]+)_([0-9]+)\]")
    for m in namespaced_pat.finditer(text):
        full_tok = m.group(0)
        tag = m.group(2)

        if full_tok in literal_escapes:
            continue

        if tag == current_prefix:
            if full_tok not in token_to_original and full_tok not in unknown_tokens:
                unknown_tokens.append(full_tok)
        else:
            if full_tok not in wrong_case_tokens:
                wrong_case_tokens.append(full_tok)

    # 2. 掃描無命名空間之簡短假 token: <TYPE_idx> 或 [TYPE_idx]
    simple_pat = re.compile(r"<([A-Z_]+_[0-9]+)>|\[([A-Z_]+_[0-9]+)\]")
    for m in simple_pat.finditer(text):
        full_tok = m.group(0)
        if full_tok in literal_escapes:
            continue
        if full_tok not in token_to_original and full_tok not in unknown_tokens:
            unknown_tokens.append(full_tok)

    # 3. 進行已知 token 的替換還原
    restored_text = text
    for tok, original in token_to_original.items():
        restored_text = restored_text.replace(tok, original)

    adoptable = len(wrong_case_tokens) == 0 and len(unknown_tokens) == 0

    return RestorationResult(
        text=restored_text,
        unknown_tokens=unknown_tokens,
        wrong_case_tokens=wrong_case_tokens,
        adoptable=adoptable,
    )
