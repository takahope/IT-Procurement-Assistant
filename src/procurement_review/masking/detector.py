import re
import uuid
from typing import Protocol, runtime_checkable

from procurement_review.domain.models import DetectedSpan, SourceSpan

ROC_LETTER_MAP = {
    "A": 10,
    "B": 11,
    "C": 12,
    "D": 13,
    "E": 14,
    "F": 15,
    "G": 16,
    "H": 17,
    "I": 34,
    "J": 18,
    "K": 19,
    "L": 20,
    "M": 21,
    "N": 22,
    "O": 35,
    "P": 23,
    "Q": 24,
    "R": 25,
    "S": 26,
    "T": 27,
    "U": 28,
    "V": 29,
    "W": 32,
    "X": 30,
    "Y": 31,
    "Z": 33,
}

COMMERCIAL_EXCLUSIONS = {
    "個人資料保護法",
    "政府採購法",
    "營業秘密法",
    "著作權法",
    "資通安全管理法",
    "資通安全管理法施行細則",
    "中央法規標準法",
    "勞動基準法",
    "智慧財產權法",
    "民法",
    "刑法",
    "行政程序法",
    "國家機密保護法",
    "採購法",
    "個資法",
    "資安法",
    "智慧財產權",
    "營業秘密",
    "專利權",
    "商標權",
    "甲方",
    "乙方",
    "丙方",
    "招標機關",
    "得標廠商",
    "履約廠商",
    "立約人",
    "立契約人",
    "專案經理",
    "專案負責人",
    "負責人",
    "代表人",
    "聯絡人",
    "承辦人",
    "審查人員",
}

ZH_SURNAMES = (
    "陳林黃張李王吳劉蔡楊許鄭謝郭洪曾邱廖賴周徐蘇葉莊呂江何蕭羅高簡朱鍾施游詹沈彭胡余盧顏柯翁魏孫樊范方鄧杜戴夏鐘汪田任姜范"
)


def _is_valid_roc_id(s: str) -> bool:
    if len(s) != 10:
        return False
    first = s[0].upper()
    if first not in ROC_LETTER_MAP:
        return False
    if not s[1:].isdigit():
        return False
    code = ROC_LETTER_MAP[first]
    n1 = code // 10
    n2 = code % 10
    weights = [1, 9, 8, 7, 6, 5, 4, 3, 2, 1, 1]
    digits = [n1, n2] + [int(c) for c in s[1:]]
    total = sum(w * d for w, d in zip(weights, digits, strict=True))
    return total % 10 == 0


def _is_valid_ubn(s: str) -> bool:
    if len(s) != 8 or not s.isdigit():
        return False
    if s.startswith(("19", "20")):
        return False
    weights = [1, 2, 1, 2, 1, 2, 4, 1]
    digits = [int(c) for c in s]
    prods = [w * d for w, d in zip(weights, digits, strict=True)]
    sum1 = sum((p // 10 + p % 10) for p in prods)
    if sum1 % 10 == 0:
        return True
    return bool(digits[6] == 7 and (sum1 + 1) % 10 == 0)


def _is_valid_luhn(card: str) -> bool:
    digits = [int(c) for c in card if c.isdigit()]
    if len(digits) != 16:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, d in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d
    return checksum % 10 == 0


@runtime_checkable
class Detector(Protocol):
    """PII 與機敏資訊偵測器介面"""

    def detect(self, text: str) -> list[DetectedSpan]:
        ...


class RuleBasedDetector:
    """離線繁體中文規則與安全偵測器"""

    def __init__(self) -> None:
        self.version = "rule-based-zh-tw-0.1.0"

    def detect(self, text: str) -> list[DetectedSpan]:
        raw_spans: list[tuple[int, int, str, str, float]] = []

        # 1. High Confidence Secrets
        # PEM private keys
        pem_pat = re.compile(
            r"-----BEGIN (?:[A-Z ]+)?PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z ]+)?PRIVATE KEY-----"
        )
        for m in pem_pat.finditer(text):
            raw_spans.append((m.start(), m.end(), "SECRET", "SECRET", 1.0))

        # AWS Access Key ID
        aws_pat = re.compile(r"(?<![A-Za-z0-9])AKIA[0-9A-Z]{16}(?![A-Za-z0-9])")
        for m in aws_pat.finditer(text):
            raw_spans.append((m.start(), m.end(), "SECRET", "SECRET", 1.0))

        # GitHub Tokens
        gh_pat = re.compile(
            r"(?<![A-Za-z0-9_])(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}(?![A-Za-z0-9_])"
        )
        for m in gh_pat.finditer(text):
            raw_spans.append((m.start(), m.end(), "SECRET", "SECRET", 1.0))

        # Bearer tokens
        bearer_pat = re.compile(r"(?<![A-Za-z0-9])Bearer\s+([A-Za-z0-9\-._~+/]+=*)")
        for m in bearer_pat.finditer(text):
            raw_spans.append((m.start(1), m.end(1), "SECRET", "SECRET", 1.0))

        # Config API Keys and passwords
        config_pat = re.compile(
            r"""(?i)(?<![A-Za-z0-9_-])(api[_-]?key|secret[_-]?key|access[_-]?token|private[_-]?key|client[_-]?secret|password|passwd|pwd)\s*[:=]\s*['"]?([A-Za-z0-9\-_./+=]{8,})['"]?"""
        )
        for m in config_pat.finditer(text):
            raw_spans.append((m.start(2), m.end(2), "SECRET", "SECRET", 1.0))

        # 2. Credit Cards
        cc_pat = re.compile(r"(?<!\d)(?:(?:\d{4}[- ]){3}\d{4}|\d{16})(?!\d)")
        for m in cc_pat.finditer(text):
            clean_digits = m.group(0).replace("-", "").replace(" ", "")
            if _is_valid_luhn(clean_digits):
                raw_spans.append((m.start(), m.end(), "CREDIT_CARD", "FINANCIAL", 1.0))

        # 3. Emails
        email_pat = re.compile(
            r"(?<![A-Za-z0-9._%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}(?![A-Za-z0-9.-])"
        )
        for m in email_pat.finditer(text):
            raw_spans.append((m.start(), m.end(), "EMAIL", "CONTACT", 1.0))

        # 4. Phones (Taiwan mobile and landline)
        mobile_pat = re.compile(
            r"(?<![A-Za-z0-9_])(09\d{2}[- ]?\d{3}[- ]?\d{3}|09\d{8})(?![A-Za-z0-9_])"
        )
        for m in mobile_pat.finditer(text):
            raw_spans.append((m.start(1), m.end(1), "PHONE", "CONTACT", 0.95))

        landline_pat = re.compile(
            r"(?<![A-Za-z0-9_])(\(0[2-8]\)\s*\d{4}[- ]?\d{4}|0[2-8][- ]?\d{4}[- ]?\d{4}|0[2-8]\d{8})(?![A-Za-z0-9_])"
        )
        for m in landline_pat.finditer(text):
            raw_spans.append((m.start(1), m.end(1), "PHONE", "CONTACT", 0.95))

        # 5. ID Numbers (Taiwan ROC ID and Unified Business Number)
        roc_pat = re.compile(r"(?<![A-Za-z0-9])[A-Z][1289]\d{8}(?![A-Za-z0-9])")
        for m in roc_pat.finditer(text):
            val = m.group(0)
            if _is_valid_roc_id(val):
                raw_spans.append((m.start(), m.end(), "ID_NUMBER", "PII", 1.0))

        ubn_pat = re.compile(r"(?:統一編號|統編|公司統編)[：:\s為]*(\d{8})")
        for m in ubn_pat.finditer(text):
            raw_spans.append((m.start(1), m.end(1), "ID_NUMBER", "PII", 1.0))

        standalone_ubn_pat = re.compile(r"(?<![A-Za-z0-9_])\d{8}(?![A-Za-z0-9_])")
        for m in standalone_ubn_pat.finditer(text):
            val = m.group(0)
            if _is_valid_ubn(val):
                raw_spans.append((m.start(), m.end(), "ID_NUMBER", "PII", 0.9))

        # 6. Locations (Taiwan addresses)
        loc_pat = re.compile(
            r"(?:臺北市|台北市|新北市|桃園市|臺中市|台中市|臺南市|台南市|高雄市|基隆市|新竹市|嘉義市|新竹縣|苗栗縣|彰化縣|南投縣|雲林縣|嘉義縣|屏東縣|宜蘭縣|花蓮縣|臺東縣|台東縣|澎湖縣|金門縣|連江縣)"
            r"(?:[^\s，。\n]{1,8}?(?:區|鄉|鎮|市))?"
            r"(?:[^\s，。\n]{1,10}?(?:路|街|大道)(?:[一二三四五六七八九十\d]+段)?)?"
            r"(?:[^\s，。\n]{1,8}?(?:巷|弄))?"
            r"(?:\d+[-之號\d]*號?)(?:\d+樓)?"
        )
        for m in loc_pat.finditer(text):
            val = m.group(0)
            raw_spans.append((m.start(), m.end(), "LOCATION", "PII", 0.95))

        # 7. Organizations
        org_pat = re.compile(
            r"([\u4e00-\u9fffA-Za-z0-9]{2,25}(?:股份有限公司|有限公司|企業社|事務所|顧問社|科技公司|行號|基金會|協會|工會|商行|醫院|診所|大學|科技大學|高級中學|國民中學|國民小學|研究院|研究所))"
        )
        for m in org_pat.finditer(text):
            val = m.group(1)
            if val not in COMMERCIAL_EXCLUSIONS:
                raw_spans.append((m.start(1), m.end(1), "ORGANIZATION", "PII", 0.95))

        specific_org_pat = re.compile(r"(?:財團法人[\u4e00-\u9fffA-Za-z0-9]{2,20}|中央研究院)")
        for m in specific_org_pat.finditer(text):
            val = m.group(0)
            if val not in COMMERCIAL_EXCLUSIONS:
                raw_spans.append((m.start(), m.end(), "ORGANIZATION", "PII", 0.95))

        # 8. Persons
        titles = "專案經理|專案負責人|負責人|代表人|聯絡人|承辦人|經理|專員|律師|會計師|組長|處長|主任|工程師|代表簽署人|簽署人|先生|小姐|君"
        person_prefix_pat = re.compile(
            rf"(?:{titles})[：:\s]*([{ZH_SURNAMES}][\u4e00-\u9fff]{{1,2}})"
        )
        known_names: set[str] = set()
        for m in person_prefix_pat.finditer(text):
            name = m.group(1)
            if name not in COMMERCIAL_EXCLUSIONS:
                raw_spans.append((m.start(1), m.end(1), "PERSON", "PII", 0.95))
                known_names.add(name)

        person_suffix_pat = re.compile(
            rf"([{ZH_SURNAMES}][\u4e00-\u9fff]{{1,2}})(?:先生|小姐|君|律師|經理|專員|處長|組長|主任|工程師)"
        )
        for m in person_suffix_pat.finditer(text):
            name = m.group(1)
            if name not in COMMERCIAL_EXCLUSIONS:
                raw_spans.append((m.start(1), m.end(1), "PERSON", "PII", 0.95))
                known_names.add(name)

        # Subsequent occurrences of known person names in the same text
        for name in known_names:
            start = 0
            while True:
                idx = text.find(name, start)
                if idx == -1:
                    break
                raw_spans.append((idx, idx + len(name), "PERSON", "PII", 0.95))
                start = idx + len(name)

        # Priority ordering for resolving overlapping spans
        type_priority = {
            "SECRET": 10,
            "CREDIT_CARD": 9,
            "ID_NUMBER": 8,
            "EMAIL": 7,
            "PHONE": 6,
            "LOCATION": 5,
            "ORGANIZATION": 4,
            "PERSON": 3,
        }

        # Sort: priority desc, length desc, start_offset asc
        sorted_spans = sorted(
            raw_spans,
            key=lambda x: (-type_priority.get(x[2], 0), -(x[1] - x[0]), x[0]),
        )

        # Resolve overlaps
        accepted: list[tuple[int, int, str, str, float]] = []
        for s_start, s_end, s_type, s_group, s_conf in sorted_spans:
            # Check overlap with already accepted spans
            overlaps = False
            for a_start, a_end, _, _, _ in accepted:
                if max(s_start, a_start) < min(s_end, a_end):
                    overlaps = True
                    break
            if not overlaps:
                accepted.append((s_start, s_end, s_type, s_group, s_conf))

        # Sort by start_offset
        accepted.sort(key=lambda x: x[0])

        # Convert to DetectedSpan
        dummy_id = "00000000-0000-0000-0000-000000000000"
        detected: list[DetectedSpan] = []
        for start_pos, end_pos, sp_type, sp_group, conf in accepted:
            original = text[start_pos:end_pos]
            span = DetectedSpan(
                span_id=str(uuid.uuid4()),
                span_type=sp_type,
                entity_group=sp_group,
                source_span=SourceSpan(
                    document_id=dummy_id,
                    block_id=dummy_id,
                    start_offset=start_pos,
                    end_offset=end_pos,
                ),
                original_text=original,
                masked_token="",
                confidence=conf,
            )
            detected.append(span)

        return detected
