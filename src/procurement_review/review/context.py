"""Context Bundle Builder for Procurement Review.

按資安審查要求全面檢索已確認文件快照，提取相關條款、原文 SourceSpan、定義詞與例外（但書），
解析跨條款與跨附件交叉引用，防護循環引用無窮迴圈，嚴格檢驗必要附件與字元預算上限。
"""

import re
import uuid

from procurement_review.documents.structure import Clause, DocumentSnapshot, SourceSpan
from procurement_review.domain.models import ContextBundle, Requirement, VersionRef

_CLAUSE_REF_RE = re.compile(
    r"(第\s*[一二三四五六七八九十百0-9]+\s*條|Article\s+\d+|Section\s+\d+(?:\.\d+)*)",
    re.IGNORECASE,
)
_APPENDIX_REF_RE = re.compile(
    r"(附件\s*[一二三四五六七八九十百0-9A-Za-z]+|附表\s*[一二三四五六七八九十百0-9A-Za-z]+|附錄\s*[一二三四五六七八九十百0-9A-Za-z]+|Appendix\s+[A-Za-z0-9]+|Schedule\s+[A-Za-z0-9]+|Exhibit\s+[A-Za-z0-9]+)",
    re.IGNORECASE,
)
_DEFINITION_RE = re.compile(
    r"[「“]([^」”]+)[」”]\s*(?:[：:]|係指|指)\s*([^。\n]+)",
)
_EXCEPTION_RE = re.compile(
    r"(但(?:符合|經|書|若)?[^。\n]+(?:不在此限|除外)?|除[^。\n]+外(?:[，,][^。\n]+)?|不在此限)",
)

# 領域常見關鍵詞詞典，輔助 obligation 語意切分
_DOMAIN_SECURITY_TERMS = [
    "保密",
    "機密",
    "機敏",
    "個人資料",
    "個資",
    "稽核",
    "備份",
    "通知",
    "通報",
    "源碼",
    "原始碼",
    "弱點",
    "SLA",
    "授權",
    "EULA",
    "責任",
    "委外",
    "複委託",
    "資安",
    "安全",
    "維護",
    "損害賠償",
    "智財",
    "智慧財產",
    "退場",
    "交付",
    "修補",
    "災難復原",
    "日誌",
    "存取",
    "憑證",
    "加密",
    "驗收",
    "授權書",
    "承諾書",
    "公證",
    "切結",
]


def _normalize_string(s: str) -> str:
    return re.sub(r"\s+", "", s).lower()


def _matches_required_document(doc: DocumentSnapshot, req_doc: str) -> bool:
    """檢查單一文件快照是否符合要求之必要文件類型（如 EULA、保密同意書等）"""
    norm_req = _normalize_string(req_doc)

    # 檢查 manifest 各類中繼欄位
    manifest = doc.manifest or {}
    candidates = [
        manifest.get("document_type", ""),
        manifest.get("doc_type", ""),
        manifest.get("title", ""),
        manifest.get("category", ""),
        doc.original_filename,
    ]
    for cand in candidates:
        if cand and norm_req in _normalize_string(str(cand)):
            return True

    # 針對 EULA / 授權書進行常見別名匹配
    if norm_req in ("eula", "原廠授權書", "原廠軟體合法授權書"):
        eula_aliases = ["eula", "授權合約", "授權書", "license", "enduser"]
        for cand in candidates:
            cand_norm = _normalize_string(str(cand))
            if any(alias in cand_norm for alias in eula_aliases):
                return True

    return False


def _extract_keywords_from_requirement(requirement: Requirement) -> set[str]:
    """從 Requirement 提取檢索關鍵詞集合"""
    keywords: set[str] = set()

    for item in requirement.evidence_requirements:
        if item.strip():
            keywords.add(item.strip())
            # 亦加入去空白版本
            keywords.add(_normalize_string(item))

    for item in requirement.protected_constraints:
        if item.strip():
            keywords.add(item.strip())

    # 從 obligation 擷取關鍵詞
    obl_text = requirement.obligation or ""
    for term in _DOMAIN_SECURITY_TERMS:
        if term.lower() in obl_text.lower():
            keywords.add(term)

    # 檢查 deterministic_checks 中可能指定之關鍵字
    for check in requirement.deterministic_checks:
        for val in check.values():
            if isinstance(val, str) and val.strip():
                keywords.add(val.strip())

    return keywords


def _clause_matches_requirement(clause: Clause, keywords: set[str]) -> bool:
    """判斷契約條款是否與要求相關"""
    c_title = clause.title or ""
    c_num = clause.clause_number or ""
    c_text = clause.text or ""

    c_all = f"{c_num} {c_title} {c_text}"

    for kw in keywords:
        if not kw:
            continue
        if kw in c_all or kw.lower() in c_all.lower():
            return True

    return False


def build_context(
    requirement: Requirement,
    documents: list[DocumentSnapshot],
    max_chars: int,
) -> ContextBundle:
    """按資安要求於文件快照中建置推論上下文組合 (ContextBundle)

    1. 檢驗 requirement.required_documents：缺少必要文件時 complete=False 並列於 unknowns。
    2. 檢查文件快照人工確認狀態：未經確認之文件列於 unknowns 與 retrieval status。
    3. 檢索與要求相關之條款，擷取精確 SourceSpan。
    4. 解析條款與附件之交叉引用（Cross References），防止循環引用（Circular References）卡死。
    5. 萃取合約名詞定義與但書例外條款。
    6. 檢核字元預算上限：超出 max_chars 時絕不截斷後宣稱完整，回傳 complete=False 與超出說明。
    """
    complete = True
    unknowns: list[str] = []
    document_retrieval_status: dict[str, str] = {}
    citations: list[str] = []
    definitions: dict[str, str] = {}
    exceptions: list[str] = []
    matched_spans: list[SourceSpan] = []

    # 1. 檢驗必要文件 (required_documents)
    for req_doc in requirement.required_documents:
        found = any(_matches_required_document(doc, req_doc) for doc in documents)
        if found:
            document_retrieval_status[req_doc] = "present"
        else:
            document_retrieval_status[req_doc] = "missing"
            unknowns.append(f"缺少必要文件: {req_doc}")
            complete = False

    # 2. 篩選已確認文件快照
    has_any_confirmed = any(doc.confirmation_ref is not None for doc in documents)
    if has_any_confirmed:
        confirmed_docs = [doc for doc in documents if doc.confirmation_ref is not None]
        unconfirmed_docs = [doc for doc in documents if doc.confirmation_ref is None]
        for ud in unconfirmed_docs:
            document_retrieval_status[ud.original_filename] = "unconfirmed"
            unknowns.append(f"文件尚未確認: {ud.original_filename}")
            complete = False
    else:
        # 合成環境未指定 confirmation_ref 時全數採納
        confirmed_docs = documents

    for doc in confirmed_docs:
        document_retrieval_status[doc.original_filename] = "retrieved"

    # 3. 關鍵字檢索條款
    keywords = _extract_keywords_from_requirement(requirement)
    matched_clauses: list[tuple[DocumentSnapshot, Clause]] = []
    matched_clause_ids: set[str] = set()

    for doc in confirmed_docs:
        for clause in doc.clauses:
            if _clause_matches_requirement(clause, keywords):
                matched_clauses.append((doc, clause))
                matched_clause_ids.add(clause.clause_id)

    # 4. 解析交叉引用 (Cross-References) 與防止循環引用 (Circular References)
    # 建立條款與附件索引
    clause_lookup: dict[str, tuple[DocumentSnapshot, Clause]] = {}
    for doc in confirmed_docs:
        for c in doc.clauses:
            if c.clause_number:
                clause_lookup[_normalize_string(c.clause_number)] = (doc, c)
            if c.title:
                clause_lookup[_normalize_string(c.title)] = (doc, c)

    visited_keys: set[str] = set()
    visiting_keys: set[str] = set()
    call_stack: list[tuple[str, str]] = []  # (key, label)

    def _resolve_references_dfs(doc: DocumentSnapshot, clause: Clause):
        nonlocal complete
        c_key = f"{doc.document_id}#{clause.clause_id}"
        c_label = clause.clause_number or clause.title or clause.clause_id

        visiting_keys.add(c_key)
        call_stack.append((c_key, c_label))

        # 掃描條款內文中的條款引用與附件引用
        clause_refs = _CLAUSE_REF_RE.findall(clause.text)
        appendix_refs = _APPENDIX_REF_RE.findall(clause.text)

        # 條款引用
        for match in clause_refs:
            ref_text = match.strip()
            norm_ref = _normalize_string(ref_text)
            # 排除條款自身編號
            if clause.clause_number and norm_ref == _normalize_string(clause.clause_number):
                continue

            if ref_text not in citations:
                citations.append(ref_text)

            target = clause_lookup.get(norm_ref)
            if target:
                t_doc, t_clause = target
                t_key = f"{t_doc.document_id}#{t_clause.clause_id}"

                if t_key in visiting_keys:
                    # 循環引用！從 call_stack 找出回圈路徑
                    cycle_start_idx = next(i for i, (k, _) in enumerate(call_stack) if k == t_key)
                    cycle_labels = [lbl for _, lbl in call_stack[cycle_start_idx:]] + [ref_text]
                    cycle_repr = " -> ".join(cycle_labels)
                    unknowns.append(f"偵測到條款循環引用: {cycle_repr}")
                    complete = False
                elif t_key not in visited_keys:
                    if t_clause.clause_id not in matched_clause_ids:
                        matched_clauses.append((t_doc, t_clause))
                        matched_clause_ids.add(t_clause.clause_id)
                    _resolve_references_dfs(t_doc, t_clause)
            else:
                document_retrieval_status[ref_text] = "missing"
                unknowns.append(f"未取得引用之文件或條款: {ref_text}")
                complete = False

        # 附件引用
        for match in appendix_refs:
            ref_text = match.strip()
            norm_ref = _normalize_string(ref_text)
            if ref_text not in citations:
                citations.append(ref_text)

            found_app = False
            for d in confirmed_docs:
                if norm_ref in _normalize_string(d.original_filename):
                    found_app = True
                    break
                for c in d.clauses:
                    if norm_ref in _normalize_string(c.clause_number or "") or norm_ref in _normalize_string(c.title or ""):
                        found_app = True
                        if c.clause_id not in matched_clause_ids:
                            matched_clauses.append((d, c))
                            matched_clause_ids.add(c.clause_id)
                        break
                if found_app:
                    break

            if not found_app:
                document_retrieval_status[ref_text] = "missing"
                unknowns.append(f"未取得引用之文件或條款: {ref_text}")
                complete = False

        call_stack.pop()
        visiting_keys.remove(c_key)
        visited_keys.add(c_key)

    # 對所有初始關鍵字命中的條款依序展開 DFS
    initial_matches = list(matched_clauses)
    for doc, clause in initial_matches:
        c_key = f"{doc.document_id}#{clause.clause_id}"
        if c_key not in visited_keys:
            _resolve_references_dfs(doc, clause)

    # 5. 萃取名詞定義與例外條款
    for doc in confirmed_docs:
        for c in doc.clauses:
            for m in _DEFINITION_RE.finditer(c.text):
                term = m.group(1).strip()
                d_text = m.group(2).strip()
                definitions[term] = d_text

    for _, c in matched_clauses:
        for m in _EXCEPTION_RE.finditer(c.text):
            exp_text = m.group(0).strip()
            if exp_text not in exceptions:
                exceptions.append(exp_text)

    # 6. 組裝 SourceSpans
    for doc, c in matched_clauses:
        if c.spans:
            matched_spans.extend(c.spans)
        else:
            bid = c.block_ids[0] if c.block_ids else str(uuid.uuid4())
            try:
                uuid.UUID(bid)
                valid_bid = bid
            except (ValueError, TypeError, AttributeError):
                valid_bid = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(bid)))

            did = str(doc.document_id)
            try:
                uuid.UUID(did)
                valid_did = did
            except (ValueError, TypeError, AttributeError):
                valid_did = str(uuid.uuid5(uuid.NAMESPACE_DNS, str(did)))

            span = SourceSpan(
                document_id=valid_did,
                block_id=valid_bid,
                start_offset=0,
                end_offset=len(c.text),
                page_number=1,
                structural_path=c.clause_number or c.title or "",
            )
            matched_spans.append(span)

    # 7. 字元預算上限檢核 (max_chars)
    total_matched_chars = (
        sum(len(c.text) for _, c in matched_clauses)
        + sum(len(v) for v in definitions.values())
        + sum(len(e) for e in exceptions)
    )

    if total_matched_chars > max_chars:
        complete = False
        unknowns.append(
            f"內文字元數 ({total_matched_chars}) 超出預算上限 ({max_chars})，無法保證完整上下文"
        )

    # 去重 unknowns 與 citations
    unique_unknowns = list(dict.fromkeys(unknowns))
    unique_citations = list(dict.fromkeys(citations))

    req_ref = VersionRef(
        id=requirement.requirement_id,
        version=requirement.version,
        sha256=requirement.rule_ref.sha256,
    )

    return ContextBundle(
        requirement_ref=req_ref,
        source_spans=matched_spans,
        definitions=definitions,
        exceptions=exceptions,
        citations=unique_citations,
        document_retrieval_status=document_retrieval_status,
        complete=complete,
        unknowns=unique_unknowns,
    )
