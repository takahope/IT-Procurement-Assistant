import hashlib
import re
import uuid
from datetime import UTC, datetime
from pathlib import Path

from procurement_review.documents.docx_reader import read_docx
from procurement_review.documents.pdf_reader import read_pdf
from procurement_review.documents.structure import (
    Clause,
    DocumentBlock,
    DocumentSnapshot,
    QualityIssue,
    SourceSpan,
)
from procurement_review.domain.errors import DomainError
from procurement_review.domain.models import RuntimePolicy
from procurement_review.storage.vault import ArtifactStore

_CLAUSE_REGEXES = [
    re.compile(r"^(第\s*[一二三四五六七八九十百0-9]+\s*條)\s*([^\n]*)"),
    re.compile(r"^(Article\s+\d+)\s*([^\n]*)", re.IGNORECASE),
    re.compile(r"^([一二三四五六七八九十]、)\s*([^\n]*)"),
    re.compile(r"^(\d+\.\d+)\s*([^\n]*)"),
]


def ingest(
    path: Path, review_id: str, policy: RuntimePolicy, artifacts: ArtifactStore
) -> DocumentSnapshot:
    """安全擷取 DOCX 或文字 PDF 文件，進行結構分段與品質問題檢測

    1. 安全檢核檔案存在與副檔名
    2. 安全加密儲存原檔於 ArtifactStore
    3. 執行 DOCX / PDF 結構擷取與品質問題偵測
    4. 建立不可變初始 DocumentSnapshot (confirmation_ref 為 None)
    """
    path = Path(path).resolve()
    if not path.exists() or not path.is_file():
        raise DomainError("CORRUPT_DOCUMENT", f"文件不存在或非普通檔案: {path}")

    raw_bytes = path.read_bytes()
    file_hash = hashlib.sha256(raw_bytes).hexdigest()

    # 安全存入 ArtifactStore
    storage_artifact_id = artifacts.put(
        case_id=review_id,
        kind="original_document",
        data=raw_bytes,
    )

    suffix = path.suffix.lower()
    blocks: list[DocumentBlock] = []
    issues: list[QualityIssue] = []

    if suffix == ".docx":
        blocks, issues = read_docx(path)
    elif suffix == ".pdf":
        blocks, issues = read_pdf(path)
    else:
        raise DomainError(
            "UNSUPPORTED_DOCUMENT_TYPE",
            f"不支援之文件類型 '{suffix}'，僅支援 .docx 與 .pdf",
        )

    document_id = str(uuid.uuid4())
    snapshot_id = str(uuid.uuid4())

    manifest = {
        "original_filename": path.name,
        "file_size": len(raw_bytes),
        "content_sha256": file_hash,
        "storage_artifact_id": storage_artifact_id,
        "ingested_at": datetime.now(UTC).isoformat(),
        "policy_mode": policy.mode.value,
        "block_count": len(blocks),
        "issue_count": len(issues),
    }

    return DocumentSnapshot(
        document_id=document_id,
        snapshot_id=snapshot_id,
        original_filename=path.name,
        content_sha256=file_hash,
        blocks=blocks,
        clauses=[],
        issues=issues,
        manifest=manifest,
        confirmation_ref=None,
    )


def segment(snapshot: DocumentSnapshot) -> DocumentSnapshot:
    """將 DocumentSnapshot 中的區塊結構化分段為契約條款 (Clause)

    保留區塊與條款之對應關係，並為每個條款建立精確的 SourceSpan 定位。
    """
    clauses: list[Clause] = []
    current_clause: Clause | None = None

    for block in snapshot.blocks:
        raw = block.raw_text.strip()
        if not raw:
            continue

        matched_num: str | None = None
        matched_title: str | None = None

        for reg in _CLAUSE_REGEXES:
            m = reg.match(raw)
            if m:
                matched_num = m.group(1).strip()
                matched_title = m.group(2).strip() or None
                break

        span = SourceSpan(
            document_id=snapshot.document_id,
            block_id=block.block_id,
            start_offset=0,
            end_offset=len(block.raw_text),
            page_number=block.page_number,
            structural_path=block.structural_path,
        )

        if matched_num:
            if current_clause:
                clauses.append(current_clause)

            current_clause = Clause(
                clause_id=f"clause-{len(clauses) + 1}",
                clause_number=matched_num,
                title=matched_title,
                text=block.raw_text,
                block_ids=[block.block_id],
                spans=[span],
            )
        else:
            if current_clause:
                current_clause.block_ids.append(block.block_id)
                current_clause.spans.append(span)
                current_clause.text += "\n" + block.raw_text
            else:
                # 尚未進入編號條款的前言或無編號段落
                current_clause = Clause(
                    clause_id=f"clause-{len(clauses) + 1}",
                    clause_number=None,
                    title=None,
                    text=block.raw_text,
                    block_ids=[block.block_id],
                    spans=[span],
                )

    if current_clause:
        clauses.append(current_clause)

    return DocumentSnapshot(
        document_id=snapshot.document_id,
        snapshot_id=snapshot.snapshot_id,
        original_filename=snapshot.original_filename,
        content_sha256=snapshot.content_sha256,
        blocks=snapshot.blocks,
        clauses=clauses,
        issues=snapshot.issues,
        manifest=snapshot.manifest,
        confirmation_ref=snapshot.confirmation_ref,
    )


def confirm_text(
    snapshot: DocumentSnapshot, corrected_blocks: list[dict], actor: str
) -> DocumentSnapshot:
    """人工文字確認與修正

    將人工校正後的文字更新至區塊，生成具備確認參照 (confirmation_ref) 之全新不可變 Snapshot。
    更新歷程與操作者記錄於 manifest 中。
    """
    existing_block_ids = {b.block_id for b in snapshot.blocks}
    for item in corrected_blocks:
        bid = item.get("block_id")
        if bid not in existing_block_ids:
            raise DomainError("BLOCK_NOT_FOUND", f"欲更正之區塊不存在於文件中: {bid}")

    corrected_map = {item["block_id"]: item["raw_text"] for item in corrected_blocks}
    updated_blocks: list[DocumentBlock] = []

    for b in snapshot.blocks:
        if b.block_id in corrected_map:
            updated_blocks.append(
                DocumentBlock(
                    block_id=b.block_id,
                    block_type=b.block_type,
                    raw_text=corrected_map[b.block_id],
                    page_number=b.page_number,
                    structural_path=b.structural_path,
                    properties={**b.properties, "confirmed_by": actor},
                )
            )
        else:
            updated_blocks.append(b)

    new_snapshot_id = str(uuid.uuid4())
    confirmation_ref = str(uuid.uuid4())

    # 重新計算更新後區塊內文雜湊
    combined_text = "".join(b.raw_text for b in updated_blocks)
    new_sha256 = hashlib.sha256(combined_text.encode("utf-8")).hexdigest()

    # 更新 manifest 歷程
    updated_manifest = dict(snapshot.manifest)
    updated_manifest["confirmation_actor"] = actor
    updated_manifest["confirmed_at"] = datetime.now(UTC).isoformat()
    updated_manifest["previous_snapshot_id"] = str(snapshot.snapshot_id)
    updated_manifest["corrected_block_count"] = len(corrected_blocks)

    # 針對已校正區塊的待確認問題進行排除或保留
    corrected_ids = set(corrected_map.keys())
    remaining_issues = [
        issue for issue in snapshot.issues if issue.block_id not in corrected_ids
    ]

    temp_snapshot = DocumentSnapshot(
        document_id=snapshot.document_id,
        snapshot_id=new_snapshot_id,
        original_filename=snapshot.original_filename,
        content_sha256=new_sha256,
        blocks=updated_blocks,
        clauses=[],
        issues=remaining_issues,
        manifest=updated_manifest,
        confirmation_ref=confirmation_ref,
    )

    # 重新對新區塊執行條款分段
    return segment(temp_snapshot)
