import uuid
import zipfile
from pathlib import Path
from typing import Any

import docx
from docx.oxml.ns import nsmap
from docx.table import Table

from procurement_review.documents.structure import DocumentBlock, QualityIssue
from procurement_review.domain.errors import DomainError

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_UNCOMPRESSED_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_COMPRESSION_RATIO = 100.0


def _validate_docx_zip(path: Path) -> None:
    """安全性檢查：檔案大小、ZIP 損毀、路徑穿越、解壓縮炸彈與巨集檢測"""
    file_size = path.stat().st_size
    if file_size > MAX_FILE_SIZE:
        raise DomainError(
            "FILE_TOO_LARGE",
            f"檔案大小 ({file_size} bytes) 超過上限 ({MAX_FILE_SIZE} bytes)",
        )

    try:
        with zipfile.ZipFile(path, "r") as zf:
            total_uncompressed = 0
            for info in zf.infolist():
                # 防禦路徑穿越
                if ".." in info.filename or info.filename.startswith(("/", "\\")):
                    raise DomainError("CORRUPT_DOCUMENT", "ZIP 封包包含非法路徑")

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                    raise DomainError(
                        "ZIP_BOMB_DETECTED",
                        f"解壓縮後大小 ({total_uncompressed} bytes) 超過上限 ({MAX_UNCOMPRESSED_SIZE} bytes)",
                    )

                if info.compress_size > 0:
                    ratio = info.file_size / info.compress_size
                    if ratio > MAX_COMPRESSION_RATIO and info.file_size > 1 * 1024 * 1024:
                        raise DomainError(
                            "ZIP_BOMB_DETECTED",
                            f"壓縮比率 ({ratio:.1f}) 超過安全臨界值 ({MAX_COMPRESSION_RATIO})",
                        )
    except zipfile.BadZipFile as e:
        raise DomainError("CORRUPT_DOCUMENT", f"無效或已損毀之 ZIP/DOCX 檔案: {e}") from e


def _extract_paragraph_text_and_issues(
    p: Any, block_id: str, structural_path: str
) -> tuple[str, list[QualityIssue]]:
    """自 paragraph XML 節點精確提取文字，檢測修訂標記與隱藏文字"""
    issues: list[QualityIssue] = []

    # 檢測修訂標記 (w:ins, w:del)
    ins_elements = p._p.xpath(".//w:ins")
    del_elements = p._p.xpath(".//w:del")
    if ins_elements or del_elements:
        authors = set()
        for elem in ins_elements + del_elements:
            author = elem.get(f"{{{nsmap['w']}}}author") or "unknown"
            authors.add(author)
        safe_msg = f"區塊存在修訂標記 (新增: {len(ins_elements)}, 刪除: {len(del_elements)})，作者: {', '.join(sorted(authors))}"
        issues.append(QualityIssue(code="TRACKED_CHANGES", block_id=block_id, safe_message=safe_msg))

    # 檢測隱藏文字 (w:vanish)
    vanish_elements = p._p.xpath(".//w:rPr/w:vanish")
    if vanish_elements:
        issues.append(
            QualityIssue(
                code="HIDDEN_TEXT",
                block_id=block_id,
                safe_message="區塊包含隱藏文字 (w:vanish) 設定",
            )
        )

    # 提取完整文字（包含 ins 內之文字節點，但排除 delText）
    text_pieces: list[str] = []
    for node in p._p.iter():
        tag = node.tag
        # 只保留常規文字 <w:t>，不將已刪除之 <w:delText> 併入
        if tag.endswith("}t") and not tag.endswith("}delText"):
            text_pieces.append(node.text or "")

    raw_text = "".join(text_pieces)
    return raw_text, issues


def read_docx(path: Path) -> tuple[list[DocumentBlock], list[QualityIssue]]:
    """讀取 DOCX 檔案，回傳結構化區塊與品質問題清單"""
    _validate_docx_zip(path)

    try:
        doc = docx.Document(path)
    except Exception as e:
        raise DomainError("CORRUPT_DOCUMENT", f"無法解析 DOCX 結構: {e}") from e

    blocks: list[DocumentBlock] = []
    issues: list[QualityIssue] = []

    # 檢驗是否有 VBA 巨集
    with zipfile.ZipFile(path, "r") as zf:
        if "word/vbaProject.bin" in zf.namelist():
            issues.append(
                QualityIssue(
                    code="MACRO_DETECTED",
                    block_id=None,
                    safe_message="文件內包含 VBA 巨集 (系統禁止執行任何巨集程式)",
                )
            )

    # 1. 頁首與頁尾
    for s_idx, section in enumerate(doc.sections):
        header = section.header
        if header:
            for p_idx, p in enumerate(header.paragraphs):
                b_id = str(uuid.uuid4())
                structural_path = f"section[{s_idx}]/header/p[{p_idx}]"
                text, p_issues = _extract_paragraph_text_and_issues(p, b_id, structural_path)
                if text.strip():
                    blocks.append(
                        DocumentBlock(
                            block_id=b_id,
                            block_type="header",
                            raw_text=text,
                            structural_path=structural_path,
                            properties={"section": s_idx},
                        )
                    )
                    issues.extend(p_issues)

        footer = section.footer
        if footer:
            for p_idx, p in enumerate(footer.paragraphs):
                b_id = str(uuid.uuid4())
                structural_path = f"section[{s_idx}]/footer/p[{p_idx}]"
                text, p_issues = _extract_paragraph_text_and_issues(p, b_id, structural_path)
                if text.strip():
                    blocks.append(
                        DocumentBlock(
                            block_id=b_id,
                            block_type="footer",
                            raw_text=text,
                            structural_path=structural_path,
                            properties={"section": s_idx},
                        )
                    )
                    issues.extend(p_issues)

    # 2. 本文段落與文字方塊
    for p_idx, p in enumerate(doc.paragraphs):
        b_id = str(uuid.uuid4())
        structural_path = f"body/p[{p_idx}]"
        text, p_issues = _extract_paragraph_text_and_issues(p, b_id, structural_path)
        if text.strip() or p_issues:
            blocks.append(
                DocumentBlock(
                    block_id=b_id,
                    block_type="paragraph",
                    raw_text=text,
                    structural_path=structural_path,
                )
            )
            issues.extend(p_issues)

        # 檢測段落內的文字方塊 (w:txbxContent)
        txbx_elements = p._p.xpath(".//w:txbxContent")
        for t_idx, txbx in enumerate(txbx_elements):
            for tp_idx, tp in enumerate(txbx.xpath(".//w:p", namespaces=nsmap)):
                tb_id = str(uuid.uuid4())
                tb_path = f"body/p[{p_idx}]/textbox[{t_idx}]/p[{tp_idx}]"
                tb_text = "".join(tp.xpath(".//w:t/text()"))
                if tb_text.strip():
                    blocks.append(
                        DocumentBlock(
                            block_id=tb_id,
                            block_type="textbox",
                            raw_text=tb_text,
                            structural_path=tb_path,
                        )
                    )
                    issues.append(
                        QualityIssue(
                            code="TEXTBOX_CONTENT",
                            block_id=tb_id,
                            safe_message=f"文字方塊內容提取於路徑 {tb_path}",
                        )
                    )

    # 3. 表格 (Table)
    for t_idx, table in enumerate(doc.tables):
        if not isinstance(table, Table):
            continue
        for r_idx, row in enumerate(table.rows):
            for c_idx, cell in enumerate(row.cells):
                cell_text = cell.text.strip()
                if not cell_text:
                    continue
                cb_id = str(uuid.uuid4())
                structural_path = f"table[{t_idx}]/row[{r_idx}]/col[{c_idx}]"
                blocks.append(
                    DocumentBlock(
                        block_id=cb_id,
                        block_type="table_cell",
                        raw_text=cell_text,
                        structural_path=structural_path,
                        properties={"table": t_idx, "row": r_idx, "col": c_idx},
                    )
                )

    return blocks, issues
