import uuid
from pathlib import Path

import pypdf

from procurement_review.documents.structure import DocumentBlock, QualityIssue
from procurement_review.domain.errors import DomainError

MAX_PDF_SIZE = 50 * 1024 * 1024  # 50 MB
MAX_PDF_PAGES = 500


def read_pdf(path: Path) -> tuple[list[DocumentBlock], list[QualityIssue]]:
    """以 pypdf 逐頁擷取 PDF 文字與區塊，精準識別掃描頁與嵌入圖檔"""
    file_size = path.stat().st_size
    if file_size > MAX_PDF_SIZE:
        raise DomainError(
            "FILE_TOO_LARGE",
            f"PDF 檔案大小 ({file_size} bytes) 超過上限 ({MAX_PDF_SIZE} bytes)",
        )

    try:
        reader = pypdf.PdfReader(str(path))
    except Exception as e:
        raise DomainError("CORRUPT_DOCUMENT", f"無法開啟或解析 PDF 檔案: {e}") from e

    if reader.is_encrypted:
        raise DomainError("ENCRYPTED_PDF", "PDF 檔案已加密保護，系統不進行密碼猜測或破解")

    num_pages = len(reader.pages)
    if num_pages > MAX_PDF_PAGES:
        raise DomainError(
            "PAGES_EXCEEDED",
            f"PDF 總頁數 ({num_pages}) 超過系統允許上限 ({MAX_PDF_PAGES})",
        )

    blocks: list[DocumentBlock] = []
    issues: list[QualityIssue] = []

    for idx, page in enumerate(reader.pages):
        page_num = idx + 1
        page_text = page.extract_text() or ""
        img_count = len(page.images)

        # 掃描頁判斷：無可擷取文字且有圖檔
        if not page_text.strip() and img_count > 0:
            b_id = str(uuid.uuid4())
            blocks.append(
                DocumentBlock(
                    block_id=b_id,
                    block_type="scanned_page",
                    raw_text="",
                    page_number=page_num,
                    structural_path=f"page[{page_num}]",
                    properties={"page": page_num, "bbox": None},
                )
            )
            issues.append(
                QualityIssue(
                    code="SCANNED_PAGE",
                    block_id=b_id,
                    safe_message=f"第 {page_num} 頁為影像掃描頁且無文字，需人工文字確認或 OCR",
                )
            )
            continue

        # 混合頁判斷：既有文字亦有嵌入圖檔
        if img_count > 0:
            issues.append(
                QualityIssue(
                    code="EMBEDDED_IMAGE",
                    block_id=None,
                    safe_message=f"第 {page_num} 頁包含 {img_count} 個嵌入影像，可能含有未擷取圖表或附表文字",
                )
            )

        # 逐段分割頁面文字（若無明確段落則保留整頁）
        paragraphs = [p.strip() for p in page_text.split("\n\n") if p.strip()]
        if not paragraphs and page_text.strip():
            paragraphs = [page_text.strip()]

        for p_idx, para in enumerate(paragraphs):
            b_id = str(uuid.uuid4())
            blocks.append(
                DocumentBlock(
                    block_id=b_id,
                    block_type="paragraph",
                    raw_text=para,
                    page_number=page_num,
                    structural_path=f"page[{page_num}]/p[{p_idx}]",
                    properties={"page": page_num, "bbox": None},
                )
            )

    return blocks, issues
