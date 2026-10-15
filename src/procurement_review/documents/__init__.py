from procurement_review.documents.docx_reader import read_docx
from procurement_review.documents.ingest import confirm_text, ingest, segment
from procurement_review.documents.pdf_reader import read_pdf
from procurement_review.documents.structure import (
    Clause,
    DocumentBlock,
    DocumentSnapshot,
    QualityIssue,
    SourceSpan,
)

__all__ = [
    "Clause",
    "DocumentBlock",
    "DocumentSnapshot",
    "QualityIssue",
    "SourceSpan",
    "confirm_text",
    "ingest",
    "read_docx",
    "read_pdf",
    "segment",
]
