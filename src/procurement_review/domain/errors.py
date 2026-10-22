class DomainError(Exception):
    """領域模型與業務規則基礎例外類別

    安全保證：safe_message 不得包含合約原文、明文金鑰、真實個資或未遮罩資訊。
    """

    def __init__(self, code: str, safe_message: str) -> None:
        self.code = code
        self.safe_message = safe_message
        super().__init__(f"[{code}] {safe_message}")

    def __repr__(self) -> str:
        return f"DomainError(code={self.code!r}, safe_message={self.safe_message!r})"
