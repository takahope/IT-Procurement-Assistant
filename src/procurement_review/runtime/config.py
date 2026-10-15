from typing import Any

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.models import RuntimePolicy


def get_default_synthetic_policy(data_root: str = "/tmp/procurement_vault") -> RuntimePolicy:
    """取得預設之合成測試執行期政策。"""
    return RuntimePolicy(
        mode=RuntimeMode.SYNTHETIC,
        data_root=data_root,
    )


def load_runtime_policy(data: dict[str, Any]) -> RuntimePolicy:
    """自資料字典解析並建立 RuntimePolicy 模型。"""
    return RuntimePolicy.model_validate(data)
