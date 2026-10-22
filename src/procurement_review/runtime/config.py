from typing import Any

from procurement_review.domain.enums import RuntimeMode
from procurement_review.domain.models import ProviderConfig, RuntimePolicy


def get_default_synthetic_policy(data_root: str = "/tmp/procurement_vault") -> RuntimePolicy:
    """取得預設之合成測試執行期政策。"""
    return RuntimePolicy(
        mode=RuntimeMode.SYNTHETIC,
        data_root=data_root,
    )


def load_runtime_policy(data: dict[str, Any]) -> RuntimePolicy:
    """自資料字典解析並建立 RuntimePolicy 模型。"""
    return RuntimePolicy.model_validate(data)


def get_approved_provider_config() -> ProviderConfig:
    """取得經資安評估與核准之單一雲端供應商設定 (Approved Provider Config)。

    安全規範：
    - 產品設定僅啟用單一已核准供應商。
    - 條款檢核項目（訓練排除、零資料留存、處理地區、次處理者、刪除承諾）均經審核。
    - 設定 request/response 大小、timeout 及預算上限。
    - 成本費率未確認時標註 unknown，嚴禁當成 0。
    """
    return ProviderConfig(
        provider="approved_cloud",
        endpoint="https://api.approved-cloud.example.com/v1/chat/completions",
        model="approved-review-v1",
        credential_ref="approved_cloud_api_key",
        price_version="2026-10-15",
        rate_limits={
            "rpm": 60,
            "tpm": 100000,
            "timeout_seconds": 30,
            "max_request_bytes": 1048576,  # 1MB
            "max_response_bytes": 2097152,  # 2MB
            "monthly_budget_cap_twd": 10000,
            "cost_status": "unknown",  # 未知成本不可視為 0
            "terms_compliance": {
                "training_opt_out": True,
                "zero_data_retention": True,
                "data_region": "Taiwan / US-West (Approved)",
                "subprocessors_vetted": True,
                "deletion_commitments": True,
            },
        },
    )


def load_provider_config(data: dict[str, Any]) -> ProviderConfig:
    """自字典載入並校驗 ProviderConfig。"""
    return ProviderConfig.model_validate(data)


def get_active_provider_config() -> ProviderConfig:
    """取得目前系統啟用之單一模型供應商設定。"""
    return get_approved_provider_config()
