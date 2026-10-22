# 雲端模型供應商接入與資安審核指南 (Provider Onboarding Guide)

本文件定義「中央研究院資訊採購合約資安審查助手」接入外部雲端大語言模型供應商之資安評估標準、合約條款檢核清單、本機設定規格與出站防護程序。

---

## 1. 核心原則與治理架構

依據中央研究院資安與個資保護政策，本系統之外部 AI 模型接入遵循以下鐵律：

1. **單一核准供應商原則 (Single Approved Provider)**：系統於任何時間點**僅啟用單一**經資安專責小組審查通過之雲端供應商，不允許多重或未受控之 fallback 管道。
2. **零外洩出站控制 (Zero-Leak Egress Control)**：依據 T9 嚴格出站組裝順序（遮罩 → encode → 殘留掃描 → 雜湊鎖定 → 人工核准 → 受控發送）。
3. **無工具調用外發 (No Tool-Calling Egress)**：模型若回傳任何 `tool_calls` 或 `function_call`，適配器立即拒絕並拋出 `TOOL_CALL_REJECTED`，嚴禁執行非預期之聯網或外部操作。
4. **零日誌洩漏 (Zero-Leak Logging)**：發生網路、協定或格式解碼錯誤時，嚴禁將原始 Payload 或 Response 內容寫入標準日誌。
5. **成本未知原則 (Cost Unknown Principle)**：計費標準或用量不明時，明確標記為 `unknown`，嚴禁虛構或假設為 0 元。
6. **合成驗收優先 (Synthetic Verification First)**：未完成合成 Payload 往返驗收通過前，嚴禁將真實案件送至該端點。

---

## 2. 供應商資安條款檢核清單 (Terms Checklist)

在將任何雲端供應商填入 `ProviderConfig` 之前，承辦人與資安人員必須逐項核對並取得書面或合約承諾：

| # | 查核項目 | 合規標準要求 | 查核要點與依據 |
|---|---------|------------|---------------|
| 1 | **訓練排除條款 (Training Opt-Out)** | 供應商嚴禁將本院上傳之合約、文字、提示詞或輸出用於模型訓練、改進或基準測試。 | 查核供應商 Enterprise / API 服務協議中的 Data Privacy Addendum (DPA) 或 Business Terms。 |
| 2 | **資料留存政策 (Data Retention)** | 必須支援零資料保留 (Zero Data Retention, ZDR)，或承諾最長不超過 30 天之安全暫存且過期自動完全銷毀。 | 確認供應商是否提供明確的 ZDR 授權或定期清除之不可逆銷毀證明。 |
| 3 | **處理與儲存地區 (Data Residency)** | 傳輸中與靜態儲存資料限於臺灣境內或資安專責小組核准之安全區域（如美國西部特定資料中心）。 | 確認 API 端點之實際 IP/地區路由與資料備份節點，嚴禁轉發未核准司法管轄區。 |
| 4 | **次處理者揭露 (Sub-processors)** | 供應商必須完整揭露所有次處理者名冊，並承擔連帶資安與保密責任；異動時須事前通知。 | 審閱次處理者（例如代管基礎設施、內容過濾服務）名單及 SOC2 / ISO 27001 認證。 |
| 5 | **安全刪除承諾 (Deletion Commitments)** | 合約終止或本院主動要求時，供應商須於約定期限內完全刪除所有複本，並出具銷毀證明。 | 檢核合約條款是否包含主動刪除 API、日誌清洗週期及到期完全銷毀機制。 |

---

## 3. 本機 `ProviderConfig` 架構與 Schema

審核通過之供應商資訊儲存於本機 `ProviderConfig`，其資料結構嚴格遵循 `src/procurement_review/domain/models.py` 之定義：

```python
class ProviderConfig(StrictBaseModel):
    provider: str                    # 供應商唯一標識（如 approved_cloud、anthropic）
    endpoint: str                    # 嚴格限 HTTPS 之專用端點位址
    model: str                       # 核准使用之特定模型版本號（如 approved-review-v1）
    credential_ref: str              # SecretStore 中的金鑰鍵名（金鑰不存於設定檔中）
    rate_limits: dict[str, Any]      # 速率限制、安全上限、成本與條款核准紀錄
    price_version: str               # 計價版本日期（如 2026-10-15）
    approval_ref: VersionRef | None  # 資安審查核准之不可變參照
```

### `rate_limits` 核心欄位規範

```json
{
  "rpm": 60,
  "tpm": 100000,
  "timeout_seconds": 30,
  "max_request_bytes": 1048576,
  "max_response_bytes": 2097152,
  "monthly_budget_cap_twd": 10000,
  "cost_status": "unknown",
  "pricing": {
    "prompt_per_1k": null,
    "completion_per_1k": null
  },
  "terms_compliance": {
    "training_opt_out": true,
    "zero_data_retention": true,
    "data_region": "Taiwan / US-West (Approved)",
    "subprocessors_vetted": true,
    "deletion_commitments": true
  }
}
```

- **大小限制**：預設 Request 上限為 1 MB (`1048576` bytes)，Response 上限為 2 MB (`2097152` bytes)。
- **連線逾時**：API 請求逾時設定為 30 秒。
- **成本估算**：若 `pricing` 數值未定或為 `null`，系統一律標示為 `unknown`，不得假設為免費或 0 元。

---

## 4. 出站控制與防護流程 (T9次序)

系統與雲端供應商互動時，絕不直接透過未受控的廠商 SDK，一律遵循以下管線：

```
[合約草稿 OutboundDraft]
          ↓
[1. 去識別化遮罩 (PII Masking)]
          ↓
[2. CloudAdapter.encode (格式序列化)]
          ↓
[3. 出站機敏殘留二次掃描 (Leak Detector Scan)]
          ↓
[4. 不可變 SHA-256 摘要鎖定 (PreparedRequest)]
          ↓
[5. 人工審查與出站核准 (EgressApproval)]
          ↓
[6. Egress Dispatcher (注入金鑰、嚴格 HTTPS POST、單次發送)]
          ↓
[7. CloudAdapter.decode (工具調用阻擋、格式解析、Usage 萃取)]
          ↓
[8. 落盤至加密受控庫 (ArtifactStore)]
```

### 工具調用阻擋 (Tool-Call Rejection)
模型若受到 Prompt Injection 嘗試輸出外部工具呼叫，適配器在解碼端即刻攔截：
```python
if choice.get("finish_reason") == "tool_calls" or "tool_calls" in msg:
    raise DomainError("TOOL_CALL_REJECTED", "Model attempted tool calling...")
```

---

## 5. 驗證與驗收程序

### 步驟一：本機整合測試
在無網路環境下，驗證適配器之編碼、解碼、拒絕、截斷與零洩漏日誌：
```bash
uv run pytest tests/integration/test_cloud_adapter.py -q
```

### 步驟二：Live 合成驗收測試
在完成使用者合規確認並取得正式 API 金鑰後，透過本機環境變數執行合成測試：
```bash
APPROVED_PROVIDER_API_KEY="sk-..." uv run pytest tests/live/test_approved_provider.py -m live -q
```
- **Live 測試預設跳過**：未設定 `APPROVED_PROVIDER_API_KEY` 時不執行任何外連。
- **稽核紀錄留存**：測試通過後，系統保留該次往返之 `request_id`、`model`、`usage` 及 `approval_hash`。
- **未通過前嚴禁處理真實案件**。
