# 資訊採購合約資安審查助手 — 運維與災難復原手冊 (Operations & Disaster Recovery Guide)

本手冊規範中央研究院資訊採購合約資安審查助手系統之加密備份、災難復原、資料留存期限（Retention Policy）與受控清除（Purge）作業流程與安全規範。

---

## 1. 架構安全與金鑰管理原則

### 1.1 階層式金鑰架構
- **Artifact 資料金鑰 (Data Key)**:
  - 每個部署實例具備一組 256 位元 (32 bytes) 主資料金鑰，於首次初始化時隨機生成並安全儲存於本機作業系統安全金鑰庫（如 macOS Keychain、Windows Credential Manager 或 Linux Secret Service）。
  - 所有合約原始檔、結構快照、遮罩映射表與暫存回覆，皆以 AES-256-GCM 獨立隨機 Nonce 加密落盤於 Vault。
- **災難復原金鑰 (Recovery Key)**:
  - 於產製加密備份時由管理員提供或指定，透過 HKDF-SHA256 演算法衍生 256 位元金鑰。
  - 獨立包裝（Wrap）Artifact 主資料金鑰，與備份封包主體分離存放。
  - **嚴格禁則**：Recovery Key 絕不可與備份檔案存放在同一實體或邏輯儲存媒體中；若遺失 Recovery Key，備份檔案將無法解密還原。

### 1.2 零網路傳輸還原保證 (Zero Transmission Guarantee)
- 備份還原（Restore）為純粹的本機檔案系統與 SQLite 資料庫重構作業。
- 還原管線中**嚴格禁止**觸發任何外部 LLM 供應商、Webhook 或日誌上傳等外部傳輸動作。
- 測試環境以 `assert captured_requests == []` 強制落實驗證。

---

## 2. 備份程序 (Backup Procedures)

### 2.1 備份機制與特性
- **SQLite 交易一致性**：透過 SQLite `backup` API 產製唯讀快照，保證 WAL 模式下無任何未提交或毀損交易。
- **完整性清單 (Manifest)**：包含資料庫與每項 Vault 加密 Artifact 的 SHA-256 雜湊值與 Schema 遷移版本。
- **AES-256-GCM 封裝**：整體備份以 Recovery Key 加密封裝，具備端對端防篡改與機密性保護。

### 2.2 CLI 備份操作步驟
```bash
uv run python -m procurement_review.cli backup \
  --data-dir /path/to/data \
  --target /path/to/backup_bundle.bundle \
  --recovery-key "YOUR_HIGH_ENTROPY_RECOVERY_KEY"
```

參數說明：
- `--data-dir`: 現有資料目錄（內含 `procurement_review.db` 與 `vault/`）。
- `--target`: 產製之備份封包目的地路徑。
- `--recovery-key`: 復原專用高強度金鑰或密語。

---

## 3. 災難復原程序 (Disaster Recovery & Restore)

### 3.1 復原檢查點與防禦機制
1. **Recovery Key 完整性校驗**：使用 Recovery Key 解密時，AES-256-GCM 認證標籤（Auth Tag）若不符，立即拋出 `RECOVERY_KEY_INVALID` 並中止還原。
2. **防靜默重置 (No-Silent-Reinit)**：若 Recovery Key 遺失或未提供，系統立即中斷，絕不嘗試以空白庫覆寫或重新初始化目標目錄。
3. **Artifact 雜湊比對**：解壓縮還原後逐一比對 SHA-256 雜湊，任一檔案不符即拒絕放行。
4. **金鑰匯入新機**：成功驗證後，自動將解開的主資料金鑰安全匯入目標機器之 OS Keychain。

### 3.2 CLI 還原操作步驟
```bash
uv run python -m procurement_review.cli restore \
  --backup /path/to/backup_bundle.bundle \
  --target /path/to/new_data_dir \
  --recovery-key "YOUR_HIGH_ENTROPY_RECOVERY_KEY"
```

---

## 4. 資料保存期限與受控清除 (Retention & Controlled Purge)

### 4.1 保存政策（Retention Policy）
- 機敏合約產物與中間記錄之預設保存期限為 **30 天**（可依合約或機敏等級設定）。
- 基準日期（`as_of`）超過 `created_at + retention_days` 即屬過期（Expired）。
- 未屆滿保存期限之案件，**嚴格禁止**未經人工核准逕行刪除合約最後原檔；必須提供 `--approved-by` 審查紀錄。

### 4.2 盤點範圍與邊界聲明
受控清除計畫（`PurgePlan`）全面盤點以下標的：
1. **原始文件 (Original Documents)**：儲存於 Vault 之原始合約檔案。
2. **轉換產物 (Converted Snapshots)**：結構快照、條款分段與萃取文字。
3. **遮罩映射 (Masking Mappings)**：個資與機敏 Token 對照表。
4. **快取與傳輸 (Cache & Replies)**：模型回傳暫存與情境 Bundle。
5. **外部匯出追蹤 (Tracked Exports)**：系統記錄之匯出檔案路徑。
   > **注意**：系統僅列出已追蹤之匯出路徑與人工處理責任，絕不擅自全磁碟掃描使用者之個人目錄或未授權路徑。
6. **備份到期政策 (Backup Retention Policy)**：
   > **注意**：系統依政策標記過期備份退役，未到期備份持續保護保留。系統**絕不宣稱**能對底層 SSD/NVMe 進行即時硬體安全抹除（Secure Erase）。

### 4.3 雙階段確認機制 (Confirmation-Bound Purge)
為防範誤刪，清除作業嚴格實施二階段確認：
1. **第一階段：乾跑預覽 (`--dry-run`)**：
   產製 `PurgePlan`，輸出欲清除標的清單及專屬之 64 位元 SHA-256 `confirmation_hash`。
   ```bash
   uv run python -m procurement_review.cli purge \
     --case-id "11111111-1111-4111-8111-111111111111" \
     --data-dir /path/to/data \
     --dry-run
   ```
2. **第二階段：綁定 Hash 執行清除**：
   確認盤點清單無誤後，將輸出的 Hash 帶入執行：
   ```bash
   uv run python -m procurement_review.cli purge \
     --case-id "11111111-1111-4111-8111-111111111111" \
     --data-dir /path/to/data \
     --confirmation-hash "b8c34f...64char_hash..."
   ```
   若 Hash 有任何單一字元不符，系統拒絕刪除任何檔案。

### 4.4 墓碑紀錄 (Tombstone Record)
- 實體 Vault 檔案刪除後，資料庫會在 `reviews` 表將案件狀態更新為 `purged`。
- 同時於 `purge_tombstones` 資料表寫入不可篡改的清除審計紀錄（包含清除時間、確認 Hash、清除標的數量與核准者）。

---

## 5. 真實模式安全檢核門 (Disaster Recovery Gate)

- **合成模式 (Synthetic)**：供本機開發與自動化測試使用，無條件通過。
- **真實模式 (Production / Real)**：
  - 強制檢核災難復原演練記錄參照（`rehearsal_record_ref`）。
  - 嚴格拒絕以全零 UUID 或全零 SHA-256 偽造演練紀錄。
  - 強制檢核資料保存政策核准參照（`retention_approval_ref`）。
