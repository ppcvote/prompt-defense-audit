# prompt-defense-audit

**確定性 LLM 提示詞防禦掃描器。** 檢查系統提示是否缺少對 12 種攻擊向量的防禦。純正則表達式 — 不需要 AI、不需要 API、< 5ms、100% 可重現。

[English Version](README.md)

```
$ npx prompt-defense-audit --zh "你是一個有用的助手。"

  Grade: F  (8/100, 1/12 defenses)

  防護狀態：

  ✗ 角色邊界 (80%)
    Partial: only 1/2 defense pattern(s)
  ✗ 指令邊界 (80%)
    No defense pattern found
  ✗ 資料保護 (80%)
    No defense pattern found
  ...
```

## 為什麼需要這個

OWASP 將**提示詞注入**列為 [LLM 應用的 #1 威脅](https://owasp.org/www-project-top-10-for-large-language-model-applications/)。但大多數開發者的系統提示完全沒有防禦。

現有的安全工具需要 LLM 呼叫（昂貴、不確定）或雲端服務（隱私問題）。這個套件**在本地、即時、免費**運行。

## 安裝

```bash
npm install prompt-defense-audit
```

## 使用方式

### 程式碼（TypeScript / JavaScript）

```typescript
import { audit, auditWithDetails } from 'prompt-defense-audit'

// 快速審計
const result = audit('你是一個客服助手。')
console.log(result.grade)    // 'F'
console.log(result.score)    // 8
console.log(result.missing)  // ['instruction-override', 'data-leakage', ...]

// 詳細審計，含每個向量的證據
const detailed = auditWithDetails(mySystemPrompt)
for (const check of detailed.checks) {
  console.log(`${check.defended ? '✅' : '❌'} ${check.nameZh}: ${check.evidence}`)
}
```

### 命令列

```bash
# 直接輸入
npx prompt-defense-audit "You are a helpful assistant."

# 從檔案讀取
npx prompt-defense-audit --file my-prompt.txt

# 從 stdin 管道
cat prompt.txt | npx prompt-defense-audit

# JSON 輸出（CI/CD 用）
npx prompt-defense-audit --json "Your prompt"

# 繁體中文輸出
npx prompt-defense-audit --zh "你的系統提示"

# 列出 12 種攻擊向量
npx prompt-defense-audit --vectors --zh
```

## 12 種攻擊向量

基於 OWASP LLM Top 10 和實際的提示詞注入研究：

| # | 向量 | 檢查內容 |
|---|------|---------|
| 1 | **角色逃逸** | 角色定義 + 邊界強制 |
| 2 | **指令覆蓋** | 拒絕條款 + 元指令保護 |
| 3 | **資料洩漏** | 系統提示 / 訓練資料洩漏防護 |
| 4 | **輸出格式操控** | 輸出格式限制 |
| 5 | **多語言繞過** | 語言特定防禦 |
| 6 | **Unicode 攻擊** | 同形字 / 零寬字元偵測 |
| 7 | **上下文溢出** | 輸入長度限制 |
| 8 | **間接注入** | 外部資料驗證 |
| 9 | **社交工程** | 情緒操控抵抗 |
| 10 | **輸出武器化** | 有害內容生成防護 |
| 11 | **濫用防護** | 速率限制 / 身份驗證意識 |
| 12 | **輸入驗證** | XSS / SQL 注入 / 清理 |

## 評級標準

| 等級 | 分數 | 意義 |
|------|------|------|
| **A** | 90-100 | 防禦覆蓋率高 |
| **B** | 70-89 | 良好，有少許缺口 |
| **C** | 50-69 | 中等，有明顯缺口 |
| **D** | 30-49 | 薄弱，大多數防禦缺失 |
| **F** | 0-29 | 危險，幾乎沒有防禦 |

## 使用情境

- **CI/CD 管道** — 如果提示詞防禦分數低於閾值，讓建置失敗
- **安全審查** — 在部署前審計程式碼中的所有系統提示
- **提示工程** — 撰寫系統提示時獲得即時回饋
- **合規** — 為安全審計記錄防禦覆蓋率
- **教育** — 學習一個好的提示詞應該有哪些防禦

### CI/CD 範例

```bash
# 如果評級低於 B 就失敗
GRADE=$(npx prompt-defense-audit --json --file prompt.txt | node -e "
  const r = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log(r.grade);
")
if [[ "$GRADE" == "D" || "$GRADE" == "F" ]]; then
  echo "提示詞防禦審計失敗：等級 $GRADE"
  exit 1
fi
```

## 運作原理

1. 解析系統提示文字
2. 對 12 個攻擊向量，使用正則表達式偵測防禦性語言
3. 當足夠的模式匹配時，該防禦為「存在」（通常 ≥ 1，部分需要 ≥ 2）
4. 同時檢查提示中是否嵌入了可疑的 Unicode 字元
5. 計算覆蓋率分數並給予字母等級

**此工具不會：**
- 將你的提示發送到任何外部服務
- 使用 LLM 呼叫（100% 基於正則表達式）
- 保證安全性（它檢查防禦性*語言*，而非實際執行行為）
- 取代滲透測試

## 限制

- 基於正則的偵測有固有限制 — 提示可能包含防禦語言但仍然脆弱
- 只檢查系統提示文字，不檢查實際 AI 模型行為
- 目前只支援英文和繁體中文模式（歡迎貢獻其他語言）
- 防禦模式是啟發式的 — 可能有誤報

## 貢獻

歡迎 PR。重點領域：

- **新語言模式** — 為日文、韓文、西班牙文等添加正則模式
- **新攻擊向量** — 提出新向量並附測試案例
- **更好的模式** — 改進現有正則以減少誤報
- **文件** — 更多範例和整合指南

## 授權

MIT — Ultra Lab (https://ultralab.tw)

## 相關資源

- [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/)
- [UltraProbe](https://ultralab.tw/probe) — 免費 AI 安全掃描器（使用此函式庫）
