# prompt-defense-audit

[![CI](https://github.com/ppcvote/prompt-defense-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/ppcvote/prompt-defense-audit/actions/workflows/ci.yml)
[![npm version](https://img.shields.io/npm/v/prompt-defense-audit)](https://www.npmjs.com/package/prompt-defense-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node.js](https://img.shields.io/node/v/prompt-defense-audit)](https://nodejs.org/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0-brightgreen)](package.json)

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

我們掃描了 **1,646 個正式環境的系統提示**（來自 4 個公開資料集），結果：
- 97.8% 缺乏間接注入防禦
- 78.3% 評等為 F（低於 45/100）
- 平均分數：36/100

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

### CI/CD 品質關卡

```bash
GRADE=$(npx prompt-defense-audit --json --file prompt.txt | node -e "
  const r = JSON.parse(require('fs').readFileSync('/dev/stdin','utf8'));
  console.log(r.grade);
")
if [[ "$GRADE" == "D" || "$GRADE" == "F" ]]; then
  echo "提示詞防禦審計失敗：等級 $GRADE"
  exit 1
fi
```

## 12 種攻擊向量

基於 [OWASP LLM Top 10](https://owasp.org/www-project-top-10-for-large-language-model-applications/) 和 1,646 個正式環境提示的實證研究：

| # | 向量 | 檢查內容 | 缺口率* |
|---|------|---------|---------|
| 1 | **角色逃逸** | 角色定義 + 邊界強制 | 92.4% |
| 2 | **指令覆蓋** | 拒絕條款 + 元指令保護 | — |
| 3 | **資料洩漏** | 系統提示 / 訓練資料洩漏防護 | 9.4% |
| 4 | **輸出格式操控** | 輸出格式限制 | 88.3% |
| 5 | **多語言繞過** | 語言特定防禦 | 64.3% |
| 6 | **Unicode 攻擊** | 同形字 / 零寬字元偵測 | — |
| 7 | **上下文溢出** | 輸入長度限制 | — |
| 8 | **間接注入** | 外部資料驗證 | 97.8% |
| 9 | **社交工程** | 情緒操控抵抗 | 71.4% |
| 10 | **輸出武器化** | 有害內容生成防護 | — |
| 11 | **濫用防護** | 速率限制 / 身份驗證意識 | — |
| 12 | **輸入驗證** | XSS / SQL 注入 / 清理 | — |

*缺口率 = 1,646 個正式環境提示中缺少此防禦的百分比。來源：[研究數據](https://github.com/ppcvote/prompt-defense-audit/blob/master/research/gap-20260405.json)。

## 評級標準

| 等級 | 分數 | 意義 |
|------|------|------|
| **A** | 90–100 | 防禦覆蓋率高 |
| **B** | 70–89 | 良好，有少許缺口 |
| **C** | 50–69 | 中等，有明顯缺口 |
| **D** | 30–49 | 薄弱，大多數防禦缺失 |
| **F** | 0–29 | 危險，幾乎沒有防禦 |

## API 參考

### `audit(prompt: string): AuditResult`

快速審計。回傳等級、分數和缺少防禦的向量 ID 清單。

```typescript
interface AuditResult {
  grade: 'A' | 'B' | 'C' | 'D' | 'F'
  score: number       // 0-100
  coverage: string    // 例如 "4/12"
  defended: number    // 已防禦的向量數
  total: number       // 12
  missing: string[]   // 缺少防禦的向量 ID
}
```

### `auditWithDetails(prompt: string): AuditDetailedResult`

詳細審計，含每個向量的證據。

```typescript
interface AuditDetailedResult extends AuditResult {
  checks: DefenseCheck[]
  unicodeIssues: { found: boolean; evidence: string }
}

interface DefenseCheck {
  id: string
  name: string          // 英文
  nameZh: string        // 繁體中文
  defended: boolean
  confidence: number    // 0-1
  evidence: string      // 人類可讀的說明
}
```

### `ATTACK_VECTORS: AttackVector[]`

包含 12 種攻擊向量定義的陣列，含雙語名稱和說明。

## 運作原理

1. 解析系統提示文字
2. 對 12 個攻擊向量，使用正則表達式偵測防禦性語言
3. 當足夠的模式匹配時，該防禦為「存在」（通常 >= 1，部分需要 >= 2）
4. 同時檢查提示中是否嵌入了可疑的 Unicode 字元
5. 計算覆蓋率分數並給予字母等級

**此工具不會：**
- 將你的提示發送到任何外部服務
- 使用 LLM 呼叫（100% 基於正則表達式）
- 保證安全性（它檢查防禦性*語言*，而非實際執行行為）
- 取代滲透測試或行為評估

## 限制

- **基於正則的偵測是啟發式的** — 提示可能包含防禦語言但仍然在執行時脆弱。此工具衡量的是*防禦意圖*，而非*實際防禦效果*。
- 只檢查系統提示文字，不檢查模型在對抗壓力下的行為。
- 目前只支援英文和繁體中文模式（歡迎貢獻其他語言）。
- 可能有誤報。詳見[研究數據](https://github.com/ppcvote/prompt-defense-audit/blob/master/research/gap-20260405.json)。
- 全形 CJK 標點符號（如 `，`）會觸發 Unicode 偵測 — 已知限制。

## 研究

此工具基於 1,646 個正式環境系統提示的實證分析，來自 4 個公開資料集：

| 資料集 | 數量 | 來源 |
|--------|------|------|
| [LouisShark/chatgpt_system_prompt](https://github.com/LouisShark/chatgpt_system_prompt) | 1,389 | GPT Store 自訂 GPT |
| [jujumilk3/leaked-system-prompts](https://github.com/jujumilk3/leaked-system-prompts) | 121 | ChatGPT、Claude、Grok、Perplexity、Cursor、v0 |
| [x1xhlol/system-prompts-and-models](https://github.com/x1xhlol/system-prompts-and-models-of-ai-tools) | 80 | Cursor、Windsurf、Devin、Augment |
| [elder-plinius/CL4R1T4S](https://github.com/elder-plinius/CL4R1T4S) | 56 | Claude、Gemini、Grok、Cursor |

主要參考文獻：
- Greshake et al. (2023), [Not what you've signed up for](https://arxiv.org/abs/2302.12173) — 間接提示注入
- Schulhoff et al. (2023), [Ignore This Title and HackAPrompt](https://arxiv.org/abs/2311.16119) — 提示注入分類學
- [OWASP LLM Top 10 (2025)](https://genai.owasp.org/llm-top-10/)

## 貢獻

請參閱 [CONTRIBUTING.md](CONTRIBUTING.md)。重點領域：新語言模式、更精確的正則、整合範例。

## 安全

請參閱 [SECURITY.md](SECURITY.md)。回報漏洞請寄 dev@ultralab.tw — 不要透過 GitHub issues。

## 授權

MIT — [Ultra Lab](https://ultralab.tw)
