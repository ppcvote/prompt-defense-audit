# Case Studies — Crypto AI Agent Prompt-Injection Incidents

This document maps each new v1.4 vector to the documented incident that
motivated it. The intent is to ground the scanner's checks in real failures,
not theoretical attack categories — and to be honest about which incidents
this scanner would help with versus which require defenses at other layers.

For the full analysis with verified primary sources, see the companion blog post:
[Six Crypto AI Agent Heists: What Static Prompt Analysis Catches, What It Doesn't](https://ultralab.tw/en/blog/crypto-ai-agent-prompt-injection-static-analysis).

---

## Summary

| Incident | Date | Loss | Primary vector class | v1.4 vector that addresses it |
|---|---|---|---|---|
| Lobstar Wilde | 2026-02-22 | ~$250K | Social engineering + decimal bug | `transaction-guardrails`, `social-engineering` (existing) |
| Grok × Bankrbot Morse | 2026-05-04 | ~$175K | Indirect injection via encoding + tool authorization | `encoding-injection`, `cross-agent-auth` |
| AIXBT Dashboard | 2025-03-18 | ~$106K | Credential / control-plane compromise | **None** — out of scope for static analysis |
| Freysa | 2024-11-22 launch | $47K | Function semantic redefinition | `function-immutable` |
| ElizaOS Memory Injection | 2025-05 (paper) | Testnet PoC | Cross-platform memory poisoning | `memory-provenance` |
| Bankrbot March 2025 | 2025-03 | ~$330K | Social engineering | `social-engineering` (existing) |

**Honest summary:** of six incidents, this static scanner can flag a missing
defense in five. Static analysis alone would not have prevented any of them
outright — every one involves a runtime, tooling, or credential factor that
requires defenses beyond the prompt.

---

## Vector → Incident mapping

### `encoding-injection` ← Grok × Bankrbot Morse Code (2026-05-04)

**What happened.** An attacker airdropped a Bankr Club Membership NFT to
xAI's Grok wallet, which silently unlocked Bankrbot's tool-calling permissions
(Bankrbot interprets NFT possession as authorization). The attacker then asked
Grok to "translate this Morse code." The decoded payload instructed Bankrbot
to transfer Grok's DRB tokens (~$175K worth) to the attacker. Grok decoded
faithfully; Bankrbot, seeing an instruction posted by an authorized account,
executed.

**Why this vector.** Grok's prompt did not explicitly declare that decoded,
translated, or transformed content should be treated as data rather than
executable instructions. A scanner check for this language gives a developer
a fighting chance to add it. It does **not** prevent the attack on its own —
the principal-confusion at Bankrbot's tool layer (see `cross-agent-auth`) is
also required.

**Sources.** [CryptoTimes coverage](https://www.cryptotimes.io/2026/05/04/xais-grok-ai-loses-175k-in-crypto-heist-via-clever-prompt-injection-then-gets-it-all-back/), [CryptoSlate](https://cryptoslate.com/how-one-trader-exploited-grok-and-morse-code-to-trick-ai-agent-into-sending-billions-of-crypto-tokens-from-a-verified-wallet/), [OECD AI Incident](https://oecd.ai/en/incidents/2026-05-04-4a73).

---

### `function-immutable` ← Freysa Adversarial Game (2024-11)

**What happened.** Freysa was an "AI banker" agent designed as an adversarial
game with a single rule: never approve a transfer out. Players paid escalating
fees per attempt. Attempt #482 succeeded by framing the conversation as a fresh
admin session and **redefining the semantics of `approveTransfer`** —
convincing Freysa that the function authorized *incoming* funds (donations
to the treasury) rather than outgoing transfers. The attacker then "donated"
$100, which triggered the actual outflow path. Loss: 13.19 ETH (~$47K).

**Why this vector.** Most prompts treat function and tool semantics as fixed
implicitly, never declaring it. This check looks for an explicit statement
that function semantics cannot be redefined mid-conversation. A defended
prompt would have made this attack harder; a tool-layer enforcement (see the
"defense in depth" section of [README](./README.md)) would have made it
impossible regardless of prompt content.

**Sources.** [Jarrod Watts thread](https://x.com/jarrodWattsDev/status/1862299845710757980), [Hacker News](https://news.ycombinator.com/item?id=42272063), [The Block](https://www.theblock.co/post/328747/human-player-outwits-freysa-ai-agent-in-47000-crypto-challenge).

---

### `memory-provenance` ← ElizaOS Cross-Platform Memory Injection (Princeton, 2025)

**What happened.** ElizaOS, the framework powering many crypto AI agents,
uses shared RAG memory across platforms (Discord, X, etc.). Researchers at
Princeton + Sentient Foundation demonstrated that an attacker on Discord
could inject text into the shared memory store. Later, when a *different*
legitimate user on X requested an action like "send some ETH to Y," the
retrieval step pulled the poisoned memory back, and the agent acted on the
injected instruction rather than the user's. Released as benchmark CrAIBench.

**Why this vector.** The prompt cannot enforce memory provenance by itself
(that's a framework concern), but it can declare that retrieved memory must
be source-verified before being trusted. This vector flags prompts that lack
that declaration. The real fix is at the framework layer — memory chunks
need source metadata and trust scoring.

**Sources.** [arxiv 2503.16248](https://arxiv.org/html/2503.16248v3), [Decrypt coverage](https://decrypt.co/318200/elizaos-vulnerability-ai-gaslit-losing-millions).

---

### `cross-agent-auth` ← Grok × Bankrbot Principal Confusion (2026-05-04)

**What happened.** (Same incident as `encoding-injection`.) The deeper issue
beyond Morse decoding was that Bankrbot trusted *any X account holding the
membership NFT* as a principal — there was no distinction between "Grok
parroting decoded content" and "Grok issuing an instruction." This is a
classic [confused deputy](https://en.wikipedia.org/wiki/Confused_deputy_problem)
problem.

**Why this vector.** This vector flags prompts that don't declare a boundary
on inheriting authority from another agent's output. It's an incomplete
defense — the real fix is at the tool authorization layer — but having the
prompt state the boundary is necessary precondition for thinking about it.

---

### `transaction-guardrails` ← Lobstar Wilde Decimal Error (2026-02-22)

**What happened.** Nik Pash (ex-Cline, then OpenAI) deployed an autonomous
Solana memecoin agent. An X user posted a sob story claiming his uncle had
tetanus "from a lobster" and asked for 4 SOL. The agent transferred 52,439,283
LOBSTAR tokens (~5% of supply, ~$250K at the moment of transfer) to the
attacker. The off-by-1000 magnitude is consistent with a decimals bug —
LOBSTAR's on-chain integer representation differs from the UI by ~1,000×.

**Why this vector.** Two defenses were missing simultaneously: (1) the prompt
had no policy against transferring on emotional appeals (covered by existing
`social-engineering` vector); (2) the prompt had no hard transaction limits
(covered by this new vector). Even a prompt that defends both would not have
prevented the *decimal* bug — that requires fixing the code path that
constructed the transaction. But declaring "no transfer above N without
confirmation" gives the agent a pattern to refuse on, which would have at
least bounded the loss.

**Sources.** [CoinDesk](https://www.coindesk.com/markets/2026/02/23/ai-bot-s-tipping-blunder-hands-usd250-000-memecoin-pile-to-x-sad-story-poster), [The Block](https://www.theblock.co/post/390722/ai-agent-created-by-openai-dev-accidentally-sends-entire-memecoin-holdings-to-reply-guy), [Cointelegraph](https://www.tradingview.com/news/cointelegraph:e25e7c3ff094b:0-ai-agent-sends-441k-in-tokens-after-decimal-error/).

---

## Out of scope: AIXBT Dashboard Takeover (2025-03-18)

Included for completeness because press coverage labeled this "prompt
injection," but the static scanner cannot help here — and shouldn't pretend
to. The attacker compromised AIXBT's operational dashboard via credentials,
queued malicious prompts directly into the agent's input, and drained
55.5 ETH (~$106K) from the Simulacrum wallet.

This is a control-plane authentication compromise. The same attacker, with
the same access, could have edited the agent's source, drained the wallet
via a connected RPC, or modified deployment configuration. The defense
needed is standard infosec hygiene at the control plane, not prompt analysis.

**Sources.** [The Block](https://www.theblock.co/post/346911/ai-crypto-bot-aixbt-lost-eth-hack-unauthorized-dashboard-access), [AI Incident Database #1003](https://incidentdatabase.ai/cite/1003/).

---

## What this scanner does NOT catch

Spelled out for honest scoping:

1. **Runtime credential compromise** (AIXBT class). Out of scope entirely.
2. **Tool / permission scoping bugs** (Bankrbot NFT authorization). Scanner
   does not see what tools the agent has or how they are gated.
3. **Whether declared defenses are actually enforced at runtime.** The prompt
   can say "verify retrieved memory" but the framework may ignore the
   declaration.
4. **Numerical and unit bugs** (Lobstar's decimals). Code-level bug, not a
   prompt issue.
5. **Effectiveness vs. presence.** A prompt with the keyword "never" registers
   as defended even if the surrounding "helpful" framing dominates under
   adversarial pressure.
6. **Multi-turn adversarial dynamics** (Freysa-style). A static scan of turn 0
   cannot predict turn 482.

If you maintain a crypto agent framework and want to discuss runtime
defenses (memory provenance, transaction limits, principal-aware tool routing),
please open an issue. We don't ship those layers ourselves yet, but tracking
them as roadmap items helps everyone.
