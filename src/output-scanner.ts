/**
 * Output Scanner — detect dangerous payloads in LLM responses
 *
 * Scans AI-generated text for web security threats before it reaches
 * downstream systems (HTML rendering, databases, shells, APIs).
 *
 * Maps to OWASP LLM02: Insecure Output Handling
 *
 * Pure regex, <5ms, zero dependencies.
 */

export interface OutputThreat {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  match: string
  position: number
  context: string
}

export interface OutputScanResult {
  safe: boolean
  threats: OutputThreat[]
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical'
  summary: string
}

interface ThreatRule {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  pattern: RegExp
  description: string
}

const THREAT_RULES: ThreatRule[] = [
  // ── XSS (Cross-Site Scripting) ──
  {
    id: 'xss-script-tag',
    name: 'Script Tag Injection',
    severity: 'critical',
    pattern: /<script[\s>][^]*?<\/script>/gi,
    description: 'Executable script block in output',
  },
  {
    id: 'xss-event-handler',
    name: 'Event Handler Injection',
    severity: 'critical',
    pattern: /\bon(?:error|load|click|mouseover|focus|blur|submit|change|input|keydown|keyup|mouseenter)\s*=/gi,
    description: 'Inline event handler attribute',
  },
  {
    id: 'xss-javascript-uri',
    name: 'JavaScript URI',
    severity: 'critical',
    pattern: /(?:href|src|action|formaction)\s*=\s*["']?\s*javascript\s*:/gi,
    description: 'JavaScript protocol in URL attribute',
  },
  {
    id: 'xss-data-uri-html',
    name: 'Data URI with HTML',
    severity: 'high',
    pattern: /(?:href|src)\s*=\s*["']?\s*data\s*:\s*text\/html/gi,
    description: 'Data URI embedding HTML content',
  },
  {
    id: 'xss-iframe-srcdoc',
    name: 'Iframe Srcdoc Injection',
    severity: 'high',
    pattern: /<iframe[^>]*srcdoc\s*=/gi,
    description: 'Iframe with inline HTML document',
  },
  {
    id: 'xss-svg-script',
    name: 'SVG Script Injection',
    severity: 'high',
    pattern: /<svg[^>]*>[\s\S]*?<script/gi,
    description: 'Script embedded in SVG element',
  },

  // ── SQL Injection ──
  {
    id: 'sqli-destructive',
    name: 'Destructive SQL Statement',
    severity: 'critical',
    pattern: /;\s*(?:DROP\s+(?:TABLE|DATABASE)|DELETE\s+FROM|TRUNCATE\s+TABLE|ALTER\s+TABLE.*DROP)/gi,
    description: 'Destructive SQL command in output',
  },
  {
    id: 'sqli-union',
    name: 'SQL UNION Injection',
    severity: 'high',
    pattern: /UNION\s+(?:ALL\s+)?SELECT\s+/gi,
    description: 'UNION-based SQL injection payload',
  },
  {
    id: 'sqli-comment-bypass',
    name: 'SQL Comment Bypass',
    severity: 'medium',
    pattern: /['"];\s*--/g,
    description: 'SQL comment-based authentication bypass',
  },

  // ── Shell Command Injection ──
  {
    id: 'shell-pipe-exec',
    name: 'Piped Shell Execution',
    severity: 'critical',
    pattern: /(?:curl|wget|fetch)\s+[^\|]*\|\s*(?:ba)?sh/gi,
    description: 'Remote script download and execution',
  },
  {
    id: 'shell-destructive',
    name: 'Destructive Shell Command',
    severity: 'critical',
    pattern: /(?:rm\s+-[rf]{2,}\s+\/(?!tmp)|mkfs\.\S+\s+\/dev\/|dd\s+if=\/dev\/(?:zero|random)\s+of=\/dev\/sd|chmod\s+777\s+\/)/gi,
    description: 'Destructive filesystem command targeting system paths',
  },
  {
    id: 'shell-reverse',
    name: 'Reverse Shell',
    severity: 'critical',
    pattern: /(?:\/dev\/tcp\/|nc\s+-[elvp]|bash\s+-i\s+>&|python[3]?\s+-c\s+['"]import\s+(?:socket|os|subprocess))/gi,
    description: 'Reverse shell payload',
  },
  {
    id: 'shell-env-exfil',
    name: 'Environment Variable Exfiltration',
    severity: 'high',
    pattern: /(?:echo\s+\$\{?(?:AWS_|OPENAI_|ANTHROPIC_)[\w]*\}?\s*\|\s*(?:curl|wget|nc|base64)|env\s*\|\s*(?:curl|wget|nc))/gi,
    description: 'Exfiltration of environment variables to external service',
  },

  // ── Path Traversal ──
  {
    id: 'path-traversal',
    name: 'Path Traversal',
    severity: 'high',
    pattern: /(?:\.\.\/){2,}(?:etc\/(?:passwd|shadow)|windows\\system32|proc\/self)/gi,
    description: 'Directory traversal to sensitive files',
  },

  // ── Credential Leakage ──
  {
    id: 'credential-api-key',
    name: 'API Key in Output',
    severity: 'critical',
    pattern: /(?:sk-[a-zA-Z0-9]{20,}|sk-proj-[a-zA-Z0-9_-]{20,}|sk-ant-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9]{36,}|gho_[a-zA-Z0-9]{36,}|AKIA[0-9A-Z]{16})/g,
    description: 'API key or access token detected',
  },
  {
    id: 'credential-private-key',
    name: 'Private Key in Output',
    severity: 'critical',
    pattern: /-----BEGIN\s+(?:RSA\s+)?(?:PRIVATE|EC)\s+KEY-----/g,
    description: 'Cryptographic private key',
  },
  {
    id: 'credential-connection-string',
    name: 'Database Connection String',
    severity: 'critical',
    pattern: /(?:mongodb|postgres|mysql|redis|mssql):\/\/[^\s"']{10,}/gi,
    description: 'Database connection string with credentials',
  },
  {
    id: 'credential-jwt',
    name: 'JWT Token',
    severity: 'high',
    pattern: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    description: 'JSON Web Token in output',
  },

  // ── Internal Network Exposure ──
  // Internal IPs demoted to info-only — too many false positives in tutorials
  // Only flag if combined with credential-like context
  // Removed: localhost references are too common in tutorials and documentation
  // to be useful as a security signal

  // ── Markdown Injection ──
  {
    id: 'markdown-link-injection',
    name: 'Malicious Markdown Link',
    severity: 'high',
    pattern: /\[([^\]]*)\]\(javascript:[^)]+\)/gi,
    description: 'Markdown link with JavaScript protocol',
  },
  {
    id: 'markdown-image-tracking',
    name: 'Tracking Pixel via Markdown',
    severity: 'medium',
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)]*(?:track|pixel|beacon|log|collect|analytics)[^)]*\)/gi,
    description: 'Image tag potentially used for tracking',
  },

  // ── Code Injection ──
  {
    id: 'code-eval',
    name: 'Dynamic Code Evaluation',
    severity: 'high',
    pattern: /(?:eval|exec)\s*\(\s*(?:request|req|input|user|data|body|params|query|args)\b/gi,
    description: 'Dynamic code evaluation with user-controlled input',
  },
  {
    id: 'code-python-import',
    name: 'Python System Import',
    severity: 'medium',
    pattern: /__import__\s*\(\s*['"](?:os|subprocess|sys|shutil|socket)['"]\s*\)/g,
    description: 'Python dynamic import of system module',
  },

  // ── JSON / Schema Injection (v1.5) ──
  // Tools defined via OpenAPI / function-call schemas can embed instructions
  // in the description / title field. LLMs treat those fields as authoritative
  // because they describe the tool. An attacker who controls a tool schema
  // (third-party MCP server, OpenAPI import, etc.) can inject directives.
  {
    id: 'schema-description-inject',
    name: 'JSON Schema Description Injection',
    severity: 'high',
    pattern: /"(?:description|title|summary)"\s*:\s*"[^"]*(?:ignore\s+(?:previous|prior|the\s+above)|system\s+prompt|override|disregard|new\s+instructions?|you\s+are\s+now)[^"]*"/gi,
    description: 'JSON schema description field contains injection directive',
  },
  {
    id: 'schema-html-comment-inject',
    name: 'Schema HTML Comment Injection',
    severity: 'medium',
    pattern: /"(?:description|title|summary|enum|examples?|default)"\s*:\s*"[^"]*<!--[^"]*"/g,
    description: 'Schema text field contains HTML comment (potential instruction smuggling)',
  },

  // ── Modality Marker Injection (v1.5) ──
  // When an upstream pipeline OCRs an image or transcribes audio, it may
  // embed marker tags (e.g. [IMAGE_CONTAINS_TEXT: ...] / [TRANSCRIPT: ...]).
  // If the LLM downstream treats those as commands, an attacker who controls
  // the image/audio can hijack the conversation.
  {
    id: 'modality-marker-injection',
    name: 'Modality Marker Hijack',
    severity: 'high',
    pattern: /\[(?:IMAGE_CONTAINS_TEXT|IMAGE_OCR|TRANSCRIPT|AUDIO_TRANSCRIPT|WHISPER|VIDEO_CAPTION|PDF_TEXT|SCREENSHOT)\s*:\s*[^\]]*(?:ignore|disregard|system\s+prompt|new\s+instructions?|override|forget|jailbreak)[^\]]*\]/gi,
    description: 'OCR/transcript marker block contains injection directive',
  },

  // ── Markdown nested JavaScript URI (v1.5 — broader than xss-javascript-uri) ──
  // xss-javascript-uri only catches HTML attributes; markdown rendered to HTML
  // can also produce a clickable javascript: URL through [text](javascript:...).
  // markdown-link-injection above catches the basic case; this catches obfuscated
  // variants using whitespace, Unicode escapes, or fragmented protocols.
  {
    id: 'markdown-obfuscated-js-uri',
    name: 'Obfuscated JavaScript URI in Markdown',
    severity: 'high',
    pattern: /\[[^\]]*\]\(\s*(?:java\s*scr?ipt|j‮avascript|javasc%72ipt|j[​‌‍]avascript)\s*:[^)]*\)/gi,
    description: 'Markdown link with obfuscated javascript: protocol',
  },

  // ── Tool-call argument injection (v1.5) ──
  // Function-call arguments can carry injection payloads. Specifically watch
  // for known PI seed phrases inside any JSON value that looks like a tool arg.
  {
    id: 'tool-arg-injection',
    name: 'Tool Call Argument Injection',
    severity: 'high',
    pattern: /"(?:url|query|prompt|message|input|content|text|body|search|q)"\s*:\s*"[^"]*(?:ignore\s+(?:all|any|every|the|previous|prior|prior\s+\w+|above)(?:\s+\w+){0,3}\s*instructions?|you\s+are\s+now\s+(?:DAN|free|unrestricted|jailbroken)|system\s*:\s*you\s+are|disregard\s+(?:everything|the\s+above|prior|previous|all))[^"]*"/gi,
    description: 'Tool-call argument contains classic prompt-injection seed phrase',
  },

  // ── Polyglot SVG with active content (v1.5) ──
  // Beyond the simple <svg><script> case caught above, SVGs can carry inline
  // event handlers OR XSL-style nested foreignObject HTML.
  {
    id: 'svg-foreign-object-html',
    name: 'SVG foreignObject HTML Injection',
    severity: 'high',
    pattern: /<svg[^>]*>[\s\S]*?<foreignObject[^>]*>[\s\S]*?<[^>]/gi,
    description: 'SVG embeds foreignObject containing HTML (potential XSS smuggling)',
  },
]

/**
 * Scan LLM output for dangerous payloads.
 *
 * @param output - The AI-generated text to scan
 * @returns Scan result with threats found
 *
 * @example
 * ```ts
 * const result = scanOutput('Here is your greeting: <script>alert(1)</script>')
 * // result.safe = false, result.riskLevel = 'critical'
 * ```
 */
export function scanOutput(output: string): OutputScanResult {
  const threats: OutputThreat[] = []

  for (const rule of THREAT_RULES) {
    rule.pattern.lastIndex = 0
    let match
    while ((match = rule.pattern.exec(output)) !== null) {
      const start = Math.max(0, match.index - 20)
      const end = Math.min(output.length, match.index + match[0].length + 20)
      threats.push({
        id: rule.id,
        name: rule.name,
        severity: rule.severity,
        match: match[0].substring(0, 100),
        position: match.index,
        context: output.substring(start, end).replace(/\n/g, ' '),
      })
    }
  }

  // Deduplicate by position
  const unique = threats.filter((t, i) =>
    !threats.some((other, j) => j < i && Math.abs(other.position - t.position) < 5)
  )

  const criticalCount = unique.filter(t => t.severity === 'critical').length
  const highCount = unique.filter(t => t.severity === 'high').length

  const riskLevel: OutputScanResult['riskLevel'] =
    criticalCount > 0 ? 'critical' :
    highCount > 0 ? 'high' :
    unique.length > 3 ? 'medium' :
    unique.length > 0 ? 'low' : 'safe'

  const summary = unique.length === 0
    ? 'No dangerous payloads detected. Output is safe for downstream use.'
    : `Found ${unique.length} threat(s): ${criticalCount} critical, ${highCount} high. Do NOT pass this output to downstream systems without sanitization.`

  return {
    safe: unique.length === 0,
    threats: unique,
    riskLevel,
    summary,
  }
}
