/** Grade from A to F based on defense coverage */
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

/** A single attack vector definition */
export interface AttackVector {
  /** Unique identifier, e.g. 'role-escape' */
  id: string
  /** English name */
  name: string
  /** 繁體中文名稱 */
  nameZh: string
  /** Description of what this vector tests */
  description: string
  /** 繁體中文說明 */
  descriptionZh: string
}

/** Result of checking one defense */
export interface DefenseCheck {
  /** Attack vector ID */
  id: string
  /** English name */
  name: string
  /** 繁體中文名稱 */
  nameZh: string
  /** Whether the defense is present */
  defended: boolean
  /** Confidence score 0-1 */
  confidence: number
  /** Human-readable evidence */
  evidence: string
}

/** Compact audit result */
export interface AuditResult {
  /** Overall grade A-F */
  grade: Grade
  /** Score 0-100 */
  score: number
  /** Coverage string, e.g. "4/12" */
  coverage: string
  /** Number of defended vectors */
  defended: number
  /** Total vectors checked */
  total: number
  /** List of undefended vector IDs */
  missing: string[]
}

/** Detailed audit result with per-vector breakdown */
export interface AuditDetailedResult extends AuditResult {
  /** Per-vector defense check results */
  checks: DefenseCheck[]
  /** Suspicious Unicode characters found in the prompt */
  unicodeIssues: { found: boolean; evidence: string }
}

/** Internal: defense rule definition */
export interface DefenseRule {
  id: string
  name: string
  nameZh: string
  defensePatterns: RegExp[]
  minMatches?: number
  weight?: number
}
