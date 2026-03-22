/**
 * prompt-defense-audit
 *
 * Deterministic prompt defense scanner for LLM system prompts.
 * Checks for MISSING defenses against 12 attack vectors.
 *
 * Pure regex — no LLM, no network calls, < 5ms, 100% reproducible.
 *
 * @example
 * ```ts
 * import { audit } from 'prompt-defense-audit'
 *
 * const result = audit('You are a helpful assistant.')
 * console.log(result.grade)    // 'F'
 * console.log(result.score)    // 8
 * console.log(result.coverage) // '1/12'
 * ```
 *
 * @license MIT
 * @see https://github.com/ppcvote/prompt-defense-audit
 */

export { audit, auditWithDetails } from './scanner'
export { ATTACK_VECTORS } from './vectors'
export type {
  AuditResult,
  AuditDetailedResult,
  DefenseCheck,
  AttackVector,
  Grade,
} from './types'
