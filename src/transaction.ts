// "Transaction evidence" mode: evaluates an lp-tx evidence package (CBOR) under the reader's own
// policy (JSON) with the lp-tx evaluator compiled to WebAssembly. Runs entirely in the page.
// It reports evidence classes per claim — never a verdict; acceptance is the reader's decision.
import { t } from './i18n'
import { loadBrickBox } from './universal'

interface Claim {
  order_ref: string
  claim: string
  status:
    | { Established: { classes: string[] } }
    | { NotEstablished: { why: string } }
    | { Contradicted: { statements: string[] } }
    | { Rejected: { reasons: string[] } }
  basis: string[]
}

interface TxReport {
  error?: string
  transaction_id: string
  policy: string
  invalid_statements: string[]
  anchoring: string
  graph: { events: number; missing_parents: string[]; sequence_gaps: string[]; duplicates: string[]; cycle: boolean }
  capture: { declared_by: string[]; scope: string[]; boundary_gaps: string[] }
  claims: Claim[]
  not_established: string[]
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c)
}

function statusHtml(c: Claim): string {
  const s = c.status
  if ('Established' in s) return `<span class="font-medium" style="color: var(--color-mint-deep)">${esc(t('tx.established'))}</span> · ${esc(s.Established.classes.join(', '))}`
  if ('NotEstablished' in s) return `<span class="font-medium">${esc(t('tx.notEstablished'))}</span> — ${esc(s.NotEstablished.why)}`
  if ('Contradicted' in s) return `<span class="font-medium">${esc(t('tx.contradicted'))}</span> — ${esc(s.Contradicted.statements.join('; '))}`
  return `<span class="font-medium">${esc(t('tx.rejected'))}</span> — ${esc(s.Rejected.reasons.join('; '))}`
}

export function renderTransaction(r: TxReport): string {
  if (r.error) return `<div class="p-4 rounded-lg text-sm" style="background: var(--color-navy-faint)">${esc(t('universal.err', { msg: r.error }))}</div>`
  const warn = [...r.invalid_statements, ...r.graph.missing_parents, ...r.graph.sequence_gaps, ...r.graph.duplicates, ...r.capture.boundary_gaps]
  const claims = r.claims
    .map((c) => `<li class="py-2 border-b" style="border-color: var(--color-navy-faint)">
      <div class="text-sm text-navy">[${esc(c.order_ref)}] ${esc(c.claim)}</div>
      <div class="text-xs mt-0.5" style="color: var(--color-navy-soft)">${statusHtml(c)}</div>
      <div class="text-xs" style="color: var(--color-navy-soft)">${esc(c.basis.join(' · '))}</div></li>`)
    .join('')
  return `<div class="p-4 rounded-lg" style="background: var(--color-navy-faint)">
    <div class="text-sm font-semibold text-navy">${esc(r.transaction_id)}</div>
    <div class="text-xs" style="color: var(--color-navy-soft)">${esc(t('tx.policy', { policy: r.policy }))} · ${esc(r.anchoring)}</div>
    <div class="text-xs mt-1" style="color: var(--color-navy-soft)">${esc(t('tx.graph', { events: r.graph.events, missing: r.graph.missing_parents.length, gaps: r.graph.sequence_gaps.length }))}</div>
    ${warn.length ? `<ul class="text-xs mt-2">${warn.map((w) => `<li>⚠ ${esc(w)}</li>`).join('')}</ul>` : ''}
    <ul class="mt-3">${claims}</ul>
    <div class="text-xs mt-3 font-medium text-navy">${esc(t('tx.notEstablishedHeading'))}</div>
    <ul class="text-xs" style="color: var(--color-navy-soft)">${r.not_established.map((n) => `<li>– ${esc(n)}</li>`).join('')}</ul>
    <p class="text-xs mt-3" style="color: var(--color-navy-soft)">${esc(t('tx.noVerdict'))}</p>
  </div>`
}

export async function verifyTransactionFiles(pkg: Uint8Array, policyJson: string): Promise<TxReport> {
  const bb = (await loadBrickBox()) as unknown as { verify_transaction(p: Uint8Array, j: string): string }
  return JSON.parse(bb.verify_transaction(pkg, policyJson)) as TxReport
}
