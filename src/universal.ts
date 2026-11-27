// "Any witness" mode (AGNOSTIC-PLAN Phase 1): runs the lp-bricks brick box, compiled to
// WebAssembly, entirely in the page. No network is used to verify; the only fetches are the
// static WASM module and (optionally) the bundled example.
import { t } from './i18n'

interface BrickBox {
  verify_digest(subjectHex: string, evidenceCbor: Uint8Array, registryJson: string, trustJson: string): string
  verify_content(content: Uint8Array, evidenceCbor: Uint8Array, registryJson: string, trustJson: string): string
  brick_box_version(): string
}

let brickBox: Promise<BrickBox> | null = null

export function loadBrickBox(): Promise<BrickBox> {
  if (!brickBox) {
    const url = '/lp-bricks/lp_bricks_wasm.js'
    brickBox = (import(/* @vite-ignore */ url) as Promise<BrickBox & { default: () => Promise<unknown> }>)
      .then(async (m) => {
        await m.default()
        return m
      })
  }
  return brickBox
}

interface UniversalBundle {
  format: string
  label?: string
  subject_sha256: string
  evidence_cbor_b64: string
  registry: unknown
  practice?: boolean
}

interface WitnessResult {
  witness: string
  verified: boolean
  trusted?: boolean
  error?: string
  promise?: { kind: 'signed_at'; unix: number } | { kind: 'before_block'; header_time: number; block_hash: string }
}

interface Report {
  accepted: boolean
  error?: string
  results?: WitnessResult[]
}

function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64.trim())
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function esc(s: string): string {
  return s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c] ?? c)
}

function promiseText(p: WitnessResult['promise']): string {
  if (!p) return ''
  if (p.kind === 'signed_at') return t('universal.signedAt', { time: new Date(p.unix * 1000).toISOString() })
  return t('universal.beforeBlock', {
    time: new Date(p.header_time * 1000).toISOString(),
    block: p.block_hash.slice(0, 16) + '…',
  })
}

export function renderUniversal(r: Report, b: UniversalBundle): string {
  if (r.error) return `<div class="p-4 rounded-lg text-sm" style="background: var(--color-navy-faint)">${esc(t('universal.err', { msg: r.error }))}</div>`
  const head = r.accepted ? t('universal.ok') : t('universal.fail')
  const rows = (r.results ?? [])
    .map((w) => {
      const status = w.verified
        ? `${t('universal.witness.verified')} · ${w.trusted ? t('universal.trusted') : t('universal.untrusted')}`
        : `${t('universal.witness.rejected')}: ${esc(w.error ?? '')}`
      return `<li class="py-2 border-b" style="border-color: var(--color-navy-faint)">
        <div class="font-medium text-navy">${esc(w.witness)}</div>
        <div class="text-xs" style="color: var(--color-navy-soft)">${status}</div>
        <div class="text-xs" style="color: var(--color-navy-soft)">${esc(promiseText(w.promise))}</div>
      </li>`
    })
    .join('')
  const notes = [
    b.practice ? `<p class="text-xs mt-2">⚠️ ${esc(t('universal.practice'))}</p>` : '',
    `<p class="text-xs mt-2" style="color: var(--color-navy-soft)">${esc(t('universal.selfRegistry'))}</p>`,
  ].join('')
  return `<div class="p-4 rounded-lg" style="background: var(--color-navy-faint)">
    <div class="text-lg font-semibold text-navy">${r.accepted ? '✅' : '❌'} ${esc(head)}</div>
    ${b.label ? `<div class="text-xs mt-1" style="color: var(--color-navy-soft)">${esc(b.label)}</div>` : ''}
    <ul class="mt-3">${rows}</ul>
    ${notes}
  </div>`
}

/** Verify a universal bundle. `content`, when given, is hashed in the page and must match. */
export async function verifyUniversal(text: string, content?: Uint8Array): Promise<{ report: Report; bundle: UniversalBundle }> {
  const bundle = JSON.parse(text) as UniversalBundle
  if (bundle.format !== 'lp-evidence/v1') throw new Error('not an lp-evidence/v1 bundle')
  const bb = await loadBrickBox()
  const ev = b64ToBytes(bundle.evidence_cbor_b64)
  const reg = JSON.stringify(bundle.registry ?? { recipes: [], witnesses: [] })
  const out = content
    ? bb.verify_content(content, ev, reg, 'null')
    : bb.verify_digest(bundle.subject_sha256, ev, reg, 'null')
  return { report: JSON.parse(out) as Report, bundle }
}
