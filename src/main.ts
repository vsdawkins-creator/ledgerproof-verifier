import './style.css'
import { verifyEntry, type VerificationResult, type Check } from './verify'
import { ApiUnavailableError } from './api'
import { verifyBundle, type EvidenceVerdict, type VerdictCheck } from './proofBundle'
import { confirmAnchorOnChain, type ChainConfirmation } from './proofBundleChain'
import { t, getLang, setLang, langSwitcherHtml, type Lang } from './i18n'

// ── Finding 11: XSS prevention ───────────────────────────────────────────────
// All values interpolated into innerHTML that originate from API responses
// (publisher_id, key_id, content_type, entry_hash, check.detail, etc.) must
// be escaped before insertion. Using textContent where possible is preferable,
// but for the template-literal rendering pipeline here we sanitise at the
// interpolation boundary. i18n catalog strings are trusted; interpolated
// params that originate from data/URLs are escaped at the call site.
function escapeHtml(s: string): string {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;')
}

// Validate a URL is safe to use as an href — must start with https://
function safeHref(url: string | undefined): string | null {
  if (!url) return null
  return url.startsWith('https://') ? url : null
}

// ── URL routing ──────────────────────────────────────────────────────────────
// Two routes auto-verify on load:
//   #/<sequence>   — direct sequence number in URL hash (e.g., #/42)
//   /r/<slug>      — human-readable slug resolved via /aliases.json
// The slug → sequence map lives in public/aliases.json and is updated whenever
// a new canonical entry is issued. Slugs with a null value are reserved but
// not yet issued; the resolver shows a friendly placeholder in that case.

// Mutable element handles — reassigned by bind() after every shell re-render
// (language switching re-renders the shell, so handles must be refreshed).
let form: HTMLFormElement | null = null
let input: HTMLInputElement | null = null
let resultEl!: HTMLDivElement

// Which input surface is active. 'lookup' = fetch a record by sequence from the
// API and run the full client-side checks (incl. the Ed25519 signature, i.e.
// attribution). 'bundle' = verify a self-contained proof bundle fully offline
// with the standard-conformant engine (existence, no network, no trust in us).
// URL routes (#/<seq>, /r/<slug>) always force 'lookup'.
type Mode = 'lookup' | 'bundle'
// Default the bare-root landing to the offline bundle verifier (the headline
// "verify without trusting us" surface). Deep links (#/<seq>, /r/<slug>) force
// 'lookup' in route(), so existing receipt links are unaffected.
let mode: Mode = 'bundle'

// A closure that re-renders whatever is currently shown, in the active language.
// Set by every show*/runVerification path; replayed after a language switch so
// the verdict re-translates without re-fetching from the network.
let lastRender: (() => void) | null = null

function modeToggleHtml(): string {
  const tab = (m: Mode, label: string) => {
    const active = m === mode
    return `<button id="mode-${m}" type="button"
      aria-pressed="${active}"
      class="flex-1 px-3 py-2 rounded-md text-sm font-medium transition
             ${active ? 'bg-navy text-cream' : 'text-navy hover:bg-cream'}"
      ${active ? '' : 'style="background: transparent"'}>${label}</button>`
  }
  return `
    <div class="flex gap-1 mb-4 p-1 rounded-lg" style="background: var(--color-navy-faint)">
      ${tab('bundle', t('mode.bundle'))}
      ${tab('lookup', t('mode.lookup'))}
    </div>`
}

function lookupFormHtml(): string {
  return `
    <form id="verify-form" class="flex gap-2">
      <input
        id="seq-input"
        type="number"
        min="0"
        placeholder="${escapeHtml(t('app.placeholder'))}"
        class="flex-1 px-4 py-2.5 border rounded-lg text-sm bg-cream text-navy
               focus:outline-none focus:ring-2 focus:ring-mint"
        style="border-color: var(--color-navy-faint)"
      />
      <button type="submit"
        class="px-5 py-2.5 bg-navy text-cream rounded-lg text-sm font-medium
               hover:bg-mint-deep transition whitespace-nowrap">
        ${t('app.verify')}
      </button>
    </form>`
}

function bundleFormHtml(): string {
  return `
    <div id="bundle-drop">
      <textarea id="bundle-input" rows="6" spellcheck="false"
        placeholder="${escapeHtml(t('bundle.placeholder'))}"
        class="w-full px-4 py-3 border rounded-lg text-xs font-mono bg-cream text-navy
               focus:outline-none focus:ring-2 focus:ring-mint resize-y"
        style="border-color: var(--color-navy-faint)"></textarea>
      <div class="flex flex-wrap items-center gap-3 mt-2">
        <button id="bundle-verify" type="button"
          class="px-5 py-2.5 bg-navy text-cream rounded-lg text-sm font-medium
                 hover:bg-mint-deep transition whitespace-nowrap">
          ${t('bundle.verify')}
        </button>
        <label for="bundle-file" class="text-xs cursor-pointer hover:underline"
               style="color: var(--color-navy-soft)">${t('bundle.drop')}</label>
        <input id="bundle-file" type="file" accept="application/json,.json" class="hidden" />
        <button id="bundle-example" type="button" class="text-xs ml-auto hover:underline"
                style="color: var(--color-navy-soft)">${t('bundle.example')}</button>
      </div>
    </div>`
}

function appShellHtml(): string {
  return `
  <div class="max-w-2xl mx-auto px-6 py-12">
    <header class="mb-8">
      <div class="flex items-start justify-between gap-4">
        <h1 class="text-2xl font-semibold text-navy tracking-tight">
          ${t('app.h1')}
        </h1>
        ${langSwitcherHtml()}
      </div>
      <p class="mt-1 text-sm" style="color: var(--color-navy-soft)">
        ${mode === 'bundle' ? t('bundle.intro') : t('app.intro')}
      </p>
    </header>

    ${modeToggleHtml()}

    <div id="input-area" class="mb-8">
      ${mode === 'bundle' ? bundleFormHtml() : lookupFormHtml()}
    </div>

    <div id="result"></div>

    <footer class="mt-16 pt-6 border-t text-xs text-center space-y-1"
            style="border-color: var(--color-navy-faint); color: var(--color-navy-soft)">
      <p>${t('app.footer1', {
        mempool: `<a href="https://mempool.space" class="hover:underline" target="_blank" rel="noopener">mempool.space</a>`,
        blockstream: `<a href="https://blockstream.info" class="hover:underline" target="_blank" rel="noopener">blockstream.info</a>`,
      })}</p>
      <p>LedgerProof℠ · <a href="https://ledgerproofhq.io" class="hover:underline" target="_blank" rel="noopener">ledgerproofhq.io</a></p>
    </footer>
  </div>
  `
}

function bind() {
  resultEl = document.querySelector<HTMLDivElement>('#result')!
  form = document.querySelector<HTMLFormElement>('#verify-form')
  input = document.querySelector<HTMLInputElement>('#seq-input')

  // ── Lookup mode ──
  form?.addEventListener('submit', async (e) => {
    e.preventDefault()
    const seq = parseInt((input?.value ?? '').trim(), 10)
    if (isNaN(seq) || seq < 0) {
      showError(t('err.invalidSeq'))
      return
    }
    await runVerification(seq)
  })

  // ── Bundle mode ──
  const bundleInput = document.querySelector<HTMLTextAreaElement>('#bundle-input')
  const dropZone = document.querySelector<HTMLDivElement>('#bundle-drop')
  document.querySelector<HTMLButtonElement>('#bundle-verify')
    ?.addEventListener('click', () => runBundleVerification(bundleInput?.value ?? ''))
  document.querySelector<HTMLInputElement>('#bundle-file')?.addEventListener('change', async (e) => {
    const f = (e.target as HTMLInputElement).files?.[0]
    if (!f) return
    const text = await f.text()
    if (bundleInput) bundleInput.value = text
    runBundleVerification(text)
  })
  document.querySelector<HTMLButtonElement>('#bundle-example')?.addEventListener('click', async () => {
    try {
      const res = await fetch('/bundle-example.json', { cache: 'no-cache' })
      const text = await res.text()
      if (bundleInput) bundleInput.value = text
      runBundleVerification(text)
    } catch (err) {
      showError(t('bundle.err.parse', { msg: err instanceof Error ? err.message : String(err) }))
    }
  })
  if (dropZone) {
    dropZone.addEventListener('dragover', (e) => e.preventDefault())
    dropZone.addEventListener('drop', async (e) => {
      e.preventDefault()
      const f = e.dataTransfer?.files?.[0]
      if (!f) return
      const text = await f.text()
      if (bundleInput) bundleInput.value = text
      runBundleVerification(text)
    })
  }

  // ── Mode toggle ──
  document.querySelector('#mode-bundle')?.addEventListener('click', () => switchMode('bundle'))
  document.querySelector('#mode-lookup')?.addEventListener('click', () => switchMode('lookup'))

  // ── Language switch — preserve current input content, replay last render ──
  const sw = document.querySelector<HTMLSelectElement>('#lang-switch')
  sw?.addEventListener('change', () => {
    const prevSeq = document.querySelector<HTMLInputElement>('#seq-input')?.value ?? ''
    const prevBundle = document.querySelector<HTMLTextAreaElement>('#bundle-input')?.value ?? ''
    setLang(sw.value as Lang)
    renderShell()
    const si = document.querySelector<HTMLInputElement>('#seq-input')
    if (si && prevSeq) si.value = prevSeq
    const bi = document.querySelector<HTMLTextAreaElement>('#bundle-input')
    if (bi && prevBundle) bi.value = prevBundle
    if (lastRender) lastRender()
  })
}

function switchMode(m: Mode) {
  if (m === mode) return
  mode = m
  lastRender = null
  renderShell()
  resultEl.innerHTML = ''
}

function renderShell() {
  document.querySelector<HTMLDivElement>('#app')!.innerHTML = appShellHtml()
  bind()
}

interface AliasMap { [slug: string]: number | null }

async function loadAliases(): Promise<AliasMap> {
  try {
    const res = await fetch('/aliases.json', { cache: 'no-cache' })
    if (!res.ok) return {}
    const raw = await res.json()
    // Strip non-string-key metadata (_comment, _schema) — only retain entries
    // whose value is a non-negative integer or null.
    const clean: AliasMap = {}
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue
      if (v === null || (typeof v === 'number' && Number.isInteger(v) && v >= 0)) {
        clean[k] = v as number | null
      }
    }
    return clean
  } catch {
    return {}
  }
}

function showSlugPending(slug: string) {
  lastRender = () => {
    resultEl.innerHTML = `
    <div class="p-4 rounded-lg text-sm"
         style="background-color: rgba(232, 168, 124, 0.15);
                border: 1px solid var(--color-accent-warm);
                color: var(--color-navy)">
      <p class="font-medium">${t('slug.pending.title', { slug: escapeHtml(slug) })}</p>
      <p class="mt-1" style="color: var(--color-navy-soft)">
        ${t('slug.pending.body')}
      </p>
    </div>
  `
  }
  lastRender()
}

function showSlugUnknown(slug: string) {
  showError(t('slug.unknown', { slug: escapeHtml(slug) }))
}

// Pre-v1.0 publisher-draft entry handling. Some early entries were issued
// before the v1.0 spec was finalized (May 6-17, 2026) and may exhibit stored-
// value artifacts that the verifier's correctness checks will flag. For those
// entries we render an explanatory errata card pointing to the canonical
// Foundation errata document, instead of surfacing a confusing FAIL banner.
// The pre-v1 list is curated in public/pre-v1-entries.json and is append-only.
interface PreV1Entry {
  errata_id: string
  summary: string
  errata_url: string
  museum_url?: string
  supersede_slug?: string
}
type PreV1Map = { [sequence: string]: PreV1Entry }

async function loadPreV1(): Promise<PreV1Map> {
  try {
    const res = await fetch('/pre-v1-entries.json', { cache: 'no-cache' })
    if (!res.ok) return {}
    const raw = await res.json()
    const clean: PreV1Map = {}
    for (const [k, v] of Object.entries(raw)) {
      if (k.startsWith('_')) continue
      if (typeof v === 'object' && v !== null && 'errata_id' in v) {
        clean[k] = v as PreV1Entry
      }
    }
    return clean
  } catch {
    return {}
  }
}

function showPreV1Card(seq: number, entry: PreV1Entry) {
  lastRender = () => {
    const supersedeLine = entry.supersede_slug
      ? `<p class="mt-2"><a href="/r/${escapeHtml(entry.supersede_slug)}"
              style="color: var(--color-navy); border-bottom: 1px solid var(--color-mint)">
              ${t('prev1.supersede', { slug: escapeHtml(entry.supersede_slug) })}
           </a></p>`
      : ''
    const museumLine = entry.museum_url
      ? `<p class="mt-1"><a href="${escapeHtml(entry.museum_url)}" target="_blank" rel="noopener"
              style="color: var(--color-navy-soft)">
              ${t('prev1.museum', { url: escapeHtml(entry.museum_url) })}
           </a></p>`
      : ''
    resultEl.innerHTML = `
    <div class="p-4 rounded-lg text-sm"
         style="background-color: rgba(232, 168, 124, 0.15);
                border: 1px solid var(--color-accent-warm);
                color: var(--color-navy)">
      <p class="font-medium">${t('prev1.title', { seq })}</p>
      <p class="mt-1" style="color: var(--color-navy-soft)">
        ${escapeHtml(entry.summary)}
      </p>
      <p class="mt-2">
        <a href="${escapeHtml(entry.errata_url)}" target="_blank" rel="noopener"
           style="color: var(--color-navy); border-bottom: 1px solid var(--color-mint)">
          ${t('prev1.errata', { id: escapeHtml(entry.errata_id) })}
        </a>
      </p>
      ${supersedeLine}
      ${museumLine}
    </div>
  `
  }
  lastRender()
}

// Routing — runs on initial load AND on hashchange (so in-tab navigation between
// #/<sequence> hashes re-triggers verification without a full page reload).
async function route() {
  const pathMatch = window.location.pathname.match(/^\/r\/([a-z0-9](?:[a-z0-9-]*[a-z0-9])?)\/?$/i)
  const hashMatch = window.location.hash.match(/^#\/(\d+)$/)

  // A sequence/slug route is always a record lookup — force that mode so the
  // sequence input exists and the result renders where the user expects it.
  if ((hashMatch || pathMatch) && mode !== 'lookup') {
    mode = 'lookup'
    renderShell()
  }

  if (hashMatch) {
    const seq = parseInt(hashMatch[1], 10)
    if (input) input.value = String(seq)
    const preV1 = await loadPreV1()
    const entry = preV1[String(seq)]
    if (entry) {
      showPreV1Card(seq, entry)
    } else {
      runVerification(seq)
    }
    return
  }

  if (pathMatch) {
    const slug = pathMatch[1].toLowerCase()
    // A purely-numeric slug is a raw entry sequence (e.g. /r/16). The canonical
    // sequence route is #/<seq>, but the Vault/scanner currently emits /r/<seq> —
    // verify it directly so those links resolve. Named slugs still use aliases.
    if (/^\d+$/.test(slug)) {
      const seq = parseInt(slug, 10)
      if (input) input.value = String(seq)
      const preV1 = await loadPreV1()
      const entry = preV1[String(seq)]
      if (entry) { showPreV1Card(seq, entry) } else { runVerification(seq) }
      return
    }
    const [aliases, preV1] = await Promise.all([loadAliases(), loadPreV1()])
    if (!(slug in aliases)) {
      showSlugUnknown(slug)
      return
    }
    const seq = aliases[slug]
    if (seq === null) {
      showSlugPending(slug)
      return
    }
    const preV1Entry = preV1[String(seq)]
    if (preV1Entry) {
      if (input) input.value = String(seq)
      showPreV1Card(seq, preV1Entry)
      return
    }
    if (input) input.value = String(seq)
    runVerification(seq)
  }
}

async function runVerification(seq: number) {
  lastRender = null
  resultEl.innerHTML = `
    <div class="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400 py-6">
      <svg class="animate-spin w-4 h-4 text-mint" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
      </svg>
      ${t('loading', { seq })}
    </div>
  `

  try {
    const result = await verifyEntry(seq)
    lastRender = () => { resultEl.innerHTML = renderResult(result) }
    lastRender()
  } catch (err) {
    // Look-up is the only path that needs our servers. When they are the
    // problem, say so and point at the mode that never needs them — never
    // report "verification failed", which implies doubt about the evidence.
    if (err instanceof ApiUnavailableError) {
      showError(t('err.apiUnavailable', { bundle: t('mode.bundle') }))
    } else {
      showError(t('err.verifyFailed', { msg: err instanceof Error ? err.message : String(err) }))
    }
  }
}

// ── Offline proof-bundle verification ────────────────────────────────────────
// Parse the pasted/dropped JSON and run the standard-conformant engine. ZERO
// network — the verdict is computed entirely here. The one optional network call
// is the user-triggered on-chain confirmation, against a PUBLIC block explorer.
function runBundleVerification(text: string) {
  lastRender = null
  const trimmed = text.trim()
  if (!trimmed) { showError(t('bundle.err.empty')); return }

  let bundle: unknown
  try {
    bundle = JSON.parse(trimmed)
  } catch (err) {
    showError(t('bundle.err.parse', { msg: err instanceof Error ? err.message : String(err) }))
    return
  }

  const verdict = verifyBundle(bundle)

  // Extract txid + op_return_payload for the optional on-chain confirm; both must
  // be strings and the bundle must not be MALFORMED for the control to appear.
  const btc = isRecord(bundle) && isRecord(bundle.bitcoin) ? bundle.bitcoin : undefined
  // Validate txid shape before it can flow into a block-explorer request path or
  // an href — a well-formed txid is exactly 64 hex chars. Not currently an XSS/SSRF
  // vector (escaped in the DOM, host is hardcoded + connect-src-locked), but this
  // closes the request-path-shaping footgun and drops the on-chain control on junk.
  const txid = btc && typeof btc.txid === 'string' && /^[0-9a-fA-F]{64}$/.test(btc.txid) ? btc.txid : null
  const payload = btc && typeof btc.op_return_payload === 'string' && /^[0-9a-fA-F]*$/.test(btc.op_return_payload)
    ? btc.op_return_payload
    : null
  const chainable = verdict.verdict !== 'MALFORMED' && txid != null && payload != null

  showVerdict(verdict, chainable ? txid : null, chainable ? payload : null, null)
}

function isRecord(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x)
}

function showVerdict(
  verdict: EvidenceVerdict,
  txid: string | null,
  payload: string | null,
  chain: ChainConfirmation | null,
) {
  lastRender = () => {
    resultEl.innerHTML = renderVerdict(verdict, txid, chain)
    // Re-wire the on-chain confirm button after each render (until confirmed).
    if (txid && payload && !chain?.confirmed) {
      const btn = document.querySelector<HTMLButtonElement>('#chain-confirm')
      btn?.addEventListener('click', async () => {
        btn.disabled = true
        btn.textContent = t('chain.checking')
        const c = await confirmAnchorOnChain(txid, payload)
        showVerdict(verdict, txid, payload, c)
      })
    }
  }
  lastRender()
}

function verdictBadge(v: EvidenceVerdict['verdict']): string {
  const cfg = v === 'PROVEN'
    ? { cls: 'bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400', label: t('verdict.proven.badge') }
    : v === 'NOT_PROVEN'
    ? { cls: 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400', label: t('verdict.notproven.badge') }
    : { cls: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400', label: t('verdict.malformed.badge') }
  return `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium ${cfg.cls}">${cfg.label}</span>`
}

function evRow(label: string, value: string, mono = false): string {
  return `<div class="flex justify-between gap-4 py-1">
    <span class="text-gray-500 flex-shrink-0">${escapeHtml(label)}</span>
    <span class="${mono ? 'font-mono break-all' : ''} text-gray-800 dark:text-gray-200 text-right">${escapeHtml(value)}</span>
  </div>`
}

function renderVerdictCheck(c: VerdictCheck): string {
  const icon = c.pass ? `<span class="text-green-500">✓</span>` : `<span class="text-red-500">✗</span>`
  return `<div class="flex items-start gap-3 px-4 py-2.5 text-sm">
    <span class="mt-0.5 text-base leading-none flex-shrink-0">${icon}</span>
    <div class="flex-1 min-w-0">
      <span class="font-mono text-xs text-gray-900 dark:text-white break-all">${escapeHtml(c.label)}</span>
      ${!c.pass && c.detail ? `<p class="text-xs text-red-500 mt-0.5 break-all">${escapeHtml(c.detail)}</p>` : ''}
    </div>
  </div>`
}

function renderVerdict(v: EvidenceVerdict, txid: string | null, chain: ChainConfirmation | null): string {
  const meaning = v.verdict === 'PROVEN'
    ? t('verdict.proven.meaning', { date: escapeHtml(v.claim?.proven_no_later_than ?? '') })
    : v.verdict === 'NOT_PROVEN'
    ? t('verdict.notproven.meaning')
    : t('verdict.malformed.meaning', { err: escapeHtml(v.error ?? '') })

  let detailCards = ''
  if (v.verdict !== 'MALFORMED' && v.claim) {
    const gap = v.claim.attestation_gap_days
    const claimCard = `
      <div class="text-xs">
        <p class="font-medium text-gray-700 dark:text-gray-300 mb-1">${t('ev.claim')}</p>
        <div class="pl-1">
          ${evRow(t('ev.sha256'), v.claim.sha256, true)}
          ${evRow(t('ev.provenBy'), v.claim.proven_no_later_than)}
          ${evRow(t('ev.observedOn'), v.claim.observed_on)}
          ${gap != null ? evRow(t('ev.gap'), t('ev.gapDays', { n: gap })) : ''}
        </div>
      </div>`
    const s = v.subject
    const subjectCard = s && (s.source || s.native_id || s.title) ? `
      <div class="text-xs">
        <p class="font-medium text-gray-700 dark:text-gray-300 mb-1">${t('ev.subject')}</p>
        <div class="pl-1">
          ${s.title ? evRow(t('ev.title'), s.title) : ''}
          ${s.source ? evRow(t('ev.source'), s.source) : ''}
          ${s.native_id ? evRow(t('ev.nativeId'), s.native_id, true) : ''}
        </div>
      </div>` : ''
    const a = v.anchor
    const anchorCard = a && a.txid ? `
      <div class="text-xs">
        <p class="font-medium text-gray-700 dark:text-gray-300 mb-1">${t('ev.anchor')}</p>
        <div class="pl-1">
          <div class="flex justify-between gap-4 py-1">
            <span class="text-gray-500 flex-shrink-0">${t('ev.txid')}</span>
            <a href="https://mempool.space/tx/${escapeHtml(a.txid)}" target="_blank" rel="noopener"
               class="font-mono break-all text-right text-mint-deep hover:underline">${escapeHtml(a.txid)}</a>
          </div>
          ${a.block_height != null ? evRow(t('ev.blockHeight'), String(a.block_height)) : ''}
          ${a.block_time ? evRow(t('ev.blockTime'), a.block_time) : ''}
        </div>
      </div>` : ''
    detailCards = `<div class="space-y-3 p-3 rounded-lg" style="background: var(--color-navy-faint)">${claimCard}${subjectCard}${anchorCard}</div>`
  }

  let chainSection = ''
  if (txid && v.verdict !== 'MALFORMED') {
    const confirmBtn = `<button id="chain-confirm" type="button"
        class="mt-1 px-4 py-2 text-xs rounded-lg border hover:bg-cream transition"
        style="border-color: var(--color-navy-faint); color: var(--color-navy)">${t('chain.confirm')}</button>`
    if (!chain) {
      chainSection = `<div>${confirmBtn}<p class="mt-1 text-xs" style="color: var(--color-navy-soft)">${t('chain.note')}</p></div>`
    } else if (chain.confirmed) {
      chainSection = `<div class="text-xs p-3 rounded-lg bg-green-50 dark:bg-green-900/10 border border-green-200 dark:border-green-800 text-green-700 dark:text-green-400">
        ${t('chain.confirmed', { n: chain.confirmations ?? '—' })}
        <p class="mt-1 text-gray-500">${t('chain.note')}</p>
      </div>`
    } else if (chain.error) {
      chainSection = `<div class="text-xs p-3 rounded-lg bg-yellow-50 dark:bg-yellow-900/10 border border-yellow-200 dark:border-yellow-800 text-yellow-800 dark:text-yellow-400 mb-2">
        ${t('chain.error', { msg: escapeHtml(chain.error) })}</div>${confirmBtn}`
    } else {
      chainSection = `<div class="text-xs p-3 rounded-lg bg-red-50 dark:bg-red-900/10 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-400">
        ${t('chain.mismatch')}<p class="mt-1 text-gray-500">${t('chain.note')}</p></div>`
    }
  }

  const passCount = v.checks.filter((c) => c.pass).length
  return `
    <div class="space-y-4">
      <div class="flex items-start justify-between gap-4">
        <p class="text-sm text-gray-700 dark:text-gray-300 flex-1">${meaning}</p>
        ${verdictBadge(v.verdict)}
      </div>
      ${v.verdict === 'PROVEN'
        ? `<p class="text-xs" style="color: var(--color-navy-soft)">${t('verdict.existence_note')} ${t('verdict.offline_note')}</p>`
        : ''}
      ${detailCards}
      ${chainSection}
      <div>
        <p class="text-xs font-medium text-gray-500 mb-1">${t('ev.checks')} (${passCount}/${v.checks.length})</p>
        <div class="border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-800">
          ${v.checks.map(renderVerdictCheck).join('')}
        </div>
      </div>
    </div>
  `
}

function showError(msg: string) {
  lastRender = () => {
    resultEl.innerHTML = `
    <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800
                rounded-lg text-sm text-red-700 dark:text-red-400">
      ${msg}
    </div>
  `
  }
  lastRender()
}

function renderResult(r: VerificationResult): string {
  const { entry, receipt, checks, overallStatus, confirmations } = r

  const statusBadge = overallStatus === 'verified'
    ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
         ${t('badge.verified')}
       </span>`
    : overallStatus === 'failed'
    ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
         ${t('badge.failed')}
       </span>`
    : `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">
         ${t('badge.partial')}
       </span>`

  const anchorTxid = receipt?.anchor_txid ? escapeHtml(receipt.anchor_txid) : null
  const anchorSection = receipt?.anchor_status === 'confirmed' && anchorTxid
    ? `<div class="mt-4 p-3 bg-orange-50 dark:bg-orange-900/10 border border-orange-200
                   dark:border-orange-800 rounded-lg text-xs space-y-1">
         <p class="font-medium text-orange-800 dark:text-orange-400">${t('anchor.title')}</p>
         <p class="font-mono break-all text-gray-600 dark:text-gray-400">
           <a href="https://mempool.space/tx/${anchorTxid}" target="_blank" rel="noopener"
              class="hover:underline text-orange-600 dark:text-orange-400">${anchorTxid}</a>
         </p>
         <p class="text-gray-500">
           ${t('anchor.block', { h: receipt!.anchor_block_height ?? '—' })}
           ${confirmations != null ? `· ${t('confirmations', { n: confirmations })}` : ''}
           ${receipt!.anchored_at ? `· ${new Date(receipt!.anchored_at).toLocaleString(getLang())}` : ''}
         </p>
       </div>`
    : ''

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">${t('result.entry', { seq: entry.sequence })}</h2>
          <p class="text-xs text-gray-500 mt-0.5">
            ${escapeHtml(entry.publisher_id)} · ${new Date(entry.entry_timestamp).toLocaleString(getLang())}
          </p>
        </div>
        ${statusBadge}
      </div>

      <!-- Checks -->
      <div class="border border-gray-200 dark:border-gray-700 rounded-lg divide-y divide-gray-100 dark:divide-gray-800">
        ${checks.map(renderCheck).join('')}
      </div>

      ${anchorSection}

      <!-- Entry details -->
      <details class="group">
        <summary class="cursor-pointer text-sm text-gray-500 hover:text-gray-700 dark:hover:text-gray-300
                         select-none list-none flex items-center gap-1.5">
          <svg class="w-3.5 h-3.5 transition group-open:rotate-90" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5l7 7-7 7"/>
          </svg>
          ${t('details.summary')}
        </summary>
        <div class="mt-3 space-y-2 text-xs">
          ${detailRow(t('detail.entryHash'), entry.entry_hash, true)}
          ${detailRow(t('detail.prevHash'), entry.prev_hash, true)}
          ${detailRow(t('detail.signature'), entry.signature, true)}
          ${detailRow(t('detail.keyId'), entry.key_id)}
          ${detailRow(t('detail.protocol'), entry.protocol_version)}
          ${detailRow(t('detail.contentType'), entry.content_type)}
          <div>
            <span class="text-gray-500 font-medium">${t('detail.content')}</span>
            <pre class="mt-1 p-2 bg-gray-50 dark:bg-gray-800 rounded text-gray-800 dark:text-gray-200
                        overflow-x-auto font-mono">${escapeHtml(JSON.stringify(entry.content, null, 2))}</pre>
          </div>
        </div>
      </details>
    </div>
  `
}

function renderCheck(check: Check): string {
  const icon = check.status === 'pass'
    ? `<span class="text-green-500">✓</span>`
    : check.status === 'fail'
    ? `<span class="text-red-500">✗</span>`
    : `<span class="text-yellow-500">⚠</span>`

  // Validate link URL — only allow https:// to prevent javascript: injection
  const safeLinkHref = safeHref(check.link)
  const name = check.nameKey ? t(check.nameKey, undefined, check.name) : check.name
  const detail = check.detailKey ? t(check.detailKey, check.detailParams, check.detail) : check.detail

  return `
    <div class="flex items-start gap-3 px-4 py-3 text-sm">
      <span class="mt-0.5 text-base leading-none flex-shrink-0">${icon}</span>
      <div class="flex-1 min-w-0">
        <span class="font-medium text-gray-900 dark:text-white">${escapeHtml(name)}</span>
        <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">${escapeHtml(detail)}</p>
      </div>
      ${safeLinkHref ? `<a href="${escapeHtml(safeLinkHref)}" target="_blank" rel="noopener"
          class="text-xs text-mint-deep hover:underline flex-shrink-0">${t('check.view')}</a>` : ''}
    </div>
  `
}

function detailRow(label: string, value: string, mono = false): string {
  return `
    <div>
      <span class="text-gray-500 font-medium">${escapeHtml(label)}</span>
      <p class="mt-0.5 ${mono ? 'font-mono break-all' : ''} text-gray-700 dark:text-gray-300">${escapeHtml(value)}</p>
    </div>
  `
}

// ── Boot ──────────────────────────────────────────────────────────────────────
document.documentElement.lang = getLang()
renderShell()
route()
window.addEventListener('hashchange', () => { route() })
