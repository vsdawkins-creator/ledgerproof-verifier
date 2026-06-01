import './style.css'
import { verifyEntry, type VerificationResult, type Check } from './verify'

// ── Finding 11: XSS prevention ───────────────────────────────────────────────
// All values interpolated into innerHTML that originate from API responses
// (publisher_id, key_id, content_type, entry_hash, check.detail, etc.) must
// be escaped before insertion. Using textContent where possible is preferable,
// but for the template-literal rendering pipeline here we sanitise at the
// interpolation boundary.
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

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div class="max-w-2xl mx-auto px-6 py-12">
    <header class="mb-10">
      <h1 class="text-2xl font-semibold text-navy tracking-tight">
        LedgerProof Verifier
      </h1>
      <p class="mt-1 text-sm" style="color: var(--color-navy-soft)">
        Independently verify that a published entry exists, was signed by the declared publisher,
        and is included in a Merkle tree anchored to Bitcoin.
      </p>
    </header>

    <form id="verify-form" class="flex gap-2 mb-8">
      <input
        id="seq-input"
        type="number"
        min="0"
        placeholder="Entry sequence number"
        class="flex-1 px-4 py-2.5 border rounded-lg text-sm bg-cream text-navy
               focus:outline-none focus:ring-2 focus:ring-mint"
        style="border-color: var(--color-navy-faint)"
      />
      <button type="submit"
        class="px-5 py-2.5 bg-navy text-cream rounded-lg text-sm font-medium
               hover:bg-mint-deep transition whitespace-nowrap">
        Verify
      </button>
    </form>

    <div id="result"></div>

    <footer class="mt-16 pt-6 border-t text-xs text-center space-y-1"
            style="border-color: var(--color-navy-faint); color: var(--color-navy-soft)">
      <p>This verifier performs all cryptographic checks in your browser using
         @noble/ed25519 and @noble/hashes.
         Bitcoin confirmation data is fetched from
         <a href="https://mempool.space" class="hover:underline" target="_blank" rel="noopener">mempool.space</a>
         with <a href="https://blockstream.info" class="hover:underline" target="_blank" rel="noopener">blockstream.info</a> as fallback.
      </p>
      <p>LedgerProof℠ · <a href="https://ledgerproofhq.io" class="hover:underline" target="_blank" rel="noopener">ledgerproofhq.io</a></p>
    </footer>
  </div>
`

const form = document.querySelector<HTMLFormElement>('#verify-form')!
const input = document.querySelector<HTMLInputElement>('#seq-input')!
const resultEl = document.querySelector<HTMLDivElement>('#result')!

form.addEventListener('submit', async (e) => {
  e.preventDefault()
  const seq = parseInt(input.value.trim(), 10)
  if (isNaN(seq) || seq < 0) {
    showError('Enter a valid sequence number (0 or greater).')
    return
  }
  await runVerification(seq)
})

// Slug → sequence resolver. Loaded once on page load; the SPA serves a single
// HTML shell at every path, so we have to consult window.location.pathname
// ourselves. Defensive: any error in slug resolution falls back to manual entry.
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
  resultEl.innerHTML = `
    <div class="p-4 rounded-lg text-sm"
         style="background-color: rgba(232, 168, 124, 0.15);
                border: 1px solid var(--color-accent-warm);
                color: var(--color-navy)">
      <p class="font-medium">Receipt for "${escapeHtml(slug)}" reserved but not yet issued.</p>
      <p class="mt-1" style="color: var(--color-navy-soft)">
        This canonical entry will resolve once it has been anchored.
        In the meantime, you can verify any other entry by sequence number above.
      </p>
    </div>
  `
}

function showSlugUnknown(slug: string) {
  showError(`No receipt registered under the slug "${escapeHtml(slug)}".`)
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
  const supersedeLine = entry.supersede_slug
    ? `<p class="mt-2"><a href="/r/${escapeHtml(entry.supersede_slug)}"
            style="color: var(--color-navy); border-bottom: 1px solid var(--color-mint)">
            Open the canonical replacement: /r/${escapeHtml(entry.supersede_slug)} →
         </a></p>`
    : ''
  const museumLine = entry.museum_url
    ? `<p class="mt-1"><a href="${escapeHtml(entry.museum_url)}" target="_blank" rel="noopener"
            style="color: var(--color-navy-soft)">
            Read the museum page → ${escapeHtml(entry.museum_url)}
         </a></p>`
    : ''
  resultEl.innerHTML = `
    <div class="p-4 rounded-lg text-sm"
         style="background-color: rgba(232, 168, 124, 0.15);
                border: 1px solid var(--color-accent-warm);
                color: var(--color-navy)">
      <p class="font-medium">Entry #${seq} — pre-v1.0 publisher-draft artifact</p>
      <p class="mt-1" style="color: var(--color-navy-soft)">
        ${escapeHtml(entry.summary)}
      </p>
      <p class="mt-2">
        <a href="${escapeHtml(entry.errata_url)}" target="_blank" rel="noopener"
           style="color: var(--color-navy); border-bottom: 1px solid var(--color-mint)">
          See ${escapeHtml(entry.errata_id)} for the full explanation →
        </a>
      </p>
      ${supersedeLine}
      ${museumLine}
    </div>
  `
}

// Routing — runs on initial load AND on hashchange (so in-tab navigation between
// #/<sequence> hashes re-triggers verification without a full page reload).
async function route() {
  const pathMatch = window.location.pathname.match(/^\/r\/([a-z0-9][a-z0-9-]*[a-z0-9])\/?$/i)
  const hashMatch = window.location.hash.match(/^#\/(\d+)$/)

  if (hashMatch) {
    const seq = parseInt(hashMatch[1], 10)
    input.value = String(seq)
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
      input.value = String(seq)
      showPreV1Card(seq, preV1Entry)
      return
    }
    input.value = String(seq)
    runVerification(seq)
  }
}

// Initial route + listen for in-tab hash navigation
route()
window.addEventListener('hashchange', () => { route() })

async function runVerification(seq: number) {
  resultEl.innerHTML = `
    <div class="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400 py-6">
      <svg class="animate-spin w-4 h-4 text-mint" fill="none" viewBox="0 0 24 24">
        <circle class="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" stroke-width="4"/>
        <path class="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8z"/>
      </svg>
      Verifying entry #${seq}…
    </div>
  `

  try {
    const result = await verifyEntry(seq)
    resultEl.innerHTML = renderResult(result)
  } catch (err) {
    showError(`Verification failed: ${err instanceof Error ? err.message : String(err)}`)
  }
}

function showError(msg: string) {
  resultEl.innerHTML = `
    <div class="p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800
                rounded-lg text-sm text-red-700 dark:text-red-400">
      ${msg}
    </div>
  `
}

function renderResult(r: VerificationResult): string {
  const { entry, receipt, checks, overallStatus, confirmations } = r

  const statusBadge = overallStatus === 'verified'
    ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-green-100 text-green-800 dark:bg-green-900/30 dark:text-green-400">
         ✓ Verified
       </span>`
    : overallStatus === 'failed'
    ? `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400">
         ✗ Failed
       </span>`
    : `<span class="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-medium
                    bg-yellow-100 text-yellow-800 dark:bg-yellow-900/30 dark:text-yellow-400">
         ⚠ Partial
       </span>`

  const anchorTxid = receipt?.anchor_txid ? escapeHtml(receipt.anchor_txid) : null
  const anchorSection = receipt?.anchor_status === 'confirmed' && anchorTxid
    ? `<div class="mt-4 p-3 bg-orange-50 dark:bg-orange-900/10 border border-orange-200
                   dark:border-orange-800 rounded-lg text-xs space-y-1">
         <p class="font-medium text-orange-800 dark:text-orange-400">Bitcoin Anchor</p>
         <p class="font-mono break-all text-gray-600 dark:text-gray-400">
           <a href="https://mempool.space/tx/${anchorTxid}" target="_blank" rel="noopener"
              class="hover:underline text-orange-600 dark:text-orange-400">${anchorTxid}</a>
         </p>
         <p class="text-gray-500">
           Block ${receipt!.anchor_block_height ?? '—'}
           ${confirmations != null ? `· ${confirmations} confirmation${confirmations !== 1 ? 's' : ''}` : ''}
           ${receipt!.anchored_at ? `· ${new Date(receipt!.anchored_at).toLocaleString()}` : ''}
         </p>
       </div>`
    : ''

  return `
    <div class="space-y-6">
      <!-- Header -->
      <div class="flex items-start justify-between gap-4">
        <div>
          <h2 class="text-lg font-semibold text-gray-900 dark:text-white">Entry #${entry.sequence}</h2>
          <p class="text-xs text-gray-500 mt-0.5">
            ${escapeHtml(entry.publisher_id)} · ${new Date(entry.entry_timestamp).toLocaleString()}
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
          Entry details
        </summary>
        <div class="mt-3 space-y-2 text-xs">
          ${detailRow('Entry hash', entry.entry_hash, true)}
          ${detailRow('Prev hash', entry.prev_hash, true)}
          ${detailRow('Signature', entry.signature, true)}
          ${detailRow('Key ID', entry.key_id)}
          ${detailRow('Protocol', entry.protocol_version)}
          ${detailRow('Content type', entry.content_type)}
          <div>
            <span class="text-gray-500 font-medium">Content</span>
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

  return `
    <div class="flex items-start gap-3 px-4 py-3 text-sm">
      <span class="mt-0.5 text-base leading-none flex-shrink-0">${icon}</span>
      <div class="flex-1 min-w-0">
        <span class="font-medium text-gray-900 dark:text-white">${escapeHtml(check.name)}</span>
        <p class="text-xs text-gray-500 dark:text-gray-400 mt-0.5">${escapeHtml(check.detail)}</p>
      </div>
      ${safeLinkHref ? `<a href="${escapeHtml(safeLinkHref)}" target="_blank" rel="noopener"
          class="text-xs text-mint-deep hover:underline flex-shrink-0">View →</a>` : ''}
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
