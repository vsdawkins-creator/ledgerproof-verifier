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

// ── URL hash routing: #/<sequence> auto-verifies on load ──────────────────────

document.querySelector<HTMLDivElement>('#app')!.innerHTML = `
  <div class="max-w-2xl mx-auto px-6 py-12">
    <header class="mb-10">
      <h1 class="text-2xl font-semibold text-gray-900 dark:text-white tracking-tight">
        LedgerProof Verifier
      </h1>
      <p class="mt-1 text-sm text-gray-500 dark:text-gray-400">
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
        class="flex-1 px-4 py-2.5 border border-gray-300 dark:border-gray-600 rounded-lg text-sm
               bg-white dark:bg-gray-900 text-gray-900 dark:text-white
               focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />
      <button type="submit"
        class="px-5 py-2.5 bg-indigo-600 text-white rounded-lg text-sm font-medium
               hover:bg-indigo-700 transition whitespace-nowrap">
        Verify
      </button>
    </form>

    <div id="result"></div>

    <footer class="mt-16 pt-6 border-t border-gray-200 dark:border-gray-800 text-xs text-gray-400 text-center space-y-1">
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

// Auto-verify if URL hash contains a sequence: #/42
const hashMatch = window.location.hash.match(/^#\/(\d+)$/)
if (hashMatch) {
  const seq = parseInt(hashMatch[1], 10)
  input.value = String(seq)
  runVerification(seq)
}

async function runVerification(seq: number) {
  resultEl.innerHTML = `
    <div class="flex items-center gap-3 text-sm text-gray-500 dark:text-gray-400 py-6">
      <svg class="animate-spin w-4 h-4 text-indigo-500" fill="none" viewBox="0 0 24 24">
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
          class="text-xs text-indigo-500 hover:underline flex-shrink-0">View →</a>` : ''}
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
