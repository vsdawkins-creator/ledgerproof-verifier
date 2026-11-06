// LedgerProof API client — reads from the public read-only endpoints.

const API_BASE = import.meta.env.VITE_API_URL ?? 'https://api.ledgerproofhq.io'

// The read API can accept a TCP connection and then never answer. A bare
// fetch() then never settles, runVerification's catch never fires, and the page
// sits on "Verifying entry #…" forever with nothing to tell the visitor the
// fault is ours. That is the exact failure this verifier exists to avoid, so
// the request is bounded and the UI is told which kind of failure it was.
const API_TIMEOUT_MS = 15_000

/** The record API could not be reached, or did not answer in time. Distinct
 *  from a bad HTTP response so the UI can say look-up is unavailable instead of
 *  claiming verification failed — nothing about a held proof is in doubt. */
export class ApiUnavailableError extends Error {
  // Declared and assigned explicitly rather than as a constructor parameter
  // property: the project builds under erasableSyntaxOnly, so the type
  // annotation has to be strippable without emitting any runtime code.
  readonly timedOut: boolean

  constructor(timedOut: boolean) {
    super(timedOut ? 'record API timed out' : 'record API unreachable')
    this.name = 'ApiUnavailableError'
    this.timedOut = timedOut
  }
}

async function get<T>(path: string): Promise<T> {
  let res: Response
  try {
    res = await fetch(`${API_BASE}${path}`, { signal: AbortSignal.timeout(API_TIMEOUT_MS) })
  } catch (err) {
    throw new ApiUnavailableError(
      err instanceof DOMException && (err.name === 'TimeoutError' || err.name === 'AbortError'),
    )
  }
  if (!res.ok) throw new Error(`API ${res.status}: ${res.statusText}`)
  return res.json()
}

export interface EntryRow {
  sequence: number
  publisher_id: string
  key_id: string
  prev_hash: string
  entry_hash: string
  signature: string
  protocol_version: string
  content_type: string
  content_hash: string
  content: unknown
  entry_json_canonical: string
  entry_timestamp: string
}

export interface ReceiptRow {
  sequence: number
  receipt_version: string
  anchor_status: 'pending' | 'confirmed'
  anchor_txid: string | null
  anchor_block_height: number | null
  anchor_block_time: string | null
  merkle_proof: Array<{ hash: string; is_left: boolean }> | null
  verify_url: string
  created_at: string
  anchored_at: string | null
}

export interface KeyRow {
  key_id: string
  publisher_id: string
  verifying_key_b64: string
  effective_from_sequence: number
  revoked_at_sequence: number | null
}

export const ledgerApi = {
  getEntry: (seq: number) => get<EntryRow>(`/v1/entries/${seq}`),
  getReceipt: (seq: number) => get<ReceiptRow>(`/v1/receipts/${seq}`),
  getKeys: (publisherId: string) =>
    get<{ keys: KeyRow[] }>(`/v1/keys?publisher_id=${publisherId}`),
  searchEntries: (limit = 20) =>
    get<{ entries: EntryRow[] }>(`/v1/entries?limit=${limit}`),
}
