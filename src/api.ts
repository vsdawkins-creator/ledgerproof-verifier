// LedgerProof API client — reads from the public read-only endpoints.

const API_BASE = import.meta.env.VITE_API_URL ?? 'https://api.ledgerproofhq.io'

async function get<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`)
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
