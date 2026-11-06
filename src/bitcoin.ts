// Bitcoin / Esplora client — mempool.space primary, blockstream.info fallback.
// Used to independently confirm the OP_RETURN anchor on-chain.

const PRIMARY = 'https://mempool.space/api'
const FALLBACK = 'https://blockstream.info/api'

async function esplora<T>(path: string): Promise<T> {
  const primaryUrl = `${PRIMARY}${path}`
  try {
    const res = await fetch(primaryUrl)
    if (res.ok) return res.json()
  } catch { /* fall through */ }

  const fallbackUrl = `${FALLBACK}${path}`
  const res = await fetch(fallbackUrl)
  if (!res.ok) throw new Error(`Esplora ${res.status} from fallback: ${res.statusText}`)
  return res.json()
}

async function esploraText(path: string): Promise<string> {
  const primaryUrl = `${PRIMARY}${path}`
  try {
    const res = await fetch(primaryUrl)
    if (res.ok) return res.text()
  } catch { /* fall through */ }

  const fallbackUrl = `${FALLBACK}${path}`
  const res = await fetch(fallbackUrl)
  if (!res.ok) throw new Error(`Esplora ${res.status}: ${res.statusText}`)
  return res.text()
}

export interface TxVout {
  scriptpubkey: string
  scriptpubkey_type: string
  value: number
}

export interface TxStatus {
  confirmed: boolean
  block_height: number | null
  block_time: number | null
  block_hash: string | null
}

export interface TxInfo {
  txid: string
  vout: TxVout[]
  status: TxStatus
}

export async function getTransaction(txid: string): Promise<TxInfo> {
  return esplora<TxInfo>(`/tx/${txid}`)
}

export async function getTipHeight(): Promise<number> {
  const text = await esploraText('/blocks/tip/height')
  return parseInt(text.trim(), 10)
}

/** Find the OP_RETURN output in a transaction and return its data as hex.
 * OP_RETURN scriptpubkey starts with "6a" (OP_RETURN opcode).
 */
export function extractOpReturn(tx: TxInfo): string | null {
  for (const out of tx.vout) {
    if (out.scriptpubkey_type === 'op_return') {
      // scriptpubkey format: 6a <len> <data> — strip the 6a and pushdata prefix
      const script = out.scriptpubkey
      if (!script.startsWith('6a')) return null
      // Skip OP_RETURN (6a) and the push opcode byte(s). Return EXACTLY the
      // declared push length rather than all remaining script hex, so a multi-push
      // or padded OP_RETURN can't cause an over-read (for the real LPR1 anchor
      // formats — a single direct push ≤ 75 bytes — this is identical to before).
      const afterOpReturn = script.slice(2)
      const firstByte = parseInt(afterOpReturn.slice(0, 2), 16)
      if (firstByte <= 75) {
        // direct push: firstByte is the data length in bytes
        return afterOpReturn.slice(2, 2 + firstByte * 2)
      }
      if (firstByte === 0x4c) {
        // OP_PUSHDATA1: next byte is the data length
        const len = parseInt(afterOpReturn.slice(2, 4), 16)
        return afterOpReturn.slice(4, 4 + len * 2)
      }
      return afterOpReturn.slice(2)
    }
  }
  return null
}

export function memPoolTxUrl(txid: string): string {
  return `https://mempool.space/tx/${txid}`
}
