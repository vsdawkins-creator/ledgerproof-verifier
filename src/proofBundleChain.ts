// Optional on-chain confirmation for the offline proof-bundle verdict.
//
// verifyBundle() proves the 15 arithmetic hops with ZERO network. The one thing
// it cannot do offline is confirm that `bitcoin.txid` is a real, confirmed
// transaction whose OP_RETURN actually carries the committed payload. That is one
// GET against a PUBLIC block explorer (mempool.space, blockstream.info fallback) —
// NOT against LedgerProof — so running it keeps the "no trust in LedgerProof"
// property while upgrading the verdict's `chain_checked` to true.

import { getTransaction, extractOpReturn, getTipHeight, memPoolTxUrl } from './bitcoin'

export interface ChainConfirmation {
  /** The tx exists, is confirmed, has an OP_RETURN, and it carries the bundle's exact payload. */
  confirmed: boolean
  /** The on-chain OP_RETURN bytes equal the bundle's op_return_payload. */
  opReturnMatches: boolean
  blockHeight: number | null
  blockTime: number | null // unix seconds
  confirmations: number | null
  txUrl: string
  error?: string
}

/** Confirm that `txid`'s OP_RETURN carries `opReturnPayloadHex` exactly, using a
 *  public block explorer. Never throws — network failure returns `error` set. */
export async function confirmAnchorOnChain(
  txid: string,
  opReturnPayloadHex: string,
): Promise<ChainConfirmation> {
  const txUrl = memPoolTxUrl(txid)
  try {
    const tx = await getTransaction(txid)
    const onChain = extractOpReturn(tx)
    const want = opReturnPayloadHex.toLowerCase()
    const opReturnMatches = onChain != null && onChain.toLowerCase() === want

    let confirmations: number | null = null
    if (tx.status.confirmed && tx.status.block_height != null) {
      try {
        const tip = await getTipHeight()
        confirmations = tip - tx.status.block_height + 1
      } catch {
        confirmations = null
      }
    }

    return {
      confirmed: !!(tx.status.confirmed && opReturnMatches),
      opReturnMatches,
      blockHeight: tx.status.block_height ?? null,
      blockTime: tx.status.block_time ?? null,
      confirmations,
      txUrl,
    }
  } catch (err) {
    return {
      confirmed: false,
      opReturnMatches: false,
      blockHeight: null,
      blockTime: null,
      confirmations: null,
      txUrl,
      error: err instanceof Error ? err.message : String(err),
    }
  }
}
