// Full verification pipeline — runs all checks independently of the LedgerProof backend.

import { sha256Hex, verifyEd25519, verifyMerkleProof, parseOpReturn } from './crypto'
import { ledgerApi, type EntryRow, type ReceiptRow, type KeyRow } from './api'
import { getTransaction, extractOpReturn, getTipHeight, memPoolTxUrl } from './bitcoin'

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'pending'

export interface Check {
  name: string
  status: CheckStatus
  detail: string
  link?: string
}

export interface VerificationResult {
  entry: EntryRow
  receipt: ReceiptRow | null
  key: KeyRow | null
  checks: Check[]
  overallStatus: 'verified' | 'failed' | 'partial'
  confirmations: number | null
}

export async function verifyEntry(sequence: number): Promise<VerificationResult> {
  const checks: Check[] = []

  // ── 1. Fetch entry ────────────────────────────────────────────────────────
  const entry = await ledgerApi.getEntry(sequence)
  checks.push({ name: 'Entry exists', status: 'pass', detail: `Sequence #${sequence} found on LedgerProof API` })

  // ── 2. Recompute entry hash ───────────────────────────────────────────────
  const computedHash = sha256Hex(new TextEncoder().encode(entry.entry_json_canonical))
  const hashMatch = computedHash === entry.entry_hash
  checks.push({
    name: 'Entry hash',
    status: hashMatch ? 'pass' : 'fail',
    detail: hashMatch
      ? `SHA-256(canonical JSON) = ${entry.entry_hash.slice(0, 16)}… ✓`
      : `Expected ${entry.entry_hash.slice(0, 16)}…, computed ${computedHash.slice(0, 16)}…`,
  })

  // ── 3. Verify content hash ────────────────────────────────────────────────
  // Use content from entry_json_canonical to preserve original key order —
  // PostgreSQL JSONB sorts keys alphabetically, so entry.content would produce a different hash.
  const canonicalEntry = JSON.parse(entry.entry_json_canonical)
  const contentBytes = new TextEncoder().encode(JSON.stringify(canonicalEntry.content))
  const computedContentHash = sha256Hex(contentBytes)
  const contentHashMatch = computedContentHash === entry.content_hash
  checks.push({
    name: 'Content hash',
    status: contentHashMatch ? 'pass' : 'fail',
    detail: contentHashMatch
      ? `SHA-256(content) = ${entry.content_hash.slice(0, 16)}… ✓`
      : `Content hash mismatch — content may have been tampered`,
  })

  // ── 4. Fetch publisher key ────────────────────────────────────────────────
  let key: KeyRow | null = null
  try {
    const { keys } = await ledgerApi.getKeys(entry.publisher_id)
    key = keys.find(k =>
      k.key_id === entry.key_id &&
      sequence >= k.effective_from_sequence &&
      (k.revoked_at_sequence == null || sequence < k.revoked_at_sequence)
    ) ?? null

    checks.push({
      name: 'Publisher key',
      status: key ? 'pass' : 'fail',
      detail: key
        ? `Key ${entry.key_id} was active at sequence ${sequence}`
        : `Key ${entry.key_id} not found or not valid at sequence ${sequence}`,
    })
  } catch (err) {
    checks.push({ name: 'Publisher key', status: 'warn', detail: `Could not fetch keys: ${err}` })
  }

  // ── 5. Verify Ed25519 signature ───────────────────────────────────────────
  if (key) {
    const sigValid = await verifyEd25519(entry.entry_hash, entry.signature, key.verifying_key_b64)
    checks.push({
      name: 'Ed25519 signature',
      status: sigValid ? 'pass' : 'fail',
      detail: sigValid
        ? `Signature over entry_hash verified against ${entry.key_id} ✓`
        : `Signature INVALID — entry may have been tampered`,
    })
  } else {
    checks.push({ name: 'Ed25519 signature', status: 'warn', detail: 'Skipped — could not load key' })
  }

  // ── 6. Fetch receipt ──────────────────────────────────────────────────────
  let receipt: ReceiptRow | null = null
  let confirmations: number | null = null

  try {
    receipt = await ledgerApi.getReceipt(sequence)
    checks.push({
      name: 'Receipt',
      status: 'pass',
      detail: `Anchor status: ${receipt.anchor_status}`,
    })
  } catch {
    checks.push({ name: 'Receipt', status: 'warn', detail: 'Receipt not found' })
  }

  // ── 7–9. Bitcoin anchor checks (only if confirmed) ────────────────────────
  if (receipt?.anchor_status === 'confirmed' && receipt.anchor_txid && receipt.merkle_proof) {
    // 7. Merkle proof structural validation (Finding 16: fix always-true check)
    const proofValid =
      Array.isArray(receipt.merkle_proof) &&
      receipt.merkle_proof.every(
        (step: unknown) =>
          typeof step === 'object' &&
          step !== null &&
          typeof (step as { hash: unknown }).hash === 'string' &&
          /^[0-9a-f]{64}$/.test((step as { hash: string }).hash) &&
          typeof (step as { is_left: unknown }).is_left === 'boolean',
      )
    checks.push({
      name: 'Merkle proof structure',
      status: proofValid ? 'pass' : 'fail',
      detail: proofValid
        ? `Proof has ${receipt.merkle_proof.length} sibling(s) — structure valid`
        : `Proof is malformed or contains invalid fields`,
    })

    // 8. Bitcoin transaction lookup
    try {
      const tx = await getTransaction(receipt.anchor_txid)
      const opReturnHex = extractOpReturn(tx)

      checks.push({
        name: 'Bitcoin OP_RETURN',
        status: opReturnHex ? 'pass' : 'fail',
        detail: opReturnHex
          ? `Found OP_RETURN in tx ${receipt.anchor_txid.slice(0, 12)}…`
          : `No OP_RETURN output in tx ${receipt.anchor_txid.slice(0, 12)}…`,
        link: memPoolTxUrl(receipt.anchor_txid),
      })

      // 9. Parse and verify OP_RETURN payload
      if (opReturnHex) {
        const parsed = parseOpReturn(opReturnHex)
        if (parsed) {
          checks.push({
            name: 'OP_RETURN magic + range',
            status: 'pass',
            detail: `QE20 magic ✓ · seq ${parsed.seqStart}–${parsed.seqEnd} · root ${parsed.merkleRoot.slice(0, 12)}…`,
          })

          // Verify Merkle proof against on-chain root
          const merkleValid = verifyMerkleProof(entry.entry_hash, receipt.merkle_proof!, parsed.merkleRoot)
          checks.push({
            name: 'Merkle proof → on-chain root',
            status: merkleValid ? 'pass' : 'fail',
            detail: merkleValid
              ? `Entry ${entry.entry_hash.slice(0, 12)}… proven in Merkle tree with on-chain root ✓`
              : `Merkle proof does not lead to on-chain root — TAMPER ALERT`,
          })
        } else {
          checks.push({
            name: 'OP_RETURN magic + range',
            status: 'fail',
            detail: `OP_RETURN payload missing QE20 magic or wrong length (${opReturnHex.length / 2} bytes)`,
          })
        }
      }

      // 10. Confirmation depth
      try {
        const tipHeight = await getTipHeight()
        if (tx.status.confirmed && tx.status.block_height) {
          confirmations = tipHeight - tx.status.block_height + 1
          checks.push({
            name: 'Confirmation depth',
            status: confirmations >= 6 ? 'pass' : 'warn',
            detail: `${confirmations} confirmation${confirmations !== 1 ? 's' : ''} (${tx.status.block_height ? `block ${tx.status.block_height}` : 'unconfirmed'})`,
          })
        }
      } catch {
        checks.push({ name: 'Confirmation depth', status: 'warn', detail: 'Could not fetch chain tip' })
      }
    } catch (err) {
      checks.push({
        name: 'Bitcoin transaction',
        status: 'warn',
        detail: `Could not fetch Bitcoin tx: ${err}`,
        link: memPoolTxUrl(receipt.anchor_txid),
      })
    }
  } else if (receipt?.anchor_status === 'pending') {
    checks.push({
      name: 'Bitcoin anchor',
      status: 'warn',
      detail: 'Entry is pending its daily Bitcoin anchor (runs at 02:00 UTC)',
    })
  }

  const failed = checks.filter(c => c.status === 'fail').length
  const warned = checks.filter(c => c.status === 'warn').length
  const overallStatus = failed > 0 ? 'failed' : warned > 0 ? 'partial' : 'verified'

  return { entry, receipt, key, checks, overallStatus, confirmations }
}
