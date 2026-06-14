// Full verification pipeline — runs all checks independently of the LedgerProof backend.

import { sha256Hex, verifyEd25519, verifyMerkleProof, parseOpReturn } from './crypto'
import { ledgerApi, type EntryRow, type ReceiptRow, type KeyRow } from './api'
import { getTransaction, extractOpReturn, getTipHeight, memPoolTxUrl } from './bitcoin'
import { t } from './i18n'

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'pending'

export interface Check {
  name: string
  // i18n: a stable name/detail key + interpolation params. `name`/`detail` carry
  // the English source as a runtime fallback, so a missing key degrades to
  // English (never a raw key). main.ts renders t(nameKey)/t(detailKey, params).
  nameKey?: string
  detailKey?: string
  detailParams?: Record<string, string | number>
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
  checks.push({ name: 'Entry exists', nameKey: 'check.entryExists', status: 'pass', detail: `Sequence #${sequence} found on LedgerProof API`, detailKey: 'cd.entryExists', detailParams: { seq: sequence } })

  // ── 2. Recompute entry hash ───────────────────────────────────────────────
  const computedHash = sha256Hex(new TextEncoder().encode(entry.entry_json_canonical))
  const hashMatch = computedHash === entry.entry_hash
  checks.push({
    name: 'Entry hash',
    nameKey: 'check.entryHash',
    status: hashMatch ? 'pass' : 'fail',
    detail: hashMatch
      ? `SHA-256(canonical JSON) = ${entry.entry_hash.slice(0, 16)}… ✓`
      : `Expected ${entry.entry_hash.slice(0, 16)}…, computed ${computedHash.slice(0, 16)}…`,
    detailKey: hashMatch ? 'cd.entryHash.pass' : 'cd.entryHash.fail',
    detailParams: { h: entry.entry_hash.slice(0, 16), exp: entry.entry_hash.slice(0, 16), got: computedHash.slice(0, 16) },
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
    nameKey: 'check.contentHash',
    status: contentHashMatch ? 'pass' : 'fail',
    detail: contentHashMatch
      ? `SHA-256(content) = ${entry.content_hash.slice(0, 16)}… ✓`
      : `Content hash mismatch — content may have been tampered`,
    detailKey: contentHashMatch ? 'cd.contentHash.pass' : 'cd.contentHash.fail',
    detailParams: { h: entry.content_hash.slice(0, 16) },
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
      nameKey: 'check.publisherKey',
      status: key ? 'pass' : 'fail',
      detail: key
        ? `Key ${entry.key_id} was active at sequence ${sequence}`
        : `Key ${entry.key_id} not found or not valid at sequence ${sequence}`,
      detailKey: key ? 'cd.publisherKey.pass' : 'cd.publisherKey.fail',
      detailParams: { kid: entry.key_id, seq: sequence },
    })
  } catch (err) {
    checks.push({ name: 'Publisher key', nameKey: 'check.publisherKey', status: 'warn', detail: `Could not fetch keys: ${err}`, detailKey: 'cd.publisherKey.warn', detailParams: { err: String(err) } })
  }

  // ── 5. Verify Ed25519 signature ───────────────────────────────────────────
  if (key) {
    const sigValid = await verifyEd25519(entry.entry_hash, entry.signature, key.verifying_key_b64)
    checks.push({
      name: 'Ed25519 signature',
      nameKey: 'check.ed25519',
      status: sigValid ? 'pass' : 'fail',
      detail: sigValid
        ? `Signature over entry_hash verified against ${entry.key_id} ✓`
        : `Signature INVALID — entry may have been tampered`,
      detailKey: sigValid ? 'cd.ed25519.pass' : 'cd.ed25519.fail',
      detailParams: { kid: entry.key_id },
    })
  } else {
    checks.push({ name: 'Ed25519 signature', nameKey: 'check.ed25519', status: 'warn', detail: 'Skipped — could not load key', detailKey: 'cd.ed25519.warn' })
  }

  // ── 6. Fetch receipt ──────────────────────────────────────────────────────
  let receipt: ReceiptRow | null = null
  let confirmations: number | null = null

  try {
    receipt = await ledgerApi.getReceipt(sequence)
    checks.push({
      name: 'Receipt',
      nameKey: 'check.receipt',
      status: 'pass',
      detail: `Anchor status: ${receipt.anchor_status}`,
      detailKey: 'cd.receipt.pass',
      detailParams: { st: receipt.anchor_status },
    })
  } catch {
    checks.push({ name: 'Receipt', nameKey: 'check.receipt', status: 'warn', detail: 'Receipt not found', detailKey: 'cd.receipt.warn' })
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
      nameKey: 'check.merkleStructure',
      status: proofValid ? 'pass' : 'fail',
      detail: proofValid
        ? `Proof has ${receipt.merkle_proof.length} sibling(s) — structure valid`
        : `Proof is malformed or contains invalid fields`,
      detailKey: proofValid ? 'cd.merkleStructure.pass' : 'cd.merkleStructure.fail',
      detailParams: { n: receipt.merkle_proof.length },
    })

    // 8. Bitcoin transaction lookup
    try {
      const tx = await getTransaction(receipt.anchor_txid)
      const opReturnHex = extractOpReturn(tx)

      checks.push({
        name: 'Bitcoin OP_RETURN',
        nameKey: 'check.opReturn',
        status: opReturnHex ? 'pass' : 'fail',
        detail: opReturnHex
          ? `Found OP_RETURN in tx ${receipt.anchor_txid.slice(0, 12)}…`
          : `No OP_RETURN output in tx ${receipt.anchor_txid.slice(0, 12)}…`,
        detailKey: opReturnHex ? 'cd.opReturn.pass' : 'cd.opReturn.fail',
        detailParams: { txid: receipt.anchor_txid.slice(0, 12) },
        link: memPoolTxUrl(receipt.anchor_txid),
      })

      // 9. Parse and verify OP_RETURN payload
      if (opReturnHex) {
        const parsed = parseOpReturn(opReturnHex)
        if (parsed) {
          checks.push({
            name: 'OP_RETURN magic + range',
            nameKey: 'check.opReturnMagic',
            status: 'pass',
            detail: `QE20 magic ✓ · seq ${parsed.seqStart}–${parsed.seqEnd} · root ${parsed.merkleRoot.slice(0, 12)}…`,
            detailKey: 'cd.opReturnMagic.pass',
            detailParams: { a: parsed.seqStart, b: parsed.seqEnd, r: parsed.merkleRoot.slice(0, 12) },
          })

          // Verify Merkle proof against on-chain root
          const merkleValid = verifyMerkleProof(entry.entry_hash, receipt.merkle_proof!, parsed.merkleRoot)
          checks.push({
            name: 'Merkle proof → on-chain root',
            nameKey: 'check.merkleRoot',
            status: merkleValid ? 'pass' : 'fail',
            detail: merkleValid
              ? `Entry ${entry.entry_hash.slice(0, 12)}… proven in Merkle tree with on-chain root ✓`
              : `Merkle proof does not lead to on-chain root — TAMPER ALERT`,
            detailKey: merkleValid ? 'cd.merkleRoot.pass' : 'cd.merkleRoot.fail',
            detailParams: { h: entry.entry_hash.slice(0, 12) },
          })
        } else {
          checks.push({
            name: 'OP_RETURN magic + range',
            nameKey: 'check.opReturnMagic',
            status: 'fail',
            detail: `OP_RETURN payload missing QE20 magic or wrong length (${opReturnHex.length / 2} bytes)`,
            detailKey: 'cd.opReturnMagic.fail',
            detailParams: { bytes: opReturnHex.length / 2 },
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
            nameKey: 'check.confDepth',
            status: confirmations >= 6 ? 'pass' : 'warn',
            detail: `${confirmations} confirmation${confirmations !== 1 ? 's' : ''} (${tx.status.block_height ? `block ${tx.status.block_height}` : 'unconfirmed'})`,
            detailKey: 'cd.confDepth',
            detailParams: {
              n: confirmations,
              block: tx.status.block_height ? t('cd.confDepth.block', { bh: tx.status.block_height }) : t('cd.confDepth.unconfirmed'),
            },
          })
        }
      } catch {
        checks.push({ name: 'Confirmation depth', nameKey: 'check.confDepth', status: 'warn', detail: 'Could not fetch chain tip', detailKey: 'cd.confDepth.warn' })
      }
    } catch (err) {
      checks.push({
        name: 'Bitcoin transaction',
        nameKey: 'check.bitcoinTx',
        status: 'warn',
        detail: `Could not fetch Bitcoin tx: ${err}`,
        detailKey: 'cd.bitcoinTx.warn',
        detailParams: { err: String(err) },
        link: memPoolTxUrl(receipt.anchor_txid),
      })
    }
  } else if (receipt?.anchor_status === 'pending') {
    checks.push({
      name: 'Bitcoin anchor',
      nameKey: 'check.bitcoinAnchor',
      status: 'warn',
      detail: 'Entry is pending its daily Bitcoin anchor (runs at 02:00 UTC)',
      detailKey: 'cd.bitcoinAnchor.pending',
    })
  }

  const failed = checks.filter(c => c.status === 'fail').length
  const warned = checks.filter(c => c.status === 'warn').length
  const overallStatus = failed > 0 ? 'failed' : warned > 0 ? 'partial' : 'verified'

  return { entry, receipt, key, checks, overallStatus, confirmations }
}
