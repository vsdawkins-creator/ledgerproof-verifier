// Offline verifier for `ledgerproof/proof-bundle/1` — the engine this whole app
// is repointed onto.
//
// Given a self-contained proof bundle, ANY third party reaches a deterministic
// verdict with ZERO network calls and without trusting LedgerProof. verifyBundle
// returns an `evidence-verdict/1` object (SPEC-EVIDENCE-VERDICT): a machine-
// readable projection an agent, a CI gate, or an auditor's tool acts on directly.
//
// This is a byte-for-byte sibling of the reference verifiers in the conformance
// suite (Python/Node/Rust/Go and the shipping @ledgerproof/sdk): the same 16
// ordered checks and the same verdict projection, proven identical to
// `golden-verdicts.json` across all 26 vectors (test/conformance.ts). It shares
// no code with the producer — a verifier that shares code with the producer
// proves nothing.
//
// Crypto is @noble/hashes (Cure53-audited) — the same SHA-256 crypto.ts already
// uses, so this adds no dependency and needs no CSP change. It does NOT reuse any
// general-purpose canonical-JSON helper that escapes non-ASCII (ensure_ascii=
// true, to match witness-server signature bytes); the proof-bundle content_hash
// is defined over RAW UTF-8 (SPEC-PROOF-BUNDLE §5), so a spec-faithful canonical
// lives here. Reusing the wrong one would pass today's all-ASCII vectors and
// silently diverge on the first accented byte.
//
// ⚠ TWO DIFFERENT MERKLE TREES — the default implementer mistake:
//   document_tree  RFC-6962   leaf sha256(0x00||h)  node sha256(0x01||L||R)
//                             direction derived from (leaf_index, tree_size)
//   anchor_tree    Bitcoin    leaf RAW               node sha256(L||R)
//                             direction from each step's explicit is_left flag
//
// v1 proves EXISTENCE, not attribution: no check here verifies the publisher
// signature (SPEC-PROOF-BUNDLE §1.4). Identity is v2. The sequence-lookup path in
// this app (verify.ts) additionally checks the Ed25519 signature, so it proves
// more; this engine is the portable, offline, standard-conformant existence proof.

import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes, concatBytes } from '@noble/hashes/utils.js'

export const PROOF_BUNDLE_SPEC = 'ledgerproof/proof-bundle/1'
export const EVIDENCE_VERDICT_VERSION = 'ledgerproof/evidence-verdict/1'

const VERIFIER = {
  implementation: 'ledgerproof-verifier (offline, in-browser, @noble)',
  spec: PROOF_BUNDLE_SPEC,
} as const

/** One executed check. `detail` is present only on failure. */
export interface VerdictCheck {
  id: string
  label: string
  pass: boolean
  detail?: string
}

/** The `evidence-verdict/1` object. `claim`/`subject`/`anchor` are absent when MALFORMED. */
export interface EvidenceVerdict {
  v: typeof EVIDENCE_VERDICT_VERSION
  spec: typeof PROOF_BUNDLE_SPEC
  verdict: 'PROVEN' | 'NOT_PROVEN' | 'MALFORMED'
  confidence: 'cryptographic' | 'none'
  error?: string
  claim?: {
    sha256: string
    proven_no_later_than: string
    observed_on: string
    observation_attested: false
    attestation_gap_days: number | null
  }
  subject?: { native_id: string | null; source: string | null; title: string | null }
  anchor?: { txid: string | null; block_height: number | null; block_time: string | null }
  chain_checked: boolean
  checks: VerdictCheck[]
  verifier: typeof VERIFIER
}

const H = (bytes: Uint8Array): Uint8Array => sha256(bytes)
const b = (n: number): Uint8Array => Uint8Array.from([n])
const REQUIRED = ['document', 'document_tree', 'log_entry', 'anchor_tree', 'bitcoin', 'claim'] as const

/** Strict hex → bytes. Odd length or a non-hex character is an error, never a
 *  silent truncation (the cross-language divergence trap, SPEC-EVIDENCE-VERDICT §5). */
function strictHex(s: unknown): Uint8Array {
  if (typeof s !== 'string' || s.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(s)) {
    throw new Error(`invalid hex: ${JSON.stringify(s)}`)
  }
  return hexToBytes(s)
}

const isObject = (x: unknown): x is Record<string, unknown> =>
  typeof x === 'object' && x !== null && !Array.isArray(x)

/** Proof-bundle canonical JSON: sorted keys, minimal separators, RAW UTF-8
 *  (ensure_ascii=false). JSON.stringify is already UTF-8-native. */
function pbCanonical(v: unknown): string {
  if (v === null || typeof v !== 'object') return JSON.stringify(v)
  if (Array.isArray(v)) return '[' + v.map(pbCanonical).join(',') + ']'
  const o = v as Record<string, unknown>
  return (
    '{' +
    Object.keys(o)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + pbCanonical(o[k]))
      .join(',') +
    '}'
  )
}

/** document_tree — RFC-6962 §2.1.1 inclusion proof (direction from index/size). */
function rfc6962Root(leaf: Uint8Array, index: number, size: number, path: Uint8Array[]): Uint8Array {
  if (!(Number.isInteger(index) && Number.isInteger(size) && index >= 0 && index < size)) {
    throw new Error('leaf_index/tree_size not integers, or index out of range')
  }
  let fn = index
  let sn = size - 1
  let r = leaf
  for (const p of path) {
    if (sn === 0) throw new Error('proof longer than tree depth')
    if ((fn & 1) === 1 || fn === sn) {
      r = H(concatBytes(b(0x01), p, r))
      if ((fn & 1) === 0) {
        for (;;) {
          fn >>= 1
          sn >>= 1
          if ((fn & 1) !== 0 || fn === 0) break
        }
      }
    } else {
      r = H(concatBytes(b(0x01), r, p))
    }
    fn >>= 1
    sn >>= 1
  }
  if (sn !== 0) throw new Error('proof shorter than tree depth')
  return r
}

/** anchor_tree — Bitcoin-style, direction from each step's explicit is_left flag. */
function anchorRoot(entryHash: Uint8Array, steps: Array<{ hash: string; is_left?: boolean }>): Uint8Array {
  let cur = entryHash // RAW leaf, no prefix
  for (const s of steps) {
    const sib = strictHex(s.hash)
    cur = s.is_left ? H(concatBytes(sib, cur)) : H(concatBytes(cur, sib))
  }
  return cur
}

function gapDays(observedOn?: string, proven?: string): number | null {
  const m1 = /^(\d{4})-(\d{2})-(\d{2})/.exec(observedOn ?? '')
  const m2 = /^(\d{4})-(\d{2})-(\d{2})/.exec(proven ?? '')
  if (!m1 || !m2) return null
  const a = Date.UTC(+m1[1]!, +m1[2]! - 1, +m1[3]!)
  const d = Date.UTC(+m2[1]!, +m2[2]! - 1, +m2[3]!)
  return Math.round((d - a) / 86_400_000)
}

/**
 * Verify a proof bundle offline. Returns an evidence-verdict/1 object; never
 * throws (a malformed bundle yields verdict MALFORMED). No network is touched —
 * confirming `bitcoin.txid` on-chain is one GET against any block explorer and is
 * the caller's to make (`chain_checked` is always false here; the UI's optional
 * on-chain confirm sets it true after an independent Esplora lookup).
 */
export function verifyBundle(bundle: unknown): EvidenceVerdict {
  const checks: VerdictCheck[] = []
  const check = (id: string, label: string, ok: boolean, detail = ''): void => {
    const c: VerdictCheck = { id, label, pass: !!ok }
    if (detail && !ok) c.detail = detail
    checks.push(c)
  }
  const malformed = (error: string): EvidenceVerdict => ({
    v: EVIDENCE_VERDICT_VERSION,
    spec: PROOF_BUNDLE_SPEC,
    verdict: 'MALFORMED',
    confidence: 'none',
    error,
    chain_checked: false,
    checks,
    verifier: VERIFIER,
  })

  if (!isObject(bundle)) return malformed('bundle is not an object')
  check('bundle.version', 'version is ledgerproof/proof-bundle/1', bundle.v === PROOF_BUNDLE_SPEC)
  for (const k of REQUIRED) {
    if (!isObject(bundle[k])) return malformed(`missing required section: ${k}`)
  }

  const d = bundle.document as Record<string, unknown>
  const dt = bundle.document_tree as Record<string, unknown>
  const le = bundle.log_entry as Record<string, unknown>
  const at = bundle.anchor_tree as Record<string, unknown>
  const btc = bundle.bitcoin as Record<string, unknown>
  const claim = bundle.claim as Record<string, unknown>
  const content = (le.content ?? {}) as Record<string, unknown>

  // HOP 1 — document -> document_tree.root
  try {
    const got = bytesToHex(
      rfc6962Root(
        H(concatBytes(b(0x00), strictHex(d.sha256))),
        dt.leaf_index as number,
        dt.tree_size as number,
        (dt.proof as string[]).map(strictHex),
      ),
    )
    check('hop1.document_inclusion', 'HOP 1  document sha256 -> document_tree.root',
      got === dt.root, `computed=${got} expected=${String(dt.root)}`)
  } catch (e) {
    check('hop1.document_inclusion', 'HOP 1  document sha256 -> document_tree.root', false, (e as Error).message)
  }

  // HOP 2 — the signed log entry commits to that root and hashes as claimed.
  // Binding tree_size / source / observed_on is load-bearing: a single inclusion
  // proof does NOT pin tree_size (the `wrong-tree-size` vector proves it).
  check('hop2a.root_commitment', 'HOP 2a log_entry.content commits to document_tree.root',
    content.merkle_root === dt.root)
  check('hop2a.tree_size_commitment', "HOP 2a' log_entry.content commits to document_tree.tree_size",
    content.tree_size === dt.tree_size, `entry=${String(content.tree_size)} bundle=${String(dt.tree_size)}`)
  check('hop2a.source_commitment', 'HOP 2a" log_entry.content commits to the document\'s source',
    content.source === d.source, `entry=${String(content.source)} bundle=${String(d.source)}`)
  check('hop2a.observed_on_commitment', 'HOP 2a"\' log_entry.content commits to claim.observed_on',
    content.batch_date === claim.observed_on,
    `entry=${String(content.batch_date)} claim=${String(claim.observed_on)}`)
  const ch = bytesToHex(H(new TextEncoder().encode(pbCanonical(content))))
  check('hop2b.content_hash', 'HOP 2b content_hash = sha256(canonical(content))',
    ch === le.content_hash, `computed=${ch} expected=${String(le.content_hash)}`)
  const ejc = typeof le.entry_json_canonical === 'string' ? le.entry_json_canonical : ''
  const eh = bytesToHex(H(new TextEncoder().encode(ejc)))
  check('hop2c.entry_hash', 'HOP 2c entry_hash = sha256(entry_json_canonical)',
    eh === le.entry_hash, `computed=${eh} expected=${String(le.entry_hash)}`)
  check('hop2d.canonical_embeds_content_hash', 'HOP 2d entry_json_canonical embeds the same content_hash',
    ejc.includes(`"content_hash":"${String(le.content_hash)}"`))

  // HOP 3 — entry_hash -> anchor_tree.root (Bitcoin-style)
  try {
    const ar = bytesToHex(anchorRoot(strictHex(le.entry_hash), at.proof as Array<{ hash: string; is_left?: boolean }>))
    check('hop3.anchor_inclusion', 'HOP 3  entry_hash -> anchor_tree.root',
      ar === at.root, `computed=${ar} expected=${String(at.root)}`)
  } catch (e) {
    check('hop3.anchor_inclusion', 'HOP 3  entry_hash -> anchor_tree.root', false, (e as Error).message)
  }

  // HOP 4 — the anchored OP_RETURN carries that root. Undecodable hex -> empty
  // bytes so the length/magic/root/range checks fail individually, never abort.
  let p: Uint8Array = new Uint8Array(0)
  try {
    p = strictHex(btc.op_return_payload)
  } catch {
    /* empty bytes; the four checks below fail on their own */
  }
  const be32 = (o: number): number =>
    p.length >= o + 4 ? ((p[o]! << 24) | (p[o + 1]! << 16) | (p[o + 2]! << 8) | p[o + 3]!) >>> 0 : -1
  check('hop4a.payload_length', 'HOP 4a op_return is 44 bytes', p.length === 44, `got ${p.length}`)
  const magic = p.length >= 4 ? String.fromCharCode(p[0]!, p[1]!, p[2]!, p[3]!) : ''
  check('hop4b.magic', 'HOP 4b op_return magic is LPR1', magic === 'LPR1', `got ${bytesToHex(p.slice(0, 4))}`)
  check('hop4c.root_in_payload', 'HOP 4c op_return root == anchor_tree.root',
    p.length >= 44 && bytesToHex(p.slice(12, 44)) === at.root)
  const seq = le.sequence as number
  const s0 = be32(4)
  const s1 = be32(8)
  check('hop4d.sequence_in_range', 'HOP 4d log sequence falls inside the anchored range',
    s0 <= seq && seq <= s1, `${s0} <= ${seq} <= ${s1}`)

  // The claim must not overstate what was proven.
  check('claim.time_equals_block_time', 'CLAIM  proven_no_later_than == bitcoin.block_time',
    claim.proven_no_later_than === btc.block_time)
  check('claim.observation_unattested', 'CLAIM  observation is explicitly marked unattested',
    claim.observation_attested === false)

  const ok = checks.every((c) => c.pass)
  return {
    v: EVIDENCE_VERDICT_VERSION,
    spec: PROOF_BUNDLE_SPEC,
    verdict: ok ? 'PROVEN' : 'NOT_PROVEN',
    confidence: ok ? 'cryptographic' : 'none',
    claim: {
      sha256: d.sha256 as string,
      proven_no_later_than: claim.proven_no_later_than as string,
      observed_on: claim.observed_on as string,
      observation_attested: false,
      attestation_gap_days: gapDays(claim.observed_on as string, claim.proven_no_later_than as string),
    },
    subject: {
      native_id: (d.native_id as string) ?? null,
      source: (d.source as string) ?? null,
      title: (d.title as string) ?? null,
    },
    anchor: {
      txid: (btc.txid as string) ?? null,
      block_height: (btc.block_height as number) ?? null,
      block_time: (btc.block_time as string) ?? null,
    },
    chain_checked: false,
    checks,
    verifier: VERIFIER,
  }
}
