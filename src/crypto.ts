// Pure-JS cryptographic primitives for independent verification.
// Uses @noble/ed25519 and @noble/hashes — both are widely audited libraries
// with no native code, so this verifier runs without WASM or server trust.

import { verifyAsync as ed25519Verify } from '@noble/ed25519'
import { sha256 } from '@noble/hashes/sha2.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'

export function sha256Hex(data: Uint8Array): string {
  return bytesToHex(sha256(data))
}

export function sha256Bytes(data: Uint8Array): Uint8Array<ArrayBuffer> {
  return sha256(data) as Uint8Array<ArrayBuffer>
}

/** Verify an Ed25519 signature.
 * @param messageHex    hex-encoded message (the entry_hash bytes)
 * @param signatureHex  128-char hex (64-byte signature)
 * @param publicKeyB64  base64-encoded 32-byte public key
 */
export async function verifyEd25519(
  messageHex: string,
  signatureHex: string,
  publicKeyB64: string,
): Promise<boolean> {
  try {
    const message = hexToBytes(messageHex)
    const signature = hexToBytes(signatureHex)
    const publicKey = hexToBytes(bytesToHex(Uint8Array.from(atob(publicKeyB64), c => c.charCodeAt(0))))
    return await ed25519Verify(signature, message, publicKey)
  } catch {
    return false
  }
}

/** Verify a Merkle inclusion proof.
 * Each sibling: { hash: hex, is_left: bool }
 * Convention: is_left=true means the SIBLING is the LEFT child.
 *   is_left=true  → SHA-256(sibling || current)  (sibling goes first)
 *   is_left=false → SHA-256(current || sibling)  (current goes first)
 * This matches the JSON written by the confirmer and the WASM verifier.
 */
export function verifyMerkleProof(
  leafHex: string,
  proof: Array<{ hash: string; is_left: boolean }>,
  rootHex: string,
): boolean {
  try {
    let current = hexToBytes(leafHex)
    for (const { hash, is_left } of proof) {
      const sibling = hexToBytes(hash)
      const combined = new Uint8Array(64)
      if (is_left) {
        combined.set(sibling, 0)
        combined.set(current, 32)
      } else {
        combined.set(current, 0)
        combined.set(sibling, 32)
      }
      current = sha256Bytes(combined)
    }
    return bytesToHex(current) === rootHex
  } catch {
    return false
  }
}

/** Parse and verify a LedgerProof OP_RETURN payload.
 * Format (44 bytes): 4-byte magic + 4-byte seq_start BE + 4-byte seq_end BE + 32-byte merkle_root.
 * Two magics share this identical layout and MUST both be accepted so the full on-chain
 * history verifies: "LPR1" (canonical, LPR v1.0+) and the legacy "QE20" (pre-v1 forensic
 * anchors). See LPR-VER-001 — the OP_RETURN tag policy permits QE20 (pre-v1) and LPR1 (v1.0+).
 * Returns parsed fields (including which magic was found) or null if invalid.
 */
export function parseOpReturn(payloadHex: string): {
  magic: string
  seqStart: number
  seqEnd: number
  merkleRoot: string
} | null {
  try {
    const bytes = hexToBytes(payloadHex)
    if (bytes.length < 44) return null
    const magic = String.fromCharCode(...bytes.slice(0, 4))
    if (magic !== 'QE20' && magic !== 'LPR1') return null
    const view = new DataView(bytes.buffer, bytes.byteOffset)
    const seqStart = view.getUint32(4, false)
    const seqEnd = view.getUint32(8, false)
    const merkleRoot = bytesToHex(bytes.slice(12, 44))
    return { magic, seqStart, seqEnd, merkleRoot }
  } catch {
    return null
  }
}
