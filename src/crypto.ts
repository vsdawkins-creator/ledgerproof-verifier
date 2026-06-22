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

/** Parse a LedgerProof OP_RETURN payload, LENGTH-DISCRIMINATING the known layouts.
 * A parser MUST branch on the exact byte length before reading any root — the root sits
 * at a different offset in each layout, so treating a 68-byte payload as "a 44 with trailing
 * data" would read a garbage window straddling two roots.
 *
 *   44 bytes: MAGIC || seq_start(u32 BE) || seq_end(u32 BE) || root(32)   — deployed legacy, root@12.
 *             MAGIC ∈ {"LPR1" (v1.0+), "QE20" (pre-v1 forensic)}.
 *   68 bytes: "LPR1" || legacy_root(32) || scitt_root(32)                 — combined SCITT, legacy@4 / scitt@36, no seq.
 *   36 bytes: "LPR1" || root(32)                                          — single-root (legacy-only or SCITT-only window).
 *
 * `merkleRoot` is always the LEGACY/primary root the legacy receipt's Merkle proof reproduces
 * (offset 12 for 44-byte, offset 4 for 68/36-byte). `scittRoot` is the SCITT root when the
 * combined layout carries one, else null. `seqStart`/`seqEnd` are null for layouts without them.
 * See LPR-VER-001 (OP_RETURN tag policy) + the SCITT profile §6.
 */
export function parseOpReturn(payloadHex: string): {
  magic: string
  seqStart: number | null
  seqEnd: number | null
  merkleRoot: string
  scittRoot: string | null
} | null {
  try {
    const bytes = hexToBytes(payloadHex)
    if (bytes.length < 4) return null
    const magic = String.fromCharCode(...bytes.slice(0, 4))
    if (bytes.length === 44) {
      if (magic !== 'QE20' && magic !== 'LPR1') return null
      const view = new DataView(bytes.buffer, bytes.byteOffset)
      return {
        magic,
        seqStart: view.getUint32(4, false),
        seqEnd: view.getUint32(8, false),
        merkleRoot: bytesToHex(bytes.slice(12, 44)),
        scittRoot: null,
      }
    }
    if (bytes.length === 68) {
      if (magic !== 'LPR1') return null
      return {
        magic,
        seqStart: null,
        seqEnd: null,
        merkleRoot: bytesToHex(bytes.slice(4, 36)),
        scittRoot: bytesToHex(bytes.slice(36, 68)),
      }
    }
    if (bytes.length === 36) {
      if (magic !== 'LPR1') return null
      return {
        magic,
        seqStart: null,
        seqEnd: null,
        merkleRoot: bytesToHex(bytes.slice(4, 36)),
        scittRoot: null,
      }
    }
    return null
  } catch {
    return null
  }
}
