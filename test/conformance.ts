// Conformance gate: the app's offline verifyBundle MUST reproduce the FROZEN
// golden projections for every vector, byte-for-byte. The goldens — not this
// verifier — are the authority (SPEC-EVIDENCE-VERDICT §3.1); a verifier conforms
// by matching them, exactly as the Python/Node/Rust/Go/SDK reference verifiers do.
//
// This is what "the web verifier is repointed onto the standard, with no drift"
// means concretely. Run: `npm run test:conformance` (Node 22+ strips the types).
//
// Fixtures are copied verbatim from ledgerproof-standard/conformance/proof-bundle-v1.
// Vectors carrying `bundle_raw` hold raw JSON text (their duplicate keys cannot
// survive re-serialization) and are parsed here exactly as any consumer would.

import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { verifyBundle, type EvidenceVerdict } from '../src/proofBundle.ts'

const here = dirname(fileURLToPath(import.meta.url))
const fx = join(here, 'fixtures', 'proof-bundle-v1')
const vectors = JSON.parse(readFileSync(join(fx, 'vectors.json'), 'utf8')).vectors as Array<{
  name: string
  bundle?: unknown
  bundle_raw?: string
}>
const goldens = JSON.parse(readFileSync(join(fx, 'golden-verdicts.json'), 'utf8')).projections as Record<
  string,
  unknown
>

/** The comparable core of a verdict (SPEC-EVIDENCE-VERDICT §3): drop `verifier`,
 *  reduce each check to {id, pass}, keep everything else. A MALFORMED verdict
 *  omits claim/subject/anchor; the golden (Python `.get()`) renders them null,
 *  so normalise undefined -> null to match. */
function project(v: EvidenceVerdict): unknown {
  return {
    v: v.v,
    spec: v.spec,
    verdict: v.verdict,
    confidence: v.confidence,
    claim: v.claim ?? null,
    subject: v.subject ?? null,
    anchor: v.anchor ?? null,
    chain_checked: v.chain_checked,
    checks: v.checks.map((c) => ({ id: c.id, pass: c.pass })),
  }
}

function canon(o: unknown): string {
  if (o === null || typeof o !== 'object') return JSON.stringify(o)
  if (Array.isArray(o)) return '[' + o.map(canon).join(',') + ']'
  const r = o as Record<string, unknown>
  return '{' + Object.keys(r).sort().map((k) => JSON.stringify(k) + ':' + canon(r[k])).join(',') + '}'
}

let pass = 0
const failures: string[] = []

// Fail-closed on coverage: the whole point of this gate is "no drift from the
// frozen standard", so a dropped/renamed vector must turn CI red rather than
// silently shrink the run. Assert the expected count and that goldens ⇄ vectors
// are in exact correspondence, in BOTH directions.
const EXPECTED_VECTOR_COUNT = 26
if (vectors.length !== EXPECTED_VECTOR_COUNT) {
  failures.push(`vector count is ${vectors.length}, expected ${EXPECTED_VECTOR_COUNT} — a vector was added or dropped`)
}
const vectorNames = new Set(vectors.map((v) => v.name))
for (const gName of Object.keys(goldens)) {
  if (!vectorNames.has(gName)) failures.push(`golden "${gName}" has no matching vector`)
}

for (const v of vectors) {
  const golden = goldens[v.name]
  if (golden === undefined) {
    failures.push(`${v.name}: NO GOLDEN`)
    continue
  }
  let got: string
  try {
    const bundle = v.bundle_raw !== undefined ? JSON.parse(v.bundle_raw) : v.bundle
    got = canon(project(verifyBundle(bundle)))
  } catch (e) {
    failures.push(`${v.name}: THREW ${(e as Error).message}`)
    continue
  }
  const want = canon(golden)
  if (got === want) {
    pass++
  } else {
    failures.push(`${v.name}:\n    got : ${got}\n    want: ${want}`)
  }
}

const total = vectors.length
if (failures.length === 0) {
  console.log(`✓ ${pass}/${total} vectors: offline verifyBundle projections byte-identical to frozen goldens`)
  process.exit(0)
} else {
  console.error(`✗ ${pass}/${total} passed — ${failures.length} FAILED:\n`)
  for (const f of failures) console.error('  ' + f + '\n')
  process.exit(1)
}
