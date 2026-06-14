// ── Verifier internationalization ────────────────────────────────────────────
// FR / DE / EN, sharing the same `lp_lang` localStorage key as the Vault app,
// pricing, and scanner so a visitor's language choice follows them across every
// LedgerProof surface. The verifier is the regulator/auditor surface (a German
// or French competent authority verifies a receipt here), so every user-facing
// string — page chrome, the verification checklist, and the verdict details —
// is localized. English is always the fallback: a missing key degrades to the
// English string passed at the call site, never to a raw key.

export type Lang = 'en' | 'de' | 'fr'
export const LANGS: Lang[] = ['en', 'de', 'fr']

type Dict = Record<string, string>

const EN: Dict = {
  // Page chrome
  'app.h1': 'LedgerProof Verifier',
  'app.intro': 'Independently verify that a published entry exists, was signed by the declared publisher, and is included in a Merkle tree anchored to Bitcoin.',
  'app.placeholder': 'Entry sequence number',
  'app.verify': 'Verify',
  'app.footer1': 'This verifier performs all cryptographic checks in your browser using @noble/ed25519 and @noble/hashes. Bitcoin confirmation data is fetched from {mempool} with {blockstream} as fallback.',
  // Errors & routing states
  'err.invalidSeq': 'Enter a valid sequence number (0 or greater).',
  'err.verifyFailed': 'Verification failed: {msg}',
  'slug.pending.title': 'Receipt for “{slug}” reserved but not yet issued.',
  'slug.pending.body': 'This canonical entry will resolve once it has been anchored. In the meantime, you can verify any other entry by sequence number above.',
  'slug.unknown': 'No receipt registered under the slug “{slug}”.',
  'prev1.title': 'Entry #{seq} — pre-v1.0 publisher-draft artifact',
  'prev1.errata': 'See {id} for the full explanation →',
  'prev1.supersede': 'Open the canonical replacement: /r/{slug} →',
  'prev1.museum': 'Read the museum page → {url}',
  'loading': 'Verifying entry #{seq}…',
  // Result chrome
  'badge.verified': '✓ Verified',
  'badge.failed': '✗ Failed',
  'badge.partial': '⚠ Partial',
  'anchor.title': 'Bitcoin Anchor',
  'anchor.block': 'Block {h}',
  'result.entry': 'Entry #{seq}',
  'details.summary': 'Entry details',
  'detail.entryHash': 'Entry hash',
  'detail.prevHash': 'Prev hash',
  'detail.signature': 'Signature',
  'detail.keyId': 'Key ID',
  'detail.protocol': 'Protocol',
  'detail.contentType': 'Content type',
  'detail.content': 'Content',
  'check.view': 'View →',
  'confirmations': '{n} confirmation(s)',
  // Check names
  'check.entryExists': 'Entry exists',
  'check.entryHash': 'Entry hash',
  'check.contentHash': 'Content hash',
  'check.publisherKey': 'Publisher key',
  'check.ed25519': 'Ed25519 signature',
  'check.receipt': 'Receipt',
  'check.merkleStructure': 'Merkle proof structure',
  'check.opReturn': 'Bitcoin OP_RETURN',
  'check.opReturnMagic': 'OP_RETURN magic + range',
  'check.merkleRoot': 'Merkle proof → on-chain root',
  'check.confDepth': 'Confirmation depth',
  'check.bitcoinAnchor': 'Bitcoin anchor',
  'check.bitcoinTx': 'Bitcoin transaction',
  // Check details
  'cd.entryExists': 'Sequence #{seq} found on LedgerProof API',
  'cd.entryHash.pass': 'SHA-256(canonical JSON) = {h}… ✓',
  'cd.entryHash.fail': 'Expected {exp}…, computed {got}…',
  'cd.contentHash.pass': 'SHA-256(content) = {h}… ✓',
  'cd.contentHash.fail': 'Content hash mismatch — content may have been tampered',
  'cd.publisherKey.pass': 'Key {kid} was active at sequence {seq}',
  'cd.publisherKey.fail': 'Key {kid} not found or not valid at sequence {seq}',
  'cd.publisherKey.warn': 'Could not fetch keys: {err}',
  'cd.ed25519.pass': 'Signature over entry_hash verified against {kid} ✓',
  'cd.ed25519.fail': 'Signature INVALID — entry may have been tampered',
  'cd.ed25519.warn': 'Skipped — could not load key',
  'cd.receipt.pass': 'Anchor status: {st}',
  'cd.receipt.warn': 'Receipt not found',
  'cd.merkleStructure.pass': 'Proof has {n} sibling(s) — structure valid',
  'cd.merkleStructure.fail': 'Proof is malformed or contains invalid fields',
  'cd.opReturn.pass': 'Found OP_RETURN in tx {txid}…',
  'cd.opReturn.fail': 'No OP_RETURN output in tx {txid}…',
  'cd.opReturnMagic.pass': 'QE20 magic ✓ · seq {a}–{b} · root {r}…',
  'cd.opReturnMagic.fail': 'OP_RETURN payload missing QE20 magic or wrong length ({bytes} bytes)',
  'cd.merkleRoot.pass': 'Entry {h}… proven in Merkle tree with on-chain root ✓',
  'cd.merkleRoot.fail': 'Merkle proof does not lead to on-chain root — TAMPER ALERT',
  'cd.confDepth': '{n} confirmation(s) ({block})',
  'cd.confDepth.block': 'block {bh}',
  'cd.confDepth.unconfirmed': 'unconfirmed',
  'cd.confDepth.warn': 'Could not fetch chain tip',
  'cd.bitcoinTx.warn': 'Could not fetch Bitcoin tx: {err}',
  'cd.bitcoinAnchor.pending': 'Entry is pending its daily Bitcoin anchor (runs at 02:00 UTC)',
}

const DE: Dict = {
  'app.h1': 'LedgerProof Verifizierer',
  'app.intro': 'Verifizieren Sie unabhängig, dass ein veröffentlichter Eintrag existiert, vom angegebenen Herausgeber signiert wurde und in einem an Bitcoin verankerten Merkle-Baum enthalten ist.',
  'app.placeholder': 'Sequenznummer des Eintrags',
  'app.verify': 'Verifizieren',
  'app.footer1': 'Dieser Verifizierer führt alle kryptografischen Prüfungen in Ihrem Browser mit @noble/ed25519 und @noble/hashes durch. Bitcoin-Bestätigungsdaten werden von {mempool} mit {blockstream} als Ausweichquelle abgerufen.',
  'err.invalidSeq': 'Geben Sie eine gültige Sequenznummer ein (0 oder größer).',
  'err.verifyFailed': 'Verifizierung fehlgeschlagen: {msg}',
  'slug.pending.title': 'Beleg für „{slug}“ reserviert, aber noch nicht ausgestellt.',
  'slug.pending.body': 'Dieser kanonische Eintrag wird auflösbar, sobald er verankert wurde. In der Zwischenzeit können Sie oben jeden anderen Eintrag per Sequenznummer verifizieren.',
  'slug.unknown': 'Kein Beleg unter dem Slug „{slug}“ registriert.',
  'prev1.title': 'Eintrag Nr. {seq} — Entwurfsartefakt eines Herausgebers vor v1.0',
  'prev1.errata': 'Siehe {id} für die vollständige Erläuterung →',
  'prev1.supersede': 'Kanonischen Ersatz öffnen: /r/{slug} →',
  'prev1.museum': 'Museumsseite lesen → {url}',
  'loading': 'Eintrag Nr. {seq} wird verifiziert…',
  'badge.verified': '✓ Verifiziert',
  'badge.failed': '✗ Fehlgeschlagen',
  'badge.partial': '⚠ Teilweise',
  'anchor.title': 'Bitcoin-Verankerung',
  'anchor.block': 'Block {h}',
  'result.entry': 'Eintrag Nr. {seq}',
  'details.summary': 'Eintragsdetails',
  'detail.entryHash': 'Eintrags-Hash',
  'detail.prevHash': 'Vorheriger Hash',
  'detail.signature': 'Signatur',
  'detail.keyId': 'Schlüssel-ID',
  'detail.protocol': 'Protokoll',
  'detail.contentType': 'Inhaltstyp',
  'detail.content': 'Inhalt',
  'check.view': 'Ansehen →',
  'confirmations': '{n} Bestätigung(en)',
  'check.entryExists': 'Eintrag existiert',
  'check.entryHash': 'Eintrags-Hash',
  'check.contentHash': 'Inhalts-Hash',
  'check.publisherKey': 'Herausgeberschlüssel',
  'check.ed25519': 'Ed25519-Signatur',
  'check.receipt': 'Beleg',
  'check.merkleStructure': 'Struktur des Merkle-Nachweises',
  'check.opReturn': 'Bitcoin OP_RETURN',
  'check.opReturnMagic': 'OP_RETURN-Magic + Bereich',
  'check.merkleRoot': 'Merkle-Nachweis → On-Chain-Wurzel',
  'check.confDepth': 'Bestätigungstiefe',
  'check.bitcoinAnchor': 'Bitcoin-Verankerung',
  'check.bitcoinTx': 'Bitcoin-Transaktion',
  'cd.entryExists': 'Sequenz Nr. {seq} in der LedgerProof-API gefunden',
  'cd.entryHash.pass': 'SHA-256(kanonisches JSON) = {h}… ✓',
  'cd.entryHash.fail': 'Erwartet {exp}…, berechnet {got}…',
  'cd.contentHash.pass': 'SHA-256(Inhalt) = {h}… ✓',
  'cd.contentHash.fail': 'Inhalts-Hash stimmt nicht überein — Inhalt könnte manipuliert worden sein',
  'cd.publisherKey.pass': 'Schlüssel {kid} war bei Sequenz {seq} aktiv',
  'cd.publisherKey.fail': 'Schlüssel {kid} nicht gefunden oder bei Sequenz {seq} nicht gültig',
  'cd.publisherKey.warn': 'Schlüssel konnten nicht abgerufen werden: {err}',
  'cd.ed25519.pass': 'Signatur über entry_hash gegen {kid} verifiziert ✓',
  'cd.ed25519.fail': 'Signatur UNGÜLTIG — Eintrag könnte manipuliert worden sein',
  'cd.ed25519.warn': 'Übersprungen — Schlüssel konnte nicht geladen werden',
  'cd.receipt.pass': 'Verankerungsstatus: {st}',
  'cd.receipt.warn': 'Beleg nicht gefunden',
  'cd.merkleStructure.pass': 'Nachweis hat {n} Geschwister — Struktur gültig',
  'cd.merkleStructure.fail': 'Nachweis ist fehlerhaft oder enthält ungültige Felder',
  'cd.opReturn.pass': 'OP_RETURN in Tx {txid}… gefunden',
  'cd.opReturn.fail': 'Kein OP_RETURN-Ausgang in Tx {txid}…',
  'cd.opReturnMagic.pass': 'QE20-Magic ✓ · Seq {a}–{b} · Wurzel {r}…',
  'cd.opReturnMagic.fail': 'OP_RETURN-Nutzlast fehlt QE20-Magic oder falsche Länge ({bytes} Bytes)',
  'cd.merkleRoot.pass': 'Eintrag {h}… im Merkle-Baum mit On-Chain-Wurzel nachgewiesen ✓',
  'cd.merkleRoot.fail': 'Merkle-Nachweis führt nicht zur On-Chain-Wurzel — MANIPULATIONSALARM',
  'cd.confDepth': '{n} Bestätigung(en) ({block})',
  'cd.confDepth.block': 'Block {bh}',
  'cd.confDepth.unconfirmed': 'unbestätigt',
  'cd.confDepth.warn': 'Chain-Spitze konnte nicht abgerufen werden',
  'cd.bitcoinTx.warn': 'Bitcoin-Tx konnte nicht abgerufen werden: {err}',
  'cd.bitcoinAnchor.pending': 'Eintrag wartet auf seine tägliche Bitcoin-Verankerung (läuft um 02:00 UTC)',
}

const FR: Dict = {
  'app.h1': 'Vérificateur LedgerProof',
  'app.intro': 'Vérifiez de façon indépendante qu’une entrée publiée existe, a été signée par l’émetteur déclaré et est incluse dans un arbre de Merkle ancré à Bitcoin.',
  'app.placeholder': 'Numéro de séquence de l’entrée',
  'app.verify': 'Vérifier',
  'app.footer1': 'Ce vérificateur effectue toutes les vérifications cryptographiques dans votre navigateur avec @noble/ed25519 et @noble/hashes. Les données de confirmation Bitcoin proviennent de {mempool}, avec {blockstream} en secours.',
  'err.invalidSeq': 'Saisissez un numéro de séquence valide (0 ou plus).',
  'err.verifyFailed': 'Échec de la vérification : {msg}',
  'slug.pending.title': 'Reçu pour « {slug} » réservé mais pas encore émis.',
  'slug.pending.body': 'Cette entrée canonique deviendra résolvable une fois ancrée. En attendant, vous pouvez vérifier toute autre entrée par numéro de séquence ci-dessus.',
  'slug.unknown': 'Aucun reçu enregistré sous le slug « {slug} ».',
  'prev1.title': 'Entrée n° {seq} — artefact de brouillon d’émetteur antérieur à la v1.0',
  'prev1.errata': 'Voir {id} pour l’explication complète →',
  'prev1.supersede': 'Ouvrir le remplacement canonique : /r/{slug} →',
  'prev1.museum': 'Lire la page musée → {url}',
  'loading': 'Vérification de l’entrée n° {seq}…',
  'badge.verified': '✓ Vérifié',
  'badge.failed': '✗ Échec',
  'badge.partial': '⚠ Partiel',
  'anchor.title': 'Ancrage Bitcoin',
  'anchor.block': 'Bloc {h}',
  'result.entry': 'Entrée n° {seq}',
  'details.summary': 'Détails de l’entrée',
  'detail.entryHash': 'Hachage de l’entrée',
  'detail.prevHash': 'Hachage précédent',
  'detail.signature': 'Signature',
  'detail.keyId': 'ID de clé',
  'detail.protocol': 'Protocole',
  'detail.contentType': 'Type de contenu',
  'detail.content': 'Contenu',
  'check.view': 'Voir →',
  'confirmations': '{n} confirmation(s)',
  'check.entryExists': 'L’entrée existe',
  'check.entryHash': 'Hachage de l’entrée',
  'check.contentHash': 'Hachage du contenu',
  'check.publisherKey': 'Clé de l’émetteur',
  'check.ed25519': 'Signature Ed25519',
  'check.receipt': 'Reçu',
  'check.merkleStructure': 'Structure de la preuve de Merkle',
  'check.opReturn': 'Bitcoin OP_RETURN',
  'check.opReturnMagic': 'Magic OP_RETURN + plage',
  'check.merkleRoot': 'Preuve de Merkle → racine on-chain',
  'check.confDepth': 'Profondeur de confirmation',
  'check.bitcoinAnchor': 'Ancrage Bitcoin',
  'check.bitcoinTx': 'Transaction Bitcoin',
  'cd.entryExists': 'Séquence n° {seq} trouvée sur l’API LedgerProof',
  'cd.entryHash.pass': 'SHA-256(JSON canonique) = {h}… ✓',
  'cd.entryHash.fail': 'Attendu {exp}…, calculé {got}…',
  'cd.contentHash.pass': 'SHA-256(contenu) = {h}… ✓',
  'cd.contentHash.fail': 'Le hachage du contenu ne correspond pas — le contenu a pu être altéré',
  'cd.publisherKey.pass': 'La clé {kid} était active à la séquence {seq}',
  'cd.publisherKey.fail': 'Clé {kid} introuvable ou non valide à la séquence {seq}',
  'cd.publisherKey.warn': 'Impossible de récupérer les clés : {err}',
  'cd.ed25519.pass': 'Signature sur entry_hash vérifiée par rapport à {kid} ✓',
  'cd.ed25519.fail': 'Signature INVALIDE — l’entrée a pu être altérée',
  'cd.ed25519.warn': 'Ignoré — impossible de charger la clé',
  'cd.receipt.pass': 'Statut d’ancrage : {st}',
  'cd.receipt.warn': 'Reçu introuvable',
  'cd.merkleStructure.pass': 'La preuve a {n} frère(s) — structure valide',
  'cd.merkleStructure.fail': 'La preuve est malformée ou contient des champs non valides',
  'cd.opReturn.pass': 'OP_RETURN trouvé dans la tx {txid}…',
  'cd.opReturn.fail': 'Aucune sortie OP_RETURN dans la tx {txid}…',
  'cd.opReturnMagic.pass': 'Magic QE20 ✓ · séq {a}–{b} · racine {r}…',
  'cd.opReturnMagic.fail': 'La charge OP_RETURN n’a pas le magic QE20 ou une longueur incorrecte ({bytes} octets)',
  'cd.merkleRoot.pass': 'Entrée {h}… prouvée dans l’arbre de Merkle avec racine on-chain ✓',
  'cd.merkleRoot.fail': 'La preuve de Merkle ne mène pas à la racine on-chain — ALERTE D’ALTÉRATION',
  'cd.confDepth': '{n} confirmation(s) ({block})',
  'cd.confDepth.block': 'bloc {bh}',
  'cd.confDepth.unconfirmed': 'non confirmé',
  'cd.confDepth.warn': 'Impossible de récupérer la pointe de la chaîne',
  'cd.bitcoinTx.warn': 'Impossible de récupérer la tx Bitcoin : {err}',
  'cd.bitcoinAnchor.pending': 'L’entrée attend son ancrage Bitcoin quotidien (à 02:00 UTC)',
}

const CATALOG: Record<Lang, Dict> = { en: EN, de: DE, fr: FR }

function detectLang(): Lang {
  try {
    const saved = localStorage.getItem('lp_lang')
    if (saved && (LANGS as string[]).includes(saved)) return saved as Lang
  } catch { /* ignore */ }
  try {
    const nav = (navigator.language || 'en').slice(0, 2).toLowerCase()
    if ((LANGS as string[]).includes(nav)) return nav as Lang
  } catch { /* ignore */ }
  return 'en'
}

let LANG: Lang = detectLang()

export function getLang(): Lang { return LANG }

export function setLang(l: Lang): void {
  LANG = (LANGS as string[]).includes(l) ? l : 'en'
  try { localStorage.setItem('lp_lang', LANG) } catch { /* ignore */ }
  document.documentElement.lang = LANG
}

// Translate `key` in the active language; interpolate {param} tokens. Falls back
// to English, then to the provided `fallback` (English source at the call site),
// then to the key itself — so the verdict text never renders as a raw key.
export function t(key: string, params?: Record<string, string | number>, fallback?: string): string {
  let s = CATALOG[LANG][key] ?? EN[key] ?? fallback ?? key
  if (params) {
    for (const [k, v] of Object.entries(params)) {
      s = s.split('{' + k + '}').join(String(v))
    }
  }
  return s
}

// The header language switcher, styled to match the verifier chrome.
export function langSwitcherHtml(): string {
  const opt = (l: Lang, label: string) =>
    `<option value="${l}"${l === LANG ? ' selected' : ''}>${label}</option>`
  return `
    <select id="lang-switch" aria-label="Language"
      class="text-xs rounded-md px-2 py-1 bg-cream text-navy cursor-pointer"
      style="border:1px solid var(--color-navy-faint)">
      ${opt('en', 'EN')}${opt('de', 'DE')}${opt('fr', 'FR')}
    </select>`
}
