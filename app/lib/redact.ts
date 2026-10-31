// Secret redaction for Workflowy content.
//
// Everything that leaves this server (tool responses) or lands in the Neon cache
// passes through here first, so secrets stored in the outline never reach the
// MCP client or the database.
//
// Owner-controlled tags (in a bullet's text or note):
//   #sec      hide this bullet and everything under it
//   #nosec    show this one bullet as-is (its children keep the inherited rule)
//   #nosecall show this bullet and everything under it as-is
// The nearest tag wins: a deeper tag overrides one further up. If #sec and an
// allow tag sit on the same bullet, #sec wins. Untagged areas get greedy
// auto-detection.

export const REDACTED = "[REDACTED]";
export const SECRET_TAG = "sec";
export const ALLOW_TAG = "nosec";
export const ALLOW_TREE_TAG = "nosecall";

export interface Inherited {
  secret: boolean;
  allowAll: boolean;
}

export type Policy = "secret" | "allow" | "auto";

export const ROOT_INHERITED: Inherited = { secret: false, allowAll: false };

function tagPattern(tag: string): RegExp {
  // Not preceded by a word char, # or -, and not followed by a word char or -.
  return new RegExp(`(^|[^\\w#-])#${tag}(?![\\w-])`, "i");
}

const SECRET_TAG_RE = tagPattern(SECRET_TAG);
const ALLOW_TAG_RE = tagPattern(ALLOW_TAG);
const ALLOW_TREE_TAG_RE = tagPattern(ALLOW_TREE_TAG);

function anyMatch(texts: Array<string | null | undefined>, re: RegExp): boolean {
  return texts.some((text) => typeof text === "string" && re.test(text));
}

export function hasAllowTag(text: string): boolean {
  return ALLOW_TAG_RE.test(text) || ALLOW_TREE_TAG_RE.test(text);
}

export function hasSecretTag(text: string): boolean {
  return SECRET_TAG_RE.test(text);
}

/** Decide how to treat one bullet, and what its children inherit (nearest tag wins). */
export function nodePolicy(
  texts: Array<string | null | undefined>,
  inherited: Inherited,
): { policy: Policy; children: Inherited } {
  if (anyMatch(texts, SECRET_TAG_RE)) {
    return { policy: "secret", children: { secret: true, allowAll: false } };
  }
  if (anyMatch(texts, ALLOW_TREE_TAG_RE)) {
    return { policy: "allow", children: { secret: false, allowAll: true } };
  }
  if (anyMatch(texts, ALLOW_TAG_RE)) {
    return { policy: "allow", children: inherited };
  }
  const policy: Policy = inherited.secret ? "secret" : inherited.allowAll ? "allow" : "auto";
  return { policy, children: inherited };
}

/** Fold a root-to-parent chain of bullets into what the next bullet inherits. */
export function inheritFromChain(
  chain: Array<Array<string | null | undefined>>,
  start: Inherited = ROOT_INHERITED,
): Inherited {
  let inherited = start;
  for (const texts of chain) {
    inherited = nodePolicy(texts, inherited).children;
  }
  return inherited;
}

/** Placeholder for a fully hidden field; keeps #tags so inheritance still works from the cache. */
export function secretPlaceholder(text: string): string {
  const tags = text.match(/(?:^|[^\w#-])#[\w-]+/g) ?? [];
  const cleaned = [...new Set(tags.map((tag) => tag.trim().replace(/^[^#]+/, "")))];
  return cleaned.length ? `${REDACTED} ${cleaned.join(" ")}` : REDACTED;
}

function luhnValid(digits: string): boolean {
  let sum = 0;
  let double = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (double) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    sum += n;
    double = !double;
  }
  return sum % 10 === 0;
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function looksRandomToken(token: string): boolean {
  if (UUID_RE.test(token)) return false;
  const hasDigit = /\d/.test(token);
  const hasLower = /[a-z]/.test(token);
  const hasUpper = /[A-Z]/.test(token);
  if (token.length >= 20 && hasDigit && hasLower && hasUpper) return true;
  if (token.length >= 40 && hasDigit && (hasLower || hasUpper)) return true;
  return false;
}

const KEYWORDS = [
  "passwords?",
  "passwd",
  "pass(?:code|phrase)s?",
  "pw",
  "pwd",
  "pins?",
  "secrets?",
  "tokens?",
  "api[ _-]?keys?",
  "access[ _-]?keys?",
  "secret[ _-]?keys?",
  "private[ _-]?keys?",
  "client[ _-]?secrets?",
  "auth(?:orization)?",
  "credentials?",
  "logins?",
  "ssn",
  "seed(?:[ _-]?phrase)?",
  "recovery[ _-]?(?:codes?|keys?|phrase)",
  "backup[ _-]?codes?",
  "security[ _-]?(?:answers?|codes?)",
  "2fa(?:[ _-]?codes?)?",
  "otp",
].join("|");

const KEYWORD_LINE_RE = new RegExp(
  `(\\b(?:${KEYWORDS})\\b\\s*(?:[:=]|=>|->|\\bis\\b)\\s*)([^\\n]+)`,
  "gi",
);

const URL_RE = /\b[a-z][a-z0-9+.-]*:\/\/[^\s<>"'`)\]]+/gi;
const SECRET_PARAM_RE =
  /([?&#;](?:access_token|refresh_token|id_token|token|api[_-]?key|apikey|key|secret|client_secret|password|passwd|pwd|pass|auth|authorization|signature|sig|session|sessionid|jwt)=)([^&#\s]*)/gi;

/** Links stay readable; only embedded credentials and secret-named query params are hidden. */
function redactUrl(url: string): string {
  return url
    .replace(/^([a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:)([^\s@/]+)(@)/i, `$1${REDACTED}$3`)
    .replace(SECRET_PARAM_RE, (_m, name: string, value: string) => (value ? `${name}${REDACTED}` : name));
}

/** Greedy auto-detection. Over-redacting is intended; the owner can add #nosec. */
export function redactText(text: string): string {
  if (!text) return text;
  let out = text;

  // PEM private key blocks.
  out = out.replace(
    /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)/g,
    REDACTED,
  );
  // Set links aside so the generic token rules below never touch them.
  const urls: string[] = [];
  out = out.replace(URL_RE, (url) => {
    urls.push(redactUrl(url));
    return `\u0000${urls.length - 1}\u0000`;
  });
  out = redactLoose(out);
  // Restore links (a labeled line like "login: <link>" may have hidden one entirely).
  return out.replace(/\u0000(\d+)\u0000/g, (_m, index: string) => urls[Number(index)] ?? REDACTED);
}

function redactLoose(text: string): string {
  let out = text;
  // "password: ...", "api key = ...", "pin is ..." -> hide the rest of the line.
  out = out.replace(KEYWORD_LINE_RE, (_m, label: string) => `${label}${REDACTED}`);
  // Bearer tokens.
  out = out.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]{8,}=*/gi, `$1${REDACTED}`);
  // Well-known key prefixes.
  out = out.replace(
    /\b(?:sk|pk|rk)[-_][A-Za-z0-9_-]{16,}|\bgh[pousr]_[A-Za-z0-9]{20,}|\bgithub_pat_\w{20,}|\bxox[abprs]-[A-Za-z0-9-]{10,}|\bAKIA[0-9A-Z]{16}\b|\bAIza[0-9A-Za-z_-]{30,}|\bglpat-[A-Za-z0-9_-]{16,}|\bnpm_[A-Za-z0-9]{30,}/g,
    REDACTED,
  );
  // Long hex strings (API keys, hashes).
  out = out.replace(/\b[0-9a-f]{32,}\b/gi, REDACTED);
  // Long random-looking tokens not inside a URL path.
  out = out.replace(/(?<![\w/.#@-])[A-Za-z0-9+/_=-]{20,}(?![\w/.-])/g, (token) =>
    looksRandomToken(token) ? REDACTED : token,
  );
  // Card-like numbers (Luhn-valid, 13-19 digits).
  out = out.replace(/\b\d(?:[ -]?\d){12,18}\b/g, (match) => {
    const digits = match.replace(/[ -]/g, "");
    return digits.length >= 13 && digits.length <= 19 && luhnValid(digits) ? REDACTED : match;
  });
  // US SSN shape.
  out = out.replace(/\b\d{3}-\d{2}-\d{4}\b/g, REDACTED);

  return out;
}

export function applyPolicy(text: string, policy: Policy): string;
export function applyPolicy(text: string | null, policy: Policy): string | null;
export function applyPolicy(text: string | null, policy: Policy): string | null {
  if (text === null || text === undefined || text === "") return text;
  if (policy === "secret") return secretPlaceholder(text);
  if (policy === "allow") return text;
  return redactText(text);
}

/** Redact a bullet's name and note given its inherited state. */
export function redactNodeFields(
  name: string,
  note: string | null,
  inherited: Inherited,
): { name: string; note: string | null; children: Inherited } {
  const { policy, children } = nodePolicy([name, note], inherited);
  return { name: applyPolicy(name, policy), note: applyPolicy(note, policy), children };
}

/** Greedy redaction over every string in an arbitrary JSON value (keys are kept). */
export function redactDeepStrings(value: unknown): unknown {
  if (typeof value === "string") return redactText(value);
  if (Array.isArray(value)) return value.map(redactDeepStrings);
  if (isRecord(value)) {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) out[key] = redactDeepStrings(child);
    return out;
  }
  return value;
}

/** True if any string inside value contains the redaction placeholder. */
export function containsPlaceholder(value: unknown): boolean {
  if (typeof value === "string") return value.includes(REDACTED);
  if (Array.isArray(value)) return value.some(containsPlaceholder);
  if (isRecord(value)) return Object.values(value).some(containsPlaceholder);
  return false;
}

/** True if any string inside value adds an allow tag (#nosec / #nosecall). */
export function containsAllowTag(value: unknown): boolean {
  if (typeof value === "string") return hasAllowTag(value);
  if (Array.isArray(value)) return value.some(containsAllowTag);
  if (isRecord(value)) return Object.values(value).some(containsAllowTag);
  return false;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// --- LLM doc format ("tag-as-key" JSON from read_doc) ---

export const DOC_META_KEYS = new Set(["ancestors", "c", "d", "l", "m", "x", "+"]);

function docTexts(node: Record<string, unknown>): string[] {
  const texts: string[] = [];
  for (const [key, value] of Object.entries(node)) {
    if (key === "d" || (!DOC_META_KEYS.has(key) && typeof value === "string")) {
      if (typeof value === "string") texts.push(value);
    }
  }
  return texts;
}

function looksLikeDocNode(node: Record<string, unknown>): boolean {
  return Object.entries(node).some(
    ([key, value]) => !DOC_META_KEYS.has(key) && typeof value === "string",
  );
}

function redactDocNode(node: Record<string, unknown>, inherited: Inherited): Record<string, unknown> {
  const { policy, children } = looksLikeDocNode(node)
    ? nodePolicy(docTexts(node), inherited)
    : { policy: (inherited.secret ? "secret" : inherited.allowAll ? "allow" : "auto") as Policy, children: inherited };
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(node)) {
    if (key === "ancestors") {
      out[key] = value; // already handled by redactDoc
    } else if (key === "c" && Array.isArray(value)) {
      out[key] = value.map((child) => (isRecord(child) ? redactDocNode(child, children) : redactValue(child, children)));
    } else if (typeof value === "string" && (key === "d" || !DOC_META_KEYS.has(key))) {
      out[key] = applyPolicy(value, policy);
    } else if (DOC_META_KEYS.has(key)) {
      out[key] = value;
    } else {
      out[key] = redactValue(value, children);
    }
  }
  return out;
}

function redactValue(value: unknown, inherited: Inherited): unknown {
  if (Array.isArray(value)) return value.map((item) => redactValue(item, inherited));
  if (isRecord(value)) return redactDocNode(value, inherited);
  if (typeof value === "string") {
    return applyPolicy(value, inherited.secret ? "secret" : inherited.allowAll ? "allow" : "auto");
  }
  return value;
}

/**
 * Redact a read_doc response. Ancestors (root-first) decide what the root inherits;
 * `extra` lets the caller add inheritance known from the cache.
 */
export function redactDoc(doc: unknown, extra: Inherited = ROOT_INHERITED): unknown {
  if (!isRecord(doc)) return redactValue(doc, extra);

  let inherited = extra;
  let ancestorsOut: unknown = undefined;
  if (Array.isArray(doc.ancestors)) {
    const redactedAncestors: unknown[] = [];
    for (const ancestor of doc.ancestors) {
      if (isRecord(ancestor)) {
        const { policy, children } = nodePolicy(docTexts(ancestor), inherited);
        const copy: Record<string, unknown> = {};
        for (const [key, value] of Object.entries(ancestor)) {
          copy[key] = typeof value === "string" ? applyPolicy(value, policy) : value;
        }
        redactedAncestors.push(copy);
        inherited = children;
      } else if (typeof ancestor === "string") {
        const { policy, children } = nodePolicy([ancestor], inherited);
        redactedAncestors.push(applyPolicy(ancestor, policy));
        inherited = children;
      } else {
        redactedAncestors.push(ancestor);
      }
    }
    ancestorsOut = redactedAncestors;
  }

  const out = redactDocNode(doc, inherited);
  if (ancestorsOut !== undefined) out.ancestors = ancestorsOut;
  return out;
}

/** Redact a flat export (nodes with parent_id), computing inheritance through parents. */
export function redactExportNodes<
  T extends { id: string; name?: string; note?: string; parent_id?: string },
>(nodes: T[]): T[] {
  const byId = new Map<string, T>();
  for (const node of nodes) if (node && typeof node.id === "string") byId.set(node.id, node);
  const childInherited = new Map<string, Inherited>();

  const inheritedFor = (parentId: string | undefined): Inherited => {
    // Walk up until a known ancestor, then fold back down.
    const chain: T[] = [];
    const seen = new Set<string>();
    let current = parentId;
    let base: Inherited = ROOT_INHERITED;
    while (current && byId.has(current) && !seen.has(current)) {
      const cached = childInherited.get(current);
      if (cached) {
        base = cached;
        break;
      }
      seen.add(current);
      chain.push(byId.get(current)!);
      current = byId.get(current)!.parent_id;
    }
    let inherited = base;
    for (const ancestor of chain.reverse()) {
      inherited = nodePolicy([ancestor.name, ancestor.note], inherited).children;
      childInherited.set(ancestor.id, inherited);
    }
    return inherited;
  };

  return nodes.map((node) => {
    if (!node || typeof node.id !== "string") return node;
    const inherited = inheritedFor(node.parent_id);
    const { policy, children } = nodePolicy([node.name, node.note], inherited);
    childInherited.set(node.id, children);
    return {
      ...node,
      name: node.name === undefined ? node.name : applyPolicy(node.name, policy),
      note: node.note === undefined ? node.note : applyPolicy(node.note, policy),
    };
  });
}
