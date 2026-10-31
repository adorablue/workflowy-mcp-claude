// Two-way conversion between Workflowy's colored-text HTML and short markers.
//
// Read:  <span class="colored c-purple">hi</span>            -> {purple}hi{/purple}
//        <span class="colored c-red bc-yellow">hi</span>     -> {red bg-yellow}hi{/red bg-yellow}
// Write: the markers turn back into the same spans, so edits never strip color.

export const COLORS = [
  "red", "orange", "yellow", "green", "blue", "purple", "pink",
  "sky", "teal", "gray", "grey", "brown", "black", "white",
];
const COLOR_SET = new Set(COLORS);

function classesToMarker(classes: string): string | null {
  const tokens = classes.trim().split(/\s+/);
  if (tokens[0] !== "colored" || tokens.length < 2) return null;
  const parts: string[] = [];
  for (const token of tokens.slice(1)) {
    const fg = /^c-([a-z]+)$/.exec(token);
    const bg = /^bc-([a-z]+)$/.exec(token);
    if (fg && COLOR_SET.has(fg[1])) parts.push(fg[1]);
    else if (bg && COLOR_SET.has(bg[1])) parts.push(`bg-${bg[1]}`);
    else return null; // unknown class: leave the HTML untouched
  }
  return parts.join(" ");
}

export function colorsToMarkers(text: string): string {
  if (!text || !text.includes("colored")) return text;
  let out = text;
  // Repeat so nested spans convert from the inside out.
  for (let i = 0; i < 5; i += 1) {
    const next = out.replace(
      /<span class="([^"]*)">((?:(?!<span\b)[\s\S])*?)<\/span>/g,
      (match, classes: string, inner: string) => {
        const marker = classesToMarker(classes);
        return marker ? `{${marker}}${inner}{/${marker}}` : match;
      },
    );
    if (next === out) break;
    out = next;
  }
  return out;
}

const MARKER_TOKEN = `(?:bg-)?(?:${COLORS.join("|")})`;
const MARKER_RE = new RegExp(
  `\\{(${MARKER_TOKEN}(?: ${MARKER_TOKEN})*)\\}([\\s\\S]*?)\\{\\/\\1\\}`,
  "g",
);

export function markersToColors(text: string): string {
  if (!text || !text.includes("{")) return text;
  let out = text;
  for (let i = 0; i < 5; i += 1) {
    const next = out.replace(MARKER_RE, (_m, marker: string, inner: string) => {
      const classes = marker
        .split(" ")
        .map((part) => (part.startsWith("bg-") ? `bc-${part.slice(3)}` : `c-${part}`));
      return `<span class="colored ${classes.join(" ")}">${inner}</span>`;
    });
    if (next === out) break;
    out = next;
  }
  return out;
}

/** Apply fn to every string value in a JSON-like structure (object keys are kept). */
export function mapStrings(value: unknown, fn: (text: string) => string): unknown {
  if (typeof value === "string") return fn(value);
  if (Array.isArray(value)) return value.map((item) => mapStrings(item, fn));
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      out[key] = mapStrings(child, fn);
    }
    return out;
  }
  return value;
}
