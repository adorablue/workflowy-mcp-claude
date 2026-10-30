export const AI_INSTRUCTIONS_BOOKMARK = "ai_instructions";

export const LINE_TYPES = [
  "todo",
  "h1",
  "h2",
  "h3",
  "p",
  "bullets",
  "code",
  "quote",
  "table",
] as const;

export const MCP_TOOL_NAMES = [
  "list_bookmarks",
  "save_bookmark",
  "delete_bookmark",
  "read_doc",
  "edit_doc",
  "search_nodes",
  "sync_nodes",
  "cache_status",
  "get_targets",
] as const;

export type McpToolName = (typeof MCP_TOOL_NAMES)[number];

export const DEFAULT_SERVER_INSTRUCTIONS = `This MCP server connects to a user's Workflowy account. Workflowy is an outliner app where notes are organized as nested bullet points (nodes).

## STOP - Read This First

Before making any Workflowy tool call, follow this checklist:

1. Call list_bookmarks first. It returns saved locations, node IDs, and the user's custom instructions.
2. Use one read_doc followed by one edit_doc whenever possible. Batch multiple edits in a single edit_doc call.
3. Use calendar and system targets directly: today, tomorrow, next_week, inbox, or None for home/root.
4. If the user shares a Workflowy link like https://beta.workflowy.com/#/b24b650a6b91, extract the 12-hex ID after #/ and use that as node_id.

## Key Concepts

- Nodes are identified by 12-character hex tags, full UUIDs, or supported special targets.
- Nodes can have name/text (n), note/description (d), type (l), completion status (x), and children (c).
- Supported line types: todo, h1, h2, h3, p, bullets, code, quote, table.
- Calendar IDs such as YYYY, YYYY-MM, and YYYY-MM-DD are valid node IDs.
- Mirrors include an m marker and mirrored children inline.

## read_doc

Use read_doc to fetch current Workflowy content before updating, deleting, or moving existing nodes. The response uses tag-as-key JSON:

{
  "b605f0e85a4a": "My Project",
  "d": "Project note",
  "c": [
    {"aa11bb22cc33": "Task 1", "l": "todo", "x": 1},
    {"dd44ee55ff66": "Task 2", "d": "Some note"}
  ],
  "ancestors": [{"None": "Home"}]
}

The first non-metadata key is the node tag. d is a note, c is children, l is line type, x: 1 means complete, and +: 1 means there is more content below the depth limit.

## edit_doc

Use edit_doc for insert, update, delete, and move operations.

Insert:
{"op": "insert", "under": "today", "items": [{"n": "New task", "l": "todo"}], "position": "top"}

Update:
{"op": "update", "ref": "aa11bb22cc33", "to": {"n": "Renamed", "d": "Updated note", "x": 1}}

Delete:
{"op": "delete", "ref": "aa11bb22cc33"}

Move:
{"op": "move", "ref": "aa11bb22cc33", "under": "dd44ee55ff66", "position": "top"}

Batch related operations into one edit_doc call.

## Tables

A table is a node with l: "table". Its children are columns, and each column's children are cells. All columns should have the same row count.

## Search and Cache

search_nodes searches the hosted cache and auto-syncs when the cache is empty or stale when rate limits allow. Use sync_nodes when you explicitly need a full refresh.

## Bookmarks

Bookmarks store frequently used Workflowy nodes with context notes. Save important locations so future conversations can use node IDs directly.

## Secrets

This server hides secrets before you see them. Text shown as [REDACTED] is hidden on purpose.

- Never copy [REDACTED] into an edit, and never rewrite a field that contains it. The server refuses such edits because they would destroy the hidden secret. Ask the user to change it in Workflowy instead.
- Tags the user controls: #sec hides a bullet and everything under it. #nosec shows one bullet as-is. #nosecall shows a bullet and everything under it as-is. The nearest tag wins; on the same bullet #sec wins.
- Never add #nosec or #nosecall yourself (the server refuses). You may suggest the user add them, or add #sec to something that looks secret.
- Moving bullets is fine, except out of a #sec area (unless the bullet has #sec itself) or moving hidden content under a #nosecall bullet; the server refuses those.
- Auto-detection is deliberately greedy. If redaction seems to hide something ordinary, tell the user so they can add #nosec.
- Never repeat secrets the user pastes into chat; suggest rotating them.`;

export const DEFAULT_TOOL_DESCRIPTIONS: Record<McpToolName, string> = {
  list_bookmarks: `START EVERY CONVERSATION BY CALLING THIS TOOL. Returns saved Workflowy locations and the user's custom AI instructions.

Use bookmark node_ids directly with read_doc. If an ai_instructions bookmark exists, this tool also returns the readable instructions from that Workflowy node.`,

  save_bookmark:
    "Save a Workflowy node with a friendly name and context notes. The context field is for the AI to describe when and how to use this node in future sessions.",

  delete_bookmark: "Delete a saved Workflowy bookmark by name.",

  read_doc: `Read a Workflowy node and its children. Accepts 12-hex tags, full UUIDs, Workflowy links, calendar IDs, and special targets such as today, tomorrow, next_week, inbox, and None.

Returns tag-as-key JSON with node text, notes, children, line types, completion status, mirrors, and ancestors.`,

  edit_doc: `Edit Workflowy nodes using insert, update, delete, and move operations.

Batch related changes in one call. Update, delete, and move should follow a read_doc call so you have current tags. Insert can target a known parent tag or a system target such as today or inbox.`,

  search_nodes:
    "Search Workflowy nodes by text in the hosted cache. Auto-syncs the cache when empty or stale when rate limits allow, then returns matches with paths, child previews, timestamps, and node IDs for read_doc.",

  sync_nodes:
    "Fetch the full Workflowy nodes export and replace the hosted search cache. Rate limited to one export per minute.",

  cache_status:
    "Show hosted Workflowy cache status, including node count, last sync time, freshness, and whether a sync is running.",

  get_targets:
    "Get special Workflowy targets from the Workflowy API, such as inbox and home/root.",
};

export function sanitizeToolDescriptions(
  descriptions: Record<string, unknown> | null | undefined,
): Partial<Record<McpToolName, string>> {
  const sanitized: Partial<Record<McpToolName, string>> = {};

  if (!descriptions) {
    return sanitized;
  }

  for (const name of MCP_TOOL_NAMES) {
    const value = descriptions[name];
    if (typeof value === "string" && value.trim()) {
      sanitized[name] = value.trim();
    }
  }

  return sanitized;
}
