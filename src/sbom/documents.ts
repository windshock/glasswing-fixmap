/**
 * Parse one or more JSON documents from a single file's text. A well-formed
 * single document takes the fast path; otherwise the text is scanned for
 * consecutive top-level JSON values, which handles both newline-delimited JSON
 * and back-to-back pretty-printed documents (both seen in real SBOM exports).
 */
export function parseJsonDocuments(text: string): unknown[] {
  try {
    return [JSON.parse(text)];
  } catch {
    // Fall through to multi-document scanning.
  }

  const documents: unknown[] = [];
  let depth = 0;
  let inString = false;
  let escaped = false;
  let start = -1;
  for (let index = 0; index < text.length; index += 1) {
    const character = text[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') {
      inString = true;
      continue;
    }
    if (character === "{" || character === "[") {
      if (depth === 0) start = index;
      depth += 1;
      continue;
    }
    if (character === "}" || character === "]") {
      if (depth === 0) throw new Error("Unbalanced JSON while scanning documents");
      depth -= 1;
      if (depth === 0 && start !== -1) {
        documents.push(JSON.parse(text.slice(start, index + 1)));
        start = -1;
      }
    }
  }
  if (depth !== 0 || inString) throw new Error("Truncated JSON document");
  if (documents.length === 0) throw new Error("No parseable JSON document found");
  return documents;
}
