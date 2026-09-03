/**
 * Parse one or more JSON documents from a single file's text. A well-formed
 * single document takes the fast path; otherwise the text is scanned for
 * consecutive top-level JSON values separated only by whitespace, which handles
 * newline-delimited JSON and back-to-back pretty-printed documents. Any
 * non-whitespace outside a JSON value is rejected — trailing or interleaved
 * garbage must not be silently accepted.
 */
export function parseJsonDocuments(text: string): unknown[] {
  try {
    return [JSON.parse(text)];
  } catch {
    // Fall through to multi-document handling.
  }

  // Some exporters emit documents separated by commas (JSON array elements
  // without the enclosing brackets). Accept that only when wrapping the whole
  // text in brackets parses as a JSON array — arbitrary garbage still fails.
  try {
    const wrapped = JSON.parse(`[${text}]`) as unknown;
    if (Array.isArray(wrapped) && wrapped.length > 0) return wrapped;
  } catch {
    // Fall through to strict whitespace-separated scanning.
  }

  const documents: unknown[] = [];
  const length = text.length;
  let index = 0;
  while (index < length) {
    while (index < length && /\s/.test(text[index]!)) index += 1;
    if (index >= length) break;
    const opener = text[index];
    if (opener !== "{" && opener !== "[") {
      throw new Error(`Unexpected non-whitespace outside a JSON document at position ${index}`);
    }

    const start = index;
    let depth = 0;
    let inString = false;
    let escaped = false;
    for (; index < length; index += 1) {
      const character = text[index];
      if (inString) {
        if (escaped) escaped = false;
        else if (character === "\\") escaped = true;
        else if (character === '"') inString = false;
        continue;
      }
      if (character === '"') inString = true;
      else if (character === "{" || character === "[") depth += 1;
      else if (character === "}" || character === "]") {
        depth -= 1;
        if (depth === 0) {
          index += 1;
          break;
        }
      }
    }
    if (depth !== 0 || inString) throw new Error("Truncated JSON document");
    documents.push(JSON.parse(text.slice(start, index)));
  }
  if (documents.length === 0) throw new Error("No parseable JSON document found");
  return documents;
}
