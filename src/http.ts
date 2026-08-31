import { createHash } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";

interface CacheMetadata {
  url: string;
  etag?: string;
  lastModified?: string;
  contentType?: string;
}

export class HttpError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly url: string,
  ) {
    super(message);
  }
}

export interface HttpClientOptions {
  cacheDirectory: string;
  offline?: boolean;
  githubToken?: string;
  retries?: number;
}

export class HttpClient {
  readonly cacheDirectory: string;
  readonly offline: boolean;
  readonly githubToken: string | undefined;
  readonly retries: number;

  constructor(options: HttpClientOptions) {
    this.cacheDirectory = options.cacheDirectory;
    this.offline = options.offline ?? false;
    this.githubToken = options.githubToken;
    this.retries = options.retries ?? 3;
  }

  async getText(url: string): Promise<string> {
    const response = await this.get(url);
    return response.body;
  }

  async getJson<T>(url: string): Promise<T> {
    const text = await this.getText(url);
    try {
      return JSON.parse(text) as T;
    } catch (error) {
      throw new Error(`Invalid JSON from ${url}: ${String(error)}`);
    }
  }

  async getOptionalJson<T>(url: string): Promise<T | undefined> {
    try {
      return await this.getJson<T>(url);
    } catch (error) {
      if (error instanceof HttpError && error.status === 404) return undefined;
      throw error;
    }
  }

  private cachePaths(url: string): { body: string; metadata: string } {
    const key = createHash("sha256").update(url).digest("hex");
    return {
      body: path.join(this.cacheDirectory, `${key}.body`),
      metadata: path.join(this.cacheDirectory, `${key}.json`),
    };
  }

  private async readCache(
    url: string,
  ): Promise<{ body: string; metadata: CacheMetadata } | undefined> {
    const paths = this.cachePaths(url);
    try {
      const [body, metadataText] = await Promise.all([
        readFile(paths.body, "utf8"),
        readFile(paths.metadata, "utf8"),
      ]);
      const metadata = JSON.parse(metadataText) as CacheMetadata;
      if (metadata.url !== url) return undefined;
      return { body, metadata };
    } catch {
      return undefined;
    }
  }

  private async writeCache(url: string, body: string, metadata: CacheMetadata): Promise<void> {
    await mkdir(this.cacheDirectory, { recursive: true });
    const paths = this.cachePaths(url);
    const suffix = `${process.pid}-${Math.random().toString(16).slice(2)}`;
    const temporaryBody = `${paths.body}.${suffix}.tmp`;
    const temporaryMetadata = `${paths.metadata}.${suffix}.tmp`;
    await Promise.all([
      writeFile(temporaryBody, body, "utf8"),
      writeFile(temporaryMetadata, `${JSON.stringify(metadata)}\n`, "utf8"),
    ]);
    await Promise.all([
      rename(temporaryBody, paths.body),
      rename(temporaryMetadata, paths.metadata),
    ]);
  }

  private async get(url: string): Promise<{ body: string; contentType?: string }> {
    const cached = await this.readCache(url);
    if (this.offline) {
      if (!cached) throw new Error(`Offline cache miss: ${url}`);
      const result: { body: string; contentType?: string } = { body: cached.body };
      if (cached.metadata.contentType) result.contentType = cached.metadata.contentType;
      return result;
    }

    let lastError: unknown;
    for (let attempt = 0; attempt <= this.retries; attempt += 1) {
      const headers = new Headers({
        Accept: "application/json, text/html;q=0.9, */*;q=0.8",
        "User-Agent": "glasswing-fixmap/0.1 (+https://github.com/)",
      });
      if (cached?.metadata.etag) headers.set("If-None-Match", cached.metadata.etag);
      if (cached?.metadata.lastModified) {
        headers.set("If-Modified-Since", cached.metadata.lastModified);
      }
      if (this.githubToken && new URL(url).hostname === "api.github.com") {
        headers.set("Authorization", `Bearer ${this.githubToken}`);
        headers.set("X-GitHub-Api-Version", "2022-11-28");
      }

      try {
        const response = await fetch(url, { headers, redirect: "follow" });
        if (response.status === 304 && cached) {
          const result: { body: string; contentType?: string } = { body: cached.body };
          if (cached.metadata.contentType) result.contentType = cached.metadata.contentType;
          return result;
        }
        if (!response.ok) {
          const error = new HttpError(
            `HTTP ${response.status} ${response.statusText}: ${url}`,
            response.status,
            url,
          );
          if (response.status !== 429 && response.status < 500) throw error;
          lastError = error;
        } else {
          const body = await response.text();
          const metadata: CacheMetadata = { url };
          const etag = response.headers.get("etag");
          const lastModified = response.headers.get("last-modified");
          const contentType = response.headers.get("content-type");
          if (etag) metadata.etag = etag;
          if (lastModified) metadata.lastModified = lastModified;
          if (contentType) metadata.contentType = contentType;
          await this.writeCache(url, body, metadata);
          const result: { body: string; contentType?: string } = { body };
          if (contentType) result.contentType = contentType;
          return result;
        }
      } catch (error) {
        if (error instanceof HttpError && error.status !== 429 && error.status < 500) throw error;
        lastError = error;
      }

      if (attempt < this.retries) {
        await new Promise((resolve) => setTimeout(resolve, 300 * 2 ** attempt));
      }
    }
    if (cached) {
      const result: { body: string; contentType?: string } = { body: cached.body };
      if (cached.metadata.contentType) result.contentType = cached.metadata.contentType;
      return result;
    }
    throw lastError instanceof Error ? lastError : new Error(`Unable to fetch ${url}`);
  }
}

export async function mapConcurrent<T, R>(
  items: T[],
  concurrency: number,
  mapper: (item: T, index: number) => Promise<R>,
): Promise<R[]> {
  const results = new Array<R>(items.length);
  let nextIndex = 0;
  const workers = Array.from({ length: Math.min(Math.max(concurrency, 1), items.length) }, async () => {
    while (true) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) return;
      results[index] = await mapper(items[index]!, index);
    }
  });
  await Promise.all(workers);
  return results;
}
