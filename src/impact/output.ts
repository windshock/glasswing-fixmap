import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import type { FixImpactDataset } from "./types.js";

export async function writeImpactDataset(dataset: FixImpactDataset, file: string): Promise<void> {
  const resolved = path.resolve(file);
  await mkdir(path.dirname(resolved), { recursive: true });
  const temporary = `${resolved}.${process.pid}.tmp`;
  await writeFile(temporary, `${JSON.stringify(dataset, null, 2)}\n`, "utf8");
  await rename(temporary, resolved);
}

export async function readImpactDataset(file: string): Promise<FixImpactDataset> {
  return JSON.parse(await readFile(file, "utf8")) as FixImpactDataset;
}
