import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import Ajv2020 from "ajv/dist/2020.js";

test("generated JSON conforms to the published schema", async () => {
  const [schemaText, datasetText] = await Promise.all([
    readFile(new URL("../schema/fixmap.schema.json", import.meta.url), "utf8"),
    readFile(new URL("../data/fixmap.json", import.meta.url), "utf8"),
  ]);
  const validate = new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true }).compile(
    JSON.parse(schemaText) as object,
  );
  const valid = validate(JSON.parse(datasetText) as unknown);
  assert.equal(valid, true, JSON.stringify(validate.errors, null, 2));
});
