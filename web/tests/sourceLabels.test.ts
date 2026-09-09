import assert from "node:assert/strict";
import test from "node:test";
import { cleanEvidenceTitle, publicEvidenceUrl } from "../src/utils/sourceLabels";

test("evidence links never fall back to the application or an invalid source", () => {
  for (const value of ["#", "/reports", "javascript:alert(1)", "http://localhost:8080", "http://127.0.0.1", "http://10.1.2.3", "https://example.com/?id=[REDACTED]"]) {
    assert.equal(publicEvidenceUrl(value), null);
  }
  assert.equal(publicEvidenceUrl("https://example.com/news?id=123#section"), "https://example.com/news?id=123");
});

test("evidence titles hide collection markup without asserting validation", () => {
  assert.equal(cleanEvidenceTitle("Source <SFURL>https://example.com/?id=[REDACTED]</SFURL>"), "Source");
  assert.ok(!cleanEvidenceTitle("").includes("validada"));
});
