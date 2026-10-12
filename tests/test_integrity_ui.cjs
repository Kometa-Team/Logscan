const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync(path.join(__dirname, "../logscan_web/static/app.js"), "utf8");
const rendering = source.slice(source.indexOf("function addKometaIntegrity("), source.indexOf("function findingTile("));

function render(integrity) {
  const element = () => ({
    children: [], textContent: "", classes: new Set(),
    append(...children) { this.children.push(...children); },
    get childElementCount() { return this.children.length; },
    classList: { add() {} },
  });
  const identity = element();
  const details = element();
  const section = element();
  section.querySelector = selector => selector === ".environment-identity" ? identity : details;
  section.classList.add = name => section.classes.add(name);
  const context = vm.createContext({ document: { createElement: element }, detailRows: rows => ({ children: rows.map(([label, value]) => ({ label, value })) }) });
  vm.runInContext(rendering, context);
  context.addKometaIntegrity(section, integrity);
  return { section, identity, details };
}

test("standalone native verification has the existing green Kometa integrity indicator", () => {
  const { section, identity, details } = render({ source: "kometa", state: "clean", reported_state: "Verified", report_location: "startup" });
  assert.equal(identity.children[0].textContent, "Integrity: Verified");
  assert.ok(section.classes.has("integrity-clean"));
  assert.equal(details.children.find(row => row.label === "Report source").value, "Kometa startup check");
});

test("unavailable and disabled checks remain neutral rather than confirmed deviations", () => {
  for (const [state, label] of [["check_unavailable", "Check unavailable"], ["disabled", "Check disabled"]]) {
    const { section, identity } = render({ source: "kometa", state, details: ["local files were not verified"] });
    assert.equal(identity.children[0].textContent, `Integrity: ${label}`);
    assert.ok(section.classes.has("integrity-unknown"));
    assert.ok(!section.classes.has("integrity-error"));
    assert.ok(!section.classes.has("integrity-clean"));
  }
});

test("modified native files are displayed as literal diagnostics and summary provenance is preserved", () => {
  const value = "modules/<script>alert(1)</script>.py";
  const { section, identity, details } = render({ source: "kometa", state: "modified", modified: [value], counts: { modified: 1 }, report_location: "summary" });
  assert.equal(identity.children[0].textContent, "Integrity: Deviations detected");
  assert.ok(section.classes.has("integrity-error"));
  assert.equal(section.children[0].children[1].children[0].textContent, value);
  assert.equal(details.children.find(row => row.label === "Report source").value, "Kometa startup-check summary");
});

test("Quickstart clean reports retain the existing label and provenance", () => {
  const { identity, details } = render({ source: "run", state: "clean", reported_state: "CLEAN" });
  assert.equal(identity.children[0].textContent, "Integrity: Clean");
  assert.equal(details.children.find(row => row.label === "Report source").value, "Run marker");
});
