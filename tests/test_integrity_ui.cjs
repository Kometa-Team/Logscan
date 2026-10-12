const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync(path.join(__dirname, "../logscan_web/static/app.js"), "utf8");
const rendering = source.slice(source.indexOf("function addKometaIntegrity("), source.indexOf("function findingTile("));
const references = source.slice(source.indexOf("function appendLineReferenceLinks("), source.indexOf("function appendRecommendationMeta("));
const ranges = source.slice(source.indexOf("function formatLineRanges("), source.indexOf("function occurrenceSummary("));

function render(integrity) {
  const element = () => ({
    children: [], textContent: "", classes: new Set(), events: {},
    append(...children) { this.children.push(...children); },
    addEventListener(name, callback) { this.events[name] = callback; },
    get childElementCount() { return this.children.length; },
    classList: { add() {} },
  });
  const identity = element();
  const details = element();
  const section = element();
  section.querySelector = selector => selector === ".environment-identity" ? identity : details;
  section.classList.add = name => section.classes.add(name);
  const opened = [];
  const context = vm.createContext({
    document: { createElement: element, createTextNode: text => ({ textContent: text }) },
    detailRows: rows => ({ ...element(), children: rows.map(([label, value]) => ({ label, value })) }),
    openLogViewer: (start, end) => opened.push([start, end]),
  });
  vm.runInContext(references + ranges + rendering, context);
  context.addKometaIntegrity(section, integrity);
  return { section, identity, details, opened };
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

test("integrity overview evidence links open the viewer at exact line ranges", () => {
  for (const reportSource of ["kometa", "run", "config"]) {
    const { details, opened } = render({ source: reportSource, state: "modified", evidence_lines: [13, 11, 12, 11, 25] });
    const row = details.children.find(candidate => candidate.children?.[0]?.textContent === "Integrity log lines");
    const links = row.children[1].children.filter(child => child.className === "line-link");
    assert.deepEqual(links.map(link => link.textContent), ["11-13", "25"]);
    for (const link of links) {
      assert.equal(link.type, "button");
      link.events.click();
    }
    assert.deepEqual(opened, [[11, 13], [25, 25]]);
  }
});

test("integrity evidence without valid physical line numbers does not create links", () => {
  for (const evidence_lines of [undefined, [], [null, 0, -1, "11", 2.5]]) {
    const { details, opened } = render({ source: "kometa", state: "check_unavailable", evidence_lines });
    assert.equal(details.children.some(row => row.children?.[0]?.textContent === "Integrity log lines"), false);
    assert.equal(opened.length, 0);
  }
});
