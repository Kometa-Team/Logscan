const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync(path.join(__dirname, "../logscan_web/static/app.js"), "utf8");
const rendering = source.slice(source.indexOf("function occurrenceSummary("), source.indexOf("async function fetchLogWindow("));
const context = vm.createContext({
  document: { createElement: () => ({
    children: [], className: "", textContent: "", classList: { add() {}, contains() { return false; } },
    append(...children) { this.children.push(...children); },
    addEventListener() {},
  }) },
  appendInlineFormatting: (node, text) => node.append(text),
  appendRecommendationMeta: (node, text) => node.append(text),
  formatLineRanges: () => "2-10001",
});
vm.runInContext(rendering, context);

test("formats exact detector occurrences without inferring counts for older or contextual findings", () => {
  assert.equal(context.occurrenceSummary({ occurrence_count: 10005 }), "10,005 occurrences");
  assert.equal(context.occurrenceSummary({ occurrence_count: 1 }), "1 occurrence");
  for (const finding of [{}, { occurrence_count: null }, { occurrence_count: "3" }, { occurrence_count: -1 }]) {
    assert.equal(context.occurrenceSummary(finding), null);
  }
});

test("explains capped evidence using the exact count and actual retained evidence length", () => {
  const finding = { occurrence_count: 10005, evidence_truncated: true };
  const body = context.recommendationBody("Title\nDescription", Array.from({ length: 10000 }, (_, index) => index + 2), 0, finding);
  assert.equal(body.children[0].className, "recommendation-meta occurrence-evidence-summary");
  assert.equal(body.children[0].textContent, "10,005 occurrences; showing the first 10,000 matching entries.");
});

test("renders old finding bodies and contextual advice without fabricated occurrence metadata", () => {
  for (const finding of [{}, { occurrence_count: null, evidence_truncated: false }]) {
    const body = context.recommendationBody("Title\nDescription", [], 0, finding);
    assert.equal(body.children.some(child => child.className.includes("occurrence-evidence-summary")), false);
  }
});

test("per-person evidence links open the exact source lines", () => {
  const opened = [];
  const element = () => {
    const node = { children: [], events: {}, className: "", textContent: "", append(...items) { this.children.push(...items); }, addEventListener(event, callback) { this.events[event] = callback; } };
    node.classList = { add(value) { node.className += ` ${value}`; }, contains(value) { return node.className.split(" ").includes(value); } };
    return node;
  };
  const links = source.slice(source.indexOf("function appendLineReferenceLinks("), source.indexOf("function formatLineRanges("));
  const renderingContext = vm.createContext({ document: { createElement: element, createTextNode: text => text }, openLogViewer: (...args) => opened.push(args), appendInlineFormatting: (node, text) => node.append(text) });
  vm.runInContext(links + rendering, renderingContext);
  const body = renderingContext.recommendationBody("People\nYetide Badaki\nLog line number(s): 75071, 83816\nBruce Langley\nLog line number(s): 75190, 83817", [75071, 75190, 83816, 83817]);
  const rows = body.children.filter(node => node.className === "recommendation-meta");
  assert.equal(rows.length, 2);
  const buttons = rows.flatMap(row => row.children).filter(node => node.className === "line-link");
  assert.deepEqual(buttons.map(button => button.textContent), ["75071", "83816", "75190", "83817"]);
  buttons.forEach(button => button.events.click());
  assert.deepEqual(opened, [[75071, 75071], [83816, 83816], [75190, 75190], [83817, 83817]]);
});
