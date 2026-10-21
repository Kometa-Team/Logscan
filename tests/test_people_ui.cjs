const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync("logscan_web/static/people.js", "utf8");
const context = vm.createContext({ document: { createElement: (tag) => ({
  tag, children: [], textContent: "", hidden: false,
  append(...children) { this.children.push(...children); },
}) } });
vm.runInContext(source.slice(source.indexOf("function styleAvailability("), source.indexOf("function addPerson(")), context);
vm.runInContext(source.slice(source.indexOf("function sourceBadges("), source.indexOf("async function runAction(")), context);

test("shows all style states in one compact person detail", () => {
  const detail = context.styleAvailability({ people_image_status: "incomplete", style_availability: {
    primary: { label: "Primary", status: "present" },
    bw: { label: "BW", status: "missing" },
    signature: { label: "Signature", status: "missing" },
    transparent: { label: "Transparent", status: "unknown" },
    excluded: { label: "Excluded", status: "not_applicable" },
  } });
  assert.equal(detail.tag, "details");
  assert.equal(detail.children[0].textContent, "Style availability: 2 missing");
  assert.equal(detail.children[1].children.length, 5);
  assert.equal(detail.children[1].children[3].textContent, "Transparent: unknown");
  assert.equal(detail.children[1].children[4].textContent, "Excluded: not applicable");
});

test("distinguishes verified completeness from pending verification", () => {
  for (const [status, label] of [["complete", "All styles available"], ["pending_verification", "Style verification pending"]]) {
    const detail = context.styleAvailability({ people_image_status: status, style_availability: { primary: { label: "Primary", status: status === "complete" ? "present" : "unknown" } } });
    assert.equal(detail.children[0].textContent, label);
  }
  assert.equal(context.styleAvailability({}).hidden, true);
});

test("pending verification does not claim artwork is confirmed missing", () => {
  const badges = context.sourceBadges(["missing"], [], [], [], null, "pending_verification");
  assert.equal(badges.children[0].textContent, "Pending verification");
});
