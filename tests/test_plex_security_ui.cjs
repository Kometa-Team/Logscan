const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");
const source = readFileSync(path.join(__dirname, "../logscan_web/static/app.js"), "utf8");
const rendering = source.slice(source.indexOf("function renderPlexSecurityStatus("), source.indexOf("function renderResults("));
const element = () => ({ children: [], hidden: true, className: "", textContent: "", setAttribute() {}, append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; } });
const target = element();
const context = vm.createContext({ document: { getElementById: () => target, createElement: element } });
vm.runInContext(rendering, context);

test("security assessment is prominent, historical, linked, and cleared between scans", () => {
  context.renderPlexSecurityStatus([{ security_assessment: { status: "affected", server_name: "Server", observations: [{ detected_version: "1.43.2.99999" }], minimum_patched_version: "1.43.3.10861", advisory_url: "https://forums.plex.tv/t/test/1" } }]);
  assert.equal(target.hidden, false);
  assert.match(target.className, /critical/);
  assert.match(target.children[0].textContent, /observed in this log/);
  assert.match(target.children[0].textContent, /not an official CVSS/);
  assert.equal(target.children[0].children[0].textContent, "Official Plex advisory");
  assert.match(target.children[1].textContent, /Log date unavailable/);
  assert.match(target.children[1].textContent, /may have been updated since/);
  context.renderPlexSecurityStatus([]);
  assert.equal(target.hidden, true);
  assert.equal(target.children.length, 0);
});

test("dates come from the log and retain ranges across historical runs", () => {
  const recommendations = [{ security_assessment: { status: "patched", server_name: "Classic Connection", observations: [], advisory_id: "PLEX-PMS-2026-09" } }];
  context.renderPlexSecurityStatus(recommendations, { first: "2023-09-25", last: "2023-09-25" });
  assert.match(target.children[0].textContent, /Plex server named: "Classic Connection"/);
  assert.match(target.children[1].textContent, /Log recorded on 2023-09-25/);
  context.renderPlexSecurityStatus(recommendations, { first: "2023-09-25", last: "2026-10-18" });
  assert.match(target.children[1].textContent, /Log spans 2023-09-25 to 2026-10-18/);
});
