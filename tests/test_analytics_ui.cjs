const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync(path.join(__dirname, "../logscan_web/static/analytics.js"), "utf8");
const rendering = source.slice(0, source.indexOf('fetch("/api/analytics")'));

function createContext() {
  const nodes = new Map();
  const element = () => ({ children: [], textContent: "", append(...children) { this.children.push(...children); }, prepend(child) { this.children.unshift(child); } });
  const context = vm.createContext({
    document: {
      createElement: element,
      querySelector(selector) {
        if (!nodes.has(selector)) nodes.set(selector, element());
        return nodes.get(selector);
      },
    },
  });
  vm.runInContext(rendering, context);
  return { context, nodes };
}

test("service totals include ImageMaid cleanup without opening an accordion", () => {
  const { context, nodes } = createContext();
  context.renderSummary({ successful_logs: 526, tools: { kometa: 523, imagemaid: 3 }, rejections: {}, imagemaid_files_removed: 27448, imagemaid_bytes_recovered: 1572864 });
  const metrics = nodes.get("#analytics-summary").children;
  assert.equal(metrics.length, 12);
  for (const [label, value] of [["ImageMaid logs", "3"], ["ImageMaid files removed", "27,448"], ["ImageMaid space recovered", "1.5 MB"]]) {
    const metric = metrics.find(item => item.children[0].textContent === label);
    assert.equal(metric.children[1].textContent, value);
    assert.equal(metric.children[0].children[0].src, "/static/imagemaid.png");
  }
  assert.equal(nodes.get("#analytics-kometa-total").textContent, "523 logs");
  assert.equal(nodes.get("#analytics-imagemaid-total").textContent, "3 logs");
});

test("ImageMaid summary handles analytics stores without cleanup data", () => {
  const { context, nodes } = createContext();
  context.renderSummary({ successful_logs: 0, rejections: {} });
  const metrics = nodes.get("#analytics-summary").children;
  assert.equal(metrics.find(item => item.children[0].textContent === "ImageMaid logs").children[1].textContent, "0");
  assert.equal(metrics.find(item => item.children[0].textContent === "ImageMaid space recovered").children[1].textContent, "0 B");
});

test("Findings uses the Logscan logo in its accordion header", () => {
  const template = readFileSync(path.join(__dirname, "../logscan_web/templates/analytics.html"), "utf8");
  assert.ok(template.includes("<summary><span>{{ tool_icon('logscan') }}Findings</span></summary>"));
});
