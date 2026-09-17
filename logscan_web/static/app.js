const form = document.querySelector("#upload-form");
const input = document.querySelector("#log-file");
const dropZone = document.querySelector("#drop-zone");
const filePill = document.querySelector("#file-pill");
const status = document.querySelector("#form-status");
const scanButton = document.querySelector("#scan-button");
const uploadErrorDetails = document.querySelector("#upload-error-details");
const unexpectedFileList = document.querySelector("#unexpected-file-list");
const results = document.querySelector("#results");
const retentionCountdown = document.querySelector("#retention-countdown");
let retentionTimer;
const batchResults = document.querySelector("#batch-results");
const batchResultLinks = document.querySelector("#batch-result-links");
const batchResultsTitle = document.querySelector("#batch-results-title");
const copyBatchResults = document.querySelector("#copy-batch-results");
const shareBatchResults = document.querySelector("#share-batch-results");
const deleteBatch = document.querySelector("#delete-batch");
const batchUnscannedTitle = document.querySelector("#batch-unscanned-title");
const batchUnscannedFiles = document.querySelector("#batch-unscanned-files");
const getHelp = document.querySelector("#get-help");
const helpDialog = document.querySelector("#help-dialog");
const helpMessage = document.querySelector("#help-message");
const copyHelpMessage = document.querySelector("#copy-help-message");
const summaryGrid = document.querySelector("#summary-grid");
const sectionNav = document.querySelector("#section-nav");
const sectionContent = document.querySelector("#section-content");
const logViewer = document.querySelector("#log-viewer");
const logCode = document.querySelector("#log-code");
const highlightMode = document.querySelector("#highlight-mode");
const nextHighlight = document.querySelector("#next-highlight");
const sectionJump = document.querySelector("#section-jump");
const viewerPosition = document.querySelector("#viewer-position");
let currentFile = null;
let currentScanId = null;
let deleteToken = null;
let currentLogLines = null;
let currentLogSections = [];
let highlightedRange = { start: 1, end: 1 };
let viewerFirstLine = 1;
let viewerLastLine = 1;
let loadingViewerChunk = false;
let extractedConfig = "";
let viewerMode = "log";
let currentRecommendations = [];
let schemaValidationFailures = [];
let currentOverview = {};
let batchScans = [];
const VIEWER_CHUNK_SIZE = 1000;

const defaultGroups = [
  { key: "overview", label: "Log Overview", description: "Details extracted from the uploaded log." },
  { key: "critical", label: "Critical issues", description: "Items most likely to prevent a successful or secure run." },
  { key: "error", label: "Errors", description: "Problems that may cause incomplete or unintended results." },
  { key: "warning", label: "Warnings", description: "Potential problems worth reviewing before your next run." },
  { key: "schema", label: "Schema issues", description: "Deprecated or invalid configuration syntax that should be updated." },
  { key: "advice", label: "Advice", description: "Configuration and performance improvements." },
];

function displayValue(value) {
  return value || "Not found in this log";
}

function uploadFailureType(message) {
  if (message.startsWith("Choose a Kometa log, text, YAML, ZIP, TAR, or GZIP file.")) {
    return "bad-filetype";
  }
  if (message.includes("does not appear to be a complete Kometa log file")
    || message.includes("does not contain a complete Kometa log file")) {
    return "invalid-kometa-log";
  }
  return "failed";
}

function uploadFailureSummary(failures) {
  const counts = failures.reduce((summary, failure) => {
    const type = uploadFailureType(failure.message);
    summary[type] = (summary[type] || 0) + 1;
    return summary;
  }, {});
  const labels = {
    "bad-filetype": "skipped - bad filetype",
    "invalid-kometa-log": "failed - not valid Kometa log file",
  };
  const categorized = Object.entries(labels)
    .filter(([type]) => counts[type])
    .map(([type, label]) => `${counts[type]} ${label}`)
  const failuresWithReasons = failures
    .filter((failure) => uploadFailureType(failure.message) === "failed")
    .map((failure) => `${failure.filename}: failed - ${failure.message}`);
  return [...categorized, ...failuresWithReasons].join("; ");
}

 function formatOverviewTimestamp(unixTimestamp) {
  const date = new Date(unixTimestamp * 1000);
  const part = (value) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${part(date.getMonth() + 1)}-${part(date.getDate())} ${part(date.getHours())}:${part(date.getMinutes())}:${part(date.getSeconds())}`;
}

function showOverview(group, overview) {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.group === group.key);
  });
  const sectionSelect = document.querySelector("#section-select");
  if (sectionSelect) sectionSelect.value = group.key;
  sectionContent.replaceChildren();
  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<h3>${group.label}</h3><p>${group.description}</p>`;
  sectionContent.append(header);
  const details = [
    ["Log name", overview.log_name],
    ...(overview.uploaded_by ? [["Log Info", { uploader: overview.uploaded_by, id: overview.uploaded_by_id, messageUrl: overview.message_url }]] : []),
    ["Number of recommendations", overview.recommendation_count],
    ["Kometa version", overview.kometa_version],
    ["Platform", overview.platform],
    ["Total memory", overview.total_memory],
    ["Available memory", overview.available_memory],
    ["Run command", overview.run_command],
    ["Start time", overview.start_time],
    ["End time", overview.finished],
    ["Run time", overview.run_time],
    ["YAML validation", overview.yaml_validation],
    ["Log Auto-Delete", overview.auto_delete],
  ];
  const grid = document.createElement("dl");
  grid.className = "overview-grid";
  details.forEach(([label, value]) => {
    const item = document.createElement("div");
    const term = document.createElement("dt");
    const definition = document.createElement("dd");
    term.textContent = label;
    if (label === "Log Info") {
      const uploader = document.createElement("a");
      uploader.href = `discord://-/users/${value.id}`;
      uploader.textContent = value.uploader;
      uploader.title = "Open Discord profile";
      definition.append("Uploader: ", uploader, document.createElement("br"));
      const link = document.createElement("a");
      const messageUrl = new URL(value.messageUrl);
      link.href = `discord://-${messageUrl.pathname}`;
      link.textContent = "Click Here";
      link.title = "Open Discord message";
      definition.append("Discord Message: ", link);
    } else {
      definition.textContent = displayValue(value);
    }
    item.append(term, definition);
    grid.append(item);
  });
  sectionContent.append(grid);
}

function selectedFiles(files) {
  if (files) input.files = makeFileList(files);
  const chosenFiles = [...input.files];
  const chosen = chosenFiles[0];
  currentFile = chosen || null;
  currentLogLines = null;
  currentLogSections = [];
  scanButton.disabled = !chosenFiles.length;
  filePill.textContent = chosenFiles.length === 1
    ? `${chosen.name} · ${formatBytes(chosen.size)}`
    : chosenFiles.length ? `${chosenFiles.length} files selected · ${formatBytes(chosenFiles.reduce((total, file) => total + file.size, 0))}` : "LOG, TXT, YAML or archive · up to 500 MB each";
  status.textContent = chosenFiles.length ? `${chosenFiles.length} file${chosenFiles.length === 1 ? "" : "s"} selected` : "Ready to scan";
  status.classList.remove("error");
  uploadErrorDetails.hidden = true;
}

function makeFileList(files) {
  const transfer = new DataTransfer();
  for (const file of files) transfer.items.add(file);
  return transfer.files;
}

function formatBytes(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1048576) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / 1048576).toFixed(1)} MB`;
}

function linkLabel(url) {
  try {
    const host = new URL(url).hostname.replace(/^www\./, "");
    if (host.endsWith("kometa.wiki")) return "Kometa documentation";
    if (host.endsWith("plex.tv")) return "Plex documentation";
    if (host.endsWith("github.com")) return "GitHub reference";
    return host;
  } catch {
    return "View documentation";
  }
}

function appendInlineFormatting(container, text) {
  const tokenPattern = /(\*\*.+?\*\*|`[^`]+`|\[?https?:\/\/[^\s\]]+\]?)/g;
  let cursor = 0;
  for (const match of text.matchAll(tokenPattern)) {
    container.append(document.createTextNode(text.slice(cursor, match.index)));
    const token = match[0];
    if (token.startsWith("**") && token.endsWith("**")) {
      const strong = document.createElement("strong");
      strong.textContent = token.slice(2, -2);
      container.append(strong);
    } else if (token.startsWith("`") && token.endsWith("`")) {
      const code = document.createElement("code");
      code.textContent = token.slice(1, -1);
      container.append(code);
    } else {
      const url = token.replace(/^\[/, "").replace(/\]$/, "");
      const link = document.createElement("a");
      link.href = url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = linkLabel(url);
      container.append(link);
    }
    cursor = match.index + token.length;
  }
  container.append(document.createTextNode(text.slice(cursor)));
}

function appendRecommendationMeta(container, text) {
  const marker = /^(.*?Line number\(s\):\s*)(.*)$/i.exec(text);
  if (!marker) {
    appendInlineFormatting(container, text);
    return;
  }
  appendInlineFormatting(container, marker[1]);
  const references = marker[2];
  const rangePattern = /\d+(?:-\d+)?/g;
  let cursor = 0;
  for (const match of references.matchAll(rangePattern)) {
    container.append(document.createTextNode(references.slice(cursor, match.index)));
    const [startText, endText] = match[0].split("-");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "line-link";
    button.textContent = match[0];
    button.title = `View log at line ${match[0]}`;
    button.addEventListener("click", () => openLogViewer(Number(startText), Number(endText || startText)));
    container.append(button);
    cursor = match.index + match[0].length;
  }
  container.append(document.createTextNode(references.slice(cursor)));
}

function formatLineRanges(lineNumbers) {
  const sorted = [...new Set(lineNumbers)].sort((left, right) => left - right);
  const ranges = [];
  for (let index = 0; index < sorted.length; index += 1) {
    const start = sorted[index];
    let end = start;
    while (sorted[index + 1] === end + 1) end = sorted[++index];
    ranges.push(start === end ? String(start) : `${start}-${end}`);
  }
  return ranges.join(", ");
}

function recommendationBody(message, evidenceLines = []) {
  const body = document.createElement("div");
  body.className = "recommendation-body";
  const hasEmbeddedEvidence = /Line number\(s\):/i.test(message);
  const lines = message.split("\n").slice(1);
  lines.forEach((line) => {
    const row = document.createElement("div");
    if (/^\s*\d+\s+line\(s\)/i.test(line)) row.className = "recommendation-meta";
    if (/^Proposed solution:/i.test(line)) row.classList.add("recommendation-solution");
    if (!line.trim()) row.classList.add("spacer");
    if (row.classList.contains("recommendation-meta")) appendRecommendationMeta(row, line);
    else appendInlineFormatting(row, line);
    body.append(row);
  });
  if (!hasEmbeddedEvidence && evidenceLines.length) {
    const row = document.createElement("div");
    row.className = "recommendation-meta";
    appendRecommendationMeta(row, `Log line number(s): ${formatLineRanges(evidenceLines)}`);
    body.append(row);
  }
  return body;
}

async function loadLogLines() {
  if (!currentFile && !currentScanId) throw new Error("Select and scan a log before opening the viewer.");
  if (!currentLogLines) {
    const response = currentFile
      ? null
      : await fetch(`/api/scans/${encodeURIComponent(currentScanId)}/log`);
    if (response && !response.ok) throw new Error("The stored log could not be loaded.");
    const text = currentFile ? await currentFile.text() : await response.text();
    currentLogLines = text.split(/\r?\n/);
    currentLogSections = findLogSections(currentLogLines);
    populateSectionJump();
  }
  return currentLogLines;
}

function isSectionDivider(line) {
  return /\|={10,}\|\s*$/.test(line);
}

function sectionTitle(line) {
  const match = /\|\s*([^|=][^|]*?)\s*\|\s*$/.exec(line);
  return match ? match[1].trim() : null;
}

function findLogSections(lines) {
  const sections = [];
  for (let index = 1; index < lines.length - 1; index += 1) {
    if (!isSectionDivider(lines[index - 1]) || !isSectionDivider(lines[index + 1])) continue;
    const title = sectionTitle(lines[index]);
    if (title) sections.push({ title, line: index + 1 });
  }
  return sections;
}

function extractConfig(lines) {
  let started = false;
  const extracted = [];
  const taggedConfig = /\[config\.py:\d+\]\s+\[[A-Z]+\]\s*\|(.*)$/;
  for (const line of lines) {
    if (!started) {
      if (line.includes("Redacted Config")) started = true;
      continue;
    }
    if (line.includes("Config Warning:") || line.includes("Initializing cache database at")) break;
    const match = taggedConfig.exec(line);
    if (!match) break;
    extracted.push(match[1].replace(/[ |]+$/, ""));
  }
  if (extracted.length > 1) extracted.pop();
  return extracted.map((line) => line.startsWith(" ") ? line.slice(1) : line).join("\n");
}

function createConfigRows(config) {
  const fragment = document.createDocumentFragment();
  config.split("\n").forEach((line, index) => {
    const row = document.createElement("div");
    row.className = "log-line";
    const number = document.createElement("span");
    number.className = "line-number";
    number.textContent = index + 1;
    const content = document.createElement("span");
    appendYamlHighlight(content, line || " ");
    row.append(number, content);
    fragment.append(row);
  });
  return fragment;
}

function appendYamlHighlight(container, line) {
  const commentIndex = line.search(/\s#/);
  const code = commentIndex === -1 ? line : line.slice(0, commentIndex);
  const comment = commentIndex === -1 ? "" : line.slice(commentIndex);
  const keyMatch = /^(\s*)([^:#][^:]*)(:)(.*)$/.exec(code);
  if (keyMatch) {
    container.append(document.createTextNode(keyMatch[1]));
    const key = document.createElement("span");
    key.className = "yaml-key";
    key.textContent = keyMatch[2];
    container.append(key, document.createTextNode(keyMatch[3]));
    const value = document.createElement("span");
    value.className = /^(\s*)(true|false|null|~)$/i.test(keyMatch[4]) ? "yaml-literal" : "yaml-value";
    value.textContent = keyMatch[4];
    container.append(value);
  } else {
    container.append(document.createTextNode(code));
  }
  if (comment) {
    const commentNode = document.createElement("span");
    commentNode.className = "yaml-comment";
    commentNode.textContent = comment;
    container.append(commentNode);
  }
}

function updateViewerMode(mode) {
  viewerMode = mode;
  const isConfig = mode === "config";
  document.querySelector("#viewer-kind").textContent = isConfig ? "Extracted configuration" : "Log viewer";
  document.querySelector("#viewer-filename").textContent = isConfig ? "config.yml" : (currentFile?.name || document.querySelector("#results-title").textContent);
  const toggle = document.querySelector("#toggle-viewer-content");
  toggle.setAttribute("aria-label", isConfig ? "View log" : "View config");
  toggle.title = isConfig ? "View log" : "View config";
  toggle.querySelector("i").className = isConfig ? "fa-solid fa-file-lines" : "fa-solid fa-file-code";
  document.querySelector(".viewer-toolbar").hidden = isConfig;
}

async function showConfigInViewer() {
  const lines = await loadLogLines();
  extractedConfig = extractConfig(lines);
  updateViewerMode("config");
  logCode.replaceChildren(
    extractedConfig
      ? createConfigRows(extractedConfig)
      : document.createTextNode("No redacted config block was found in this log."),
  );
  logCode.scrollTop = 0;
}

function populateSectionJump() {
  sectionJump.replaceChildren();
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = currentLogSections.length ? "Select a section" : "No sections found";
  sectionJump.append(placeholder);
  currentLogSections.forEach((section) => {
    const option = document.createElement("option");
    option.value = section.line;
    option.textContent = `${section.title} — line ${section.line.toLocaleString()}`;
    sectionJump.append(option);
  });
  sectionJump.disabled = currentLogSections.length === 0;
}

function createLogRows(first, last) {
  const fragment = document.createDocumentFragment();
  for (let lineNumber = first; lineNumber <= last; lineNumber += 1) {
    const row = document.createElement("div");
    row.className = "log-line";
    row.dataset.line = lineNumber;
    if (lineNumber >= highlightedRange.start && lineNumber <= highlightedRange.end) row.classList.add("highlighted");
    const matchingRecommendations = recommendationsForLine(lineNumber);
    const schemaFailures = schemaFailuresForLine(lineNumber);
    const matchingItems = [...matchingRecommendations, ...schemaFailures];
    if (matchingItems.length) {
      row.classList.add("recommendation-line", ...matchingRecommendations.map((item) => `recommendation-${item.severity}`));
      if (schemaFailures.length) row.classList.add("schema-validation-line");
      row.tabIndex = 0;
      row.title = "View details";
      row.addEventListener("click", () => openRecommendationDialog(matchingItems));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openRecommendationDialog(matchingItems); }
      });
    }
    const number = document.createElement("span");
    number.className = "line-number";
    number.textContent = lineNumber;
    const content = document.createElement("span");
    content.textContent = currentLogLines[lineNumber - 1] || " ";
    row.append(number, content);
    fragment.append(row);
  }
  return fragment;
}

function recommendationLineNumbers(item) {
  const matches = `${item.message || ""}`.matchAll(/(?:line number\(s\)|log line number\(s\)):\s*([\d,\-\s]+)/gi);
  const values = [...(item.evidence_lines || [])];
  for (const match of matches) {
    for (const range of match[1].matchAll(/(\d+)(?:-(\d+))?/g)) {
      const start = Number(range[1]);
      const end = Number(range[2] || range[1]);
      for (let line = start; line <= end; line += 1) values.push(line);
    }
  }
  return new Set(values);
}

function recommendationsForLine(lineNumber) {
  const selectedSeverity = highlightMode.value;
  return currentRecommendations.filter((item) => (selectedSeverity === "all" || item.severity === selectedSeverity)
    && ["critical", "error", "warning"].includes(item.severity)
    && recommendationLineNumbers(item).has(lineNumber));
}

function schemaFailuresForLine(lineNumber) {
  return schemaValidationFailures.filter((failure) => failure.line === lineNumber).map((failure) => ({
    severity: "schema validation",
    title: "Kometa config schema validation failed",
    message: `Schema validation failure\n\n${failure.message}${failure.path ? `\n\nConfig path: ${failure.path}` : ""}`,
    evidence_lines: [failure.line],
  }));
}

function highlightedLineNumbers() {
  const lines = new Set();
  currentRecommendations.forEach((item) => {
    if ((highlightMode.value === "all" || item.severity === highlightMode.value)
      && ["critical", "error", "warning"].includes(item.severity)) {
      recommendationLineNumbers(item).forEach((lineNumber) => lines.add(lineNumber));
    }
  });
  schemaValidationFailures.forEach((failure) => lines.add(failure.line));
  return [...lines].filter((lineNumber) => lineNumber >= 1 && lineNumber <= currentLogLines.length)
    .sort((left, right) => left - right);
}

function updateNextHighlightControl() {
  const hasHighlights = currentLogLines && highlightedLineNumbers().length > 0;
  nextHighlight.disabled = !hasHighlights;
  nextHighlight.title = hasHighlights ? "Go to the next highlighted line" : "No lines match this highlight mode";
}

function goToNextHighlightedLine() {
  if (!currentLogLines) return;
  const lines = highlightedLineNumbers();
  if (!lines.length) return;
  const nextLine = lines.find((lineNumber) => lineNumber > highlightedRange.start) || lines[0];
  renderLogWindow(nextLine);
}

function openRecommendationDialog(items) {
  const item = items[0];
  document.querySelector("#recommendation-severity").textContent = items.length === 1
    ? `${item.severity} recommendation`
    : `${items.length} recommendations`;
  document.querySelector("#recommendation-title").textContent = items.length === 1 ? item.title : "Recommendations for this line";
  const content = document.querySelector("#recommendation-content");
  content.replaceChildren();
  items.forEach((recommendation) => {
    if (items.length > 1) {
      const title = document.createElement("h3");
      title.textContent = recommendation.title;
      content.append(title);
    }
    content.append(recommendationBody(recommendation.message, recommendation.evidence_lines));
  });
  document.querySelector("#recommendation-dialog").showModal();
}

function updateViewerPosition() {
  viewerPosition.textContent = `Lines ${viewerFirstLine.toLocaleString()}–${viewerLastLine.toLocaleString()} of ${currentLogLines.length.toLocaleString()}`;
}

function renderLogWindow(targetStart, targetEnd = targetStart) {
  const total = currentLogLines.length;
  const startTarget = Math.max(1, Math.min(total, Number(targetStart) || 1));
  const endTarget = Math.max(startTarget, Math.min(total, Number(targetEnd) || startTarget));
  highlightedRange = { start: startTarget, end: endTarget };
  viewerFirstLine = Math.max(1, startTarget - Math.floor(VIEWER_CHUNK_SIZE / 2));
  viewerLastLine = Math.min(
    total,
    Math.max(viewerFirstLine + VIEWER_CHUNK_SIZE - 1, endTarget + Math.floor(VIEWER_CHUNK_SIZE / 2)),
  );
  if (viewerLastLine === total) viewerFirstLine = Math.max(1, viewerLastLine - VIEWER_CHUNK_SIZE + 1);
  const fragment = createLogRows(viewerFirstLine, viewerLastLine);
  logCode.replaceChildren(fragment);
  updateViewerPosition();
  updateNextHighlightControl();
  requestAnimationFrame(() => {
    logCode.querySelector(`[data-line="${startTarget}"]`)?.scrollIntoView({ block: "center" });
  });
}

function loadAdjacentLogChunk(direction) {
  if (loadingViewerChunk || !currentLogLines) return;
  const total = currentLogLines.length;
  if (direction === "next" && viewerLastLine >= total) return;
  if (direction === "previous" && viewerFirstLine <= 1) return;
  loadingViewerChunk = true;

  if (direction === "next") {
    const first = viewerLastLine + 1;
    const last = Math.min(total, first + VIEWER_CHUNK_SIZE - 1);
    logCode.append(createLogRows(first, last));
    viewerLastLine = last;
  } else {
    const previousHeight = logCode.scrollHeight;
    const last = viewerFirstLine - 1;
    const first = Math.max(1, last - VIEWER_CHUNK_SIZE + 1);
    logCode.prepend(createLogRows(first, last));
    viewerFirstLine = first;
    logCode.scrollTop += logCode.scrollHeight - previousHeight;
  }
  updateViewerPosition();
  requestAnimationFrame(() => { loadingViewerChunk = false; });
}

async function openLogViewer(targetStart = 1, targetEnd = targetStart) {
  try {
    await loadLogLines();
    if (!logViewer.open) logViewer.showModal();
    updateViewerMode("log");
    renderLogWindow(targetStart, targetEnd);
  } catch (error) {
    alert(error.message);
  }
}

function showGroup(group, recommendations) {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.group === group.key);
  });
  const sectionSelect = document.querySelector("#section-select");
  if (sectionSelect) sectionSelect.value = group.key;
  sectionContent.replaceChildren();
  const header = document.createElement("div");
  header.className = "section-header";
  const title = document.createElement("h3");
  title.textContent = group.label;
  const copy = document.createElement("p");
  copy.textContent = group.description;
  header.append(title, copy);
  sectionContent.append(header);

  const matches = recommendations
    .filter((item) => item.severity === group.key)
    .sort((left, right) => {
      const summaryIds = ["kometa_critical", "kometa_error", "kometa_warning"];
      const leftPriority = summaryIds.indexOf(left.id);
      const rightPriority = summaryIds.indexOf(right.id);
      if (leftPriority !== rightPriority) {
        return (leftPriority === -1 ? summaryIds.length : leftPriority)
          - (rightPriority === -1 ? summaryIds.length : rightPriority);
      }
      return left.title.localeCompare(right.title);
    });
  if (!matches.length) {
    const empty = document.createElement("div");
    empty.className = "empty-state";
    empty.textContent = `No ${group.label.toLowerCase()} were found.`;
    sectionContent.append(empty);
    return;
  }
  const list = document.createElement("div");
  list.className = "recommendation-list";
  matches.forEach((item, index) => {
    const details = document.createElement("details");
    details.className = `recommendation ${item.severity}`;
    details.open = true;
    const summary = document.createElement("summary");
    const dot = document.createElement("span");
    dot.className = "severity-dot";
    const titleText = document.createElement("span");
    titleText.textContent = item.title;
    const chevron = document.createElement("span");
    chevron.className = "chevron";
    chevron.textContent = "›";
    summary.append(dot, titleText, chevron);
    const body = recommendationBody(item.message, item.evidence_lines);
    details.append(summary, body);
    list.append(details);
  });
  sectionContent.append(list);
}

function summaryCard(label, value, small = false) {
  const card = document.createElement("div");
  card.className = "summary-card";
  const name = document.createElement("div");
  name.className = "summary-label";
  name.textContent = label;
  const content = document.createElement("div");
  content.className = `summary-value${small ? " small" : ""}`;
  content.textContent = value;
  card.append(name, content);
  return card;
}

function renderBatchResults(scans, admin = false) {
  if (!scans.length) {
    batchResults.hidden = true;
    return;
  }
  batchResultLinks.replaceChildren();
  batchResultsTitle.textContent = admin ? "Private deletion links" : "Uploaded scan results";
  const sortedScans = [...scans].sort((left, right) => left.filename.localeCompare(right.filename, undefined, {
    numeric: true,
    sensitivity: "base",
  }));
  sortedScans.forEach((scan) => {
    const item = document.createElement("li");
    const link = document.createElement("a");
    link.href = scan.result_url || `/scan/${encodeURIComponent(scan.id)}`;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    link.textContent = scan.filename;
    item.append(link);
    batchResultLinks.append(item);
  });
  const publicBatchUrl = scans[0]?.batch_public_url || scans[0]?.batch_result_url;
  shareBatchResults.hidden = !publicBatchUrl;
  shareBatchResults.dataset.url = publicBatchUrl || "";
  deleteBatch.hidden = !scans[0]?.batch_private_url;
  const unscannedFiles = scans[0]?.unscanned_files || [];
  batchUnscannedFiles.replaceChildren(...unscannedFiles.map((entry) => {
    const item = document.createElement("li");
    const filename = typeof entry === "string" ? entry : entry.filename;
    const reason = typeof entry === "string" ? "Not scanned" : entry.reason;
    item.textContent = `${filename} — ${reason}`;
    return item;
  }));
  batchUnscannedTitle.hidden = !unscannedFiles.length;
  batchUnscannedFiles.hidden = !unscannedFiles.length;
  batchResults.hidden = false;
  batchResults.scrollIntoView({ behavior: "smooth", block: "start" });
}

function renderResults(data) {
  deleteToken = new URLSearchParams(location.hash.slice(1)).get("delete");
  updateRetentionCountdown(data);
  const { metadata, recommendations, overview = {}, categories = defaultGroups } = data;
  currentRecommendations = recommendations;
  currentOverview = overview;
  if (data.expires_at) {
    overview.auto_delete = formatOverviewTimestamp(data.expires_at);
  }
  const groups = [...categories].sort((left, right) => left.priority - right.priority);
  document.querySelector("#results-title").textContent = data.filename;
  if (summaryGrid) summaryGrid.replaceChildren(
    summaryCard("Log details", `${metadata.line_count.toLocaleString()} lines · ${formatBytes(metadata.size_bytes)}${metadata.kometa_version ? `\nKometa ${metadata.kometa_version}` : ""}`, true),
    summaryCard("Critical", metadata.counts.critical),
    summaryCard("Warnings", metadata.counts.warning),
    summaryCard("Schema", metadata.counts.schema),
    summaryCard("Advice", metadata.counts.advice),
  );

  sectionNav.replaceChildren();
  const sectionSelect = document.createElement("select");
  sectionSelect.id = "section-select";
  sectionSelect.className = "section-select";
  sectionSelect.setAttribute("aria-label", "View a log section");
  groups.forEach((group) => {
    const recommendationCount = recommendations.filter((item) => item.severity === group.key).length;
    if (group.key !== "overview" && recommendationCount === 0) return;
    const option = document.createElement("option");
    option.value = group.key;
    option.textContent = group.key === "overview" ? group.label : `${group.label} (${recommendationCount})`;
    sectionSelect.append(option);
    const button = document.createElement("button");
    button.type = "button";
    button.className = "nav-button";
    button.dataset.group = group.key;
    const label = document.createElement("span");
    label.textContent = group.label;
    button.append(label);
    if (group.key !== "overview") {
      const badge = document.createElement("span");
      badge.className = "nav-count";
      badge.textContent = recommendationCount;
      button.append(badge);
    }
    button.addEventListener("click", () => group.key === "overview"
      ? showOverview(group, overview)
      : showGroup(group, recommendations));
    sectionNav.append(button);
  });
  sectionSelect.addEventListener("change", () => {
    const group = groups.find((item) => item.key === sectionSelect.value);
    if (group) group.key === "overview" ? showOverview(group, overview) : showGroup(group, recommendations);
  });
  sectionNav.prepend(sectionSelect);
  showOverview(groups[0], overview);
  results.hidden = false;
  currentScanId = data.id || currentScanId;
  document.querySelector("#delete-scan").hidden = !deleteToken;
  results.scrollIntoView({ behavior: "smooth", block: "start" });
}

input.addEventListener("change", () => selectedFiles());
["dragenter", "dragover"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.add("dragover");
}));
["dragleave", "drop"].forEach((eventName) => dropZone.addEventListener(eventName, (event) => {
  event.preventDefault();
  dropZone.classList.remove("dragover");
}));
dropZone.addEventListener("drop", (event) => {
  const files = [...event.dataTransfer.files];
  if (files.length) selectedFiles(files);
});

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = [...input.files];
  if (!files.length) return;
  dropZone.classList.add("loading");
  scanButton.disabled = true;
  status.textContent = `Scanning 0 of ${files.length} logs…`;
  status.classList.remove("error");
  try {
    const failures = [];
    status.textContent = `Scanning ${files.length} log${files.length === 1 ? "" : "s"}…`;
    const body = new FormData();
    files.forEach((file) => body.append("log", file));
    const response = await fetch("/api/scan", { method: "POST", body });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      failures.push({ filename: files.map((file) => file.name).join(", "), message: data.error || "The scan could not be completed." });
    }
    const scans = response.ok ? (data.scans || [data]) : [];
    scans.forEach((scan) => Object.assign(scan, { batch_result_url: data.batch_result_url, batch_admin_url: data.batch_admin_url, unscanned_files: data.unscanned_files || [] }));
    const completed = scans;
    if (!completed.length) throw new Error(uploadFailureSummary(failures));
    if (data.batch_admin_url) {
      location.href = data.batch_admin_url;
      return;
    }
    status.textContent = failures.length
      ? `${completed.length} scan${completed.length === 1 ? "" : "s"} complete; ${uploadFailureSummary(failures)}`
      : `${completed.length} scan${completed.length === 1 ? "" : "s"} complete`;
    batchScans = completed;
    if (batchScans.length > 1) renderBatchResults(batchScans);
    currentScanId = completed[0].id;
    deleteToken = completed[0].delete_token;
    history.replaceState({}, "", `/scan/${encodeURIComponent(completed[0].id)}#delete=${encodeURIComponent(deleteToken)}`);
    renderResults(completed[0]);
  } catch (error) {
    const marker = "Unexpected files:";
    if (error.message.includes(marker)) {
      const [summary, names] = error.message.split(marker, 2);
      status.textContent = summary.trim();
      unexpectedFileList.replaceChildren(...names.split(",").map((name) => {
        const item = document.createElement("li");
        item.textContent = name.trim();
        return item;
      }));
      uploadErrorDetails.hidden = false;
    } else {
      status.textContent = error.message;
    }
    status.classList.add("error");
  } finally {
    dropZone.classList.remove("loading");
    scanButton.disabled = false;
  }
});

document.querySelector("#view-log").addEventListener("click", () => openLogViewer(1));
document.querySelector("#toggle-viewer-content").addEventListener("click", () => {
  if (viewerMode === "config") openLogViewer(highlightedRange.start);
  else showConfigInViewer().catch((error) => alert(error.message));
});
getHelp.addEventListener("click", () => {
  if (!currentScanId) return;
  const filename = document.querySelector("#results-title").textContent;
  const resultUrl = new URL(`/scan/${encodeURIComponent(currentScanId)}`, location.origin);
  helpMessage.value = `I require assistance reviewing my Kometa log file \`${filename}\`, the link to my Logscan results can be found [here](${resultUrl}).`;
  helpDialog.showModal();
});
copyHelpMessage.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(helpMessage.value);
    copyHelpMessage.textContent = "Copied";
  } catch {
    helpMessage.select();
    document.execCommand("copy");
  }
});
document.querySelector("#close-help").addEventListener("click", () => helpDialog.close());
copyBatchResults.addEventListener("click", async () => {
  const markdown = batchScans
    .map((scan) => `- [${scan.filename}](${new URL(`/scan/${encodeURIComponent(scan.id)}`, location.origin)})`)
    .join("\n");
  if (!markdown) return;
  try {
    await navigator.clipboard.writeText(markdown);
    copyBatchResults.title = "Copied";
  } catch {
    alert("Your browser could not copy the result links.");
  }
});
shareBatchResults.addEventListener("click", async () => {
  const url = shareBatchResults.dataset.url;
  if (!url) return;
  try {
    if (navigator.share) await navigator.share({ title: "Kometa Logscan batch results", url });
    else await navigator.clipboard.writeText(url);
    shareBatchResults.title = "Public batch link copied";
  } catch (error) {
    if (error.name !== "AbortError") alert("Your browser could not share the batch link.");
  }
});
deleteBatch.addEventListener("click", async () => {
  const privateUrl = batchScans[0]?.batch_private_url;
  if (!privateUrl || !await ConfirmDialog.show({
    title: "Delete all batch logs?",
    message: "This permanently deletes every log and scan result in this batch.",
    confirmText: "Delete all",
  })) return;
  const [, , batchId, , token] = new URL(privateUrl).pathname.split("/");
  const response = await fetch(`/api/batches/${encodeURIComponent(batchId)}/admin/${encodeURIComponent(token)}`, { method: "DELETE" });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({}));
    alert(payload.error || "Unable to delete the batch.");
    return;
  }
  location.assign("/");
});
function downloadConfig() {
  if (!extractedConfig) return false;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([extractedConfig], { type: "text/yaml;charset=utf-8" }));
  link.download = downloadFilename("config");
  link.click();
  URL.revokeObjectURL(link.href);
  return true;
}
function filenamePart(value) {
  return String(value || "").trim().replace(/[<>:"/\\|?*\x00-\x1f]/g, "");
}

function downloadFilename() {
  const originalName = currentFile?.name || document.querySelector("#results-title").textContent;
  const name = filenamePart(originalName.replace(/\.[^.]+$/, ""));
  const uploader = filenamePart(currentOverview.uploaded_by);
  const now = new Date();
  const part = (value) => String(value).padStart(2, "0");
  const timestamp = `${now.getFullYear()}${part(now.getMonth() + 1)}${part(now.getDate())}-${part(now.getHours())}${part(now.getMinutes())}${part(now.getSeconds())}`;
  return [name || "log", ...(uploader ? [uploader] : []), timestamp].join("-") + ".log";
}

async function downloadLog() {
  const lines = await loadLogLines();
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" }));
  link.download = downloadFilename();
  link.click();
  URL.revokeObjectURL(link.href);
}
const downloadDialog = document.querySelector("#download-dialog");
document.querySelector("#open-download").addEventListener("click", () => downloadDialog.showModal());
document.querySelector("#open-download-main").addEventListener("click", () => downloadDialog.showModal());
document.querySelector("#download-log-option").addEventListener("click", async () => {
  try { await downloadLog(); document.querySelector("#download-dialog").close(); } catch (error) { alert(error.message); }
});
document.querySelector("#download-config-option").addEventListener("click", async () => {
  try {
    if (!extractedConfig) extractedConfig = extractConfig(await loadLogLines());
    if (!downloadConfig()) alert("No redacted config block was found in this log.");
    else document.querySelector("#download-dialog").close();
  } catch (error) { alert(error.message); }
});
document.querySelector("#download-both-option").addEventListener("click", async () => {
  try {
    if (!extractedConfig) extractedConfig = extractConfig(await loadLogLines());
    await downloadLog();
    if (!downloadConfig()) alert("The log was downloaded, but it contains no redacted config block.");
    document.querySelector("#download-dialog").close();
  } catch (error) { alert(error.message); }
});
document.querySelector("#close-download").addEventListener("click", () => downloadDialog.close());
document.querySelector("#close-recommendation").addEventListener("click", () => document.querySelector("#recommendation-dialog").close());
document.querySelector("#delete-scan").addEventListener("click", async () => {
  if (!currentScanId || !deleteToken || !await ConfirmDialog.show({ title: "Delete this scan?", message: "This permanently deletes the log and its scan results.", confirmText: "Delete scan" })) return;
  const response = await fetch(`/api/scans/${encodeURIComponent(currentScanId)}`, {
    method: "DELETE",
    headers: { "X-Delete-Token": deleteToken },
  });
  if (!response.ok) {
    alert("The log could not be deleted. The deletion link may be invalid.");
    return;
  }
  const wasBatchScan = batchScans.some((scan) => scan.id === currentScanId);
  if (wasBatchScan) {
    batchScans = batchScans.filter((scan) => scan.id !== currentScanId);
    renderBatchResults(batchScans);
    results.hidden = true;
    currentScanId = null;
    deleteToken = null;
    history.replaceState({}, "", "/");
    return;
  }
  location.href = "/";
});
window.addEventListener("hashchange", () => {
  deleteToken = new URLSearchParams(location.hash.slice(1)).get("delete");
  document.querySelector("#delete-scan").hidden = !deleteToken;
});
document.querySelector("#close-viewer").addEventListener("click", () => logViewer.close());
highlightMode.addEventListener("change", () => {
  if (currentLogLines && viewerMode === "log") renderLogWindow(highlightedRange.start);
});
nextHighlight.addEventListener("click", goToNextHighlightedLine);
sectionJump.addEventListener("change", () => {
  if (!sectionJump.value) return;
  const targetLine = Number(sectionJump.value);
  renderLogWindow(targetLine, targetLine);
});
logViewer.addEventListener("click", (event) => {
  if (event.target === logViewer) logViewer.close();
});
document.querySelector("#recommendation-dialog").addEventListener("click", (event) => {
  if (event.target === document.querySelector("#recommendation-dialog")) document.querySelector("#recommendation-dialog").close();
});
downloadDialog.addEventListener("click", (event) => {
  if (event.target === downloadDialog) downloadDialog.close();
});
helpDialog.addEventListener("click", (event) => {
  if (event.target === helpDialog) helpDialog.close();
});
logCode.addEventListener("scroll", () => {
  if (viewerMode !== "log") return;
  if (logCode.scrollTop + logCode.clientHeight >= logCode.scrollHeight - 240) {
    loadAdjacentLogChunk("next");
  } else if (logCode.scrollTop <= 120) {
    loadAdjacentLogChunk("previous");
  }
});

const initialScan = JSON.parse(document.querySelector("#initial-scan").textContent);
const initialBatch = JSON.parse(document.querySelector("#initial-batch").textContent);

function updateRetentionCountdown(scan) {
  if (!retentionCountdown || !scan?.expires_at) return;
  clearInterval(retentionTimer);
  const render = () => {
    const remainingMinutes = Math.max(0, Math.ceil((scan.expires_at * 1000 - Date.now()) / 60000));
    const hours = Math.floor(remainingMinutes / 60);
    const minutes = remainingMinutes % 60;
    retentionCountdown.textContent = remainingMinutes
      ? `This log file will be automatically deleted in ${hours} hour${hours === 1 ? "" : "s"} and ${minutes} minute${minutes === 1 ? "" : "s"}.`
      : "This log file is scheduled for deletion.";
  };
  render();
  retentionTimer = setInterval(render, 30000);
}

if (initialScan) {
  currentScanId = initialScan.id;
  const fragment = new URLSearchParams(location.hash.slice(1));
  deleteToken = fragment.get("delete");
  renderResults(initialScan);
}
if (initialBatch) {
  batchScans = initialBatch;
  renderBatchResults(batchScans, initialBatch.some((scan) => scan.result_url.includes("#delete=")));
}
