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
const previousHighlight = document.querySelector("#previous-highlight");
const nextHighlight = document.querySelector("#next-highlight");
const sectionJump = document.querySelector("#section-jump");
const viewerPosition = document.querySelector("#viewer-position");
let currentFile = null;
let currentScanId = null;
let deleteToken = null;
let currentLogLines = null;
let currentLogSections = [];
let currentLogTotal = 0;
let highlightedRange = { start: 1, end: 1 };
let viewerNavigationLines = null;
let viewerFirstLine = 1;
let viewerLastLine = 1;
let loadingViewerChunk = false;
let extractedConfig = "";
let viewerMode = "log";
let currentRecommendations = [];
let schemaValidationFailures = [];
let currentSchemaBranch = "master";
let currentOverview = {};
let batchScans = [];
const VIEWER_CHUNK_SIZE = 1000;

const defaultGroups = [
  { key: "overview", label: "Log Overview", description: "Details extracted from the uploaded log." },
  { key: "critical", label: "Critical issues", description: "Items most likely to prevent a successful or secure run." },
  { key: "error", label: "Errors", description: "Problems that may cause incomplete or unintended results." },
  { key: "warning", label: "Warnings", description: "Potential problems worth reviewing before your next run." },
  { key: "schema", label: "Schema validation", description: "Live config.yml schema results plus deprecated or invalid configuration syntax." },
  { key: "advice", label: "Advice", description: "Configuration and performance improvements." },
];

function displayValue(value) {
  return value || "Not found in this log";
}

function uploadFailureType(message) {
  if (message.startsWith("Choose a Kometa log, text, YAML, ZIP, 7-Zip, TAR, GZIP, BZIP2, XZ, or Zstandard file.")) {
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

function setSectionSelectSeverity(select, key) {
  if (select) select.dataset.severity = key;
}

function showOverview(group, overview) {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.group === group.key);
  });
  const sectionSelect = document.querySelector("#section-select");
  if (sectionSelect) { sectionSelect.value = group.key; setSectionSelectSeverity(sectionSelect, group.key); }
  sectionContent.replaceChildren();
  const header = document.createElement("div");
  header.className = "section-header";
  header.innerHTML = `<h3>${group.label}</h3><p>${group.description}</p>`;
  sectionContent.append(header);
  const details = [
    ["Log name", overview.log_name],
    ...(overview.uploaded_by ? [["Log Info", { uploader: overview.uploaded_by, id: overview.uploaded_by_id, messageUrl: overview.message_url }]] : []),
    ["Findings", overview.finding_count ?? overview.recommendation_count],
    ["Lines scanned", overview.line_count],
    ["Log size", overview.size_display],
    ["Compressed archive size", overview.archive_compressed_size_display],
    ["Uncompressed archive size", overview.archive_uncompressed_size_display],
    ["Compression ratio", overview.archive_compression_ratio],
    ["Archive size reduction", overview.archive_reduction_percent],
    ["Start time", overview.start_time],
    ["End time", overview.finished],
    ["Run time", overview.run_time],
    ["Configuration validation", overview.yaml_validation],
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
      const uploader = value.id ? document.createElement("a") : document.createElement("span");
      if (value.id) {
        uploader.href = `discord://-/users/${value.id}`;
        uploader.title = "Open Discord profile";
      }
      uploader.textContent = value.uploader;
      definition.append("Uploader: ", uploader);
      if (value.messageUrl) {
        try {
          const messageUrl = new URL(value.messageUrl);
          if (messageUrl.protocol === "https:" && ["discord.com", "www.discord.com"].includes(messageUrl.hostname)) {
            const link = document.createElement("a");
            link.href = `discord://-${messageUrl.pathname}`;
            link.textContent = "Click Here";
            link.title = "Open Discord message";
            definition.append(document.createElement("br"), "Discord Message: ", link);
          }
        } catch (_error) {
          // Uploader attribution is still useful when a legacy message URL is malformed.
        }
      }
    } else {
      definition.textContent = displayValue(value);
    }
    if (label === "Configuration validation" && Number(overview.yaml_issue_count) > 0) {
      const openFirstIssue = () => {
        const firstIssue = schemaIssueRecommendations()
          .filter((candidate) => Number(candidate.config_line) > 0)
          .sort((left, right) => Number(left.config_line) - Number(right.config_line))[0];
        showConfigInViewer(Number(firstIssue?.config_line) || 0).catch((error) => alert(error.message));
      };
      item.classList.add("overview-validation-issue");
      item.tabIndex = 0;
      item.setAttribute("role", "button");
      item.setAttribute("aria-label", `${value}. Review the first issue in config.yml`);
      item.addEventListener("click", openFirstIssue);
      item.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          openFirstIssue();
        }
      });
    }
    item.append(term, definition);
    grid.append(item);
  });
  sectionContent.append(grid);
  const sectionRunTimes = overview.section_run_times || [];
  if (sectionRunTimes.length) {
    const runtimeSection = document.createElement("details");
    runtimeSection.className = "runtime-summary";
    const runtimeSummary = document.createElement("summary");
    const runtimeSummaryTitle = document.createElement("span");
    runtimeSummaryTitle.textContent = "Longest section run times";
    const runtimeSummaryCount = document.createElement("span");
    runtimeSummaryCount.className = "runtime-summary-count";
    runtimeSummaryCount.textContent = `${sectionRunTimes.length.toLocaleString()} section${sectionRunTimes.length === 1 ? "" : "s"}`;
    const runtimeChevron = document.createElement("span");
    runtimeChevron.className = "chevron";
    runtimeChevron.textContent = "\u203a";
    runtimeSummary.append(runtimeSummaryTitle, runtimeSummaryCount, runtimeChevron);
    const runtimeBody = document.createElement("div");
    runtimeBody.className = "runtime-summary-body";
    const runtimeHeader = document.createElement("div");
    runtimeHeader.className = "runtime-summary-header";
    const runtimeLabel = document.createElement("label");
    runtimeLabel.htmlFor = "runtime-limit";
    runtimeLabel.textContent = "Show";
    const runtimeLimit = document.createElement("select");
    runtimeLimit.id = "runtime-limit";
    runtimeLimit.setAttribute("aria-label", "Number of section run times to show");
    [["10", "Top 10"], ["25", "Top 25"], ["100", "Top 100"], ["all", `All (${sectionRunTimes.length.toLocaleString()})`]].forEach(([value, label]) => {
      const option = document.createElement("option");
      option.value = value;
      option.textContent = label;
      runtimeLimit.append(option);
    });
    runtimeHeader.append(runtimeLabel, runtimeLimit);
    const runtimeNote = document.createElement("p");
    runtimeNote.setAttribute("aria-live", "polite");
    const runtimeList = document.createElement("ol");
    runtimeList.className = "runtime-list";
    const renderRunTimes = () => {
      const limit = runtimeLimit.value === "all" ? sectionRunTimes.length : Number(runtimeLimit.value);
      runtimeList.replaceChildren();
      const visibleRunTimes = sectionRunTimes.slice(0, limit);
      visibleRunTimes.forEach((runtime, index) => {
        const row = document.createElement("li");
        const rank = document.createElement("span");
        rank.className = "runtime-rank";
        rank.textContent = `${index + 1} of ${sectionRunTimes.length}`;
        const link = document.createElement("button");
        link.type = "button";
        link.className = "runtime-line-link";
        link.textContent = runtime.name;
        link.title = `View ${runtime.name} in the log`;
        link.addEventListener("click", () => openRuntimeLine(runtime, visibleRunTimes));
        const duration = document.createElement("span");
        duration.className = "runtime-duration";
        duration.textContent = runtime.duration;
        row.append(rank, link, duration);
        runtimeList.append(row);
      });
      runtimeNote.textContent = `Showing ${Math.min(limit, sectionRunTimes.length).toLocaleString()} of ${sectionRunTimes.length.toLocaleString()} sections, sorted by duration. Zero-second sections are excluded.`;
    };
    runtimeLimit.addEventListener("change", renderRunTimes);
    renderRunTimes();
    runtimeBody.append(runtimeHeader, runtimeNote, runtimeList);
    runtimeSection.append(runtimeSummary, runtimeBody);
    sectionContent.append(runtimeSection);
  }
  const plexConfigurations = overview.plex_configurations || [];
  if (plexConfigurations.length) {
    const plexHeading = document.createElement("h4");
    plexHeading.className = "overview-subheading";
    plexHeading.textContent = "Plex Configuration";
    sectionContent.append(plexHeading);
    const plexList = document.createElement("div");
    plexList.className = "plex-configuration-list";
    plexConfigurations.forEach((configuration) => {
      const panel = document.createElement("details");
      panel.className = "plex-configuration";
      const summary = document.createElement("summary");
      const title = document.createElement("span");
      title.textContent = configuration.title;
      const chevron = document.createElement("span");
      chevron.className = "chevron";
      chevron.textContent = "\u203a";
      summary.append(title, chevron);
      const body = document.createElement("div");
      body.className = "plex-configuration-body";
      (configuration.lines || []).forEach((line) => {
        const row = document.createElement("p");
        row.textContent = line;
        body.append(row);
      });
      panel.append(summary, body);
      plexList.append(panel);
    });
    sectionContent.append(plexList);
  }
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
    : chosenFiles.length ? `${chosenFiles.length} files selected · ${formatBytes(chosenFiles.reduce((total, file) => total + file.size, 0))}` : "LOG, TXT, or YAML · ZIP, 7Z, TAR, GZIP, BZIP2, XZ, or Zstandard · up to 1 GB each";
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

function appendLineReferenceLinks(container, references) {
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

function appendRecommendationMeta(container, text) {
  const marker = /^(.*?Line number\(s\):\s*)(.*)$/i.exec(text);
  if (!marker) {
    appendInlineFormatting(container, text);
    return;
  }
  const references = marker[2];
  const referenceCount = [...references.matchAll(/\d+(?:-\d+)?/g)].length;
  if (referenceCount <= 12) {
    appendInlineFormatting(container, marker[1]);
    appendLineReferenceLinks(container, references);
    return;
  }
  const details = document.createElement("details");
  details.className = "line-reference-overflow";
  const summary = document.createElement("summary");
  summary.textContent = `${referenceCount} matching line references`;
  const links = document.createElement("div");
  appendLineReferenceLinks(links, references);
  details.append(summary, links);
  container.append(details);
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

function recommendationBody(message, evidenceLines = [], configLine = 0) {
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
  if (configLine) {
    const row = document.createElement("div");
    row.className = "recommendation-meta";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "line-link";
    button.textContent = `Open config.yml at line ${configLine}`;
    button.title = `View extracted configuration at line ${configLine}`;
    button.addEventListener("click", () => showConfigInViewer(configLine).then(() => {
      if (!logViewer.open) logViewer.showModal();
    }).catch((error) => alert(error.message)));
    row.append(button);
    body.append(row);
  } else if (!hasEmbeddedEvidence && evidenceLines.length) {
    const row = document.createElement("div");
    row.className = "recommendation-meta";
    appendRecommendationMeta(row, `Log line number(s): ${formatLineRanges(evidenceLines)}`);
    body.append(row);
  }
  return body;
}

async function fetchLogWindow(start, count = VIEWER_CHUNK_SIZE) {
  const url = "/api/scans/" + encodeURIComponent(currentScanId) + "/log?start=" + start + "&count=" + count;
  const response = await fetch(url);
  if (response.status === 404) throw new Error("This stored log has expired or was deleted, so its source lines are no longer available.");
  if (!response.ok) throw new Error("The stored log could not be loaded (HTTP " + response.status + ").");
  const payload = await response.json();
  if (!currentLogLines) currentLogLines = new Array(payload.total);
  currentLogTotal = payload.total;
  currentLogLines.length = payload.total;
  payload.lines.forEach((line, index) => { currentLogLines[payload.start - 1 + index] = line; });
  currentLogSections = payload.sections || currentLogSections;
  if (!extractedConfig && payload.config) extractedConfig = payload.config;
  populateSectionJump();
  return payload;
}

async function loadLogLines() {
  if (!currentFile && !currentScanId) throw new Error("Select and scan a log before opening the viewer.");
  if (!currentLogLines) {
    if (currentScanId) {
      await fetchLogWindow(1);
    } else {
      const text = await currentFile.text();
      currentLogLines = text.split(/\r?\n/);
      currentLogTotal = currentLogLines.length;
      currentLogSections = findLogSections(currentLogLines);
      populateSectionJump();
    }
  }
  return currentLogLines;
}

async function ensureLogWindow(first, last) {
  await loadLogLines();
  if (!currentScanId) return;
  let missingStart = null;
  for (let line = first; line <= last; line += 1) {
    if (!(line - 1 in currentLogLines)) {
      missingStart = line;
      break;
    }
  }
  if (missingStart !== null) await fetchLogWindow(missingStart, Math.max(VIEWER_CHUNK_SIZE, last - missingStart + 1));
  const keepFirst = Math.max(1, first - (VIEWER_CHUNK_SIZE * 2));
  const keepLast = Math.min(currentLogTotal, last + (VIEWER_CHUNK_SIZE * 2));
  Object.keys(currentLogLines).forEach((key) => {
    const line = Number(key) + 1;
    if (line < keepFirst || line > keepLast) delete currentLogLines[key];
  });
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
  const taggedConfig = /\[config\.py:\d+\]\s+\[([A-Z]+)\]\s*\|(.*)$/;
  for (const line of lines) {
    if (!started) {
      if (line.includes("Redacted Config")) started = true;
      continue;
    }
    if (line.includes("Config Warning:") || line.includes("Initializing cache database at")) break;
    const match = taggedConfig.exec(line);
    if (!match) break;
    if (["CRITICAL", "ERROR", "WARNING"].includes(match[1])) break;
    extracted.push(match[2].replace(/[ |]+$/, ""));
  }
  if (extracted.length > 1) extracted.pop();
  return extracted.map((line) => line.startsWith(" ") ? line.slice(1) : line).join("\n");
}

function createConfigRows(config, targetStart = 0, targetEnd = targetStart) {
  const fragment = document.createDocumentFragment();
  config.split("\n").forEach((line, index) => {
    const row = document.createElement("div");
    const lineNumber = index + 1;
    const matchingItems = schemaRecommendationsForConfigLine(lineNumber);
    row.className = "log-line";
    row.dataset.line = lineNumber;
    if (targetStart && lineNumber >= targetStart && lineNumber <= targetEnd) row.classList.add("highlighted");
    if (matchingItems.length) {
      row.classList.add("recommendation-line", "schema-validation-line");
      row.tabIndex = 0;
      row.title = "View schema issue";
      row.addEventListener("click", () => openRecommendationDialog(matchingItems));
      row.addEventListener("keydown", (event) => {
        if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openRecommendationDialog(matchingItems); }
      });
    }
    const number = document.createElement("span");
    number.className = "line-number";
    number.textContent = lineNumber;
    const content = document.createElement("span");
    const issueRanges = matchingItems
      .filter((item) => item.config_column && item.config_end_column)
      .map((item) => ({ start: item.config_column - 1, end: item.config_end_column - 1 }));
    appendYamlHighlight(content, line || " ", issueRanges);
    row.append(number, content);
    fragment.append(row);
  });
  return fragment;
}

function appendYamlSegment(container, text, className, offset, issueRanges) {
  const boundaries = new Set([0, text.length]);
  issueRanges.forEach((range) => {
    const start = Math.max(0, Math.min(text.length, range.start - offset));
    const end = Math.max(start, Math.min(text.length, range.end - offset));
    if (end > start) {
      boundaries.add(start);
      boundaries.add(end);
    }
  });
  const points = [...boundaries].sort((left, right) => left - right);
  for (let index = 0; index < points.length - 1; index += 1) {
    const start = points[index];
    const end = points[index + 1];
    if (end <= start) continue;
    const value = text.slice(start, end);
    const isIssue = issueRanges.some((range) => range.start < offset + end && range.end > offset + start);
    if (!className && !isIssue) {
      container.append(document.createTextNode(value));
      continue;
    }
    const span = document.createElement("span");
    if (className) span.classList.add(className);
    if (isIssue) span.classList.add("schema-issue-token");
    span.textContent = value;
    container.append(span);
  }
}

function appendYamlHighlight(container, line, issueRanges = []) {
  const commentIndex = line.search(/\s#/);
  const code = commentIndex === -1 ? line : line.slice(0, commentIndex);
  const comment = commentIndex === -1 ? "" : line.slice(commentIndex);
  const keyMatch = /^(\s*)([^:#][^:]*)(:)(.*)$/.exec(code);
  const segments = [];
  if (keyMatch) {
    segments.push([keyMatch[1], ""]);
    segments.push([keyMatch[2], "yaml-key"]);
    segments.push([keyMatch[3], ""]);
    segments.push([keyMatch[4], /^(\s*)(true|false|null|~)$/i.test(keyMatch[4]) ? "yaml-literal" : "yaml-value"]);
  } else {
    segments.push([code, ""]);
  }
  if (comment) segments.push([comment, "yaml-comment"]);

  let offset = 0;
  segments.forEach(([value, className]) => {
    appendYamlSegment(container, value, className, offset, issueRanges);
    offset += value.length;
  });
}

function setHighlightOptions(isConfig) {
  const options = isConfig
    ? [["schema", "Schema issues"]]
    : [["all", "All Warnings, Errors and Critical"], ["critical", "Critical Only"], ["error", "Error Only"], ["warning", "Warning Only"]];
  highlightMode.replaceChildren(...options.map(([value, label]) => {
    const option = document.createElement("option");
    option.value = value;
    option.textContent = label;
    return option;
  }));
  highlightMode.disabled = isConfig;
  document.querySelector(".highlight-mode-control label").textContent = isConfig ? "Highlight mode" : "Change Highlight Mode";
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
  document.querySelector(".viewer-toolbar").hidden = false;
  setHighlightOptions(isConfig);
  document.querySelector(".section-jump-control label").textContent = isConfig ? "Jump to schema issue" : "Jump to section";
  if (isConfig) populateSchemaIssueJump();
  else populateSectionJump();
}

async function showConfigInViewer(targetStart = 0, targetEnd = targetStart) {
  viewerNavigationLines = null;
  const lines = await loadLogLines();
  if (!extractedConfig && !currentScanId) extractedConfig = extractConfig(lines);
  updateViewerMode("config");
  logCode.replaceChildren(
    extractedConfig
      ? createConfigRows(extractedConfig, targetStart, targetEnd)
      : document.createTextNode("No redacted config block was found in this log."),
  );
  logCode.scrollTop = 0;
  const configLineCount = extractedConfig ? extractedConfig.split("\n").length : 0;
  const schemaIssueCount = schemaIssueRecommendations().length;
  viewerPosition.textContent = `${configLineCount.toLocaleString()} config line${configLineCount === 1 ? "" : "s"} | ${schemaIssueCount.toLocaleString()} schema issue${schemaIssueCount === 1 ? "" : "s"}`;
  updateHighlightNavigationControls();
  if (targetStart) {
    highlightedRange = { start: targetStart, end: targetEnd };
    requestAnimationFrame(() => logCode.querySelector(`[data-line="${targetStart}"]`)?.scrollIntoView({ block: "center" }));
  }
  if (!logViewer.open) logViewer.showModal();
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

function populateSchemaIssueJump() {
  sectionJump.replaceChildren();
  const failures = schemaIssueRecommendations()
    .filter((item) => Number(item.config_line) > 0)
    .sort((left, right) => Number(left.config_line) - Number(right.config_line));
  const placeholder = document.createElement("option");
  placeholder.value = "";
  placeholder.textContent = failures.length ? "Select a schema issue" : "No schema issues found";
  sectionJump.append(placeholder);
  failures.forEach((failure, index) => {
    const option = document.createElement("option");
    option.value = failure.config_line;
    option.textContent = `${index + 1}. ${failure.title || failure.path || "Schema issue"} - line ${failure.config_line}`;
    sectionJump.append(option);
  });
  sectionJump.disabled = failures.length === 0;
}

function schemaRecommendationsForConfigLine(lineNumber) {
  return schemaIssueRecommendations().filter((item) => Number(item.config_line) === lineNumber);
}

function schemaIssueRecommendations(recommendations = currentRecommendations) {
  return recommendations.filter((item) => item.severity === "schema"
    && !["live_schema_passed", "live_schema_unavailable"].includes(item.id));
}

function createLogRows(first, last) {
  const fragment = document.createDocumentFragment();
  for (let lineNumber = first; lineNumber <= last; lineNumber += 1) {
    const row = document.createElement("div");
    row.className = "log-line";
    row.dataset.line = lineNumber;
    if (lineNumber >= highlightedRange.start && lineNumber <= highlightedRange.end) row.classList.add("highlighted");
    const matchingItems = recommendationsForLine(lineNumber);
    if (matchingItems.length) {
      row.classList.add("recommendation-line", ...matchingItems.map((item) => `recommendation-${item.severity}`));
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

function highlightedLineNumbers() {
  if (viewerMode === "log" && viewerNavigationLines?.length) return viewerNavigationLines;
  if (viewerMode === "config") {
    return [...new Set(schemaIssueRecommendations().map((item) => Number(item.config_line)))]
      .filter((lineNumber) => Number.isInteger(lineNumber) && lineNumber >= 1)
      .sort((left, right) => left - right);
  }
  const lines = new Set();
  currentRecommendations.forEach((item) => {
    if ((highlightMode.value === "all" || item.severity === highlightMode.value)
      && ["critical", "error", "warning"].includes(item.severity)) {
      recommendationLineNumbers(item).forEach((lineNumber) => lines.add(lineNumber));
    }
  });
  return [...lines].filter((lineNumber) => lineNumber >= 1 && lineNumber <= currentLogLines.length)
    .sort((left, right) => left - right);
}

function updateHighlightNavigationControls() {
  const runtimeContext = viewerMode === "log" && viewerNavigationLines?.length;
  const hasHighlights = currentLogLines && highlightedLineNumbers().length > 0;
  previousHighlight.disabled = !hasHighlights;
  nextHighlight.disabled = !hasHighlights;
  previousHighlight.title = hasHighlights
    ? `Go to the previous ${runtimeContext ? "ranked section" : "highlighted line"}` : "No lines match this highlight mode";
  nextHighlight.title = hasHighlights
    ? `Go to the next ${runtimeContext ? "ranked section" : "highlighted line"}` : "No lines match this highlight mode";
}

function goToHighlightedLine(direction) {
  if (!currentLogLines) return;
  const lines = highlightedLineNumbers();
  if (!lines.length) return;
  if (viewerMode === "log" && viewerNavigationLines?.length) {
    const currentIndex = viewerNavigationLines.indexOf(highlightedRange.start);
    const offset = direction === "previous" ? -1 : 1;
    const fallbackIndex = direction === "previous" ? 0 : -1;
    const targetIndex = (Math.max(currentIndex, fallbackIndex) + offset + lines.length) % lines.length;
    renderLogWindow(lines[targetIndex]);
    return;
  }
  const targetLine = direction === "previous"
    ? [...lines].reverse().find((lineNumber) => lineNumber < highlightedRange.start) || lines.at(-1)
    : lines.find((lineNumber) => lineNumber > highlightedRange.start) || lines[0];
  if (viewerMode === "config") showConfigInViewer(targetLine).catch((error) => alert(error.message));
  else renderLogWindow(targetLine);
}

function goToPreviousHighlightedLine() {
  goToHighlightedLine("previous");
}

function goToNextHighlightedLine() {
  goToHighlightedLine("next");
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

async function renderLogWindow(targetStart, targetEnd = targetStart) {
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
  await ensureLogWindow(viewerFirstLine, viewerLastLine);
  const fragment = createLogRows(viewerFirstLine, viewerLastLine);
  logCode.replaceChildren(fragment);
  updateViewerPosition();
  updateHighlightNavigationControls();
  requestAnimationFrame(() => {
    logCode.querySelector(`[data-line="${startTarget}"]`)?.scrollIntoView({ block: "center" });
  });
}

async function loadAdjacentLogChunk(direction) {
  if (loadingViewerChunk || !currentLogLines) return;
  const total = currentLogLines.length;
  if (direction === "next" && viewerLastLine >= total) return;
  if (direction === "previous" && viewerFirstLine <= 1) return;
  loadingViewerChunk = true;

  if (direction === "next") {
    const first = viewerLastLine + 1;
    const last = Math.min(total, first + VIEWER_CHUNK_SIZE - 1);
    await ensureLogWindow(first, last);
    logCode.replaceChildren(createLogRows(first, last));
    viewerFirstLine = first;
    viewerLastLine = last;
    logCode.scrollTop = 300;
  } else {
    const last = viewerFirstLine - 1;
    const first = Math.max(1, last - VIEWER_CHUNK_SIZE + 1);
    await ensureLogWindow(first, last);
    logCode.replaceChildren(createLogRows(first, last));
    viewerFirstLine = first;
    viewerLastLine = last;
    logCode.scrollTop = Math.max(0, logCode.scrollHeight - logCode.clientHeight - 300);
  }
  updateViewerPosition();
  requestAnimationFrame(() => { loadingViewerChunk = false; });
}

async function openLogViewer(targetStart = 1, targetEnd = targetStart) {
  try {
    await loadLogLines();
    if (!logViewer.open) logViewer.showModal();
    updateViewerMode("log");
    viewerNavigationLines = null;
    await renderLogWindow(targetStart, targetEnd);
  } catch (error) {
    alert(error.message);
  }
}

function runtimeTargetLine(lines, runtime) {
  if (!lines.length) return 1;
  const recordedIndex = Math.max(0, Math.min(lines.length - 1, Number(runtime.line || 1) - 1));
  const name = `${runtime.name || ""}`.trim().toLocaleLowerCase();
  const duration = `${runtime.duration || ""}`.trim().toLocaleLowerCase();
  const candidates = [];
  lines.forEach((line, index) => {
    const current = line.toLocaleLowerCase();
    if (!current.includes("finished") || !current.includes(name)) return;
    const block = `${line}\n${lines[index + 1] || ""}`.toLocaleLowerCase();
    if (!duration || block.includes(duration)) candidates.push(index);
  });
  if (!candidates.length) {
    lines.forEach((line, index) => {
      const current = line.toLocaleLowerCase();
      if (current.includes("finished") && current.includes(name)) candidates.push(index);
    });
  }
  const targetIndex = candidates.length
    ? candidates.reduce((closest, candidate) => (
      Math.abs(candidate - recordedIndex) < Math.abs(closest - recordedIndex) ? candidate : closest
    ), candidates[0])
    : recordedIndex;
  return targetIndex + 1;
}

async function openRuntimeLine(runtime, rankedRunTimes = [runtime]) {
  try {
    const lines = await loadLogLines();
    viewerNavigationLines = [...new Set(rankedRunTimes.map((item) => runtimeTargetLine(lines, item)))];
    const targetLine = runtimeTargetLine(lines, runtime);
    if (!logViewer.open) logViewer.showModal();
    updateViewerMode("log");
    await renderLogWindow(targetLine);
  } catch (error) {
    alert(error.message);
  }
}

function showGroup(group, recommendations) {
  document.querySelectorAll(".nav-button").forEach((button) => {
    button.classList.toggle("active", button.dataset.group === group.key);
  });
  const sectionSelect = document.querySelector("#section-select");
  if (sectionSelect) { sectionSelect.value = group.key; setSectionSelectSeverity(sectionSelect, group.key); }
  sectionContent.replaceChildren();
  const header = document.createElement("div");
  header.className = "section-header";
  const title = document.createElement("h3");
  title.textContent = group.label;
  const copy = document.createElement("p");
  copy.textContent = group.description;
  header.append(title, copy);
  sectionContent.append(header);

  const matches = (group.key === "schema"
    ? schemaIssueRecommendations(recommendations)
    : recommendations.filter((item) => item.severity === group.key))
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
  if (group.key === "schema") {
    const firstIssue = [...matches]
      .filter((item) => Number(item.config_line) > 0)
      .sort((left, right) => Number(left.config_line) - Number(right.config_line))[0];
    const review = document.createElement("div");
    review.className = "schema-review";
    const count = document.createElement("strong");
    count.textContent = `${matches.length.toLocaleString()} schema issue${matches.length === 1 ? "" : "s"} found`;
    const guidance = document.createElement("p");
    guidance.textContent = "Review each issue in context inside the extracted config.yml file.";
    const button = document.createElement("button");
    button.type = "button";
    button.className = "primary-button compact";
    button.textContent = firstIssue ? "Review issues in config" : "Open extracted config";
    button.addEventListener("click", () => {
      const targetLine = Number(firstIssue?.config_line) || 0;
      showConfigInViewer(targetLine).then(() => {
        if (!logViewer.open) logViewer.showModal();
      }).catch((error) => alert(error.message));
    });
    review.append(count, guidance, button);
    sectionContent.append(review);
    return;
  }
  const list = document.createElement("div");
  list.className = "recommendation-list";
  matches.forEach((item, index) => {
    const details = document.createElement("details");
    details.className = `recommendation ${item.severity}`;
    details.open = false;
    const summary = document.createElement("summary");
    const dot = document.createElement("span");
    dot.className = "severity-dot";
    const titleText = document.createElement("span");
    titleText.textContent = item.title;
    const chevron = document.createElement("span");
    chevron.className = "chevron";
    chevron.textContent = "›";
    summary.append(dot, titleText, chevron);
    const body = recommendationBody(item.message, item.evidence_lines, item.config_line);
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
  `${value}`.split("\n").forEach((line, index) => {
    if (index) content.append(document.createElement("br"));
    content.append(line);
  });
  card.append(name, content);
  return card;
}

function detailRows(rows) {
  const list = document.createElement("dl");
  list.className = "environment-details";
  rows.filter(([, value]) => value !== undefined && value !== null && value !== "").forEach(([label, value]) => {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const definition = document.createElement("dd");
    term.textContent = label;
    definition.textContent = Array.isArray(value) ? value.join(", ") : value;
    wrapper.append(term, definition);
    list.append(wrapper);
  });
  return list;
}

function environmentSection(kind, title, summary, rows, open = false) {
  const section = document.createElement("details");
  section.className = `environment-section environment-${kind}`;
  section.open = open;
  const heading = document.createElement("summary");
  const badge = document.createElement("span");
  badge.className = "environment-logo";
  badge.textContent = kind === "quickstart" ? "QS" : title.slice(0, 1);
  const identity = document.createElement("span");
  identity.className = "environment-identity";
  const name = document.createElement("strong");
  name.textContent = title;
  const description = document.createElement("span");
  description.textContent = summary;
  identity.append(name, description);
  const chevron = document.createElement("span");
  chevron.className = "chevron";
  chevron.textContent = ">";
  heading.append(badge, identity, chevron);
  section.append(heading, detailRows(rows));
  return section;
}

function findingTile(label, severity, count) {
  const tile = document.createElement("button");
  tile.type = "button";
  tile.className = `finding-tile finding-${severity}`;
  tile.disabled = !Number(count);
  const value = document.createElement("strong");
  value.textContent = Number(count || 0).toLocaleString();
  const name = document.createElement("span");
  name.textContent = label;
  tile.append(value, name);
  tile.addEventListener("click", () => document.querySelector(`.nav-button[data-group="${severity}"]`)?.click());
  return tile;
}

function renderSummary(metadata, overview) {
  if (!summaryGrid) return;
  const metricGrid = document.createElement("section");
  metricGrid.className = "scan-metric-grid";
  metricGrid.setAttribute("aria-label", "Scan summary");
  const metricHeading = document.createElement("h3");
  metricHeading.className = "summary-section-heading";
  metricHeading.textContent = "Scan summary";
  metricGrid.append(metricHeading,
    summaryCard("Lines scanned", Number(metadata.line_count || 0).toLocaleString()),
    summaryCard("Log size", formatBytes(metadata.size_bytes || 0)),
    summaryCard("Run time", overview.run_time || metadata.run_time || "Unknown", true),
    summaryCard("Findings", Object.values(metadata.counts).reduce((total, count) => total + Number(count || 0), 0).toLocaleString()),
  );

  const findings = document.createElement("section");
  findings.className = "finding-grid";
  findings.setAttribute("aria-label", "Findings");
  const findingsHeading = document.createElement("h3");
  findingsHeading.className = "summary-section-heading";
  findingsHeading.textContent = "Findings";
  findings.append(findingsHeading,
    findingTile("Critical", "critical", metadata.counts.critical),
    findingTile("Errors", "error", metadata.counts.error),
    findingTile("Warnings", "warning", metadata.counts.warning),
    findingTile("Schema", "schema", metadata.counts.schema),
    findingTile("Advice", "advice", metadata.counts.advice),
  );

  const environment = document.createElement("section");
  environment.className = "environment-panel";
  const heading = document.createElement("h3");
  heading.textContent = "Environment";
  environment.append(heading);
  environment.append(environmentSection("kometa", "Kometa", [
    metadata.kometa_version,
    metadata.kometa_branch && metadata.kometa_branch !== "unknown" ? metadata.kometa_branch : null,
    metadata.installation_method,
  ].filter(Boolean).join(" · ") || "Version not recorded", [
    ["Version", metadata.kometa_version],
    ["Branch", metadata.kometa_branch],
    ["Installation", metadata.installation_method],
    ["Platform", overview.platform || metadata.runtime_platform],
    ["Total memory", overview.total_memory],
    ["Available memory", overview.available_memory],
    ["Run command", overview.run_command],
  ], true));

  const configurations = overview.plex_configurations || [];
  const plexLines = configurations.flatMap((section) => section.lines || []);
  const maintenance = plexLines.map((line) => line.match(/Scheduled maintenance running between\s+(.+)/i)?.[1]).find(Boolean);
  const servers = overview.plex_servers || [];
  if (servers.length || configurations.length) {
    const first = servers[0] || {};
    const summary = [first.name, first.version, first.platform].filter(Boolean).join(" · ") || `${configurations.length} libraries`;
    const rows = servers.flatMap((server, index) => [
      [servers.length > 1 ? `Server ${index + 1}` : "Server", server.name],
      ["Plex version", server.version],
      ["Host platform", server.platform],
    ]);
    rows.push(["Libraries", configurations.length], ["Maintenance window", maintenance]);
    environment.append(environmentSection("plex", "Plex", summary, rows));
  }

  const quickstart = metadata.quickstart || {
    detected: metadata.quickstart_run,
    version: metadata.quickstart_version,
    branch: metadata.quickstart_branch,
    mode: null,
    flags: [],
    metadata: {},
  };
  if (quickstart.detected) {
    const extra = quickstart.metadata || {};
    environment.append(environmentSection("quickstart", "Quickstart", [
      quickstart.version,
      quickstart.branch !== "unknown" ? quickstart.branch : null,
      quickstart.mode,
    ].filter(Boolean).join(" · ") || "Detected", [
      ["Version", quickstart.version],
      ["Branch", quickstart.branch],
      ["Runtime mode", quickstart.mode || extra.runtime],
      ["Platform", extra.platform],
      ["Workspace", extra.workspace],
      ["Configuration", extra.config],
      ["Launcher", extra.launcher],
      ["Launch flags", quickstart.flags || []],
    ]));
  }
  summaryGrid.replaceChildren(metricGrid, findings, environment);
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

async function loadCurrentKometaVersions(data) {
  try {
    const response = await fetch("/api/kometa-versions");
    if (!response.ok) throw new Error();
    const versions = await response.json();
    const loggedBranch = data.metadata?.kometa_branch;
    const comparisonBranch = ["develop", "nightly"].includes(loggedBranch) ? "develop" : "master";
    Object.assign(data.overview, {
      current_comparison_branch: comparisonBranch,
      current_branch_version: versions[comparisonBranch] || "Unavailable",
      current_master_version: versions.master || "Unavailable",
      current_develop_version: versions.develop || "Unavailable",
      current_versions_checked: versions.checked_at ? new Date(versions.checked_at).toLocaleString() : "Unavailable",
    });
  } catch (_error) {
    Object.assign(data.overview, {
      current_comparison_branch: "Unavailable",
      current_branch_version: "Unavailable",
      current_master_version: "Unavailable",
      current_develop_version: "Unavailable",
      current_versions_checked: "Unavailable",
    });
  }
  if (document.querySelector(".nav-button.active")?.dataset.group === "overview") {
    showOverview(defaultGroups[0], data.overview);
  }
}
async function loadSchemaValidation(data) {
  if (!data.id || data.schema_validation_loaded) return;
  const updated = { ...data, metadata: { ...data.metadata, counts: { ...data.metadata.counts } } };
  updated.schema_validation_loaded = true;
  updated.recommendations = data.recommendations.filter((item) => !`${item.id}`.startsWith("live_schema_"));
  try {
    const response = await fetch(`/api/scans/${encodeURIComponent(data.id)}/validate-config`, { method: "POST" });
    const validation = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(validation.error || "Schema validation could not run.");
    currentSchemaBranch = validation.branch === "master" ? "master" : "develop";
    schemaValidationFailures = validation.failures || [];
    if (validation.schema_directive_missing) {
      const schemaUrl = `https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/${currentSchemaBranch}/json-schema/config-schema.json`;
      updated.recommendations.push({
        id: "live_schema_directive_advice",
        severity: "advice",
        title: "Enable config.yml validation in VS Code",
        message: `Enable config.yml validation in VS Code\nYour config.yml does not include a YAML language-server schema directive, so supported editors cannot provide Kometa-aware validation and available-value suggestions while you edit.\n\nProposed solution: Add this as the first line of your original config.yml:\n\n\`# yaml-language-server: $schema=${schemaUrl}\`\n\nThe downloaded config from Logscan includes this line automatically.`,
        evidence_lines: [],
      });
    }
    if (schemaValidationFailures.length) {
      validation.failures.forEach((failure, index) => updated.recommendations.push({
        id: `live_schema_${index}`,
        severity: "schema",
        title: failure.title || `Invalid configuration: ${failure.path || "config root"}`,
        message: `${failure.title || "Schema validation issue"}\nImpact: ${failure.urgency || "Action required"}. Kometa may reject this setting or skip the affected functionality.\n\nLocation: ${failure.location || failure.path || "config root"}\n\nIssue: ${failure.explanation || failure.message}${failure.accepted ? `\n\n${failure.accepted}` : ""}\n\nHow to fix: ${failure.action || "Correct this setting using the Kometa documentation."}\n\nSchema path: ${failure.path || "config root"}\nSource log line: ${failure.line}\nValidated against: Kometa ${validation.branch} schema`,
        evidence_lines: [],
        config_line: failure.config_line,
        config_column: failure.config_column,
        config_end_column: failure.config_end_column,
      }));
    }
  } catch (error) {
    updated.recommendations.push({
      id: "live_schema_unavailable",
      severity: "schema",
      title: "JSON Schema validation unavailable",
      message: error.message,
      evidence_lines: [],
    });
  }
  updated.metadata.counts.schema = schemaIssueRecommendations(updated.recommendations).length;
  updated.metadata.counts.advice = updated.recommendations.filter((item) => item.severity === "advice").length;
  updated.overview = { ...updated.overview, finding_count: updated.recommendations.length };
  renderResults(updated, false);
}
function applySupportDestination(data, groups, recommendations) {
  const fragment = new URLSearchParams(location.hash.slice(1));
  const sectionKey = fragment.get("section");
  const viewer = fragment.get("viewer");
  const group = groups.find((item) => item.key === sectionKey);
  if (group && document.querySelector(`#section-select option[value="${group.key}"]`)) {
    group.key === "overview" ? showOverview(group, data.overview || {}) : showGroup(group, recommendations);
  }
  if (viewer === "config" && !logViewer.open) {
    showConfigInViewer().catch((error) => alert(error.message));
  } else if (viewer === "log" && !logViewer.open) {
    openLogViewer(1).catch((error) => alert(error.message));
  }
}

function renderResults(data, runSchemaValidation = true) {
  if (data.id && data.id !== currentScanId) currentLogLines = null;
  if (data.id) {
    currentScanId = data.id;
    currentFile = null;
  }
  deleteToken = new URLSearchParams(location.hash.slice(1)).get("delete");
  updateRetentionCountdown(data);
  const { metadata, recommendations, overview = {}, categories = defaultGroups } = data;
  const schemaIssueCount = Number(metadata.counts.schema) || 0;
  const schemaUnavailable = recommendations.some((item) => item.id === "live_schema_unavailable");
  const quickstartBranch = metadata.quickstart_branch && metadata.quickstart_branch !== "unknown"
    ? ` - ${metadata.quickstart_branch[0].toUpperCase()}${metadata.quickstart_branch.slice(1)}`
    : "";
  overview.run_launcher = metadata.quickstart_run
    ? `Quickstart ${metadata.quickstart_version || "version unknown"}${quickstartBranch}`
    : "Direct Kometa run";
  overview.yaml_issue_count = schemaIssueCount;
  overview.yaml_validation = schemaUnavailable
    ? "Live schema validation unavailable"
    : schemaIssueCount
      ? `${schemaIssueCount.toLocaleString()} schema issue${schemaIssueCount === 1 ? "" : "s"} detected`
      : data.schema_validation_loaded
        ? "No schema issues detected"
        : "Live schema validation pending";
  currentRecommendations = recommendations;
  currentSchemaBranch = metadata.kometa_branch === "master" ? "master" : "develop";
  currentOverview = overview;
  if (data.expires_at) {
    overview.auto_delete = formatOverviewTimestamp(data.expires_at);
  }
  const groups = [...categories].sort((left, right) => left.priority - right.priority);
  document.querySelector("#results-title").textContent = data.filename;
  renderSummary(metadata, overview);

  sectionNav.replaceChildren();
  const sectionSelect = document.createElement("select");
  sectionSelect.id = "section-select";
  sectionSelect.className = "section-select";
  sectionSelect.setAttribute("aria-label", "View a log section");
  groups.forEach((group) => {
    const recommendationCount = group.key === "schema"
      ? schemaIssueRecommendations(recommendations).length
      : recommendations.filter((item) => item.severity === group.key).length;
    if (group.key !== "overview" && recommendationCount === 0) return;
    const option = document.createElement("option");
    option.value = group.key;
    option.dataset.severity = group.key;
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
  applySupportDestination(data, groups, recommendations);
  results.scrollIntoView({ behavior: "smooth", block: "start" });
  if (runSchemaValidation) loadSchemaValidation(data);
  loadCurrentKometaVersions(data);
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

let scanStatusTimer = null;
const scanPhaseLabels = {
  uploading: "Uploading",
  queued: "Waiting for scanner",
  scanning: "Extracting and scanning",
  saving: "Saving results",
  complete: "Scan complete",
  failed: "Scan failed",
};
function elapsedLabel(seconds) {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}
function stopScanStatus() {
  if (scanStatusTimer) clearInterval(scanStatusTimer);
  scanStatusTimer = null;
}
function renderCompletedJob(result) {
  const scans = result.scans || [result];
  scans.forEach((scan) => Object.assign(scan, {
    batch_result_url: result.batch_result_url,
    batch_admin_url: result.batch_admin_url,
    unscanned_files: result.unscanned_files || [],
  }));
  batchScans = scans;
  status.textContent = `${scans.length} scan${scans.length === 1 ? "" : "s"} complete`;
  dropZone.classList.remove("loading");
  scanButton.disabled = false;
  if (scans.length > 1) {
    renderBatchResults(scans);
    return;
  }
  currentScanId = scans[0].id;
  deleteToken = scans[0].delete_token;
  history.replaceState({}, "", `/scan/${encodeURIComponent(scans[0].id)}#delete=${encodeURIComponent(deleteToken)}`);
  renderResults(scans[0]);
}

async function refreshScanStatus(jobId, recover = false) {
  const response = await fetch(`/api/scan-jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
  if (!response.ok) return;
  const job = await response.json();
  const aheadLabel = job.ahead_count === 0
    ? "no scans ahead"
    : `${job.ahead_count} scan${job.ahead_count === 1 ? "" : "s"} ahead`;
  const phaseLabel = job.phase === "queued" && job.queue_position
    ? `Waiting for scanner · Queue position ${job.queue_position} (${aheadLabel})`
    : scanPhaseLabels[job.phase] || "Scanning";
  status.textContent = `${phaseLabel} · ${elapsedLabel(job.elapsed_seconds || 0)}`;
  if (job.phase === "failed") {
    status.textContent = job.error || "The scan could not be completed.";
    status.classList.add("error");
    sessionStorage.removeItem("activeScanJob");
    stopScanStatus();
    dropZone.classList.remove("loading");
    scanButton.disabled = false;
  } else if (job.phase === "complete") {
    sessionStorage.removeItem("activeScanJob");
    stopScanStatus();
    if (job.redirect_url) {
      location.assign(job.redirect_url);
    } else if (job.result) {
      renderCompletedJob(job.result);
    }
  }
}
function watchScanStatus(jobId, recover = false) {
  stopScanStatus();
  refreshScanStatus(jobId, recover).catch(() => {});
  scanStatusTimer = setInterval(() => refreshScanStatus(jobId, recover).catch(() => {}), 2000);
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = [...input.files];
  if (!files.length) return;
  dropZone.classList.add("loading");
  scanButton.disabled = true;
  status.textContent = `Scanning 0 of ${files.length} logs…`;
  status.classList.remove("error");
  const jobId = crypto.randomUUID();
  sessionStorage.setItem("activeScanJob", jobId);
  watchScanStatus(jobId);
  try {
    const failures = [];
    status.textContent = `Scanning ${files.length} log${files.length === 1 ? "" : "s"}…`;
    const body = new FormData();
    files.forEach((file) => body.append("log", file));
    const response = await fetch("/api/scan", { method: "POST", body, headers: { "X-Scan-Job-ID": jobId } });
    const data = await response.json().catch(() => ({}));
    if (response.status === 202) {
      watchScanStatus(jobId, true);
      return;
    }
    sessionStorage.removeItem("activeScanJob");
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
    // A lost connection does not mean the server stopped scanning. Keep the
    // job ID so this tab (or a refreshed one) can recover the result.
    if (error instanceof TypeError) {
      status.textContent = "Connection interrupted. Checking scan status…";
      status.classList.remove("error");
      watchScanStatus(jobId, true);
      return;
    }
    sessionStorage.removeItem("activeScanJob");
  } finally {
    if (!sessionStorage.getItem("activeScanJob")) {
      stopScanStatus();
      dropZone.classList.remove("loading");
      scanButton.disabled = false;
    }
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
function configForDownload() {
  if (/^\s*#\s*yaml-language-server:\s*\$schema=/im.test(extractedConfig)) return extractedConfig;
  const schemaUrl = `https://raw.githubusercontent.com/Kometa-Team/Kometa/refs/heads/${currentSchemaBranch}/json-schema/config-schema.json`;
  return `# yaml-language-server: $schema=${schemaUrl}\n${extractedConfig}`;
}

function downloadConfig() {
  if (!extractedConfig) return false;
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([configForDownload()], { type: "text/yaml;charset=utf-8" }));
  link.download = downloadFilename("config");
  link.click();
  URL.revokeObjectURL(link.href);
  return true;
}
function filenamePart(value) {
  return String(value || "").trim().replace(/[<>:"/\\|?*\x00-\x1f]/g, "");
}

function downloadFilename(kind = "log") {
  const originalName = currentFile?.name || document.querySelector("#results-title").textContent;
  const name = filenamePart(originalName.replace(/\.[^.]+$/, ""));
  const uploader = filenamePart(currentOverview.uploaded_by);
  const now = new Date();
  const part = (value) => String(value).padStart(2, "0");
  const timestamp = `${now.getFullYear()}${part(now.getMonth() + 1)}${part(now.getDate())}-${part(now.getHours())}${part(now.getMinutes())}${part(now.getSeconds())}`;
  const extension = kind === "config" ? ".yml" : ".log";
  return [name || "log", ...(uploader ? [uploader] : []), timestamp].join("-") + extension;
}

async function downloadLog() {
  const link = document.createElement("a");
  if (currentScanId) {
    link.href = "/api/scans/" + encodeURIComponent(currentScanId) + "/log";
  } else {
    const lines = await loadLogLines();
    link.href = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/plain;charset=utf-8" }));
  }
  link.download = downloadFilename();
  link.click();
  if (!currentScanId) URL.revokeObjectURL(link.href);
}
const downloadDialog = document.querySelector("#download-dialog");
document.querySelector("#open-download").addEventListener("click", () => downloadDialog.showModal());
document.querySelector("#open-download-main").addEventListener("click", () => downloadDialog.showModal());
document.querySelector("#download-log-option").addEventListener("click", async () => {
  try { await downloadLog(); document.querySelector("#download-dialog").close(); } catch (error) { alert(error.message); }
});
document.querySelector("#download-config-option").addEventListener("click", async () => {
  try {
    if (!extractedConfig && !currentScanId) extractedConfig = extractConfig(await loadLogLines());
    if (!downloadConfig()) alert("No redacted config block was found in this log.");
    else document.querySelector("#download-dialog").close();
  } catch (error) { alert(error.message); }
});
document.querySelector("#download-both-option").addEventListener("click", async () => {
  try {
    if (!extractedConfig && !currentScanId) extractedConfig = extractConfig(await loadLogLines());
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
  if (currentLogLines && viewerMode === "log") {
    viewerNavigationLines = null;
    renderLogWindow(highlightedRange.start);
  }
});
previousHighlight.addEventListener("click", goToPreviousHighlightedLine);
nextHighlight.addEventListener("click", goToNextHighlightedLine);
sectionJump.addEventListener("change", () => {
  if (!sectionJump.value) return;
  const targetLine = Number(sectionJump.value);
  viewerNavigationLines = null;
  if (viewerMode === "config") showConfigInViewer(targetLine).catch((error) => alert(error.message));
  else renderLogWindow(targetLine, targetLine);
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

const activeScanJob = sessionStorage.getItem("activeScanJob");
if (activeScanJob) {
  dropZone.classList.add("loading");
  scanButton.disabled = true;
  watchScanStatus(activeScanJob, true);
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
