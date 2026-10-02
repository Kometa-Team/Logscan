const dialog = document.querySelector("#support-navigation-dialog");
const closeButton = document.querySelector("#support-navigation-close");
const links = document.querySelector("#support-navigation-links");
const deleteForm = document.querySelector("#support-delete-form");
const filterPanel = document.querySelector(".support-filter-panel");

if (filterPanel && window.matchMedia("(max-width: 560px)").matches && !filterPanel.hasAttribute("data-active-filters")) {
  filterPanel.open = false;
}

const fields = {
  title: document.querySelector("#support-navigation-title"),
  uploader: document.querySelector("#support-navigation-uploader"),
  source: document.querySelector("#support-navigation-source"),
  expires: document.querySelector("#support-navigation-expires"),
  findings: document.querySelector("#support-navigation-findings"),
  environment: document.querySelector("#support-navigation-environment"),
};

document.querySelectorAll(".support-navigate").forEach((button) => {
  button.addEventListener("click", () => {
    if (!dialog || !links) return;

    Object.entries(fields).forEach(([name, field]) => {
      if (field) field.textContent = button.dataset[name] || "Unknown";
    });

    const options = button.nextElementSibling;
    links.replaceChildren(...Array.from(options?.children || [], (link) => link.cloneNode(true)));
    if (deleteForm) {
      const view = encodeURIComponent(deleteForm.dataset.view || "mine");
      deleteForm.action = `/support/logs/${encodeURIComponent(button.dataset.scanId)}/delete?view=${view}`;
    }
    dialog.showModal();
  });
});

closeButton?.addEventListener("click", () => dialog?.close());
dialog?.addEventListener("click", (event) => {
  if (event.target === dialog) dialog.close();
});
deleteForm?.addEventListener("submit", (event) => {
  if (!window.confirm(`Permanently delete ${fields.title?.textContent || "this log"}?`)) event.preventDefault();
});
const uploadDialog = document.querySelector("#support-upload-dialog");
const uploadForm = document.querySelector("#support-upload-form");
const uploadInput = document.querySelector("#support-log-file");
const uploadDrop = document.querySelector("#support-upload-drop");
const uploadSelection = document.querySelector("#support-upload-selection");
const uploadStatus = document.querySelector("#support-upload-status");
const uploadSubmit = document.querySelector("#support-upload-submit");
const uploadClose = document.querySelector("#support-upload-close");
const uploadCancel = document.querySelector("#support-upload-cancel");
let uploadStatusTimer = null;

const uploadPhaseLabels = {
  uploading: "Uploading",
  queued: "Waiting for scanner",
  validating: "Validating",
  scanning: "Extracting and scanning",
  saving: "Saving results",
  complete: "Scan complete",
  failed: "Scan failed",
};

function uploadElapsedLabel(seconds) {
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${String(seconds % 60).padStart(2, "0")}`;
}

function selectedUploadFiles(files = [...(uploadInput?.files || [])]) {
  if (!uploadSelection || !uploadSubmit) return;
  if (!files.length) {
    uploadSelection.textContent = "LOG, TXT, YAML, or supported archives · 1 GB max after extraction";
    uploadSubmit.disabled = true;
    return;
  }
  uploadSelection.textContent = files.length === 1
    ? files[0].name
    : `${files.length} files selected · ${files.map((file) => file.name).join(", ")}`;
  uploadSubmit.disabled = false;
  if (uploadStatus) {
    uploadStatus.textContent = `Ready to scan ${files.length} file${files.length === 1 ? "" : "s"}`;
    uploadStatus.classList.remove("error");
  }
}

function setUploadBusy(busy) {
  if (!uploadDialog || !uploadDrop || !uploadSubmit) return;
  uploadDialog.dataset.busy = busy ? "true" : "false";
  uploadDrop.classList.toggle("loading", busy);
  uploadSubmit.disabled = busy || !(uploadInput?.files.length);
  if (uploadClose) uploadClose.disabled = busy;
  if (uploadCancel) uploadCancel.disabled = busy;
}

function stopUploadStatus() {
  if (uploadStatusTimer) clearInterval(uploadStatusTimer);
  uploadStatusTimer = null;
}

function completedUploadDestination(result) {
  if (result.batch_admin_url || result.batch_result_url) {
    return result.batch_admin_url || result.batch_result_url;
  }
  const scan = (result.scans || [result])[0];
  if (!scan?.id) return null;
  const url = scan.result_url || `/scan/${encodeURIComponent(scan.id)}`;
  return scan.delete_token ? `${url}#delete=${encodeURIComponent(scan.delete_token)}` : url;
}

async function refreshSupportUpload(jobId) {
  const response = await fetch(`/api/scan-jobs/${encodeURIComponent(jobId)}`, { cache: "no-store" });
  if (!response.ok) return;
  const job = await response.json();
  const ahead = job.ahead_count === 0
    ? "no scans ahead"
    : `${job.ahead_count} scan${job.ahead_count === 1 ? "" : "s"} ahead`;
  const phase = job.phase === "queued" && job.queue_position
    ? `Waiting for scanner · Queue position ${job.queue_position} (${ahead})`
    : uploadPhaseLabels[job.phase] || "Scanning";
  uploadStatus.textContent = `${phase} · ${uploadElapsedLabel(job.elapsed_seconds || 0)}`;
  if (job.phase === "failed") {
    sessionStorage.removeItem("supportActiveScanJob");
    stopUploadStatus();
    setUploadBusy(false);
    uploadStatus.textContent = job.error || "The scan could not be completed.";
    uploadStatus.classList.add("error");
  } else if (job.phase === "complete") {
    sessionStorage.removeItem("supportActiveScanJob");
    stopUploadStatus();
    const destination = job.redirect_url || completedUploadDestination(job.result || {});
    if (destination) location.assign(destination);
    else location.reload();
  }
}

function watchSupportUpload(jobId) {
  stopUploadStatus();
  setUploadBusy(true);
  refreshSupportUpload(jobId).catch(() => {});
  uploadStatusTimer = setInterval(() => refreshSupportUpload(jobId).catch(() => {}), 2000);
}

function openSupportUpload() {
  if (!uploadDialog) return;
  if (!uploadDialog.open) uploadDialog.showModal();
  uploadDrop?.focus();
}

function closeSupportUpload() {
  if (uploadDialog?.dataset.busy !== "true") uploadDialog?.close();
}

document.querySelectorAll(".support-upload-open").forEach((button) => {
  button.addEventListener("click", openSupportUpload);
});
uploadClose?.addEventListener("click", closeSupportUpload);
uploadCancel?.addEventListener("click", closeSupportUpload);
uploadDialog?.addEventListener("cancel", (event) => {
  if (uploadDialog.dataset.busy === "true") event.preventDefault();
});
uploadDialog?.addEventListener("click", (event) => {
  if (event.target === uploadDialog) closeSupportUpload();
});
uploadInput?.addEventListener("change", () => selectedUploadFiles());
uploadDrop?.addEventListener("keydown", (event) => {
  if (event.key === "Enter" || event.key === " ") {
    event.preventDefault();
    uploadInput.click();
  }
});
["dragenter", "dragover"].forEach((eventName) => uploadDrop?.addEventListener(eventName, (event) => {
  event.preventDefault();
  uploadDrop.classList.add("dragover");
}));
["dragleave", "drop"].forEach((eventName) => uploadDrop?.addEventListener(eventName, (event) => {
  event.preventDefault();
  uploadDrop.classList.remove("dragover");
}));
uploadDrop?.addEventListener("drop", (event) => {
  if (!event.dataTransfer?.files.length) return;
  uploadInput.files = event.dataTransfer.files;
  selectedUploadFiles([...event.dataTransfer.files]);
});

uploadForm?.addEventListener("submit", async (event) => {
  event.preventDefault();
  const files = [...uploadInput.files];
  if (!files.length) return;
  const jobId = crypto.randomUUID();
  sessionStorage.setItem("supportActiveScanJob", jobId);
  uploadStatus.classList.remove("error");
  uploadStatus.textContent = `Uploading ${files.length} file${files.length === 1 ? "" : "s"}`;
  watchSupportUpload(jobId);
  try {
    const body = new FormData();
    files.forEach((file) => body.append("log", file));
    const response = await fetch("/api/scan", {
      method: "POST",
      body,
      headers: { "X-Scan-Job-ID": jobId },
    });
    const data = await response.json().catch(() => ({}));
    if (response.status === 202) return;
    sessionStorage.removeItem("supportActiveScanJob");
    stopUploadStatus();
    if (!response.ok) throw new Error(data.error || "The scan could not be completed.");
    const destination = completedUploadDestination(data);
    if (destination) location.assign(destination);
    else location.reload();
  } catch (error) {
    if (error instanceof TypeError) {
      uploadStatus.textContent = "Connection interrupted. Checking scan status…";
      watchSupportUpload(jobId);
      return;
    }
    sessionStorage.removeItem("supportActiveScanJob");
    stopUploadStatus();
    setUploadBusy(false);
    uploadStatus.textContent = error.message;
    uploadStatus.classList.add("error");
  }
});

const recoveredUploadJob = sessionStorage.getItem("supportActiveScanJob");
if (recoveredUploadJob && uploadDialog) {
  openSupportUpload();
  uploadStatus.textContent = "Recovering scan status…";
  watchSupportUpload(recoveredUploadJob);
}
