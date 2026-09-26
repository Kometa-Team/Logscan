const dialog = document.querySelector("#support-navigation-dialog");
const closeButton = document.querySelector("#support-navigation-close");
const links = document.querySelector("#support-navigation-links");
const deleteForm = document.querySelector("#support-delete-form");

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
    if (deleteForm) deleteForm.action = `/support/logs/${encodeURIComponent(button.dataset.scanId)}/delete`;
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