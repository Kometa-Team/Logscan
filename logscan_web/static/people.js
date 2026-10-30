const gallery = document.querySelector("#people-gallery");
const pagination = document.querySelector("#people-pagination");
const exportLink = document.querySelector("#people-export");
const tagSearch = document.querySelector("#tag-search");
const tagInput = document.querySelector("#tag-search-input");
const tagClear = document.querySelector("#tag-search-clear");
const tagCount = document.querySelector("#tag-search-count");
const dynamicTagFilters = document.querySelector("#dynamic-tag-filters");
const { googleImageSearchTile, imageCard, noImage } = window.PeopleImages;
const query = new URLSearchParams(location.search);
let tagQuery = query.get("tag") || "";
const selectedTags = new Set(query.getAll("tags"));
let actionsEnabled = false;
const page = Number(query.get("page")) || 1;

function filteredParams(nextPage) {
  const params = new URLSearchParams();
  if (tagQuery) params.set("tag", tagQuery);
  [...selectedTags].sort().forEach((tag) => params.append("tags", tag));
  if (nextPage > 1) params.set("page", nextPage);
  return params;
}

function updateControls() {
  tagInput.value = tagQuery;
  tagClear.hidden = !tagQuery;
  tagCount.hidden = !tagQuery;
  tagCount.textContent = tagQuery ? "Searching..." : "";
  exportLink.href = `/api/people/export?${filteredParams(1)}`;
}

function navigate(nextPage = 1) {
  location.href = `/people?${filteredParams(nextPage)}`;
}

function applyTagSearch() {
  const nextQuery = tagInput.value.trim();
  if (nextQuery === tagQuery) return;
  tagQuery = nextQuery;
  navigate();
}
tagSearch.addEventListener("submit", (event) => { event.preventDefault(); applyTagSearch(); });
tagInput.addEventListener("input", () => { tagClear.hidden = !tagInput.value; });
tagClear.addEventListener("click", () => { tagInput.value = ""; applyTagSearch(); });

function renderDynamicTagFilters(availableTags) {
  dynamicTagFilters.replaceChildren();
  availableTags.forEach(({ category, tag, count }) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = `dynamic-tag-filter ${category}`;
    button.setAttribute("aria-pressed", selectedTags.has(tag));
    button.append(document.createTextNode(tag));
    const total = document.createElement("span");
    total.textContent = count;
    button.append(total);
    button.addEventListener("click", () => {
      if (selectedTags.has(tag)) selectedTags.delete(tag);
      else selectedTags.add(tag);
      navigate();
    });
    dynamicTagFilters.append(button);
  });
  dynamicTagFilters.hidden = !availableTags.length;
}

function addImage(images, image, label, missingMessage, name) {
  images.append(image ? imageCard({ ...image, label, alt: `${name} ${label}` }) : noImage(missingMessage));
}

function sourceBadges(sources = [], requesters = [], metadataTags = [], provenanceTags = [], tmdbImagesUrl = null, imageStatus = null) {
  const badges = document.createElement("div");
  badges.className = "source-badges";
  sources.forEach((source) => {
    const badge = document.createElement("span");
    badge.className = `source-badge ${source}`;
    badge.textContent = source === "missing" ? imageStatus === "pending_verification" ? "Kometa verification pending" : "Missing Kometa" : source[0].toUpperCase() + source.slice(1);
    if (source === "missing" && imageStatus === "pending_verification") {
      badge.title = "A Kometa repository check could not finish. Logscan retries automatically when services are available and their rate limits allow it.";
    }
    badges.append(badge);
  });
  metadataTags.forEach((tag) => {
    const badge = document.createElement(tmdbImagesUrl ? "a" : "span");
    badge.className = `source-badge metadata ${tag === "Missing TMDb" ? "blocked" : "ready"}`;
    badge.textContent = tag;
    if (tmdbImagesUrl) {
      badge.href = tmdbImagesUrl;
      badge.target = "_blank";
      badge.rel = "noopener";
      badge.title = "Open TMDb profile images";
    }
    badges.append(badge);
  });
  provenanceTags.forEach((tag) => {
    const badge = document.createElement("span");
    badge.className = "source-badge provenance";
    badge.textContent = tag;
    badges.append(badge);
  });
  requesters.forEach((requester) => {
    const badge = document.createElement("span");
    badge.className = "source-badge requester";
    badge.textContent = `Requested by ${requester.name}`;
    badges.append(badge);
  });
  return badges;
}

async function runAction(person, action, card) {
  const response = await fetch(`/api/people/${encodeURIComponent(person.person_key)}/${action}`, { method: "POST" });
  if (!response.ok) return alert(`That person could not be ${action === "check" ? "marked complete" : "excluded"}.`);
  card.remove();
  if (!gallery.children.length) gallery.textContent = "No people match these filters.";
}

function styleAvailability(person) {
  const availability = document.createElement("details");
  availability.className = "people-variant-section people-style-availability";
  const styleStatuses = Object.values(person.style_availability || {});
  if (styleStatuses.length) {
    const summary = document.createElement("summary");
    const missingCount = styleStatuses.filter((style) => style.status === "missing").length;
    summary.textContent = missingCount ? `Style availability: ${missingCount} missing` : person.people_image_status === "complete" ? "All styles available" : "Style verification pending";
    const statuses = document.createElement("ul");
    styleStatuses.forEach((style) => {
      const item = document.createElement("li");
      item.textContent = `${style.label}: ${style.status.replaceAll("_", " ")}${style.status === "unknown" && style.reason ? ` — ${style.reason}` : ""}`;
      statuses.append(item);
    });
    availability.append(summary, statuses);
  } else availability.hidden = true;
  return availability;
}

function addTmdbImage(images, person) {
  const imageLabel = person.tmdb_image_source === "log" ? "TMDb image from log" : person.tmdb_image_source === "saved" ? "Previously verified TMDb image" : "Current TMDb Image";
  const noImageMessage = person.tmdb_image_status === "unknown" || person.tmdb_image_status === "known_available" ? "TMDb preview unavailable" : "No current TMDb image";
  addImage(images, person.tmdb_image, imageLabel, noImageMessage, person.name);
}

function addPerson(person, targetGallery = gallery, searchResult = false) {
  const card = document.createElement("article");
  card.className = "person-card";
  if (person.sources?.includes("missing")) card.classList.add("missing-kometa-person");
  if (person.flag_reason) card.classList.add("flagged-person");

  const controls = document.createElement("div");
  controls.className = "person-controls";
  const check = document.createElement("button");
  check.className = "ok-person";
  check.type = "button";
  check.title = "Mark complete";
  check.setAttribute("aria-label", `Mark ${person.name} complete`);
  check.innerHTML = '<i class="fa-solid fa-check" aria-hidden="true"></i>';
  check.addEventListener("click", () => runAction(person, "check", card));

  const flag = document.createElement("button");
  flag.className = "flag-person";
  flag.type = "button";
  flag.title = "Flag for review";
  flag.setAttribute("aria-label", `Flag ${person.name} for review`);
  flag.innerHTML = '<i class="fa-solid fa-flag" aria-hidden="true"></i>';
  flag.disabled = !person.tmdb_id;
  flag.addEventListener("click", async () => {
    const reason = await window.FlagDialog.show(person.name);
    if (!reason) return;
    const response = await fetch(`/api/people/${encodeURIComponent(person.person_key)}/flag`, {
      method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ reason }),
    });
    if (!response.ok) return alert("That person could not be flagged.");
    navigate(1);
  });

  const exclude = document.createElement("button");
  exclude.className = "danger-button exclude-person";
  exclude.type = "button";
  exclude.title = "Exclude this person";
  exclude.setAttribute("aria-label", `Exclude ${person.name}`);
  exclude.innerHTML = '<i class="fa-solid fa-ban" aria-hidden="true"></i>';
  exclude.addEventListener("click", () => runAction(person, "exclude", card));
  controls.append(check, flag, exclude);
  controls.hidden = searchResult || !actionsEnabled;
  if (!controls.hidden) card.classList.add("has-person-controls");

  const heading = document.createElement("h2");
  if (person.tmdb_person_url) {
    const link = document.createElement("a");
    link.href = person.tmdb_person_url;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = person.name;
    heading.append(link);
  } else heading.textContent = person.name;

  const identity = document.createElement("div");
  identity.className = "person-identity";
  identity.append(heading, sourceBadges(person.sources, person.requested_by, person.metadata_tags, person.provenance_tags, person.tmdb_images_url, person.people_image_status));
  const detail = document.createElement("p");
  detail.textContent = person.tmdb_id ? `TMDb ID: ${person.tmdb_id}` : "TMDb ID unresolved";
  if (person.log_url) {
    detail.append(" · ");
    const logLink = document.createElement("a");
    logLink.href = person.log_url;
    logLink.textContent = "Source log";
    detail.append(logLink);
  }
  const knownFor = document.createElement("p");
  knownFor.append("Known For: ", person.known_for_department || "Not specified");
  if (person.known_for?.length) {
    knownFor.append(" (");
    person.known_for.forEach((credit, index) => {
      if (index) knownFor.append(", ");
      const link = document.createElement("a");
      link.href = credit.url; link.target = "_blank"; link.rel = "noopener"; link.textContent = credit.title;
      knownFor.append(link);
    });
    knownFor.append(")");
  }

  const guidance = document.createElement("aside");
  guidance.className = "person-guidance";
  if (person.metadata_tags?.includes("Missing TMDb")) {
    const label = document.createElement("strong");
    label.textContent = "TMDb image required";
    const message = document.createElement("span");
    if (person.tmdb_images_url) {
      message.append("Find a suitable portrait using ");
      const imageSearch = googleImageSearchTile(person.name);
      imageSearch.className = "";
      imageSearch.replaceChildren(document.createTextNode("Google Image Search"));
      message.append(imageSearch, ", then submit it to ");
      const link = document.createElement("a");
      link.href = person.tmdb_images_url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = "TMDb profile images";
      message.append(link, ". Once a suitable image is available on TMDb, search again to request the poster.");
    } else {
      message.textContent = "This person could not be resolved on TMDb. Resolve the TMDb person before processing their poster.";
    }
    guidance.append(label, message);
  } else guidance.hidden = true;

  const images = document.createElement("div");
  images.className = "image-row";
  addTmdbImage(images, person);
  const variantSection = document.createElement("details");
  variantSection.className = "people-variant-section";
  if (Object.keys(person.style_availability || {}).length) {
    const summary = document.createElement("summary");
    summary.textContent = "Show all seven Kometa poster styles";
    const imageSearch = googleImageSearchTile(person.name);
    imageSearch.className = "people-image-search";
    imageSearch.replaceChildren(document.createTextNode("Google Image Search"));
    variantSection.append(summary, window.PeopleImages.styleGallery(person), imageSearch);
  } else variantSection.hidden = true;

  const flagReason = document.createElement("aside");
  flagReason.className = "flag-reason";
  if (person.flag_reason) {
    const label = document.createElement("strong"); label.textContent = "Flag Reason";
    flagReason.append(label, document.createTextNode(person.flag_reason));
  } else flagReason.hidden = true;
  card.append(controls, identity, detail, knownFor, guidance, flagReason, images, styleAvailability(person), variantSection);
  targetGallery.append(card);
  return card;
}

function pageLink(number, label, disabled = false) {
  const link = document.createElement(disabled ? "span" : "a");
  link.textContent = label;
  if (!disabled) {
    link.href = `/people?${filteredParams(number)}`;
  }
  link.className = disabled ? "pagination-disabled" : "secondary-button";
  return link;
}

function pageJumper(currentPage, totalPages) {
  const status = document.createElement("span"); status.className = "page-jumper"; status.append("Page ");
  const select = document.createElement("select"); select.setAttribute("aria-label", "Page number");
  for (let number = 1; number <= totalPages; number += 1) {
    const option = document.createElement("option"); option.value = number; option.textContent = number; option.selected = number === currentPage; select.append(option);
  }
  select.addEventListener("change", () => navigate(Number(select.value)));
  status.append(select, ` of ${totalPages}`);
  return status;
}

updateControls();
const apiParams = filteredParams(page);
apiParams.set("per_page", matchMedia("(max-width: 760px)").matches ? "10" : "25");
apiParams.set("background", "1");
const loadingPanel = document.querySelector("#people-loading");
const loadingTitle = document.querySelector("#people-loading-title");
const loadingDetail = document.querySelector("#people-loading-detail");
const loadingElapsed = document.querySelector("#people-loading-elapsed");
const loadingRetry = document.querySelector("#people-loading-retry");
const githubWarning = document.querySelector("#people-github-warning");
const githubAdmin = document.querySelector("#people-github-admin");
let loadingTimer;
let loadingStarted;
let renderedPeople = "";
let stopped = false;

function renderPeoplePage({ people, page: currentPage, total: totalResults, total_pages: totalPages, actions_enabled: canManagePeople, available_tags: availableTags, loading }) {
  const signature = JSON.stringify([people, currentPage, totalResults, totalPages, canManagePeople, availableTags, !people.length && loading?.refreshing]);
  // Keep loaded portraits and expanded cards in place during progress polling.
  if (signature === renderedPeople) return;
  renderedPeople = signature;
  actionsEnabled = canManagePeople;
  renderDynamicTagFilters(availableTags);
  if (tagQuery) tagCount.textContent = `${totalResults} ${totalResults === 1 ? "result" : "results"}`;
  gallery.replaceChildren();
  if (!people.length) gallery.textContent = loading?.refreshing ? "The People list is still being prepared." : "No people match these filters.";
  else people.forEach((person) => addPerson(person));
  pagination.replaceChildren(pageLink(currentPage - 1, "Previous", currentPage === 1), pageJumper(currentPage, totalPages), pageLink(currentPage + 1, "Next", currentPage === totalPages));
}

function updatePeopleLoading(loading, hasPeople, pendingChecks = false) {
  const elapsed = Math.floor((Date.now() - loadingStarted) / 1000);
  loadingElapsed.textContent = `${elapsed}s`;
  const busy = Boolean(loading?.refreshing);
  loadingPanel.dataset.busy = String(busy);
  loadingRetry.hidden = busy;
  const authentication = loading?.github_authentication;
  const expiresAt = Number(authentication?.expires_at) * 1000;
  let warning = "";
  if (authentication?.state === "expired") {
    warning = "The GitHub token has expired. An administrator needs to renew it to restore poster verification.";
  } else if (authentication?.state === "rejected") {
    warning = "GitHub rejected the configured token. It may have expired, been revoked, or be invalid. An administrator needs to renew or replace it.";
  } else if (authentication?.state === "missing") {
    warning = "No GitHub token is configured. Poster verification uses GitHub's limited public allowance; an administrator can add a read-only token.";
  } else if (expiresAt > Date.now() && expiresAt - Date.now() <= 7 * 86400000) {
    warning = `The GitHub token expires on ${new Date(expiresAt).toLocaleString()}. An administrator should renew it before then.`;
  }
  githubWarning.hidden = !warning;
  githubWarning.textContent = warning;
  if (githubAdmin) githubAdmin.hidden = !warning;
  loadingTitle.textContent = loading?.message || "People loaded";
  if (busy && loading.total > 0 && Number.isFinite(loading.completed)) {
    loadingTitle.textContent += ` (${loading.completed} of ${loading.total})`;
  }
  const retryAt = Number(loading?.retry_at) * 1000;
  if (retryAt > Date.now()) {
    loadingDetail.textContent = `GitHub has temporarily paused poster verification. Checks can resume after ${new Date(retryAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}. ${hasPeople ? "Saved people remain available below." : "The list will appear as soon as people are available."}`;
  } else if (busy) {
    loadingDetail.textContent = `${hasPeople ? "Showing saved people while their details and posters are checked." : "Waiting for IMDb, TMDb, or Kometa poster checks."} Unavailable checks stay pending. ${elapsed >= 15 ? "Some services are responding slowly; you can keep searching while this runs." : "You can search for a person while this runs."}`;
  } else {
    loadingDetail.textContent = loading?.phase === "failed" ? "The refresh stopped. Saved people remain available; use Check again to retry." : pendingChecks ? "People loaded. Some poster checks are unavailable and remain pending; open a person's style details for the reason." : "People loaded. Expand a person to review all seven poster styles.";
  }
}

async function loadPeoplePage(retry = false) {
  clearTimeout(loadingTimer);
  stopped = false;
  if (retry) {
    loadingStarted = Date.now();
    loadingRetry.hidden = true;
  }
  const controller = new AbortController();
  const requestTimeout = setTimeout(() => controller.abort(), 15000);
  try {
    const params = new URLSearchParams(apiParams);
    if (retry) params.set("retry", "1");
    const response = await fetch(`/api/people?${params}`, { signal: controller.signal, cache: "no-store" });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to load people.");
    if (stopped) return;
    renderPeoplePage(data);
    updatePeopleLoading(data.loading, data.people.length > 0, data.people.some((person) => Object.values(person.style_availability || {}).some((style) => style.status === "unknown")));
    if (data.loading?.refreshing) {
      if (Date.now() - loadingStarted >= 180000) {
        loadingPanel.dataset.busy = "false";
        loadingRetry.hidden = false;
        loadingDetail.textContent = "Verification is taking longer than expected. Saved people remain available. Use Check again to see the latest progress.";
      } else loadingTimer = setTimeout(() => loadPeoplePage(), 1500);
    }
  } catch (error) {
    if (stopped) return;
    loadingPanel.dataset.busy = "false";
    loadingRetry.hidden = false;
    loadingTitle.textContent = error.name === "AbortError" ? "The People service is taking too long to respond" : "Unable to refresh people";
    loadingDetail.textContent = `${error.name === "AbortError" ? "The request timed out." : error.message} ${renderedPeople ? "The people already loaded are still available." : "Use Check again to retry."}`;
  } finally {
    clearTimeout(requestTimeout);
  }
}

loadingRetry.addEventListener("click", () => loadPeoplePage(true));
window.addEventListener("pagehide", () => { stopped = true; clearTimeout(loadingTimer); });
loadingStarted = Date.now();
loadPeoplePage();
