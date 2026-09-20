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
let page = Number(query.get("page")) || 1;

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

function sourceBadges(sources, requesters = [], metadataTags = [], provenanceTags = [], tmdbImagesUrl = null) {
  const badges = document.createElement("div");
  badges.className = "source-badges";
  sources.forEach((source) => {
    const badge = document.createElement("span");
    badge.className = `source-badge ${source}`;
    badge.textContent = source === "missing" ? "Missing Kometa" : source[0].toUpperCase() + source.slice(1);
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

function addPerson(person) {
  const card = document.createElement("article");
  card.className = "person-card";
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
    const reason = await FlagDialog.show(person.name);
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
  controls.hidden = !actionsEnabled;

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
  identity.append(heading, sourceBadges(person.sources, person.requested_by, person.metadata_tags, person.provenance_tags, person.tmdb_images_url));
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
      message.append("Use the Google Image Search tile below to find an acceptable person poster, then upload it to ");
      const link = document.createElement("a");
      link.href = person.tmdb_images_url;
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = "TMDb profile images";
      message.append(link, ".");
    } else {
      message.textContent = "This person could not be resolved on TMDb. Resolve the TMDb person before processing their poster.";
    }
    guidance.append(label, message);
  } else guidance.hidden = true;

  const images = document.createElement("div");
  images.className = "image-row";
  addImage(images, person.tmdb_image, "Current TMDb Image", "No current TMDb image", person.name);
  if (person.kometa_image) {
    addImage(images, { preview_url: person.kometa_image, download_url: person.kometa_image }, "Kometa Repo Image", "", person.name);
  }
  images.append(googleImageSearchTile(person.name));
  (person.kometa_variant_images || []).forEach((variant) => addImage(images, { preview_url: variant.url, download_url: variant.url }, variant.label, "", person.name));

  const flagReason = document.createElement("aside");
  flagReason.className = "flag-reason";
  if (person.flag_reason) {
    const label = document.createElement("strong"); label.textContent = "Flag Reason";
    flagReason.append(label, document.createTextNode(person.flag_reason));
  } else flagReason.hidden = true;
  card.append(controls, identity, detail, knownFor, guidance, flagReason, images);
  gallery.append(card);
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
fetch(`/api/people?${apiParams}`).then(async (response) => {
  const data = await response.json();
  if (!response.ok) throw new Error(data.error || "Unable to load people.");
  return data;
}).then(({ people, page: currentPage, total: totalResults, total_pages: totalPages, actions_enabled: canManagePeople, available_tags: availableTags }) => {
  actionsEnabled = canManagePeople;
  renderDynamicTagFilters(availableTags);
  if (tagQuery) tagCount.textContent = `${totalResults} ${totalResults === 1 ? "result" : "results"}`;
  gallery.replaceChildren();
  if (!people.length) gallery.textContent = "No people match these filters.";
  else people.forEach(addPerson);
  pagination.replaceChildren(pageLink(currentPage - 1, "Previous", currentPage === 1), pageJumper(currentPage, totalPages), pageLink(currentPage + 1, "Next", currentPage === totalPages));
}).catch((error) => { gallery.textContent = error.message; });
