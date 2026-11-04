/* TMDb identity selection and manual requests share the existing People dataset. */
/* global addPerson */
(() => {
  const form = document.querySelector("#poster-search");
  const input = document.querySelector("#poster-search-input");
  const status = document.querySelector("#poster-search-status");
  const choices = document.querySelector("#poster-search-choices");
  const result = document.querySelector("#poster-search-result");
  const notice = document.querySelector("#poster-search-notice");
  const noticeMessage = document.querySelector("#poster-search-notice-message");
  const noticeView = document.querySelector("#poster-search-notice-view");
  let searchVersion = 0;

  function revealSearch() {
    status.focus({ preventScroll: true });
    status.scrollIntoView({ behavior: "instant", block: "start" });
  }

  function showStatus(message, action = "View search") {
    status.textContent = message;
    noticeMessage.textContent = message;
    noticeView.textContent = action;
    notice.hidden = false;
  }

  noticeView.addEventListener("click", () => { revealSearch(); notice.hidden = true; });
  document.querySelector("#poster-search-notice-dismiss").addEventListener("click", () => { notice.hidden = true; });

  async function readResponse(response) {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to complete the request. Please try again.");
    return data;
  }

  function showPerson(person, sourcePerson) {
    result.replaceChildren();
    const card = addPerson(person, result, true);
    if (person.can_add || (person.already_added && person.people_image_status !== "complete")) {
      const add = document.createElement("button");
      add.type = "button";
      add.className = "secondary-button";
      add.textContent = person.already_added ? sourcePerson && person.can_add ? "Use this person" : "Already requested" : "Request poster";
      add.disabled = person.already_added && !(sourcePerson && person.can_add);
      add.addEventListener("click", async () => {
        add.disabled = true;
        try {
          const data = await readResponse(await fetch("/api/people/request", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": form.dataset.csrf },
            body: JSON.stringify({ tmdb_id: person.tmdb_id, ...(sourcePerson ? { source_key: sourcePerson.person_key } : {}) }),
          }));
          add.textContent = "Already requested";
          showStatus(data.message, "View result");
          if (sourcePerson) window.location.reload();
        } catch (error) {
          showStatus(error.message, "View result");
          add.disabled = false;
        }
      });
      card.append(add);
    }
    if (!person.can_add && person.people_image_status !== "complete" && !person.metadata_tags?.includes("Missing TMDb")) {
      const message = document.createElement("p");
      message.textContent = person.request_unavailable_reason || "Style verification is unavailable. Please try again later.";
      card.append(message);
    }
  }

  async function search(query, sourcePerson = null) {
    const version = ++searchVersion;
    choices.replaceChildren();
    result.replaceChildren();
    form.setAttribute("aria-busy", "true");
    input.blur();
    showStatus(`Searching TMDb for ${sourcePerson?.name || query} and verifying poster styles…`);
    revealSearch();
    try {
      const data = await readResponse(await fetch(`/api/people/search?${new URLSearchParams({ q: query })}`));
      if (version !== searchVersion) return;
      if (data.people?.length) {
        showPerson(data.people[0], sourcePerson);
        showStatus(`Poster check complete for ${data.people[0].name}. Review the result below.`, "View result");
      } else {
        const count = data.choices.length;
        showStatus(count ? `Found ${count} TMDb ${count === 1 ? "match" : "matches"}${sourcePerson ? ` for ${sourcePerson.name}` : ""}. Select the correct person below.` : "No people found on TMDb. Try another name or a TMDb ID.", count ? "View matches" : "View search");
        data.choices.forEach((person) => {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "poster-search-choice";
          button.setAttribute("aria-label", `Select ${person.name}, TMDb ${person.tmdb_id}`);
          const preview = document.createElement("span");
          preview.className = "poster-search-portrait";
          const missing = document.createElement("span");
          missing.textContent = "No profile image";
          missing.hidden = Boolean(person.profile_image_url);
          if (person.profile_image_url) {
            const image = document.createElement("img");
            image.src = person.profile_image_url;
            image.alt = person.name;
            image.loading = "lazy";
            image.decoding = "async";
            image.width = 64;
            image.height = 96;
            image.addEventListener("error", () => { image.hidden = true; missing.hidden = false; });
            preview.append(image);
          }
          preview.append(missing);
          const identity = document.createElement("span");
          identity.className = "poster-search-identity";
          const name = document.createElement("strong");
          name.textContent = person.name;
          const id = document.createElement("span");
          id.textContent = `TMDb ID: ${person.tmdb_id}`;
          const knownFor = document.createElement("span");
          knownFor.textContent = `Known For: ${person.known_for_department || "Not specified"}${person.known_for?.length ? ` (${person.known_for.filter(Boolean).join(", ")})` : ""}`;
          identity.append(name, id, knownFor);
          button.append(preview, identity);
          button.addEventListener("click", () => search(String(person.tmdb_id), sourcePerson));
          choices.append(button);
        });
      }
    } catch (error) {
      if (version === searchVersion) showStatus(error.message);
    } finally {
      if (version === searchVersion) {
        form.setAttribute("aria-busy", "false");
        revealSearch();
      }
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    search(input.value.trim());
  });
  window.PeopleSearch = {
    searchFor(person) {
      input.value = person.original_name || person.name;
      return search(input.value.trim(), person);
    },
  };
})();
