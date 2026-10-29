/* TMDb identity selection and manual requests share the existing People dataset. */
/* global addPerson */
(() => {
  const form = document.querySelector("#poster-search");
  const input = document.querySelector("#poster-search-input");
  const status = document.querySelector("#poster-search-status");
  const choices = document.querySelector("#poster-search-choices");
  const result = document.querySelector("#poster-search-result");
  let searchVersion = 0;

  async function readResponse(response) {
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Unable to complete the request. Please try again.");
    return data;
  }

  function showPerson(person) {
    result.replaceChildren();
    const card = addPerson(person, result, true);
    if (person.can_add || (person.already_added && person.people_image_status !== "complete")) {
      const add = document.createElement("button");
      add.type = "button";
      add.className = "secondary-button";
      add.textContent = person.already_added ? "Already requested" : "Request poster";
      add.disabled = person.already_added;
      add.addEventListener("click", async () => {
        add.disabled = true;
        try {
          const data = await readResponse(await fetch("/api/people/request", {
            method: "POST",
            headers: { "Content-Type": "application/json", "X-CSRF-Token": form.dataset.csrf },
            body: JSON.stringify({ tmdb_id: person.tmdb_id }),
          }));
          add.textContent = "Already requested";
          status.textContent = data.message;
        } catch (error) {
          status.textContent = error.message;
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

  async function search(query) {
    const version = ++searchVersion;
    choices.replaceChildren();
    result.replaceChildren();
    status.textContent = "Searching TMDb and verifying poster styles…";
    try {
      const data = await readResponse(await fetch(`/api/people/search?${new URLSearchParams({ q: query })}`));
      if (version !== searchVersion) return;
      if (data.people?.length) {
        showPerson(data.people[0]);
        status.textContent = "";
      } else {
        status.textContent = data.choices.length ? "Select the correct TMDb person." : "No people found on TMDb.";
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
          button.addEventListener("click", () => search(String(person.tmdb_id)));
          choices.append(button);
        });
      }
    } catch (error) {
      if (version === searchVersion) status.textContent = error.message;
    }
  }

  form.addEventListener("submit", (event) => {
    event.preventDefault();
    search(input.value.trim());
  });
})();
