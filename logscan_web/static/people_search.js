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
    if (person.can_add) {
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
    } else {
      const message = document.createElement("p");
      message.textContent = person.people_image_status === "complete" ? "All seven styles are available." : "Style verification is unavailable. Please try again later.";
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
        status.textContent = "Seven Kometa People Poster styles";
      } else {
        status.textContent = data.choices.length ? "Select the correct TMDb person." : "No people found on TMDb.";
        data.choices.forEach((person) => {
          const button = document.createElement("button");
          button.type = "button";
          button.className = "secondary-button";
          button.textContent = `${person.name} · TMDb ${person.tmdb_id} · ${person.known_for_department || "Department unknown"}${person.known_for?.length ? ` · ${person.known_for.filter(Boolean).join(", ")}` : ""}`;
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
