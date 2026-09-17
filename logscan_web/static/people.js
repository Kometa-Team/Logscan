const gallery = document.querySelector("#people-gallery");
const { googleImageSearchTile, imageCard, noImage } = window.PeopleImages;

function tmdbProfilesUrl(person) {
  return `https://www.themoviedb.org/person/${encodeURIComponent(person.tmdb_id)}/images/profiles`;
}

function uploadTile(person) {
  const link = document.createElement("a");
  link.className = "upload-image-tile";
  link.href = tmdbProfilesUrl(person);
  link.target = "_blank";
  link.rel = "noopener";
  link.innerHTML = '<strong>Upload Image to TMDb</strong><span>Press the <svg class="inline-plus-icon" viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="9"></circle><path d="M12 8v8M8 12h8"></path></svg> icon next to "Images" on TMDb</span>';
  return link;
}

async function complete(key, card) {
  if (!await ConfirmDialog.show({ title: "Mark person complete?", message: "This person will be removed from the missing-images backlog.", confirmText: "Mark complete" })) return;
  const response = await fetch(`/api/people/${encodeURIComponent(key)}`, { method: "DELETE" });
  if (!response.ok) return alert("That person could not be removed.");
  card.remove();
  if (!gallery.children.length) gallery.textContent = "No missing people are waiting for images.";
}

async function addPerson(person) {
  const card = document.createElement("article");
  card.className = "person-card";
  const heading = document.createElement("h2");
  const page = document.createElement("a");
  page.href = `/people/${encodeURIComponent(person.key)}`;
  page.textContent = person.name;
  heading.append(page);
  const detail = document.createElement("p");
  if (person.tmdb_id) {
    detail.append("TMDb ID: ");
    const tmdbLink = document.createElement("a");
    tmdbLink.href = `https://www.themoviedb.org/person/${encodeURIComponent(person.tmdb_id)}`;
    tmdbLink.target = "_blank";
    tmdbLink.rel = "noopener";
    tmdbLink.textContent = person.tmdb_id;
    detail.append(tmdbLink);
  } else detail.textContent = "TMDb match not found";
  const images = document.createElement("div");
  images.className = "image-row";
  const actions = document.createElement("div");
  actions.className = "person-actions";
  const completeButton = document.createElement("button");
  completeButton.className = "danger-button";
  completeButton.textContent = "Mark complete";
  completeButton.addEventListener("click", () => complete(person.key, card));
  actions.append(completeButton);
  card.append(heading, detail, images, actions);
  gallery.append(card);
  try {
    const response = await fetch(`/api/people/${encodeURIComponent(person.key)}/images?limit=5`);
    const data = await response.json();
    (data.images || []).forEach((image) => images.append(imageCard(image)));
    if (!data.images?.length) images.append(noImage());
    images.append(googleImageSearchTile(person.name));
    if (person.tmdb_id) images.append(uploadTile(person));
  } catch {
    images.append(noImage());
    images.append(googleImageSearchTile(person.name));
    if (person.tmdb_id) images.append(uploadTile(person));
  }
}

fetch("/api/people").then((response) => response.json()).then(async ({ people }) => {
  if (!people.length) { gallery.textContent = "No missing people are waiting for images."; return; }
  for (const person of people) await addPerson(person);
}).catch(() => { gallery.textContent = "Unable to load missing people."; });
