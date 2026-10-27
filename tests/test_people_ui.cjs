const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { test } = require("node:test");
const vm = require("node:vm");

const source = readFileSync("logscan_web/static/people.js", "utf8");
const context = vm.createContext({ document: { createElement: (tag) => ({
  tag, children: [], textContent: "", hidden: false,
  append(...children) { this.children.push(...children); },
}) } });
vm.runInContext(source.slice(source.indexOf("function styleAvailability("), source.indexOf("function addPerson(")), context);
vm.runInContext(source.slice(source.indexOf("function sourceBadges("), source.indexOf("async function runAction(")), context);

test("shows all style states in one compact person detail", () => {
  const detail = context.styleAvailability({ people_image_status: "incomplete", style_availability: {
    primary: { label: "Primary", status: "present" },
    bw: { label: "BW", status: "missing" },
    signature: { label: "Signature", status: "missing" },
    transparent: { label: "Transparent", status: "unknown" },
    excluded: { label: "Excluded", status: "not_applicable" },
  } });
  assert.equal(detail.tag, "details");
  assert.equal(detail.children[0].textContent, "Style availability: 2 missing");
  assert.equal(detail.children[1].children.length, 5);
  assert.equal(detail.children[1].children[3].textContent, "Transparent: unknown");
  assert.equal(detail.children[1].children[4].textContent, "Excluded: not applicable");
});

test("distinguishes verified completeness from pending verification", () => {
  for (const [status, label] of [["complete", "All styles available"], ["pending_verification", "Style verification pending"]]) {
    const detail = context.styleAvailability({ people_image_status: status, style_availability: { primary: { label: "Primary", status: status === "complete" ? "present" : "unknown" } } });
    assert.equal(detail.children[0].textContent, label);
  }
  assert.equal(context.styleAvailability({}).hidden, true);
});

test("pending verification does not claim artwork is confirmed missing", () => {
  const badges = context.sourceBadges(["missing"], [], [], [], null, "pending_verification");
  assert.equal(badges.children[0].textContent, "Pending verification");
});

test("log image previews have a source label and lookup failures do not claim absence", () => {
  const images = [];
  const rendering = vm.createContext({ addImage: (...args) => images.push(args) });
  vm.runInContext(source.slice(source.indexOf("function addTmdbImage("), source.indexOf("function addPerson(")), rendering);
  const image = { preview_url: "https://image.tmdb.org/t/p/w342/profile.jpg" };
  rendering.addTmdbImage({}, { name: "Bruce Langley", tmdb_image: image, tmdb_image_source: "log", tmdb_image_status: "available" });
  assert.equal(images[0][1], image);
  assert.equal(images[0][2], "TMDb image from log");
  rendering.addTmdbImage({}, { tmdb_image_status: "unknown" });
  assert.equal(images[1][3], "TMDb preview unavailable");
  rendering.addTmdbImage({}, { tmdb_image_status: "missing" });
  assert.equal(images[2][3], "No current TMDb image");
});

function searchHarness(responses) {
  class Element {
    constructor(tag) {
      this.tag = tag; this.children = []; this.events = {}; this.dataset = {}; this.attributes = {};
      this.classList = { add: () => {} };
    }
    append(...children) { this.children.push(...children); }
    replaceChildren(...children) { this.children = children; }
    setAttribute(key, value) { this.attributes[key] = value; }
    addEventListener(key, callback) { this.events[key] = callback; }
  }
  const ids = Object.fromEntries(["poster-search", "poster-search-input", "poster-search-status", "poster-search-choices", "poster-search-result"].map((id) => [id, new Element("div")]));
  ids["poster-search"].dataset.csrf = "server-token";
  const calls = [];
  const sandbox = vm.createContext({
    document: { createElement: (tag) => new Element(tag), createTextNode: (text) => text, querySelector: (selector) => ids[selector.slice(1)] },
    window: {}, URLSearchParams,
    fetch: async (...args) => {
      calls.push(args);
      const next = responses.shift();
      return { ok: !next.error, json: async () => next };
    },
  });
  vm.runInContext(readFileSync("logscan_web/static/people_images.js", "utf8"), sandbox);
  vm.runInContext("const { imageCard, noImage, googleImageSearchTile } = window.PeopleImages; const gallery = document.createElement('div'); const actionsEnabled = false;", sandbox);
  vm.runInContext(source.slice(source.indexOf("function addImage("), source.indexOf("async function runAction(")), sandbox);
  vm.runInContext(source.slice(source.indexOf("function styleAvailability("), source.indexOf("function pageLink(")), sandbox);
  vm.runInContext(readFileSync("logscan_web/static/people_search.js", "utf8"), sandbox);
  return { ids, calls, sandbox, async search(value) {
    ids["poster-search-input"].value = value;
    ids["poster-search"].events.submit({ preventDefault() {} });
    await new Promise(setImmediate);
  } };
}

function descendants(element, predicate) {
  return [element, ...(element.children || []).flatMap((child) => typeof child === "object" ? descendants(child, predicate) : [])].filter(predicate);
}

function searchPerson(status = "incomplete", alreadyAdded = false) {
  return {
    tmdb_id: 777, name: "张子枫 <script>", sources: [], tmdb_person_url: "https://www.themoviedb.org/person/777",
    known_for_department: "Acting", known_for: [{ title: "A known film", url: "https://www.themoviedb.org/movie/123" }],
    tmdb_image: { preview_url: "https://image.tmdb.org/t/p/w342/profile.jpg", download_url: "/api/tmdb/image-download?image_path=/profile.jpg" },
    tmdb_image_status: "available", people_image_status: status, can_add: status === "incomplete", already_added: alreadyAdded,
    style_availability: Object.fromEntries(["primary", "bw", "diiivoy", "diiivoycolor", "rainier", "signature", "transparent"].map((key, index) => [key, {
      label: key, status: status === "pending_verification" ? "unknown" : status === "complete" || index % 2 === 0 ? "present" : "missing",
      image_url: `https://raw.githubusercontent.com/Kometa-Team/People-Images/master/P/Images/${key}.jpg`,
    }])),
  };
}

test("search reuses the People card with only the TMDb image expanded and seven styles collapsed", async () => {
  const person = searchPerson();
  const harness = searchHarness([{ people: [person] }, { message: "Poster requested" }]);
  await harness.search("777");
  const card = harness.ids["poster-search-result"].children[0];
  assert.equal(card.className, "person-card");
  const visibleImages = card.children.find((child) => child.className === "image-row");
  assert.equal(visibleImages.children.length, 1);
  assert.equal(descendants(visibleImages, (node) => node.tag === "img")[0].src, person.tmdb_image.preview_url);
  const sections = descendants(card, (node) => node.tag === "details");
  assert.equal(sections.length, 2);
  assert(sections.every((node) => !node.open));
  const grid = descendants(card, (node) => node.className === "poster-style-gallery")[0];
  assert.equal(grid.children.length, 7);
  assert.equal(descendants(grid, (node) => node.tag === "img").length, 4);
  const previews = descendants(grid, (node) => node.className === "person-image");
  const downloads = descendants(grid, (node) => node.className === "image-download");
  assert.equal(previews.length, 4); assert.equal(downloads.length, 4);
  previews.forEach((preview, index) => assert.equal(preview.href, downloads[index].href));
  assert.equal(descendants(card, (node) => node.tag === "h2")[0].children[0].textContent, person.name);
  const button = descendants(card, (node) => node.textContent === "Request poster")[0];
  await button.events.click();
  assert.equal(button.textContent, "Already requested"); assert.equal(button.disabled, true);
  const [url, options] = harness.calls[1];
  assert.equal(url, "/api/people/request");
  assert.deepEqual(JSON.parse(options.body), { tmdb_id: 777 });
  assert.equal(options.headers["X-CSRF-Token"], "server-token");
});

test("name search offers separate Unicode identities and fetches the selected exact TMDb ID", async () => {
  const harness = searchHarness([{ choices: [{ tmdb_id: 777, name: "Renée", profile_image_url: "https://image.tmdb.org/t/p/w185/renee.jpg", known_for_department: "Acting", known_for: ["Film"] }, { tmdb_id: 778, name: "Renée" }] }, { people: [searchPerson()] }]);
  await harness.search("Renée");
  const choices = harness.ids["poster-search-choices"].children;
  assert.equal(choices.length, 2);
  assert.equal(choices[0].attributes["aria-label"], "Select Renée, TMDb 777");
  assert.equal(descendants(choices[0], (node) => node.tag === "img")[0].src, "https://image.tmdb.org/t/p/w185/renee.jpg");
  assert.equal(descendants(choices[0], (node) => node.textContent === "Known For: Acting (Film)").length, 1);
  assert.equal(descendants(choices[1], (node) => node.textContent === "TMDb ID: 778").length, 1);
  assert.equal(descendants(choices[1], (node) => node.textContent === "No profile image")[0].hidden, false);
  choices[1].events.click();
  await new Promise(setImmediate);
  assert.equal(harness.calls[1][0], "/api/people/search?q=778");
});

test("failed search thumbnails retain identity and show a missing-photo placeholder", async () => {
  const harness = searchHarness([{ choices: [{ tmdb_id: 777, name: "Mel Gibson", profile_image_url: "https://image.tmdb.org/t/p/w185/mel.jpg" }] }]);
  await harness.search("Mel Gibson");
  const choice = harness.ids["poster-search-choices"].children[0];
  const image = descendants(choice, (node) => node.tag === "img")[0];
  const placeholder = descendants(choice, (node) => node.textContent === "No profile image")[0];
  assert.equal(placeholder.hidden, true);
  image.events.error();
  assert.equal(image.hidden, true);
  assert.equal(placeholder.hidden, false);
  assert.equal(choice.attributes["aria-label"], "Select Mel Gibson, TMDb 777");
});

test("selected search and main-list cards share identical metadata, image layout and collapsed sections", async () => {
  const person = searchPerson("complete");
  const harness = searchHarness([{ people: [person] }]);
  await harness.search("777");
  const searchCard = harness.ids["poster-search-result"].children[0];
  const listCard = harness.sandbox.addPerson(person, harness.sandbox.document.createElement("div"));
  const serialize = (card) => JSON.stringify(card, (key, value) => ["events", "classList"].includes(key) ? undefined : value);
  assert.equal(serialize(searchCard), serialize(listCard));
  for (const card of [searchCard, listCard]) {
    assert.equal(card.children.find((child) => child.className === "image-row").children.length, 1);
    assert.equal(descendants(card, (node) => node.textContent === "Show all seven Kometa poster styles").length, 1);
    assert.equal(descendants(card, (node) => node.textContent === "A known film").length, 1);
    assert.equal(descendants(card, (node) => node.className === "people-image-search").length, 1);
    assert(descendants(card, (node) => node.tag === "details").every((node) => !node.open));
  }
});

test("complete and unavailable inventories have no request button and keep seven gallery states", async () => {
  for (const state of ["complete", "pending_verification"]) {
    const harness = searchHarness([{ people: [searchPerson(state)] }]);
    await harness.search("777");
    const card = harness.ids["poster-search-result"].children[0];
    assert.equal(descendants(card, (node) => node.textContent === "Request poster").length, 0);
    const grid = descendants(card, (node) => node.className === "poster-style-gallery")[0];
    assert.equal(grid.children.length, 7);
    if (state === "pending_verification") {
      assert.equal(descendants(grid, (node) => node.textContent === "Verification unavailable").length, 7);
      assert.equal(descendants(grid, (node) => node.textContent === "Missing").length, 0);
    } else assert.equal(descendants(grid, (node) => node.tag === "img").length, 7);
  }
});

test("duplicate requests stay disabled and failed requests can be retried with a visible error", async () => {
  const duplicate = searchHarness([{ people: [searchPerson("incomplete", true)] }]);
  await duplicate.search("777");
  assert.equal(descendants(duplicate.ids["poster-search-result"], (node) => node.textContent === "Already requested")[0].disabled, true);
  const failing = searchHarness([{ people: [searchPerson()] }, { error: "TMDb unavailable" }]);
  await failing.search("777");
  const button = descendants(failing.ids["poster-search-result"], (node) => node.textContent === "Request poster")[0];
  await button.events.click();
  assert.equal(button.disabled, false);
  assert.equal(failing.ids["poster-search-status"].textContent, "TMDb unavailable");
});
