const siteNav = document.querySelector(".site-nav");

siteNav?.addEventListener("keydown", (event) => {
  if (event.key === "Escape") {
    siteNav.open = false;
    siteNav.querySelector("summary")?.focus();
  }
});

document.addEventListener("click", (event) => {
  if (siteNav?.open && !siteNav.contains(event.target)) siteNav.open = false;
});
