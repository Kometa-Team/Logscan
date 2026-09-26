function closeDestinationMenus(except = null) {
  document.querySelectorAll(".support-destinations[open]").forEach((details) => {
    if (details !== except) details.open = false;
  });
}

function positionDestinationMenu(details) {
  const summary = details.querySelector("summary");
  const menu = details.querySelector(".support-destination-menu");
  if (!summary || !menu) return;

  const trigger = summary.getBoundingClientRect();
  const menuWidth = menu.offsetWidth;
  const menuHeight = menu.offsetHeight;
  const gutter = 8;
  const left = Math.min(
    window.innerWidth - menuWidth - gutter,
    Math.max(gutter, trigger.right - menuWidth),
  );
  const roomBelow = window.innerHeight - trigger.bottom;
  const top = roomBelow >= menuHeight + gutter
    ? trigger.bottom + 5
    : Math.max(gutter, trigger.top - menuHeight - 5);

  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}

document.querySelectorAll(".support-destinations").forEach((details) => {
  details.addEventListener("toggle", () => {
    if (!details.open) return;
    closeDestinationMenus(details);
    requestAnimationFrame(() => positionDestinationMenu(details));
  });
});

document.addEventListener("click", (event) => {
  if (!event.target.closest(".support-destinations")) closeDestinationMenus();
});

window.addEventListener("resize", () => closeDestinationMenus());
document.querySelector(".support-table-wrap")?.addEventListener("scroll", () => closeDestinationMenus());
