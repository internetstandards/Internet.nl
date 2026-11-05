const header = document.querySelector("header");
const toggleMenu = document.querySelector(".toggle-menu");
const menu = document.getElementById("nav-controls");
const main = document.querySelector("main");
const footer = document.querySelector("footer");

/* TOGGLE MOBILE MENU */
function setMenuOpen(open) {
  menu.classList.toggle("active", open);
  toggleMenu.setAttribute("aria-expanded", open);
  main.toggleAttribute("inert", open);
  footer.toggleAttribute("inert", open);
}

toggleMenu.addEventListener("click", () => setMenuOpen(!menu.classList.contains("active")));

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && menu.classList.contains("active")) {
    setMenuOpen(false);
  }
});

/* TOGGLE DROPDOWN MENU */
const toggleSubMenus = document.querySelectorAll('[id^="toggle-subnav"]');

function setSubMenuOpen(toggleSubMenu, open) {
  document.getElementById(toggleSubMenu.getAttribute("aria-controls")).classList.toggle("expanded", open);
  toggleSubMenu.setAttribute("aria-expanded", open);
}

toggleSubMenus.forEach((toggleSubMenu) => {
  toggleSubMenu.addEventListener("click", () =>
    setSubMenuOpen(toggleSubMenu, toggleSubMenu.getAttribute("aria-expanded") !== "true")
  );
});

// close dropdowns when the header slides away, because they hang below it and would stay in view
function closeSubMenus() {
  toggleSubMenus.forEach((toggleSubMenu) => setSubMenuOpen(toggleSubMenu, false));
}

/* STICKY HEADER */
const headerHeight = header.offsetHeight;
const scrollWatcher = document.createElement("div");
header.before(scrollWatcher);

new IntersectionObserver((entries) => {
  header.classList.toggle("stuck", !entries[0].isIntersecting);
}).observe(scrollWatcher);

let lastScrollY = window.scrollY;
const buffer = 100;

window.addEventListener("scroll", () => {
  const currentY = window.scrollY;
  const delta = currentY - lastScrollY;

  if (currentY <= headerHeight) {
    header.classList.remove("not-scrolling-up");
  } else if (Math.abs(delta) > buffer) {
    header.classList.toggle("not-scrolling-up", delta > 0);
    if (delta > 0) {
      closeSubMenus();
    }
    lastScrollY = currentY;
  }
});
