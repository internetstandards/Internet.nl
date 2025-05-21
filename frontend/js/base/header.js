import { validateElements } from "../lib/utils.js";

const elements = {
  toggleMenu: document.querySelector(".toggle-menu"),
  menu: document.getElementById("nav-controls"),
  main: document.querySelector("main"),
  footer: document.querySelector("footer"),
  toggleSubMenu: document.getElementById("toggle-subnav"),
  subMenu: document.querySelector(".nav-sublist"),
  header: document.querySelector("header"),
};

function header() {
  /* TOGGLE MOBILE MENU */
  const { toggleMenu, menu, main, footer } = elements;

  toggleMenu.addEventListener("click", () => {
    menu.classList.toggle("active");

    toggleMenu.setAttribute("aria-expanded", menu.classList.contains("active"));
    main.toggleAttribute("inert", menu.classList.contains("active"));
    footer.toggleAttribute("inert", menu.classList.contains("active"));
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && menu.classList.contains("active")) {
      menu.classList.remove("active");
      toggleMenu.setAttribute("aria-expanded", "false");
      main.removeAttribute("inert");
      footer.removeAttribute("inert");
    }
  });

  /* TOGGLE DROPDOWN MENU */
  const toggleSubMenu = document.getElementById("toggle-subnav");
  const subMenu = document.querySelector(".nav-sublist");

  toggleSubMenu.addEventListener("click", () => {
    subMenu.classList.toggle("expanded");

    toggleSubMenu.setAttribute(
      "aria-expanded",
      subMenu.classList.contains("expanded")
    );
  });

  /* STICKY HEADER */
  const header = document.querySelector("header");
  const headerHeight = header.offsetHeight;
  const scrollWatcher = document.createElement("div");

  scrollWatcher.setAttribute("data-scroll-watcher", "");
  header.before(scrollWatcher);

  const navObserver = new IntersectionObserver((entries) => {
    header.classList.toggle("stuck", !entries[0].isIntersecting);
  });

  navObserver.observe(scrollWatcher);

  let prevScrollY = window.scrollY;
  let lastHideScrollY = prevScrollY;
  let ticking = false;
  const buffer = 50;

  window.addEventListener(
    "scroll",
    () => {
      const currentY = window.scrollY;

      if (!ticking) {
        ticking = true;
        requestAnimationFrame(() => {
          const isScrollingDown = currentY > prevScrollY;

          if (currentY <= headerHeight) {
            header.classList.remove("not-scrolling-up");
          } else if (isScrollingDown) {
            header.classList.add("not-scrolling-up");
            lastHideScrollY = currentY;
          } else {
            if (lastHideScrollY - currentY > buffer) {
              header.classList.remove("not-scrolling-up");
            }
          }

          prevScrollY = currentY;
          ticking = false;
        });
      }
    },
    { passive: true }
  );
}

if (validateElements(elements, "header")) {
  header();
}

export default headerBehavior;
