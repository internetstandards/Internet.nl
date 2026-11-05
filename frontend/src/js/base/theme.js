import { validateElements } from "../lib/utils.js";

const elements = {
  currentTheme: document.querySelector(".current-theme-desktop"),
  themeSelector: document.getElementById("toggle-subnav-theme"),
  light: document.getElementById("theme-light"),
  dark: document.getElementById("theme-dark"),
  system: document.getElementById("theme-system"),
};

/**
 * Save the theme in a cookie, shared between the language subdomains
 * @param {string} theme - Theme name
 */
function saveTheme(theme) {
  const domain = document.documentElement.dataset.cookieDomain;
  let cookie = `theme=${theme};path=/;max-age=31536000;samesite=lax`;
  if (domain && location.hostname.endsWith(domain)) {
    cookie += `;domain=${domain}`;
  }
  if (location.protocol === "https:") {
    cookie += ";secure";
  }
  document.cookie = cookie;
}

/**
 * Apply the theme to the page and the theme selector
 * @param {string} theme - Theme name: light, dark or system
 */
function showTheme(theme) {
  elements.themeSelector.classList.remove("moon", "system", "sun");

  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    delete document.documentElement.dataset.theme;
  }

  switch (theme) {
    case "light":
      elements.themeSelector.classList.add("sun");
      elements.currentTheme.textContent = elements.light.textContent;
      break;
    case "dark":
      elements.themeSelector.classList.add("moon");
      elements.currentTheme.textContent = elements.dark.textContent;
      break;
    default:
      elements.themeSelector.classList.add("system");
      elements.currentTheme.textContent = elements.system.textContent;
      break;
  }
}

function themeSwitch() {
  showTheme(document.documentElement.dataset.theme);

  for (const theme of ["light", "dark", "system"]) {
    elements[theme].addEventListener("click", () => {
      saveTheme(theme);
      showTheme(theme);
    });
  }
}

if (validateElements(elements, "theme")) {
  themeSwitch();
}

export default themeSwitch;
