import { validateElements } from "../lib/utils.js";

const elements = {
  currentTheme: document.querySelector(".current-theme-desktop"),
  themeSelector: document.getElementById("toggle-subnav-theme"),
  light: document.getElementById("theme-light"),
  dark: document.getElementById("theme-dark"),
  system: document.getElementById("theme-system"),
};

/**
 * Get a cookie value by name
 * @param {string} name - Cookie name
 * @returns {string|null} Cookie value or null if not found
 */
function getCookie(name) {
  // Split all cookies into an array
  const allCookies = document.cookie.split(";");

  // Look for the cookie with the matching name
  const matchingCookie = allCookies.find((cookie) =>
    cookie.trim().startsWith(`${name}=`)
  );

  // Return the value if found, null if not found
  if (!matchingCookie) {
    return null;
  }

  return matchingCookie.split("=")[1];
}

/**
 * Set a cookie with specified parameters
 * @param {string} name - Cookie name
 * @param {string} value - Cookie value
 * @param {number} days - Cookie duration in days
 */
function setCookie(name, value, days) {
  const date = new Date();
  date.setDate(date.getDate() + days);

  const cookieValue = encodeURIComponent(value);
  const expires = `expires=${date.toUTCString()}`;
  const path = "path=/";

  document.cookie = `${name}=${cookieValue};${expires};${path}`;
}

/**
 * Get the preferred theme based on cookie or system preference
 * @returns {string} Theme name
 */
function getPreferredTheme() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
}

/**
 * Set the theme and save it to cookie
 * @param {string} theme - Theme name
 */
function setTheme(theme) {
  setCookie("theme", theme, 365);

  document.documentElement.setAttribute("data-theme", theme);
  elements.themeSelector.classList.remove("moon", "system", "sun");

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

/**
 * Initialize theme switching functionality
 */
function themeSwitch() {
  // Set initial theme
  setTheme(getCookie("theme"));

  // Add click handler for theme buttons
  elements.light.addEventListener("click", () => {
    setTheme("light");
  });

  elements.dark.addEventListener("click", () => {
    setTheme("dark");
  });

  elements.system.addEventListener("click", () => {
    setTheme("system");
  });
}

// Initialize theme switching if required elements are present
if (validateElements(elements, "theme")) {
  themeSwitch();
}

export default themeSwitch;
