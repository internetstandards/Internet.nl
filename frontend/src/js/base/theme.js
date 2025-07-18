import { validateElements } from "../lib/utils.js";

const elements = {
  toggleTheme: document.getElementById("theme-toggle"),
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
  document.documentElement.setAttribute("data-theme", theme);
  setCookie("theme", theme, 365);
}

/**
 * Initialize theme switching functionality
 */
function themeSwitch() {
  // Set initial theme
  if (!getCookie("theme")) setTheme(getPreferredTheme());

  // Add click handler for theme toggle
  elements.toggleTheme.addEventListener("click", () => {
    const currentTheme = document.documentElement.getAttribute("data-theme");
    const newTheme = currentTheme === "dark" ? "light" : "dark";
    setTheme(newTheme);
  });
}

// Initialize theme switching if required elements are present
if (validateElements(elements, "theme")) {
  themeSwitch();
}

export default themeSwitch;
