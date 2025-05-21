import { validateElements } from "../lib/utils.js";

const elements = {
  toggleTheme: document.getElementById("theme-toggle"),
};

function themeSwitch() {
  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }

  function getPreferredTheme() {
    return (
      localStorage.getItem("theme") ||
      (window.matchMedia("(prefers-color-scheme: dark)").matches
        ? "dark"
        : "light")
    );
  }

  const currentTheme = getPreferredTheme();
  document.documentElement.setAttribute("data-theme", currentTheme);

  elements.toggleTheme.addEventListener("click", () => {
    const newTheme =
      document.documentElement.getAttribute("data-theme") === "dark"
        ? "light"
        : "dark";
    setTheme(newTheme);
  });
}

if (validateElements(elements, "theme")) {
  themeSwitch();
}

export default themeSwitch;
