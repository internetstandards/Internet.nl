import { hideJSLess } from "../lib/utils.js";

/**
 * Initialize theme
 */
function initialize() {
  const savedTheme = localStorage.getItem("theme");
  if (savedTheme) {
    document.documentElement.dataset.theme = savedTheme;
  }
  hideJSLess();
}

export default initialize;
