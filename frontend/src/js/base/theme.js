const selector = document.getElementById("toggle-subnav-theme");
const icons = { light: "sun", dark: "moon", system: "system" };

// on the parent domain for all language subdomains, and without the Secure flag so the HTTP connection test can read it
function saveTheme(theme) {
  const domain = document.documentElement.dataset.cookieDomain;
  let cookie = `theme=${theme};path=/;max-age=31536000;samesite=lax`;
  if (domain && location.hostname.endsWith(domain)) {
    cookie += `;domain=${domain}`;
  }
  document.cookie = cookie;
}

function showTheme(theme) {
  if (theme === "light" || theme === "dark") {
    document.documentElement.dataset.theme = theme;
  } else {
    theme = "system";
    delete document.documentElement.dataset.theme;
  }
  selector.classList.remove(...Object.values(icons));
  selector.classList.add(icons[theme]);
  document.querySelector(".current-theme-desktop").textContent =
    document.getElementById(`theme-${theme}`).textContent;
}

showTheme(document.documentElement.dataset.theme);

for (const theme of Object.keys(icons)) {
  document.getElementById(`theme-${theme}`).addEventListener("click", () => {
    saveTheme(theme);
    showTheme(theme);
  });
}
