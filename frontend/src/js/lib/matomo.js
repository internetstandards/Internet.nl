const _paq = window._paq || [];

/**
 * Initialize Matomo tracking with optional cookie disabling
 * @param {boolean} disableCookies - Whether to disable cookies
 */
function matomoGeneratedCode(disableCookies) {
  const subdomainTracking = document.getElementById(
    "matomo-subdomain-tracking"
  )?.textContent;
  if (subdomainTracking) {
    _paq.push(["setCookieDomain", subdomainTracking]);
  }

  if (disableCookies) {
    _paq.push(["disableCookies"]);
  }

  _paq.push(["trackPageView"]);
  _paq.push(["enableLinkTracking"]);

  const matomoUrl = document.getElementById("matomo-url")?.textContent;
  const siteId = document.getElementById("matomo-siteid")?.textContent;

  if (matomoUrl) {
    _paq.push(["setTrackerUrl", `${matomoUrl}piwik.php`]);
    _paq.push(["setSiteId", siteId]);

    const script = document.createElement("script");
    script.type = "text/javascript";
    script.async = true;
    script.defer = true;
    script.src = `${matomoUrl}piwik.js`;
    document.head.appendChild(script);
  }
}

// Check if Matomo is configured
const siteId = document.getElementById("matomo-siteid")?.textContent;
if (siteId) {
  // This is deprecated starting from firefox 135
  const dntEnabled =
    window?.doNotTrack === "1" ||
    navigator?.doNotTrack === "1" ||
    navigator?.doNotTrack === "yes" ||
    navigator?.msDoNotTrack === "1" ||
    window?.external?.msTrackingProtectionEnabled?.();

  matomoGeneratedCode(dntEnabled);
}
