const _paq = _paq || [];

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
  // Do Not Track detection based on https://dev.to/corbindavenport/how-to-correctly-check-for-do-not-track-with-javascript-135d
  const doNotTrack =
    window.doNotTrack ||
    navigator.doNotTrack ||
    navigator.msDoNotTrack ||
    "msTrackingProtectionEnabled" in window.external;

  if (doNotTrack) {
    // The browser supports Do Not Track
    const dntEnabled =
      window.doNotTrack == "1" ||
      navigator.doNotTrack == "yes" ||
      navigator.doNotTrack == "1" ||
      navigator.msDoNotTrack == "1" ||
      ("msTrackingProtectionEnabled" in window.external &&
        window.external.msTrackingProtectionEnabled());

    matomoGeneratedCode(dntEnabled);
  } else {
    // Do Not Track is not supported
    matomoGeneratedCode(false);
  }
}
