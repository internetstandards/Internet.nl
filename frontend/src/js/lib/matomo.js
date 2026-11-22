// piwik.js reads its command queue from the global _paq
const _paq = (window._paq = window._paq || []);
const { matomoUrl: url, matomoSiteId: siteId, matomoCookieDomain: cookieDomain } = document.documentElement.dataset;

if (url && siteId) {
  if (cookieDomain) {
    _paq.push(["setCookieDomain", cookieDomain]);
  }
  if (["1", "yes"].includes(navigator.doNotTrack) || window.doNotTrack === "1") {
    _paq.push(["disableCookies"]);
  }
  _paq.push(["trackPageView"]);
  _paq.push(["enableLinkTracking"]);
  _paq.push(["setTrackerUrl", `${url}piwik.php`]);
  _paq.push(["setSiteId", siteId]);

  const script = document.createElement("script");
  script.async = true;
  script.src = `${url}piwik.js`;
  document.head.appendChild(script);
}
