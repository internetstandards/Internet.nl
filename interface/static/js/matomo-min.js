var _paq=_paq||[];function matomoGeneratedCode(disableCookies){var d=$("#matomo-subdomain-tracking").text();if(""!=d){_paq.push(["setCookieDomain",d]);}
if(disableCookies){_paq.push(['disableCookies']);}
_paq.push(['trackPageView']);_paq.push(['enableLinkTracking']);(function(){var u=$("#matomo-url").text();var siteid=$("#matomo-siteid").text();if(""!=u){_paq.push(['setTrackerUrl',u+'piwik.php']);_paq.push(['setSiteId',siteid]);var d=document,g=d.createElement('script'),s=d.getElementsByTagName('script')[0];g.type='text/javascript';g.async=true;g.defer=true;g.src=u+'piwik.js';s.parentNode.insertBefore(g,s);}})();}
if(""!=$("#matomo-siteid").text()){if(window.doNotTrack||navigator.doNotTrack||navigator.msDoNotTrack||'msTrackingProtectionEnabled'in window.external){if(window.doNotTrack=="1"||navigator.doNotTrack=="yes"||navigator.doNotTrack=="1"||navigator.msDoNotTrack=="1"||('msTrackingProtectionEnabled'in window.external&&window.external.msTrackingProtectionEnabled())){matomoGeneratedCode(true);}else{matomoGeneratedCode(false);}}else{matomoGeneratedCode(false);}}