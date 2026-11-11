// loaded synchronously in head, so the theme is set before the page renders
const theme = document.cookie.match(/(?:^|; )theme=(light|dark)(?:;|$)/);
if (theme) {
  document.documentElement.dataset.theme = theme[1];
}
