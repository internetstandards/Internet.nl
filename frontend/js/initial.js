
// (function() {
//   const savedTheme = localStorage.getItem('theme');
//   if (savedTheme) {
//     document.documentElement.setAttribute('data-theme', savedTheme);
//   }
// })();

const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
  document.documentElement.dataset.theme = savedTheme;
}