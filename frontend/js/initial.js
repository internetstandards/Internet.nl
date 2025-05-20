const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
  document.documentElement.dataset.theme = savedTheme;
}