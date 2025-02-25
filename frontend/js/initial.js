
(function() {
  const savedTheme = localStorage.getItem('theme');
  if (savedTheme) {
    document.documentElement.setAttribute('data-theme', savedTheme);
  }
})();
  
(function() {
  const savedLanguage = localStorage.getItem('language') || 'nl';
  const languageSelect = document.getElementById('language-select');
  if (languageSelect) {
    languageSelect.value = savedLanguage;
  }
})();
