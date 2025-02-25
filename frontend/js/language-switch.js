const languageForm = document.querySelector('.language-form');
const languageSelect = document.getElementById('language-select');

function setLanguage(language) {
  localStorage.setItem('language', language);
}

languageSelect.addEventListener('change', function() {
  const selectedLanguage = languageSelect.value;
  setLanguage(selectedLanguage);
  languageForm.submit();
});