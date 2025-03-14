const languageForm = document.querySelector('.language-form');
const languageSelect = document.getElementById('language-select');

languageSelect.addEventListener('change', function() {
  languageForm.submit();
});