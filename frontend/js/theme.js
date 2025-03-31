const toggleTheme = document.getElementById('theme-toggle');

function setTheme(theme) {
  document.documentElement.setAttribute('data-theme', theme);
  localStorage.setItem('theme', theme);
}

function getPreferredTheme() {
  return localStorage.getItem('theme') || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
}

const currentTheme = getPreferredTheme();
document.documentElement.setAttribute('data-theme', currentTheme);

toggleTheme.setAttribute(
  'aria-label',
  currentTheme === 'dark' ? 'Schakel naar lichte thema' : 'Schakel naar donkere thema'
);

toggleTheme.addEventListener('click', () => {
  const newTheme = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
  setTheme(newTheme);

  toggleTheme.setAttribute(
    'aria-label',
    newTheme === 'dark' ? 'Schakel naar lichte thema' : 'Schakel naar donkere thema'
  );
});
