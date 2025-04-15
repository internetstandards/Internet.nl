/* TOGGLE MOBILE MENU */
const toggleMenu = document.querySelector('.toggle-menu');
const menu = document.getElementById('nav-controls');
const main = document.querySelector('main');
const footer = document.querySelector('footer');

toggleMenu.addEventListener('click', () => {
  menu.classList.toggle('active');
  
  toggleMenu.setAttribute('aria-expanded', menu.classList.contains('active'));
  main.toggleAttribute('inert', menu.classList.contains('active'));
  footer.toggleAttribute('inert', menu.classList.contains('active'));
});

/* TOGGLE DROPDOWN MENU */
const toggleSubMenu = document.getElementById('toggle-subnav');
const subMenu = document.querySelector('.nav-sublist');

toggleSubMenu.addEventListener('click', () => {
  subMenu.classList.toggle('expanded');

  toggleSubMenu.setAttribute('aria-expanded', subMenu.classList.contains('expanded'));
});

/* STICKY HEADER */
const header = document.querySelector('header');
const scrollWatcher = document.createElement('div');

scrollWatcher.setAttribute('data-scroll-watcher', '');
header.before(scrollWatcher);

const navObserver = new IntersectionObserver((entries) => {
  header.classList.toggle('stuck', !entries[0].isIntersecting)
});

navObserver.observe(scrollWatcher);
