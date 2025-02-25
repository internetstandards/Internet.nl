const toggleMenu = document.querySelector('.toggle-menu');

const menu = document.querySelector('.nav-controls');
const main = document.querySelector('main');
const footer = document.querySelector('footer');

toggleMenu.addEventListener('click', () => {
  menu.classList.toggle('active');

  main.toggleAttribute('inert', menu.classList.contains('active'));
  footer.toggleAttribute('inert', menu.classList.contains('active'));
});