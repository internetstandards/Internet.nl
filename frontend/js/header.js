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

document.addEventListener('keydown', (event) => {
  if (event.key === 'Escape' && menu.classList.contains('active')) {
    menu.classList.remove('active');
    toggleMenu.setAttribute('aria-expanded', 'false');
    main.removeAttribute('inert');
    footer.removeAttribute('inert');
  }
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
const headerHeight = header.offsetHeight;
const scrollWatcher = document.createElement('div');

scrollWatcher.setAttribute('data-scroll-watcher', '');
header.before(scrollWatcher);

const navObserver = new IntersectionObserver((entries) => {
  header.classList.toggle('stuck', !entries[0].isIntersecting)
});

navObserver.observe(scrollWatcher);

// let prevScrollY     = window.pageYOffset;
// let ticking         = false;

// window.addEventListener('scroll', () => {
//   const currentY = window.pageYOffset;

//   if (!ticking) {
//     ticking = true;
//     requestAnimationFrame(() => {
//       const isScrollingDown = currentY >= prevScrollY;
//       header.classList.toggle(
//         'not-scrolling-up',
//         currentY > headerHeight && isScrollingDown
//       );
//       prevScrollY = currentY;
//       ticking     = false;
//     });
//   }
// }, { passive: true });

let prevScrollY     = window.pageYOffset;
let lastHideScrollY = prevScrollY;
let ticking         = false;
const buffer        = 200;

window.addEventListener('scroll', () => {
  const currentY = window.pageYOffset;

  if (!ticking) {
    ticking = true;
    requestAnimationFrame(() => {
      const isScrollingDown = currentY > prevScrollY;

      if (currentY <= headerHeight) {
        // Always show the header when near the top
        header.classList.remove('not-scrolling-up');
      } else if (isScrollingDown) {
        // Scrolling down past headerHeight -> hide
        header.classList.add('not-scrolling-up');
        lastHideScrollY = currentY;
      } else {
        // Scrolling up by more than buffer -> show
        if (lastHideScrollY - currentY > buffer) {
          header.classList.remove('not-scrolling-up');
        }
      }

      prevScrollY = currentY;
      ticking     = false;
    });
  }
}, { passive: true });
