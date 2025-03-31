const carousel = document.querySelector('.explanation-list');
const dots = document.querySelectorAll('.dot');
const items = document.querySelectorAll('.explanation-list li');

carousel.addEventListener('scroll', () => {
  let index = [...items].findIndex(item => {
    const rect = item.getBoundingClientRect();
    return rect.left >= 0 && rect.left < window.innerWidth / 2;
  });

  dots.forEach(dot => dot.classList.remove('active'));
  if (index !== -1) dots[index].classList.add('active');
});

dots.forEach((dot, index) => {
  const headerId = items[index].querySelector('h3').id;
  const headerText = document.getElementById(headerId).textContent;
  dot.querySelector('button').setAttribute('aria-label', `Scroll naar ${headerText}`);
  
  dot.addEventListener('click', () => {
    items[index].scrollIntoView({ behavior: 'smooth', inline: 'center', block: 'nearest' });
  });
});
