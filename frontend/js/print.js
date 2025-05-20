if (window.matchMedia) {
  const mediaQueryList = window.matchMedia('print');
  mediaQueryList.addEventListener('change', (mql) => {
    if (mql.matches) {
      document.querySelectorAll('details').forEach((el) => {
        el.open = true;
      });
    }
  });
}