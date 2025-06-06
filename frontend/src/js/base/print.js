function print() {
  if (window.matchMedia) {
    const mediaQueryList = window.matchMedia("print");
    mediaQueryList.addEventListener("change", (mql) => {
      if (mql.matches) {
        if (document.querySelectorAll("details").length > 0) {
          elements.details.forEach((el) => {
            el.open = true;
          });
        }
      }
    });
  }
}

print();

export default print;
