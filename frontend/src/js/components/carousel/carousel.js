const list = document.querySelector(".knowledge-list");

// browsers with ::scroll-marker draw the dots in CSS; the unbranded About page has no carousel
if (list && !CSS.supports("selector(::scroll-marker)")) {
  const items = list.querySelectorAll("li");
  const dots = document.querySelectorAll(".dot");

  list.addEventListener("scroll", () => {
    const index = [...items].findIndex((item) => {
      const rect = item.getBoundingClientRect();
      return rect.left >= 0 && rect.left < window.innerWidth / 2;
    });
    dots.forEach((dot, i) => dot.classList.toggle("active", i === index));
  });

  dots.forEach((dot, index) => {
    dot.querySelector("button").addEventListener("click", () => {
      items[index].scrollIntoView({ behavior: "smooth", inline: "center", block: "nearest" });
    });
  });
}
