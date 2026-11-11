const button = document.getElementById("load-more");
const cards = document.querySelectorAll(".load-more > .card:nth-child(n+6)");
let shown = 0;

button?.addEventListener("click", () => {
  for (const card of [...cards].slice(shown, shown + 3)) {
    card.classList.add("visible");
  }
  shown += 3;
  button.classList.toggle("hidden", shown >= cards.length);
});
