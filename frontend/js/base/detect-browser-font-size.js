function detectBrowserFontSize() {
  const testElement = document.createElement("div");
  testElement.style.position = "absolute";
  testElement.style.visibility = "hidden";
  testElement.style.height = "1rem";
  document.body.appendChild(testElement);

  const actualEm = testElement.getBoundingClientRect().height;
  document.body.removeChild(testElement);

  const threshold = 20;
  document.body.classList.toggle("font-large", actualEm >= threshold);
}

detectBrowserFontSize();

export default detectBrowserFontSize;
