// Check if ::details-content is supported
const supportsDetailsContent = CSS.supports("selector(::details-content)");

if (!supportsDetailsContent) {
  const details = document.querySelector('.action-card details');

  // only proceed if a <details> actually exists
  if (details) {
    const toggleDetailsOpen = () => {
      if (window.innerWidth > 900) {
        details.setAttribute('open', '');
      } else {
        details.removeAttribute('open');
      }
    };

    // Run once on load
    toggleDetailsOpen();

    // Run on window resize
    window.addEventListener('resize', toggleDetailsOpen);
  }
}