const supportsDetailsContent = CSS.supports("selector(::details-content)");

if (!supportsDetailsContent) {
  const details = document.querySelector('.action-card details');

  if (details) {
    const toggleDetailsOpen = () => {
      if (window.innerWidth > 900) {
        details.setAttribute('open', '');
      } else {
        details.removeAttribute('open');
      }
    };

    toggleDetailsOpen();

    window.addEventListener('resize', toggleDetailsOpen);
  }
}