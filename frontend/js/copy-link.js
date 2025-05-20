const shareBtn = document.getElementById('copy-link');

if (shareBtn) {
  shareBtn.addEventListener('click', function() {
    const link = window.location.href;

    if (!window.isSecureContext) {
      alert('Sharing is only supported over HTTPS. Please access this page via HTTPS to share.');
      return;
    }

    if (navigator.share) {
      navigator.share({
        url: link
      })
      .catch(() => {
        fallbackCopy(link);
      });
    } else {
      fallbackCopy(link);
    }
  });
}

function fallbackCopy(link) {
  navigator.clipboard.writeText(link)
    .then(() => {
      shareBtn.classList.add('copied');
      setTimeout(() => {
        shareBtn.classList.remove('copied');
      }, 5000);
    })
    .catch(() => {
      alert('Unable to share or copy link. Please copy manually: ' + link);
    });
}