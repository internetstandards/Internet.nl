import { validateElements } from "../../lib/utils.js";

const elements = {
  shareBtn: document.getElementById("copy-link"),
};

function copyLink() {
  elements.shareBtn.addEventListener('click', function() {
    const link = window.location.href;

    if (!window.isSecureContext) {
      alert("Unable to share or copy link. Please copy manually: " + link);
      return;
    }

    if (navigator.share) {
      navigator.share({
        url: link
      })

    } else {
      fallbackCopy(link);
    }
  });

  function fallbackCopy(link) {
    navigator.clipboard.writeText(link)
      .then(() => {
        elements.shareBtn.classList.add('copied');
        setTimeout(() => {
          elements.shareBtn.classList.remove('copied');
        }, 5000);
      })
      .catch(() => {
        alert('Unable to share or copy link. Please copy manually: ' + link);
      });
      
  }  
}

if (validateElements(elements, "copy-link")) {
  copyLink();
}

export default copyLink;
