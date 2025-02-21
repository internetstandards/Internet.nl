// scripts inspired by
// http://www.html5accessibility.com/tests/imagecheck.html

function ImageCheck() {
    /* `unique` is replaced when building the frontend */
    var unique = "@@unique@@";
    if (check_if_images_enabled()) {
        // Is the image 1px big, If so, than the images are enabled and we can use the CSS with backgroundimage
        var objHead = document.getElementsByTagName('head');
        var objCSS_noimages = objHead[0].appendChild(document.createElement('link'));
        objCSS_noimages.id = 'noimages';
        objCSS_noimages.rel = 'stylesheet';
        /* Web browsers (at least firefox, chromium) *always* get the cached
         * version for these javascript-loaded css files.
         * #unique is added to always get the file from the server if a newer
         * version exists.
         */
        objCSS_noimages.href = '/static/css/alt.css'+'#'+unique;
        objCSS_noimages.type = 'text/css';
    }
    if (check_if_browser_in_high_contrast()) {
        var objHead = document.getElementsByTagName('head');
        var objCSS_highcontrast = objHead[0].appendChild(document.createElement('link'));
        objCSS_highcontrast.id = 'highcontrast';
        objCSS_highcontrast.rel = 'stylesheet';
        /* Web browsers (at least firefox, chromium) *always* get the cached
         * version for these javascript-loaded css files.
         * #unique is added to always get the file from the server if a newer
         * version exists.
         */
        objCSS_highcontrast.href = '/static/css/high-contrast.css'+'#'+unique;
        objCSS_highcontrast.type = 'text/css';
    }
}

function check_if_images_enabled() {
    if (document.getElementById('flag').offsetWidth == 1) {
        return true;
    } else {
        return false;
    }
}

function check_if_browser_in_high_contrast() {
    var testelement, colorcheck;
    //Create a test div
    testelement = document.createElement("div");
    //Set its color style to something unusual
    testelement.style.color = "rgb(31,41,59)";
    testelement.id = 'highcontrast_check';
    //Attach to body so we can inspect it
    document.body.appendChild(testelement);
    //Use standard means if available, otherwise use the IE methods
    colorcheck = document.defaultView ? document.defaultView.getComputedStyle(testelement, null).color : testelement.currentStyle.color;
    //Delete the test DIV
    document.body.removeChild(testelement);
    //get rid of extra spaces in result
    colorcheck = colorcheck.replace(/ /g, "");

    //Check if we got back what we set
    //If not we are in high contrast mode
    if (colorcheck !== "rgb(31,41,59)") {
        return true;
    } else {
        return false;
    }
}

if (window.attachEvent) {
  window.attachEvent('onload', ImageCheck);
} else if (window.addEventListener) {
  window.addEventListener("load", ImageCheck, false);
} else {
  window.onload = ImageCheck;
}
