/* internet.nl
   functions.js
*/

/*
 * Hide text elements that are only shown when JavaScript is not working
 */
function HideJSLess() {
    var jsless = $(".jsless");
    if (jsless.length) {
        jsless.each(function() {
            $(this).addClass("hidethis").attr("aria-hidden", true);
        });
    }
}


$(document).ready(function(){

    /**
     * headroom.js used under The MIT License (MIT)
     * https://wicky.nillia.ms/headroom.js/
     */
    if(Headroom.cutsTheMustard && document.addEventListener){
    /* for IE 9 or greater */
        /* select the header element */
        var theHeader = document.querySelector("header");

        /* extra styling for body if we want to make the header fixed */
        var fixedHeaderbody = document.querySelector("body");
        fixedHeaderbody.classList.add("body-with-semifixed-header");

        /* construct an instance of Headroom, passing the element */
        var fixedHeader = new Headroom(theHeader, {
            "offset": 205,
            "tolerance": 5,
            "classes": {
                "initial": "header-js-animated",
                "pinned": "header-pinned",
                "unpinned": "header-unpinned"
            }
        });
        /* initialise */
        fixedHeader.init();
    }

    $("#form-connection-test").submit(function(e){
        e.preventDefault();
        window.location = "/connection/";
    });
});
