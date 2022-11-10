/**
 * Redirect to the results page.
 */
function enableResults() {
    var toResults = $("#continue");
    /* check if we should redirect */
    if (toResults.length) {
            window.location = "results";
    }
}


/**
 * Update the probe with the finished status.
 * If the probe is already done continue.
 * If this is the last running probe redirect to the results page.
 */
function showResults(category, results) {
    if ($("#"+category+"-summary").attr('aria-busy') == "false") {
        return;
    }
    if(--probesRunning <= 0) {
        enableResults();
    }
    if(results != undefined) {
        var probeFinished = $("#probe-finished").text();
        $("#"+category+"-summary").attr('aria-busy', false).text(probeFinished);
        $("#"+category+"-icon").attr("src", "/static/probe-animation-ready.gif");
    }
}


/**
 * Parse the statuses of the probes.
 * If at least on probe is not finished signal a retry.
 */
function parseStatuses(json) {
    var retry = false;
    for (var i=0; i<json.length; i++) {
        var obj = json[i];
        if (obj.done === true && obj.success === true) {
            showResults(obj.name, obj);
        } else if (obj.done === true && obj.success === false) {
            showError(obj.name);
        } else {
            retry = true;
        }
    }
    return retry;
}


/**
 * Show the error status for this probe.
 */
function showError(category) {
    --probesRunning;

    /* update probe text */
    var testErrorSummary = $("#probe-error-summary").html();
    $("#"+category+"-summary").attr('aria-busy', false).html(testErrorSummary);
    $("#"+category+"-icon").attr("src", '/static/probe-error.png');

    /* disable redirect */
    var testErrorNoRedirection = $("#probes-no-redirection").html();
    $("#continue").removeAttr("id").attr("href", "/").text(testErrorNoRedirection);

    /* show the no redirect message */
    $(".jsless").removeClass("hidethis").attr("aria-hidden", false);
}


/**
 * Check which probes are still running and show the error status for these.
 */
function showErrors() {
    $("#probes > div").each(function() {
        var name = $(".probe-name", this).text();
        var is_busy = $("#"+name+"-summary").attr('aria-busy');
        if (is_busy == "true") {
            showError(name);
        }
    });
}


/**
 * Poll to get the status of the probes.
 * If the probes are not done and there is still time wait, and poll again.
 * On error show the error status of the still running probes.
 */
function pollProbes(testurl, retryCount) {
    if (typeof(retryCount) === 'undefined') {
        retryCount=parseInt(javascriptRetries);
    }
    if (retryCount < 0) {
        showErrors();
    } else {
        $.ajax({
            url: testurl,
            dataType: "json",
            success: function(json) {
                var retry = parseStatuses(json);
                if (retry == true) {
                    setTimeout(function() {
                        pollProbes(testurl, retryCount-1); },
                        parseInt(javascriptTimeout)
                    );
                }
            },
            error: function() {
                showErrors();
            }
        });
    }
};

/**
 * Start the probes.
 */
function startProbes() {
    $.ajaxSetup({cache: false});
    /* Init some global variables */
    javascriptRetries = $("#javascript-retries").text();
    javascriptTimeout = $("#javascript-timeout").text();
    probesRunning = 0;

    /* Show text about auto redirection when we have the results */
    $(".probing-text").removeClass('hidethis').attr('aria-hidden', false);

    /* Start the probes */
    $("#probes > div").each(function() {
        ++probesRunning;
    });
    probesUrl = $("#probes-url").text();
    pollProbes(probesUrl);
}


if (window.attachEvent) {
  window.attachEvent('onload', HideJSLess);
  window.attachEvent('onload', startProbes);
} else if (window.addEventListener) {
  window.addEventListener("load", HideJSLess, false);
  window.addEventListener("load", startProbes, false);
} else {
  window.onload = "ImageCheck();HideJSLess();startProbes();";
}
