function enableResults() {
    window.location = $("#continue").attr('href');
}


function showResults(category, results) {
    if(results != undefined) {
        var probeFinished = $("#probe-finished").text();
        $("#"+category+"-summary").attr('aria-busy', false).text(probeFinished);
        if(results.icon != undefined)
            $("#"+category+"-icon").attr("src", "/static/probe-animation-ready.gif");
    }
}


function test_cb(test_id){
    completed_conn_tests++
    if (completed_conn_tests >= 5){
        $.ajax({
            url: "/connection/finished/"+test_id,
            dataType: "json",
            success: function (json) {
                showResults("ipv6", json.connipv6);
                showResults("resolver", json.connresolver);
                enableResults();
            },
        });
    }
}


function fetchTest(url, test_id){
    $.ajax({
        dataType: 'jsonp',
        url: "http://"+url,
        timeout: 6000,
        success: function (resp) {
            test_cb(test_id);
        },
        error: function(js, stat, err) {
            test_cb(test_id);
        }
    });
}


function startConnectionTest(test_id){
    var connTestDomain = $("#conn-test-domain").text();
    var ipv6TestAddr = $("#ipv6-test-addr").text();
    fetchTest(test_id+".bogus.conn.test-ns-signed."+connTestDomain, test_id);
    fetchTest(test_id+".aaaa.conn.test-ns-signed."+connTestDomain, test_id);
    fetchTest(test_id+".a.conn.test-ns-signed."+connTestDomain, test_id);
    fetchTest(test_id+".a-aaaa.conn.test-ns6-signed."+connTestDomain, test_id);
    fetchTest("["+ipv6TestAddr+"]/connection/addr-test/"+test_id+"/", test_id);
}


function kickStartConnectionTest(){
    $.ajaxSetup({cache: false});
    /* Init global variable */
    completed_conn_tests = 0;

    /* Show text about auto redirection when we have the results */
    $(".probing-text").removeClass('hidethis').attr('aria-hidden', false);

    $(document).ready(function(){
        $.ajax({
            url: "/connection/gettestid/",
            dataType: 'json',
            success: function(resp){
                var test_id = resp.test_id;
                startConnectionTest(test_id);
                $(".connforward").attr("href", "/connection/"+test_id+"/results");
            },
            error: function(err) {
                /* show error when we can't get a test_id */
            }
        });
    });
}


if (window.attachEvent) {
  window.attachEvent('onload', HideJSLess);
  window.attachEvent('onload', kickStartConnectionTest);
} else if (window.addEventListener) {
  window.addEventListener("load", HideJSLess, false);
  window.addEventListener("load", kickStartConnectionTest, false);
} else {
  window.onload = "ImageCheck();HideJSLess();kickStartConnectionTest();";
}
