
function printStep(t) {
    $("#kdf-steps").append($("<li>").attr("class", "fixed").text(t));
}

function start(e) {
    console.log("starting");
    var email = $("#email").val();
    console.log("email: "+email);
    var password = $("#password").val();
    var steps = $("#kdf-steps");
    steps.empty();
    printStep("starting");
    var worker = new Worker("/js/kdf-worker.js");
    worker.onmessage = function(event) {
        //console.log(event.data);
        if (event.data.what == "A")
            printStep("A: "+event.data.A_hex);
        else if (event.data.what == "B")
            printStep("B: "+event.data.B_hex);
        else if (event.data.what == "C")
            printStep("C: "+event.data.C_hex);
        else if (event.data.what == "log")
            console.log(event.data.text);
    };
    worker.postMessage({"email": email, "password": password});
}


$(function() {
      $("#init").text("JS running");
      $("#submit").on("click", start);
});
