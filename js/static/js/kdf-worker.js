
importScripts("sjcl.js");

function console_log(text) {
    //postMessage({what: "log", log: text});
};

// derived from https://github.com/kpreid/cubes/blob/master/util.js#L719

// The callback will be called with parameters (response), or (null,
// opt exception) in the event of a failure.
function fetchResource(url, body, callback) {
    // TODO: review this code
    //if (typeof console !== "undefined")
    //  console_log("Fetching", url);
    var xhr = new XMLHttpRequest();
    xhr.open("POST", url, true);
    xhr.responseType = "json";
    xhr.setRequestHeader("content-type", "application/json");
    xhr.onreadystatechange = function () {
      if (xhr.readyState != XMLHttpRequest.DONE) {
        return;
      }
      console_log("state-change: "+xhr.status);
      //if (typeof console !== "undefined")
      //  console_log("completed", url, xhr.status);
      if (xhr.status == 200) {
        callback(xhr.response, null);
      } else {
        if (typeof console !== "undefined")
          console.log("XHR reported failure:", xhr.readyState, xhr.status);
        callback(null, null);
      }
    };
    try {
      xhr.send(JSON.stringify(body));
    } catch (e) {
      if (typeof console !== "undefined")
        console.log("XHR send crashed:", e);
      setTimeout(function () {
        callback(null, e);
      }, 0);
    }
  }

var c1 = 10000;
var scrypt_N, scrypt_r, scrypt_p;
var c2 = 10000;

function KW(tag) {
    return "identity.mozilla.com/keywrapping/v1/"+tag;
}

function KWE(tag, email) {
    // TODO: utf8(email)
    return "identity.mozilla.com/keywrapping/v1/"+tag+":"+email;
}

function PBKDF_A(email, password, cb) {
    var from_string = sjcl.codec.utf8String.toBits;
    var to_hex = sjcl.codec.hex.fromBits;
    var salt = from_string(KWE("first-PBKDF", email));
    var A_hex = to_hex(sjcl.misc.pbkdf2(from_string(password), salt, c1, 32*8));
    cb(A_hex);
}

function scrypt(A_hex, cb) {
    var from_string = sjcl.codec.utf8String.toBits;
    var from_hex = sjcl.codec.hex.toBits;
    var to_hex = sjcl.codec.hex.fromBits;
    // fake scrypt for now
    //var B_hex = to_hex(sjcl.misc.pbkdf2(from_hex(A_hex), "scrypt", c1, 32*8));
    fetchResource("/scrypt", {A_hex: A_hex}, function(d) { cb(d.B_hex); });
}

function PBKDF_C(email, B_hex, cb) {
    var from_string = sjcl.codec.utf8String.toBits;
    var from_hex = sjcl.codec.hex.toBits;
    var to_hex = sjcl.codec.hex.fromBits;
    var salt = from_string(KWE("second-PBKDF", email));
    var C_hex = to_hex(sjcl.misc.pbkdf2(from_hex(B_hex), salt, c2, 32*8));
    cb(C_hex);
}

self.onmessage = function(event) {
    console_log("worker got event");
    console_log(event.data);
    var email = event.data.email;
    var password = event.data.password;
    var got_C = function(C_hex) {
        postMessage({what: "C", C_hex: C_hex});
    };
    var got_B = function(B_hex) {
        postMessage({what: "B", B_hex: B_hex});
        PBKDF_C(email, B_hex, got_C);
    };
    var got_A = function(A_hex) {
        postMessage({what: "A", A_hex: A_hex});
        scrypt(A_hex, got_B);
    };
    PBKDF_A(email, password, got_A);
};

