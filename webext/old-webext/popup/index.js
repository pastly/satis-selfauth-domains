function splitURL(url) {
    // Let the browser do the work
    var l = document.createElement("a");
    l.href = url;
    // see .protocol, .hostname, and .pathname of returned object
    log_debug(l);
    return l
}
function populatePopupWindow(tabs) {
    let link = splitURL(tabs[0].url);
    setCurrentPage(link);
    setIsOnion(link);
    setIsSatis(link);
    let errorElement = document.getElementById("error");
    if (!errorElement.classList.contains("hidden")) {
        errorElement.classList.add("hidden");
    }
}

function setCurrentPage(link) {
    if (link.hostname == "")
        return;
    if (link.hostname.indexOf(".") < 0)
        return;
    document.getElementById("current_page").innerHTML = link.hostname;
}

function setIsOnion(link) {
    if (link.hostname == "")
        return;
    if (link.hostname.slice(-6) != ".onion")
        return;
    document.getElementById("is_onion").classList.remove("hidden");
}

function setIsSatis(link) {
    if (link.hostname == "")
        return;
    let host = link.hostname;
    // must have at least two "." in hostname for it to be
    // possibly a SATIS name (like "aaaabbbbccccdddd.example.com")
    if ((host.match(/\./g) || []).length < 2)
        return;
    let subdomain = host.substring(0, host.indexOf("."));
    // if subdomain isn't exactly the right number of chars, it
    // can't be a SATIS name
    if (subdomain.length != 56)
        return;
    satisInfo = onion_v3decode(subdomain);
    if (!satisInfo)
        return;
    document.getElementById("is_satis").classList.remove("hidden");
    document.getElementById("cert_check_form").classList.remove("hidden");
    document.getElementById("url_v3onion").value = subdomain;
}

/**
 * Takes a string, probably from the user. Determines whether or not
 * it decodes into a valid v3 onion public key.
 */
function validatePubkey(pubkey) {
    // The following is a v3 onion address
    // zfob4nth675763zthpij33iq4pz5q4qthr3gydih4qbdiwtypr2e3bqd
    // And the following is that, but in hex instead
    // c95c1e3667f7fbff6f333bd09ded10e3f3d872133c766c0d07e402345a787c744d8603
    pubkey = pubkey.replace(":", "").replace(" ", "");
    pubkey = hexToBytes(pubkey);
    pubkey = base32.encode(pubkey);
    if (pubkey.length != 56) {
        return false;
    }
    return onion_v3valid(pubkey);
}

function addGUIEventListeners() {
    let elm = document.getElementById("cert_check_form");
    elm.addEventListener("submit", doCertCheckForm);
}

function doCertCheckForm(event) {
    // Cancel form submission
    event.preventDefault();
    let input = document.getElementById("input_pubkey").value;
    input = input.replace(/\s+/g, "");
    let url_v3onion = document.getElementById("url_v3onion").value;
    let v3onion = onion_v3decode(url_v3onion);
    if (!v3onion) {
        tellError("No longer think we are visiting a SATIS URL");
        return;
    }
    if (!validatePubkey(input)) {
        tellError("Not a valid pubkey");
        return;
    }
    input_v3onion = base32.encode(hexToBytes(input));
    if (input_v3onion == url_v3onion) {
        tellSuccess("This pubkey matches the onion address in the URL");
    } else {
        tellError("This pubkey is a valid onion address, but not the one in the URL");
    }
    log_debug("user gave", input_v3onion);
    log_debug("we are at", url_v3onion);
}

function tellSuccess(msg) {
    let successElement = document.getElementById("success");
    let errorElement = document.getElementById("error");
    successElement.innerHTML = msg;
    successElement.classList.remove("hidden");
    errorElement.classList.add("hidden");
    log_debug(msg);
}

function tellError(error) {
    let successElement = document.getElementById("success");
    let errorElement = document.getElementById("error");
    errorElement.innerHTML = error;
    errorElement.classList.remove("hidden");
    successElement.classList.add("hidden");
    log_debug(error);
}

function main() {
    browser.tabs.query({active: true, currentWindow: true})
        .then(populatePopupWindow)
        .catch(log_error);
    addGUIEventListeners();
}
main();
