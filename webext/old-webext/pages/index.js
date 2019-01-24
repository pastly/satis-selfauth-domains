function isValidSig(get) {
    return get.validSig == "true";
}

function setTitle(get) {
    let elm = document.getElementById("title");
    let good = get.error == null;
    if (good) {
        elm.innerHTML = "Everything is great!";
        elm.className = "good";
    } else {
        elm.innerHTML = "Oh no! Something went wrong.";
        elm.className = "bad";
    }
}

function setValidity(get) {
    let elmBefore = document.getElementById("notValidBefore");
    let elmAfter = document.getElementById("notValidAfter");
    let notBefore = parseInt(get.timeCenter) - parseInt(get.timeWindow / 2);
    let notAfter = parseInt(get.timeCenter) + parseInt(get.timeWindow / 2);
    let now = Date.now() / 1000;
    let inValidPeriod = now >= notBefore && now <= notAfter;
    elmBefore.innerHTML = new Date(notBefore * 1000);
    elmAfter.innerHTML = new Date(notAfter * 1000);
    let elmCurrent = document.getElementById("currentTime");
    elmCurrent.innerHTML = new Date(now * 1000);
    elmCurrent.className = inValidPeriod ? "good" : "bad";
}

function setFingerprints(get) {
    let elmUsed = document.getElementById("usedCert");
    let elmExpected = document.getElementById("expectedCert");
    let good = get.fingerprint == get.fingerprintInSig;
    elmUsed.innerHTML = get.fingerprint;
    elmExpected.innerHTML = get.fingerprintInSig;
    elmUsed.className = good ? "good" : "bad";
}

function setDomain(get) {
    let elmVisiting = document.getElementById("visitingDomain");
    let elmExpected = document.getElementById("expectedDomain");
    let good = get.domain == get.domainInSig;
    elmVisiting.innerHTML = get.domain;
    elmExpected.innerHTML = get.domainInSig;
    elmVisiting.className = good ? "good" : "bad";
}

function setMessage(get) {
    if (get.error == null) {
        let elm = document.getElementById("successMessage");
        let domain = get.domain;
        elm.innerHTML = "The connection to <span id=urlDomain>" + domain +
            "</span> has been verified as secure using self-authenticating "+
            "names thanks to SATIS.";
        elm.classList.remove("hidden");
    } else {
        let elm = document.getElementById("errorMessage");
        elm.innerHTML = decodeURIComponent(get.error);
        elm.classList.remove("hidden");
    }
}

function main() {
    var get = {};
    location.search.replace('?', '').split('&').forEach(function (val) {
        split = val.split("=", 2);
        log_debug(split[0], split[1])
        get[split[0]] = split[1];
    });
    setTitle(get);
    setValidity(get);
    setFingerprints(get);
    setDomain(get);
    setMessage(get);
}


main();
