var nacl = null;

function splitURL(url) {
    // Let the browser do the work
    var l = document.createElement("a");
    l.href = url;
    // see .protocol, .hostname, and .pathname of returned object
    return l
}

function satisDomainToRegular(host) {
    // take aaaabbbbbcccc.onion.example.com and return example.com
    // return nulll if input isn't a satis domain
    if (!log_assert(onion_v3extractFromDomain(host)))
        return null;
    return host.substring(56 + ".onion.".length);
}

function byteStringToUint8Array(s) {
    let arr = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
        arr[i] = s.charCodeAt(i);
    }
    return arr;
}

function parseSubjectFromSecurityInfo(securityInfo) {
    let str = securityInfo.certificates[0].ASN1Objects[0].children[5]['value'];
    let splits = str.split("\n");
    for (let str of splits) {
        if (str.length < 1)
            continue;
        if (str.substring(0, 2) != "CN")
            continue;
        return str.split(" = ")[1];
    }
}

function parseSubjectAltsFromSecurityInfo(securityInfo) {
    let alts = [];
    let extensions = securityInfo.certificates[0].ASN1Objects[0].children[7].children;
    for (let ext of extensions) {
        if (ext.name != "Certificate Subject Alt Name")
            continue;
        let splits = ext.value.split("\n");
        for (let str of splits) {
            if (str.substring(0, 10) != "DNS Name: ")
                continue;
            alts.push(str.substring(10));
        }
    }
    return alts;
}

function parseFingerprintFromSecurityInfo(securityInfo) {
    let fp = securityInfo.certificates[0].fingerprint.sha256;
    return fp.replace(/:/g, "");
}

function parseTLSVersionFromSecurityInfo(securityInfo) {
    return securityInfo.protocolVersion;
}

function parseValidityFromSecurityInfo(securityInfo) {
    /* See .startGMT and .endGMT and pass those strings to Date.parse */
    return securityInfo.certificates[0].validity;
}

function certContainsProperNames(urlDomain, subject, subjectAlts) {
    if (!log_assert(onion_v3extractFromDomain(urlDomain), "Should have",
            "already determined that urlDomain isn't a Alliuminate domain.")) {
        return false;
    }
    let urlBase = onion_extractBaseDomain(urlDomain);
    if (!log_assert(urlBase, "Should have been able to get the base domain",
            "from Alliuminate domain", urlDomain)) {
        return false;
    }
    if (urlBase != subject) {
        log_debug("Cert does not contain proper names because urlBase",
            urlBase, "does not match the subject", subject);
        return false;
    }
    if (!subjectAlts.includes(urlDomain)) {
        log_debug("Cert does not contain proper names because", urlDomain,
            "is not in the subjectAlts", subjectAlts);
        return false;
    }
    log_debug("Yes cert checks out.", urlBase, "is subject and",
        urlDomain, "is in subjectAlts");
    return true;
}

function satisSignatureValidInTime(satisHeaderValue, securityInfo) {
    let certValidity = parseValidityFromSecurityInfo(securityInfo);
    let certStart = Date.parse(certValidity.startGMT) / 1000;
    let certEnd = Date.parse(certValidity.endGMT) / 1000;
    let sigStart = satisHeaderValue.timeCenter - satisHeaderValue.timeWindow / 2;
    let sigEnd = satisHeaderValue.timeCenter + satisHeaderValue.timeWindow / 2;
    let now = Date.now() / 1000;
    if (sigStart < certStart) {
        // If the signature claims to be valid before the beginning of the
        // certificate's validity, don't let it be
        sigStart = certStart;
    }
    if (sigEnd > certEnd) {
        // If the signature claims to be valid after the end of the
        // certificate's validity, don't let it be
        sigEnd = certEnd;
    }
    //let secondsAfterStart = now - sigStart;
    //let secondsBeforeEnd = sigEnd - now;
    //log_debug("Signature been valid for", secondsAfterStart,
    //    "secs and will stop being valid in", secondsBeforeEnd, "secs")
    return now >= sigStart && now <= sigEnd;
}

function getSatisHeaderValue(responseHeaders) {
    for (let header of responseHeaders) {
        if (header.name == "X-Alliuminate")
            return header.value;
    }
    return null;
}

function parseSatisHeaderValue(onion, base64Value) {
    let a = new SatisHeaderValue(nacl, onion, base64Value);
    return a;
}

function testListener(details) {
    let requestType = details.type;
    log_object(details);
    if (requestType != "main_frame") {
        log_debug("Ignoring request type", requestType);
        return;
    }
    let securityInfo = details.securityInfo;
    if (securityInfo.state != "secure")
        return;


    let url = splitURL(details.url);
    if (!onion_v3extractFromDomain(url.hostname)) {
        log_debug("No longer considering", url.hostname, "because it does",
            "not appear to be a Alliuminate domain.");
        return;
    }

    //
    // At this point, we are visiting a satis domain name, but we known nothing
    // else. We don't know if the proper domains are in the TLS cert. We don't
    // know if the SATIS HTTP header was provided. We don't know if the SATIS
    // HTTP header checks out.
    //

    let subject = parseSubjectFromSecurityInfo(securityInfo);
    let subjectAlts = parseSubjectAltsFromSecurityInfo(securityInfo);
    let fingerprint = parseFingerprintFromSecurityInfo(securityInfo);
    let responseHeaders = details.responseHeaders;
    let satisHeaderValue = null;
    let errorMessage = null;

    if (!certContainsProperNames(url.hostname, subject, subjectAlts)) {
        errorMessage = "The TLS certificate does not have the proper " +
            "hostnames in the right places.";
        return generateRedirect(satisHeaderValue, url.hostname, fingerprint,
            errorMessage);
    }
    let onion = onion_v3extractFromDomain(url.hostname);
    if (!log_assert(onion))
        return;
    onion = new Onion(onion);
    satisHeaderValue = getSatisHeaderValue(responseHeaders);
    if (!satisHeaderValue) {
        log_debug("No longer considering", url.hostname, "because the",
            "webserver didn't provide a Alliuminate HTTP header");
        errorMessage = "The webserver didn't provide a Alliuminate HTTP header.";
        return generateRedirect(satisHeaderValue, url.hostname, fingerprint,
            errorMessage);
    }

    satisHeaderValue = parseSatisHeaderValue(onion, satisHeaderValue);

    log_object(satisHeaderValue);

    if (!satisHeaderValue.validSig) {
        errorMessage = "The signature in the Alliuminate HTTP header is not "+
            "valid. Either it is malformed or it was generated with the "+
            "wrong key.";
    } else if (!satisHeaderValue.readAllBytes) {
        errorMessage = "The Alliuminate HTTP header had extra data.";
    } else if (!satisSignatureValidInTime(satisHeaderValue, securityInfo)) {
        errorMessage = "The Alliuminate signature is not considered valid at "+
            "this time.";
    } else if (fingerprint != satisHeaderValue.fingerprint) {
        errorMessage = "The fingerprint in the TLS cert doesn't match the "+
            "one in the Alliuminate HTTP header.";
    } else if (url.hostname != satisHeaderValue.domain) {
        errorMessage = "The domain in the Alliuminate HTTP header is not the "+
            "one we are visiting.";
    } else if (!satisHeaderValue.validSig) {
        log_debug("The signature in the X-Alliuminate header didn't check "+
            "out.");
        errorMessage = "The signature in the Alliuminate HTTP header didn't "+
            "check out.";
    }

    if (!errorMessage) {
        return;
    }
    return generateRedirect(satisHeaderValue, url.hostname, fingerprint,
        errorMessage);

}

function generateRedirect(satisHeaderValue, urlHostname, tlsFingerprint,
        errorMessage) {
    let pageURL = browser.extension.getURL("pages/index.html");
    let validSig = satisHeaderValue ? satisHeaderValue.validSig : null;
    let domain = satisHeaderValue ? satisHeaderValue.domain : null;
    let fpInSig = satisHeaderValue ? satisHeaderValue.fingerprint : null;
    let timeCenter = satisHeaderValue ? satisHeaderValue.timeCenter : null;
    let timeWindow = satisHeaderValue ? satisHeaderValue.timeWindow : null;
    pageURL = addParam(pageURL, "validSig", validSig);
    pageURL = addParam(pageURL, "domain", urlHostname);
    pageURL = addParam(pageURL, "domainInSig", domain);
    pageURL = addParam(pageURL, "fingerprint", tlsFingerprint);
    pageURL = addParam(pageURL, "fingerprintInSig", fpInSig);
    pageURL = addParam(pageURL, "timeCenter", timeCenter);
    pageURL = addParam(pageURL, "timeWindow", timeWindow);
    pageURL = addParam(pageURL, "error", errorMessage);
    return { "redirectUrl": pageURL };
}

function addParam(url, param, value) {
   var a = document.createElement('a'), regex = /(?:\?|&amp;|&)+([^=]+)(?:=([^&]*))*/g;
   var match, str = []; a.href = url; param = encodeURIComponent(param);
   while (match = regex.exec(a.search))
       if (param != match[1]) str.push(match[1]+(match[2]?"="+match[2]:""));
   str.push(param+(value?"="+ encodeURIComponent(value):""));
   a.search = str.join("&");
   return a.href;
}


function addHTTPSEventListeners() {
    //browser.webRequest.onCompleted.addListener(
    browser.webRequest.onHeadersReceived.addListener(
        testListener,
        {urls: ["<all_urls>"]},
        ["blocking", "responseHeaders", "securityInfo"]
    );
}

addHTTPSEventListeners();
nacl_factory.instantiate(function (nacl_) {
    nacl = nacl_;
});
