function parseUint32FromByteBuffer(buffer, position) {
    let view = new DataView(buffer, position, 4);
    return view.getUint32(0);
}

function parseUint64FromByteBuffer(buffer, position) {
    let view = new DataView(buffer, position, 8);
    let hi = view.getUint32(0);
    let lo = view.getUint32(4);
    return hi * Math.pow(2, 32) + lo;
}

function parseStringFromByteBuffer(buffer, position, length) {
    let s = new TextDecoder("utf-8").decode(buffer.slice(position, position+length));
    return s;
}

function byteStringToUint8Array(s) {
    let arr = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
        arr[i] = s.charCodeAt(i);
    }
    return arr;
}

/**
 * Add a URL parameter to the given url
 */
function addParam(url, param, value) {
    var a = document.createElement('a'), regex = /(?:\?|&amp;|&)+([^=]+)(?:=([^&]*))*/g;
    var match, str = []; a.href = url; param = encodeURIComponent(param);
    while (match = regex.exec(a.search))
        if (param != match[1]) str.push(match[1]+(match[2]?"="+match[2]:""));
    str.push(param+(value?"="+ encodeURIComponent(value):""));
    a.search = str.join("&");
    return a.href;
}

/**
 * Split a url string into its parts via an anchor tag
 */
function splitURL(url) {
    // Let the browser do the work
    var l = document.createElement("a");
    l.href = url;
    // see .protocol, .hostname, and .pathname of returned object
    return l
}

function _tokey(s) {
    return "satis-" + s;
}

/**
 * Store value *v* under key *k* in sessionStorage.
 *
 * *v* is an object, which we will convert to a string before putting in
 * sessionStorage.
 *
 * *k* is a string that we will add a prefix to before using it as a key in
 * sessionStorage
 */
function ssput(k, v) {
    k = _tokey(k);
    v = JSON.stringify(v);
    sessionStorage.setItem(k, v);
}

/**
 * Get the value under key *k* out of sessionStorage.
 *
 * *k* is a string that we will add a prefix to before using it as a key in
 * sessionStorage.
 *
 * We will parse the value from a string back into an object before returning
 * it. We will happily return null if nothing is stored under the given key.
 */
function ssget(k) {
    k = _tokey(k);
    let v = JSON.parse(sessionStorage.getItem(k));
    return v;
}

/**
 * As ssput, but in localStorage instead of sessionStorage
 */
function lsput(k, v) {
    k = _tokey(k);
    v = JSON.stringify(v);
    localStorage.setItem(k, v);
}

/**
 * As lsget, but from localStorage instead of sessionStorage
 */
function lsget(k) {
    k = _tokey(k);
    let v = JSON.parse(localStorage.getItem(k));
    return v;
}

function sendMessage(id, msg) {
    return browser.runtime.sendMessage({'id': id, 'msg': msg});
}

function findSATDomainList(doc) {
    let list = doc.getElementById("satDomainList");
    if (!list) {
        log_debug("There is no domain list in this page.");
        return;
    }
    let out = new Set();
    for (let li of list.children) {
        let satName = null;
        let baseName = null;
        for (ele of li.getElementsByTagName("span")) {
            if (ele.classList.contains("satDomainSATName")) {
                satName = ele.textContent;
            } else if (ele.classList.contains("satDomainBaseName")) {
                baseName = ele.textContent;
            }
        }
        if (satName && baseName) {
            log_debug("Adding", satName, "to", baseName);
            out.add({'satName': satName, 'baseName': baseName});
        } else {
            log_debug("Ignoring element:");
            log_object(ele);
        }
    }
    return out;
}

function handleSattestations(sat) {
    if (! "sattestor_domain" in sat) {
        log_debug("msg does not contain sattestor");
        return;
    }
    if (! "sattestor_onion" in sat) {
        log_debug("msg does not contain onion");
        return;
    }
    if (! "sattestor_labels" in sat) {
        log_debug("msg does not contain labels");
        return;
    }
    if (! "url" in sat) {
        log_debug("msg does not contain url");
        return;
    }
    if (! "isSatUrl" in sat) {
        log_debug("msg does not contain isSatUrl");
        return;
    }

    let out = new Set();

    let satName, baseName;
    if (sat.isSatUrl) {
        satName = sat.sattestor_onion + "onion." + sat.sattestor_domain;
        baseName = sat.sattestor_domain;
    } else {
        satName = sat.sattestor_domain;
        baseName = onion_extractBaseDomain(sat.sattestor_domain);
    }


    let sattestor_labels = sat.sattestor_labels.split(",");

    // Declare that this sattestor accepts any labels for which it is trusted
    out.add({'satName': satName, 'baseName': baseName, 'labels': sattestor_labels});

    if ("sattestees" in sat) {
        for (let sattestee of sat.sattestees) {
            if (! "domain" in sattestee) {
                log_debug(`sattestee does not contain sattestee: ${sattestee}`);
                continue;
            }
            if (! "onion" in sattestee) {
                log_debug(`sattestee does not contain onion: ${sattestee}`);
                continue;
            }
            if (! "labels" in sattestee) {
                log_debug(`sattestee does not contain labels: ${sattestee}`);
                continue;
            }
            let labels = sattestee.labels.split(",");

            let badLabel = false;
            for (let sattestee_label of labels) {
                let found = 0;
                for (let sattestor_label of sattestor_labels) {
                    if (sattestee_label == sattestor_label) {
                        found = 1;
                    }
                }
                if (!found) {
                    log_debug(`${satName} not trusted for label ${sattestee_label}. Skipping.`);
                    badLabel = true;
                    break;
                }
            }
            if (badLabel) {
                continue;
            }
            // TODO Add labels and valid_after
            out.add({'satName': sattestee.onion + "onion." + sattestee.domain, 'baseName': sattestee.domain, 'labels': labels});
        }
    } else {
        log_debug("msg does not contain sattestees");
    }

    return {"url": sat.url, 'labels': sattestor_labels, "set": out, "wellknown": true, "satUrl": sat.isSatUrl};
}

function sendSATDomainListRequest(resp) {
    const wellKnownResource = resp.origin + "/.well-known/sattestation.json?onion=" + resp.onion;
    log_debug("Fetching well-known sat ", wellKnownResource);
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() {
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
            log_debug(`Received responseText: ${xmlHttp.responseText}`);
            sendMessage("validateParseSattestation", { 'response': xmlHttp.responseText, 'url': document.URL });
        } else {
            log_debug(`Fetching well-known sat returned ${xmlHttp.status}, readystate ${xmlHttp.readyState}`);
        }
    }
    log_object(wellKnownResource);
    //xmlHttp.responseType = 'json';
    xmlHttp.open("GET", wellKnownResource, true);
    xmlHttp.send();
}

function fetchSATDomainList(win) {
    log_debug("Starting process for fetching sattestations from " + window.origin + " (" + window.document.URL + ")");
    let response = sendMessage("parseUrl", {'origin': window.origin, 'url': window.document.URL });
    response.then(sendSATDomainListRequest);
}

function lightlyParseSatJSON(content) {
    let trimmedContent = content.trim();
    const sattestationPropRe = /^{\s*"sattestation"\s*:\s*/;
    let satArr = trimmedContent.split(sattestationPropRe);
    if (satArr.length !== 2) {
        log_debug("Text doesn't start with sattestation property.");
        return;
    }
    let satIdx = content.indexOf(satArr[1]);

    const sigPropRe = /"signature"\s*:\s*"[a-zA-Z0-9/\+=]*"\s*}$/;
    let startOfSigObject = trimmedContent.search(sigPropRe);
    if (startOfSigObject === -1) {
        log_debug("Text doesn't end with the signature property.");
        return;
    }

    // signature: <base64 encoded sig>
    let sigKV = trimmedContent.substring(startOfSigObject, trimmedContent.length - "}".length);
    let sigKVArr = sigKV.split(":");
    if (!sigKVArr[0].startsWith("\"signature\"") || sigKVArr.length !== 2) {
        log_debug("Sig property is malformed (1).");
        return;
    }
    let sigKey = sigKVArr[0].trim();
    if (sigKey !== "\"signature\"") {
        log_debug("Signature property is not exactly 'signature'.");
        return;
    }
    let sig = sigKVArr[1].trim();
    // Strip quote at beginning and end of string
    if (sig.charAt(0) !== "\"") {
        log_debug("Signature does not begin with a quote.");
        return;
    }
    if (sig.charAt(sig.length - 1) !== "\"") {
        log_debug("Signature does not end with a quote.");
        return;
    }
    sig = sig.substring(1, sig.length - 1);

    let unparsedSat = satArr[1].substring(0, startOfSigObject - satIdx - 1);
    if (unparsedSat === 0) {
        log_debug("There is no sattestation in this document.");
        return;
    }

    let lastComma = unparsedSat.lastIndexOf(',');
    if (lastComma === -1) {
        log_debug("Last comma (before sig) not found.");
        return;
    }
    unparsedSat = unparsedSat.substring(0, lastComma);

    return {'sig': sig, 'unparsedContent': unparsedSat};
}

function findSATSigInMetaTag(doc) {
    let list = doc.getElementsByTagName("meta");
    if (!list) {
        log_debug("There is aren't any meta tag elements in this page");
        return;
    }
    for (let li of list) {
        if (li.hasAttribute("http-equiv") && li.hasAttribute("content")) {
            let httpEquiv = li.getAttribute("http-equiv");
            let content = li.getAttribute("content");
            if (httpEquiv.toLowerCase() === "x-sat-sig") {
                // First sig wins.
                return content;
            }
        } else {
            log_debug("Ignoring element:");
            log_object(li);
        }
    }
    return;
}

function validateAndParseSattestation(msg) {
    if (! "response" in msg) {
        log_debug("msg does not contain unparsedContent");
        return;
    }
    let lightlyParsed = lightlyParseSatJSON(msg.response);

    if (!lightlyParsed) {
        log_debug("Lightly parsing JSON failed.");
        return;
    }

    if (! "sig" in lightlyParsed) {
        log_debug("msg does not contain sig");
        return;
    }
    if (!log_assert(nacl != null, "NaCl wasn't initialized in time")) {
        return;
    }
    let details = secInfoCache[msg.url];
    if (!details) {
        log_debug("Cached SecInfo not found");
        return;
    }
    let url = splitURL(msg.url);

    let isSatUrl = true;
    let onion = onion_v3extractFromPossibleSATUrl(url);
    if (!onion) {
        log_debug(`Self-authenticating url not found in ${url}`);
        onion = onion_v3extractFromPossibleSATDomain(url.hostname);
        if (!onion) {
            log_debug("Stopped considering", url.hostname, "because not",
                "a self-authenticating domain name");
            return;
        } else {
            log_debug(`Self-authenticating domain found in ${url.hostname}`);
            isSatUrl = false;
        }
    } else {
        log_debug(`Self-authenticating url found in ${url}`);
    }

    onion = new Onion(onion);

    let taggedUnparsedContent = "sattestation-list-v0 " + lightlyParsed.unparsedContent;
    log_debug(`Verifying tagged message: '${taggedUnparsedContent}'`);

    // Base64-encoded string to binary string
    let sigDecode = "";
    try {
      sigDecode = window.atob(lightlyParsed.sig);
    } catch (err) {
      log_debug("Exception in atob(): ", err);
      return;
    }

    if (sigDecode.length !== 64) {
      log_debug(`Signature is an incorrect length: ${sigDecode.length}`);
      return;
    }

    // Binary string to array of u8
    let sigAsBytes = byteStringToUint8Array(sigDecode);
    let contentAsBytes = byteStringToUint8Array(taggedUnparsedContent);

    parsedContent = validateAndParseJson(lightlyParsed.unparsedContent, contentAsBytes, sigAsBytes, onion);
    if (!parsedContent) {
        return;
    }

    parsedContent.url = url;
    parsedContent.isSatUrl = isSatUrl;

    return parsedContent;
}

function validateAndParseJson(unparsedMsg, signedMsg, sig, onion) {
    let validSig = nacl.crypto_sign_verify_detached(
        sig, signedMsg, onion.pubkey);

    if (!validSig) {
        log_debug("Signature not valid for content in sattestation");
        return;
    }

    let parsedContent = "";
    try {
        parsedContent = JSON.parse(unparsedMsg);
    } catch (e) {
        log_error(e);
        return;
    }
    return parsedContent;
}
