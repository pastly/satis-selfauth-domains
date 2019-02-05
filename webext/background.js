var nacl = null;

var SAT_LIST_UPDATE_INTERVAL = 600; // seconds

var preload = {
    'satis.system33.pw': {
        'alts': ['hllvtjcjomneltczwespyle2ihuaq5hypqaavn3is6a7t2dojuaa6rydonion.satis.system33.pw']
    },
};

function certContainsProperNames(urlDomain, subject, subjectAlts) {
    if (!log_assert(onion_v3extractFromPossibleAlliuminatedDomain(urlDomain),
        "Should have already determined that urlDomain isn't ",
        "a Alliuminated domain.")) {
        return false;
    }
    let urlBase = onion_extractBaseDomain(urlDomain);
    if (!log_assert(urlBase, "Should have been able to get the base ",
        "domain from Alliuminate domain", urlDomain)) {
        return false;
    }
    if (urlBase != subject) {
        log_debug("Cert does not contain proper names because urlBase",
            urlBase, "does not match the subject", subject);
        return false;
    }
    if (!subjectAlts.includes(urlDomain)) {
        log_debug("Cert does not contain proper names because",
            urlDomain, "is not in the subjectAlts", subjectAlts);
        return false;
    }
    //log_debug("Yes cert checks out.", urlBase, "is subject and",
    //    urlDomain, "is in subjectAlts");
    return true;
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

function _return_without_altsvc_header(headers) {
    headers = headers.filter(h => h.name != 'alt-svc')
    //headers.push({'name': 'removed-alt-svc', 'value': 'yes'});
    //log_object(headers);
    return {'responseHeaders': headers};
}

function _returnWithSelectAltSvcHeaders(headers, altsvcHeaders) {
    // Return with alt-svc headers filtered out of *headers* and the contents
    // of *altsvc_headers* put into it instead
    headers = headers.filter(h => h.name != 'alt-svc')
    // The spread operator, used like python's extend() method on arrays
    headers.push(...altsvcHeaders);
    return {'responseHeaders': headers};
}

/**
 * Determine if we should keep an alt-svc header.
 *
 * If it's not a special one that we care about having extra restrictions,
 * return true.
 *
 * If it's a special one -- an onion address or an alliuminated domain -- then
 * return false if it doesn't pass the extra restirctions. If it does pass,
 * return the OnionSig object.
 */
function _shouldKeepAltSvcHeader(as, headers, origin) {

    let onion = null;
    let is_allium_domain = false;
    let is_onion_domain = false;
    // Is it a alliuminated name?
    onion = onion_v3extractFromPossibleAlliuminatedDomain(as.domain);
    if (!onion) {
        // Is it a v3 onion?
        onion = onion_v3extractFromPossibleOnionDomain(as.domain);
        if (onion) {
            is_onion_domain = true;
        }
    } else {
        is_allium_domain = true;
    }

    // Not either, so just give it to the user
    if (!onion) {
        return true;
    }
    onion = new Onion(onion);

    /*
     * There's an AltSvc header and it is either for a .onion or an
     * alliuminated domain name.  We now expect a signature from the onion
     * service encoded in the domain name, and will only give the AltSvc header
     * to the browser if everything checks out.
     */

    // For the onion service in this alt-svc header, require that there is an
    // onion sig header signed by it. There may be more than one onion sig
    // header, so we have to search for it.
    let onionSig = null;
    for (let os of getOnionSigHeaders(headers)) {
        os = new OnionSig(nacl, onion, os);
        if (os.validSig && os.readAllBytes) {
            onionSig = os;
            break;
        }
    }
    if (!onionSig) {
        log_debug("Alt-Svc is a self-auth domain or .onion but no onion sig",
            "header so we don't trust it and won't give it to the user");
        return false;
    }

    /*
     * Temoprary? Maybe? We're doing all this for plain onion service alt-svc
     * headers as a tacked-on thing right now. The signatures were originally
     * planned to have [56chars]onion.foo.com which would match the alt-svc
     * exactly.
     *
     * So if we have an alliuminated domain name, it should be in the signature
     * exactly.
     *
     * But if we have an onion domain like [56chars].onion, then we need to
     * take the friendly domain (foo.com), combine it with the onion in the
     * alt-svc header, and look for the result ([56chars]onion.foo.com) in the
     * onion sig header.
     *
     * Instead of combining the two, we could rework the server side a little
     * bit: (1) have Tor generate multiple onion sigs or not include the full
     * alliuminated name in the signed data. (2) make changes to the nginx
     * template.
     *
     * I think doing that is harder and not not necessarily even better.
     */
    // If we have an alliuminated domain, look for it exactly in the onion
    // sig header.
    if (is_allium_domain && onionSig.domain != as.domain) {
        log_debug("The onion sig header is for a different domain",
            "than the one in the alt-svc header. Not giving",
            "the alt-svc header to the user. (",
            onionSig.domain, "vs", as.domain, ")");
        return false;
    }
    // If we have an onion domain, look for it and the origin domain to be
    // together in the sig header
    else if (is_onion_domain && onion.str + "onion." + origin != onionSig.domain) {
        log_debug("The onion sig header contains", onionSig.domain,
            "but we are looking for", onion.str + "onion." + origin,
            "so we are not giving it to the user.");
        return false;
    }

    /*
     * Temporary-ish
     *
     * Once Tor Browswer supports the securityInfo API, we should pass the
     * secInfo object into onionSigValidInTime instead of null
     */
    // Require the current time to be within the validity window in the onion
    // sig header
    if (!onionSigValidInTime(onionSig, null)) {
        let start = new Date(1000*(onionSig.timeCenter - onionSig.timeWindow/2));
        let end = new Date(1000*(onionSig.timeCenter + onionSig.timeWindow/2));
        let now = new Date();
        log_debug("The onion sig header is not currently valid. It is valid",
            "from", start, "to", end, "but it is currently", now);
        return false;
    }

    /*
     * DISABLED
     *
     * Tor Browser doesn't support the securityInfo API yet.
     *
    // Require the base domain in the onion sig to be listed in the TLS
    // certificate
    let secInfo = await browser.webRequest.getSecurityInfo(
        details.requestId, {"certificateChain": true, "rawDER": true});
    if (secInfo.state != "secure") {
        log_debug("We don't trust anything about alt-svc headers",
            "received over insecure connections. Not giving to",
            "user");
        return _return_without_altsvc_header(headers);
    }
    let certDomains = getSubjectAlts(secInfo);
    certDomains.push(getSubject(secInfo));
    let baseDomain = onion_extractBaseDomain(onionSig.domain);
    if (certDomains.indexOf(baseDomain) < 0) {
        log_debug(baseDomain, "is not in the TLS cert:", certDomains,
            "so not giving alt-svc to user");
        return _return_without_altsvc_header(headers);
    }
     */

    return onionSig;
}

function _storeAltSvcInState(origin, alt, onPreload, validOnionSig) {
    let sites = ssget("altsvcs") || {};
    if (!(origin in sites)) {
        sites[origin] = {
            'alts': {},
        };
    }
    if (!(alt in sites[origin]['alts'])) {
        sites[origin]['alts'][alt] = {};
    }
    sites[origin]['alts'][alt] = {
        'onpreload': onPreload,
        'onionsig': validOnionSig,
    }
    ssput("altsvcs", sites);
    //log_object(sites);
}

async function onHeadersReceived_filterAltSvc(details) {
    let headers = details.responseHeaders;
    let origin = splitURL(details.url).hostname;

    let keptAltSvc = [];
    for (let as_ of getAltSvcHeaders(headers)) {
        let as = new AltSvc(as_);
        // If couldn't parse domain out of header, nothing to do
        if (!as.domain) {
            continue;
        }
        let shouldKeep = _shouldKeepAltSvcHeader(as, headers, origin);
        if (!shouldKeep) {
            log_debug('Not telling client about', as.domain);
            continue;
        }
        log_debug('Keeping alt-svc header for', as.domain);
        let onPreload = false;
        let preload = ssget("preload") || {};
        //log_debug(origin);
        //log_debug(as.domain);
        //log_object(preload[origin]['alts']);
        if (!(origin in preload)) {
            log_debug("origin not in preload");
        }
        else if (preload[origin]['alts'].indexOf(as.domain) < 0) {
            log_debug("alt not in preload");
        }
        else {
            onPreload = true;
        }
        let validOnionSig = false;
        if (typeof shouldKeep == 'boolean') {
            // do nothing
        } else {
            let onionSig = shouldKeep;
            validOnionSig = onionSig.validSig && onionSig.readAllBytes;
        }

        _storeAltSvcInState(origin, as.domain, onPreload, validOnionSig);
        keptAltSvc.push({'name': 'alt-svc', 'value': as.str});
    }

    return _returnWithSelectAltSvcHeaders(headers, keptAltSvc);
}

async function onHeadersReceived_verifySelfAuthConnection(details) {
    let url = splitURL(details.url);
    let secInfo = await browser.webRequest.getSecurityInfo(
        details.requestId, {"certificateChain": true, "rawDER": true});

    if (secInfo.state != "secure") {
        log_debug("Stopped considering", url.hostname, "becuase not",
            "a secure connection");
        return;
    }

    let onion = onion_v3extractFromPossibleAlliuminatedDomain(url.hostname);
    if (!onion) {
        log_debug("Stopped considering", url.hostname, "because not",
            "a self-authenticating domain name");
        return;
    }

    /*
     * At this point, we are visiting a satis domain name, but we known
     * nothing else.  We don't know if the proper domains are in the TLS
     * cert. We don't know if the SATIS HTTP header was provided. We don't
     * know if the SATIS HTTP header checks out.
     */

    let subject = getSubject(secInfo);
    let subjectAlts = getSubjectAlts(secInfo);
    let fingerprint = getFingerprint(secInfo);
    let responseHeaders = details.responseHeaders;

    let sigHeader = null;
    let err = null;

    let rightNames = certContainsProperNames(
        url.hostname, subject, subjectAlts);
    if (!rightNames) {
        err = "The TLS certificate doesn't have the proper " +
            "domains in the right places";
        return generateRedirect(sigHeader, url.hostname, fingerprint,
            err);
    }

    if (!log_assert(onion)) return;
    onion = new Onion(onion);

    sigHeader = getOnionSigHeader(responseHeaders);
    if (!sigHeader) {
        err = "The webserver didn't provide an onion sig header";
        return generateRedirect(sigHeader, url.hostname, fingerprint,
            err);
    }
    sigHeader = new OnionSig(nacl, onion, sigHeader);

    if (!sigHeader.validSig) {
        err  = "The sig in the onion sig header is not valid. " +
            "Either it is malformed or it was generated with " +
            "the wrong key.";
    } else if (!sigHeader.readAllBytes) {
        err = "The onion sig header had extra data.";
    } else if (!onionSigValidInTime(sigHeader, secInfo)) {
        err = "The Alliuminate signature is not considered valid at " +
            "this time.";
    } else if (fingerprint != sigHeader.fingerprint) {
        err = "The fingerprint in the TLS cert doesn't match the " +
            "one in the Alliuminate HTTP header.";
    } else if (url.hostname != sigHeader.domain) {
        err = "The domain in the Alliuminate HTTP header is not the " +
            "one we are visiting.";
    } else if (!sigHeader.validSig) {
        err = "The signature in the Alliuminate HTTP header didn't " +
            "check out.";
    }

    if (!!err) {
        return generateRedirect(sigHeader, url.hostname, fingerprint,
            err);
    }
}

function onMessage_giveAltSvcs(origin) {
    let sites = ssget("altsvcs") || {};
    if (origin in sites) {
        return sites[origin]['alts'];
    }
    return {};
}

function onMessage_satDomainList(obj) {
    let url = splitURL(obj.url);
    let list = Array.from(obj.set);
    log_debug("Found set of SAT domain mappings from", url.hostname);
    
    // Make sure we are visiting a SAT domain
    let onion = onion_v3extractFromPossibleAlliuminatedDomain(url.hostname);
    if (!onion) {
        log_debug("We are not currently visiting a SAT domain, so "+
            "ignoring mappings");
        return;
    }
    let baseDomain = onion_extractBaseDomain(url.hostname);
    onion = new Onion(onion);
    if (!onion) {
        log_debug("The domain looks like a SAT domain, but didn't parse "+
            "correctly. Ignoring set of mappings.");
        return;
    }

    // Only keep SAT domain --> T domain mappings
    // like [56char]onion.example.com --> example.com
    let keepList = [];
    for (mapping of list) {
        let from_name = mapping.from;
        let to_name = mapping.to;
        log_debug("Inspecting mapping from", from_name, "to", to_name);
        if (!from_name.endsWith(to_name)) {
            log_debug("Ignoring", from_name, "bc it doesn't end with", to_name);
            continue;
        }
        let o = onion_v3extractFromPossibleAlliuminatedDomain(from_name);
        if (!o) {
            log_debug("Ignoring", from_name, "bc it isn't a SAT domain (1)");
            continue;
        }
        o = onion = new Onion(o);
        if (!o) {
            log_debug("Ignoring", from_name, "bc it isn't a SAT domain (2)");
            continue;
        }
        log_debug("Keeping", from_name, "to", to_name);
        keepList.push(mapping);
    }
    list = keepList;
    if (list.length < 1) {
        log_debug("No valid mappings remain. Nothing to do");
        return "Thanks (unused 1)";
    }

    // Add it to the trusted storage if necessary
    let trustedSATLists = lsget("trustedSATLists") || {};
    let hash = sha3_256.create().update(new Uint8Array(url)).hex();
    if (!(hash in trustedSATLists)) {
        log_debug("Adding", url, "to trusted SAT lists");
        trustedSATLists[hash] = {
            "lastUpdate": Math.floor(Date.now() / 1000),
            "id": hash.slice(0, 8),
            "updateURL": obj.url,
            "list": list,
        };
        lsput("trustedSATLists", trustedSATLists);
        setTimeout(updateSATList, SAT_LIST_UPDATE_INTERVAL * 1000, hash);
        return "Thanks (used)";
    } else {
        log_debug("Already have mappings from this domain.");
        return "Thanks (unused 2)";
    }
}

function onMessage_giveTrustedSATLists(msg) {
    let d = lsget("trustedSATLists") || {};
    return d;
}

function onMessage(msg_obj, sender, responseFunc) {
    let id = msg_obj.id;
    let msg = msg_obj.msg;
    if (id == "giveAltSvcs") {
        responseFunc(onMessage_giveAltSvcs(msg));
    } else if (id == "giveTrustedSATLists") {
        responseFunc(onMessage_giveTrustedSATLists(msg));
    } else if (id == "satDomainList") {
        responseFunc(onMessage_satDomainList(msg));
    } else {
        log_error("Got message id we don't know how to handle.",
            "Ignoring: ", id);
    }
}

function addEventListeners() {
    browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived_filterAltSvc,
        {urls: ["<all_urls>"]},
        ["blocking", "responseHeaders"]
    );
    browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived_verifySelfAuthConnection,
        {urls: ["<all_urls>"]},
        ["blocking", "responseHeaders"]
    );
}

function updateSATList(hash) {
    let d = lsget("trustedSATLists") || {};
    if (!(hash in d)) {
        log_debug("List", hash, "not in trusted SAT list storage. "+
            "Nothing to do");
        return;
    }
    let listObj = d[hash];
    var xmlHttp = new XMLHttpRequest();
    xmlHttp.onreadystatechange = function() {
        if (xmlHttp.readyState == 4 && xmlHttp.status == 200) {
            let set = findSATDomainList(xmlHttp.responseXML);
            d = lsget("trustedSATLists") || {};
            d[hash].lastUpdate = Math.floor(Date.now() / 1000);
            d[hash].list = Array.from(set);
            log_debug("Updated list", hash);
            lsput("trustedSATLists", d);
        }
    }
    log_object(listObj.updateURL);
    xmlHttp.responseType = 'document';
    xmlHttp.open("GET", listObj.updateURL, true);
    xmlHttp.send();
    setTimeout(updateSATList, SAT_LIST_UPDATE_INTERVAL * 1000, hash);
}

function scheduleSATUpdates() {
    let d = lsget("trustedSATLists") || {};
    for (hash in d) {
        let listObj = d[hash];
        let now = new Date()
        let nextUpdate = new Date(
            (listObj.lastUpdate + SAT_LIST_UPDATE_INTERVAL) * 1000);
        let updateIn = nextUpdate - now;
        if (updateIn < 0) {
            updateIn = 0;
        }
        log_debug("Scheduling update of list", listObj.id, "in", updateIn/1000,
            "seconds");
        setTimeout(updateSATList, updateIn, hash);
    }
}

ssput("preload", preload);
lsput("trustedSATLists", {});
addEventListeners();
scheduleSATUpdates();
browser.runtime.onMessage.addListener(onMessage);
nacl_factory.instantiate(function (nacl_) {
    nacl = nacl_;
});
