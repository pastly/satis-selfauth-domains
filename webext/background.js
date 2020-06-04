var nacl = null;
var try_fetch = true;

var secInfoCache = {}
var waitingForMetaTag = {}

const SAT_LIST_UPDATE_INTERVAL = 3600; // seconds
const PERSONAL_LIST_HASH = sha3_256.create().update("personal").hex();

function getTrustedSatLists() {
    let d = lsget("trustedSATLists") || {};
    let out = {};
    for (hash in d) {
        let listObj = d[hash];
        if (!listObj.is_trusted || !listObj.is_enabled) {
            continue;
        }
        out[hash] = listObj;
    }
    return out;
}

function satListsContaining(domain) {
    let d = lsget("trustedSATLists") || {};
    let out = {};
    for (hash in d) {
        let listObj = d[hash];
        if (!listObj.is_trusted || !listObj.is_enabled) {
            continue;
        }
        for (item of listObj.list) {
            if (item.satName == domain) {
                out[hash] = listObj;
                break;
            }
        }
    }
    return out;
}

function certContainsProperNames(urlDomain, subject, subjectAlts) {
    let certDomains = subjectAlts;
    certDomains.push(subject);
    if (!log_assert(onion_v3extractFromPossibleSATDomain(urlDomain),
        "Should have already determined that urlDomain isn't ",
        "a SAT domain.")) {
        return false;
    }
    let urlBase = onion_extractBaseDomain(urlDomain);
    if (!log_assert(urlBase, "Should have been able to get the base ",
        "domain from SAT domain", urlDomain)) {
        return false;
    }
    if (!certDomains.includes(urlBase)) {
        log_debug("Cert does not contain proper names because urlBase",
            urlBase, "does not match the subject", subject);
        return false;
    }

    let settings = lsget("settings") || new Settings();
    if (settings.wildcardSATDomainsAllowed &&
            !certDomains.includes(urlDomain)) {
        /* Rollout relaxation and setting: allow SAT domain to be covered by a
         * wildcard, if the user chooses.
         */
        let wildcard = "*" + urlDomain.substr(urlDomain.indexOf("."));
        log_debug("Checking if", wildcard,
            "is in certificate (covers the SAT doamin)");
        if (!certDomains.includes(wildcard)) {
            log_error(
                "Cert does not contain the SAT domain nor a wildcard covering",
                "it. This should be impossible.");
            return false;
        } else {
            // Yes the user wants to allow a wildcard to cover a SAT domain,
            // and such wildcard exists in the certificate
        }
    } else {
        // Yes the certificate contains the SAT domain exactly
    }

    log_debug("TLS cert contains all proper names for this SAT domain");
    return true;
}

function generateRedirect_badSigEtc(
        satisHeaderValue, urlHostname, tlsFingerprint, errorMessage) {
    let pageURL = browser.extension.getURL("pages/badSigEtc.html");
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

function generateRedirect_notOnTrustedSATList(urlHostname) {
    let pageURL = browser.extension.getURL("pages/notOnTrustedSATList.html");
    pageURL = addParam(pageURL, "domain", urlHostname);
    return { "redirectUrl": pageURL };
}

function generateRedirect_nullSetAttestedLabel(urlHostname, selfLabels, satLabels, errorMessage) {
    let pageURL = browser.extension.getURL("pages/nullSetAttestedLabel.html");
    pageURL = addParam(pageURL, "domain", urlHostname);
    pageURL = addParam(pageURL, "selfLabels", selfLabels);
    pageURL = addParam(pageURL, "satLabels", satLabels);
    pageURL = addParam(pageURL, "error", errorMessage);
    return { "redirectUrl": pageURL };
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
 * Determine if the given alt-svc is a SAT domain or onion service, and if so,
 * if there is a valid onion sig.
 *
 * - If not a SAT domain or onion service, return true
 * - If a SAT domain or onion service and no onion sig header, return false
 * - If a SAT domain or onion service and something doesn't check out, return
 * false
 * - If a SAT domain or onion service and everything checks out, return the
 *   onionSig object
 */
function _extractOnionSigForPossibleSATAltSvc(as, headers, origin, secInfo) {
    let settings = lsget("settings") || new Settings();
    let onion = null;
    let isSATDomain = false;
    let isOnionDomain = false;
    // Is it a sat domain name?
    if (as.domain) {
        onion = onion_v3extractFromPossibleSATDomain(as.domain);
        if (!onion) {
            // Is it a v3 onion?
            onion = onion_v3extractFromPossibleOnionDomain(as.domain);
            if (onion) {
                isOnionDomain = true;
            }
        } else {
            isSATDomain = true;
        }
    } else {
        // No domain, so can't be either SAT or v3 onion
    }

    // Not either
    if (!onion) {
        return true;
    }
    onion = new Onion(onion);

    /*
     * There's an AltSvc header and it is either for a .onion or an
     * SAT domain name.  We now expect a signature from the onion
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
        log_debug("Alt-Svc is a SAT domain or .onion but no onion sig",
            "header.");
        return false;
    }

    /*
     * If we have an SAT domain name, it should be in the signature exactly.
     *
     * But if we have an onion domain like [56chars].onion, then we need to
     * take the friendly domain (foo.com), combine it with the onion in the
     * alt-svc header, and look for the result ([56chars]onion.foo.com) in the
     * onion sig header.
     *
     * Instead of combining the two, we could rework the server side a little
     * bit: (1) have Tor generate multiple onion sigs or not include the full
     * SAT name in the signed data. (2) make changes to the nginx
     * template.
     *
     * I think doing that is harder and not not necessarily even better.
     */
    if (isSATDomain && onionSig.domain != as.domain) {
        log_debug("The onion sig header is for a different domain",
            "than the one in the alt-svc header. Not giving",
            "the alt-svc header to the user. (",
            onionSig.domain, "vs", as.domain, ")");
        return false;
    } else if (isOnionDomain &&
               (origin != onionSig.domain && onion.str + "onion." + origin != onionSig.domain)) {
        log_debug("The onion sig header contains", onionSig.domain,
            "but we are looking for", onion.str + "onion." + origin,
            "so we are not giving it to the user.");
        return false;
    }

    /*
     * Require the current time to be within the validity window in the onion
     */
    if (!onionSigValidInTime(onionSig, secInfo)) {
        let start = new Date(1000*(onionSig.timeCenter - onionSig.timeWindow/2));
        let end = new Date(1000*(onionSig.timeCenter + onionSig.timeWindow/2));
        let now = new Date();
        log_debug("The onion sig header is not currently valid. It is valid",
            "from", start, "to", end, "but it is currently", now);
        return false;
    }

    /* If the AltSvc is a SAT domain and the user has this option enabled,
     * check that it is in the TLS certificate */
    if (isSATDomain && !settings.satAltSvcNotInTLSCertAllowed) {
        log_debug("SAT domain Alt-Svc must be in TLS cert. Checking ...")
        if (!log_assert(secInfo, "We must have securityInfo API")) {
            return false;
        }
        let certDomains = getSubjectAlts(secInfo);
        certDomains.push(getSubject(secInfo));
        if (!certDomains.includes(as.domain)) {
            log_debug("SAT domain Alt-Svc not in TLS cert. Not using it");
            return false;
        } else {
            log_debug("SAT domain Alt-Svc is in TLS cert.");
        }
    }

    /* If the AltSvc is a SAT domain, check that the trad. domain part is in
     * the TLS certificate */
    if (isSATDomain) {
        let baseDomain = onion_extractBaseDomain(as.domain);
        log_debug(
            "SAT domain Alt-Svc must have trad. domain part (", baseDomain,
            ") in TLS cert. Checking ...");
        let certDomains = getSubjectAlts(secInfo);
        certDomains.push(getSubject(secInfo));
        if (!certDomains.includes(baseDomain)) {
            log_debug("Trad. domain part is not in TLS cert. Not using it");
            return false;
        } else {
            log_debug("Trad. domain part is in TLS cert.");
        }
    }

    return onionSig;
}

async function tryGetSecurityInfo(reqId) {
    let secInfo = null;
    try {
        secInfo = await browser.webRequest.getSecurityInfo(
            reqId, {"certificateChain": true, "rawDER": true});
    } catch (e) {
        if (e instanceof TypeError) {
            log_debug(
                "Caught exception trying to get securityInfo, assuming we",
                "don't have that API in the browser:", e);
            return null;
        } else {
            throw e;
        }
    }
    return secInfo;
}

function _storeAltSvcInState(
        origin, alt, validOnionSig, userTrusts, userDistrusts) {
    let sites = lsget("altsvcs") || {};
    if (!(origin in sites)) {
        sites[origin] = {
            'alts': {},
        };
    }
    if (!(alt.str in sites[origin]['alts'])) {
        sites[origin]['alts'][alt.str] = {};
    }
    sites[origin]['alts'][alt.str] = {
        'alt': alt,
        'validOnionSig': validOnionSig,
        'userTrusts': userTrusts,
        'userDistrusts': userDistrusts,
    }
    lsput("altsvcs", sites);
}

async function onHeadersReceived_filterAltSvc(details) {
    let headers = details.responseHeaders;
    let origin = splitURL(details.url).hostname;
    let secInfo = await tryGetSecurityInfo(details.requestId);

    let sites = lsget("altsvcs") || {};
    let keptAltSvc = [];
    for (let as_ of getAltSvcHeaders(headers)) {
        let as = new AltSvc(as_);
        // First, store it if we don't have it yet.
        if (!(origin in sites)) {
            sites[origin] = {'alts': {}};
        }
        if (!(as.str in sites[origin].alts)) {
            log_debug("Adding", as.str, "to", origin, "'s list of known altsvcs");
            sites[origin].alts[as.str] = {
                'alt': as,
                'validOnionSig': false,
                'userTrusts': false,
                'userDistrusts': false,
            };
        }
        // Make sure user either only trusts (and not distrusts), only
        // distrusts (and not trusts), or neither trusts nor distrusts
        //
        // This condition is a lot to unpack ...
        // - trusts and userDistrusts can't both be true. That's the condition
        // inside the assert. If this fails, the string is logged.
        // - log_assert returns the result of the condition
        // - and we negate the returned result, so that if the result is false,
        // we execute the body of this if statement.
        //
        // This works out to essentially
        //     if (!log_assert(!bad, "log message")) { / * ... */ }
        //     ==> if (!!bad) { /* ... */ }
        //     ==> if (bad) { /* ... */ }
        let trusts = sites[origin].alts[as.str].userTrusts;
        if (!log_assert(
                !(trusts && sites[origin].alts[as.str].userDistrusts),
                "User both trusts and distrusts this altsvc. Failing safe.")) {
            trusts = false;
        }
        // Only keep the alt-svc if the user trusts it
        if (trusts) {
            log_debug("Keeping Alt-Svc", as.str, "for origin", origin);
            keptAltSvc.push({'name': 'alt-svc', 'value': as.str});
        } else {
            log_debug("Removing Alt-Svc", as.str, "for origin", origin);
        }
        // Check the onion sig header, if any
        let onionSig = _extractOnionSigForPossibleSATAltSvc(
            as, headers, origin, secInfo);
        if (typeof onionSig == 'boolean' && onionSig) {
            // returning true means the alt-svc is not a SAT domain or onion
            // service, don't do anything special
        } else if (typeof onionSig == 'boolean' && !onionSig) {
            // returning false means it is a SAT domain or onion service, but
            // something was wrong (missing onion sig, or it didn't verify
            // correctly). Set validOnionSig to false
            sites[origin].alts[as.str].validOnionSig = false;
        } else {
            // Otherwise it returned the onionSig object
            sites[origin].alts[as.str].validOnionSig = onionSig.validSig && onionSig.readAllBytes;
        }
    }
    lsput("altsvcs", sites);
    return _returnWithSelectAltSvcHeaders(headers, keptAltSvc);
}

async function onHeadersReceived_verifySelfAuthConnection(details) {
    let url = splitURL(details.url);
    let secInfo = await tryGetSecurityInfo(details.requestId);

    if (!log_assert(secInfo, "We must have securityInfo API")) {
        return;
    }

    if (secInfo.state != "secure") {
        log_debug("Stopped considering", url.hostname, "becuase not",
            "a secure connection");
        return;
    }

    let isSatDomain = false;
    let onion = onion_v3extractFromPossibleSATUrl(url);
    if (!onion) {
        log_debug(`Self-authenticating url not found in ${url}`);
        onion = onion_v3extractFromPossibleSATDomain(url.hostname);
        if (!onion) {
            log_debug("Stopped considering", url.hostname, "because not",
                "a self-authenticating domain name");
            return;
        }
        isSatDomain = true;
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

    let hostname = url.hostname;
    if (!isSatDomain) {
        hostname = `${onion}onion.${hostname}`;
    }
    let rightNames = certContainsProperNames(
        hostname, subject, subjectAlts);
    if (!rightNames) {
        err = "The TLS certificate doesn't have the proper " +
            "domains in the right places";
        return generateRedirect_badSigEtc(sigHeader, url.hostname, fingerprint,
            err);
    }

    if (!log_assert(onion)) return;
    onion = new Onion(onion);

    sigHeader = getOnionSigHeader(responseHeaders);
    if (!sigHeader) {
        if (details.satSig) {
            sigHeader = details.satSig;
        } else {
            err = "The webserver didn't provide an onion sig header";
            if (details.url in waitingForMetaTag && waitingForMetaTag[details.url]) {
                delete waitingForMetaTag[details.url];
                return generateRedirect_badSigEtc(sigHeader, url.hostname, fingerprint,
                    err);
            } else {
                waitingForMetaTag[details.url] = true;
                return;
            }
        }
    }
    log_debug("sigHeader: ", sigHeader);
    sigHeader = new OnionSig(nacl, onion, sigHeader);

    if (!sigHeader.validSig) {
        err  = "The sig in the onion sig header is not valid. " +
            "Either it is malformed or it was generated with " +
            "the wrong key.";
    } else if (!sigHeader.readAllBytes) {
        err = "The onion sig header had extra data.";
    } else if (!onionSigValidInTime(sigHeader, secInfo)) {
        err = "The SAT domain signature is not considered valid at " +
            "this time.";
    } else if (fingerprint != sigHeader.fingerprint) {
        err = "The fingerprint in the TLS cert doesn't match the " +
            "one in the SAT HTTP header.";
    } else if (url.hostname != sigHeader.domain && hostname != sigHeader.domain) {
        err = "The domain in the SAT HTTP header is not the " +
            "one we are visiting.";
    } else if (!sigHeader.validSig) {
        err = "The signature in the SAT HTTP header didn't " +
            "check out.";
    }

    if (!!err) {
        log_error(err);
        return generateRedirect_badSigEtc(sigHeader, url.hostname, fingerprint,
            err);
    }

    let attestedSat = onHeadersReceived_allowAttestedSATDomainsOnly(details);

    // attestedSat is:
    //   undefined if this connection should not consider sattestation
    //   true if it is sattested
    //   Object with a 'redirectUrl' property if it failed validation
    if (attestedSat && attestedSat === true) {
        if (sigHeader.isV1) {
            let lists = satListsContaining(url.hostname);
            if (!lists) {
                err = "Null sattestors list";
            }

            let selfLabels = sigHeader.labels;
            let sattestedLabels = [];

            for (let sattestor in lists) {
                sattestedLabels.push.apply(sattestor.labels);
            }
            let foundMatch = false;
            for (let label of selfLabels) {
                if (label === "*") {
                    foundMatch = true;
                    break;
                }

                if ("*" in sattestedLabels) {
                    foundMatch = true;
                    break;
                }
                if (label in sattestedLabels) {
                    foundMatch = true;
                    break;
                }
            }

            if (!foundMatch) {
                err = "Label sets agreement not found.";
            }

            if (!!err) {
                return generateRedirect_nullSetAttestedLabel(url.hostname, selfLabels, sattestedLabels, err);
            }
        } else {
            return attestedSat;
        }
    }
}

function onHeadersReceived_allowAttestedSATDomainsOnly(details) {
    let d = lsget("settings") || new Settings();
    if (!d.attestedSATDomainsOnly)
        return;
    let url = splitURL(details.url);
    // When the user visits a non-SAT domain, do nothing special. This only
    // ever applies to SAT domains.
    let onion = onion_v3extractFromPossibleSATUrl(url);
    if (!onion) {
        log_debug(`Self-authenticating url not found in ${url}`);
        onion = onion_v3extractFromPossibleSATDomain(url.hostname);
        if (!onion) {
            log_debug("Stopped considering", url.hostname, "because not",
                "a self-authenticating domain name");
            return;
        }
    }

    // The option is enabled if we've gotten here, and we are visiting a SAT
    // domain. The user only wants to visit a SAT domain if it is attested for
    // on a list of theirs.  All this function needs to do is make sure the
    // domain is on a trusted SAT list. Another event handler will do the
    // checks to make sure the onion sig is present and checks out with the TLS
    // certificate.
    //
    // If there's zero list hashes in the returned object, then we will look for
    // a credential in the HTTP headers.
    let lists = satListsContaining(url.hostname);
    if (hash in lists) {
        log_debug("So far we are allowing", url.hostname, "because it",
            "appears in list", lists[hash].name);
        return true;
    }

    let b64TokenHeaders = getSatTokenHeaders(details.responseHeaders);
    for (let b64TokenHeader of b64TokenHeaders) {
        try {
            tokenHeaderAsBytes = window.atob(b64TokenHeader);
        } catch (err) {
            log_debug("Exception in atob(): ", err);
            continue;
        }
        let lightlyParsed = lightlyParseSatJSON(tokenHeaderAsBytes);
        let taggedUnparsedContent = "sattestation-list-v0" + lightlyParsed.unparsedContent;

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

        let parsedContent;
        let trustedSatList = getTrustedSatLists();
        for (let sat in trustedSatList) {
            log_debug(`Validating credential using ${sat.name}`);
            if (sat.list.length === 0) {
                continue;
            }
            let satName = sat.list[0].satName;
            let o = onion_v3extractFromPossibleSATDomain(satName);
            if (!o) {
                log_debug(`${satName} is not a sata`);
                continue;
            }
            let onion = new Onion(o);
            if (!o) {
                log_debug(`${satName} does not start with a valid onion address`);
                continue;
            }
            parsedContent = validateAndParseJson(contentAsBytes, taggedUnparsedContent, sigAsBytes, onion);
            if (parsedContent) {
                log_debug(`${satName} validates credential`);
                break;
            }

            log_debug(`${satName} does not validate credential`);
        }

        if (parsedContent) {
            let expectedTokenProperties = ["sat_list_version", "sattestor",
                "sattestor_onion", "sattestor_labels", "sattestee", "sattestee_onion",
                "sattestee_labels", "valid_after"];
            let badProp = false;
            for (let prop of expectedTokenProperties) {
                if (! prop in parsedContent) {
                    log_debug(`Token missing ${prop}. Malformed.`);
                    badProp = true;
                    break;
                }
            }

            if (badProp) {
                continue;
            }

            if (parsedContent.sat_list_version !== 1) {
                log_debug("Token version is not 1.");
                continue;
            }

            if (parsedContent.sattestee != url.hostname) {
                log_debug(`Token sattestee (${parsedContent.sattestee}) is not this site.`);
                continue;
            }

            let validAfter = Date.parse(parsedContent.valid_after);
            let secondsValid = Date.now() - validAfter;
            // Roughly, within a few days.
            let threeMonths = 60*60*24*30*3;

            if (secondValid < 0) {
                log_debug(`Token valid_after (${parsedContent.valid_after}) is yet valid.`);
                continue;
            }

            if (validSeconds > threeMonths) {
                log_debug(`Token valid_after (${parsedContent.valid_after}) is expired.`);
                continue;
            }

            log_debug("Provided token is valid");
            return true;
        }
    }

    log_debug(url.hostname, "is not on any trusted SAT list so disallowing");

    return generateRedirect_notOnTrustedSATList(url.hostname);

}

async function onHeadersReceived_cacheSecurityInfo(details) {
    let url = details.url
    secInfoCache[url] = details
    secInfoCache[url].secInfo = await tryGetSecurityInfo(details.requestId);
}

function findRewriteSATDomain(baseDomain) {
    let d = lsget("trustedSATLists") || {};
    for (h in d) {
        let listObj = d[h];
        if (!listObj.is_enabled || !listObj.do_rewrite) {
            continue;
        }
        let match = listObj.list.find(function(i) {return i.baseName == baseDomain});
        if (!match) {
            continue;
        }
        let satDomain = match.satName;
        return satDomain;
        let newUrl = url.href.replace(match.baseName, match.satName);
        return newUrl;
    }
    return null;
}

function onBeforeRequest_rewriteSATDomains(details) {
    log_debug("onBeforeRequest: requestId: ", details.requestId);
    log_debug("onBeforeRequest: url: ", details.url);
    return new Promise((resolve, reject) => {
        try {
            let url = splitURL(details.url);
            let satDomain = findRewriteSATDomain(url.hostname);
            if (satDomain) {
                let newUrl = url.href.replace(url.hostname, satDomain);
                resolve({"redirectUrl": newUrl});
            } else {
                resolve({"cancel": false});
            }
        } catch (e) {
            log_error(e);
            reject(e);
        }
    });
}

function onBeforeRequest_cacheOnionAddressConnection(details) {
    log_debug("onBeforeRequest: requestId: ", details.requestId);
    log_debug("onBeforeRequest: url: ", details.url);
    return new Promise((resolve, reject) => {
        try {
            let url = splitURL(details.url);

            let onion = onion_v3extractFromPossibleSATDomain(url.hostname);
            if (!onion) {
                log_debug("Stopped considering", url.hostname, "because not",
                    "a self-authenticating domain name");
                resolve({"cancel": false});
            } else if (`${onion}.onion` == onion_extractBaseDomain(url.hostname)) {
                log_debug("Stopped considering", url.hostname, "because not",
                    "a self-authenticating domain name - it's a raw onion address");
                resolve({"cancel": false});
            } else {
                console.log(`onion: ${onion}`);

                //if (!try_fetch) {
                //    log_debug("We're looping.");
                //    resolve({"cancel": true});
                //}
                fetch("https://www.sysrqb.xyz", {method: 'GET', credentials: 'omit'})
                  .then((response) => {
                    if (response.ok) {
                      console.log(`Successful response from ${onion}`);
                    } else {
                      console.log(`Failure response from ${onion}`);
                    }
                  })
                  .catch((error) => {
                    console.log(`Exception thrown: ${error}`);
                  });
                try_fetch = false;

                resolve({"cancel": false});
            }
        } catch (e) {
            log_error(e);
            reject(e);
        }
    });
}

function onMessage_giveAltSvcs(origin) {
    let sites = lsget("altsvcs") || {};
    if (origin in sites) {
        return sites[origin]['alts'];
    }
    return {};
}

function onMessage_satDomainList(obj) {
    let url = splitURL(obj.url);
    let list = Array.from(obj.set);
    let wellknown = obj.wellknown;
    let satUrl = obj.satUrl;
    let hostname = url.hostname;
    log_debug("Found set of SAT domain mappings from", url.hostname);

    // Make sure we are visiting a SAT domain
    let onion = onion_v3extractFromPossibleSATUrl(url);
    if (!onion) {
        log_debug(`Self-authenticating url not found in ${url}`);
        onion = onion_v3extractFromPossibleSATDomain(url.hostname);
        if (!onion) {
            log_debug("We are not currently visiting a SAT domain, so "+
                "ignoring mappings");
            return;
        }
    } else {
        // Use canonical subdomain
        hostname = `${onion}onion.${hostname}`;
    }

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
        let satName = mapping.satName;
        let baseName = mapping.baseName;
        let labels = mapping.labels;
        log_debug("Inspecting mapping from", satName, "to", baseName);
        if (!satName.endsWith(baseName)) {
            log_debug("Ignoring", satName, "bc it doesn't end with", baseName);
            continue;
        }
        let o = onion_v3extractFromPossibleSATDomain(satName);
        if (!o) {
            log_debug("Ignoring", satName, "bc it isn't a SAT domain (1)");
            continue;
        }
        o = onion = new Onion(o);
        if (!o) {
            log_debug("Ignoring", satName, "bc it isn't a SAT domain (2)");
            continue;
        }
        log_debug("Keeping", satName, "to", baseName, "with labels", labels);
        keepList.push(mapping);
    }
    list = keepList;
    if (list.length < 1) {
        log_debug("No valid mappings remain. Nothing to do");
        return "Thanks (unused 1)";
    }

    // Add it to the trusted storage if necessary
    let trustedSATLists = lsget("trustedSATLists") || {};
    let hash = sha3_256.create().update(hostname).hex();
    if (!(hash in trustedSATLists)) {
        log_debug("Adding", hostname, "to trusted SAT lists");
        let updateUrl = hostname;
        if (wellknown) {
            updateUrl = updateUrl + "/.well-known/sattestation.json";
        }
        if (satUrl) {
            updateUrl = updateUrl + "?onion=" + onion.onion;
        }
        trustedSATLists[hash] = new SATList(
            updateUrl, list, false, false, false, null,
            onion_extractBaseDomain(hostname), wellknown, satUrl);
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

function onMessage_giveTrustedSATListsContaining(msg) {
    return satListsContaining(msg);
}

function onMessage_setSATDomainListName(msg) {
    let d = lsget("trustedSATLists") || {};
    if (!(msg.hash in d)) {
        log_error("Asked to set SAT domain list name", msg.name, "for id",
            msg.hash, "but we don't know about that list");
        return false;
    }
    d[msg.hash].name = msg.name;
    lsput("trustedSATLists", d);
    return true;
}

function onMessage_setSATDomainListTrusted(msg) {
    let d = lsget("trustedSATLists") || {};
    if (!(msg.hash in d)) {
        log_error("Asked to set SAT domain list is_trusted", msg.trusted,
            "for id", msg.hash, "but we don't know about that list");
        return false;
    }
    log_debug("Setting is_trusted to", msg.trusted);
    log_debug("Setting is_enabled to", msg.trusted);
    d[msg.hash].is_trusted = msg.trusted;
    d[msg.hash].is_enabled = msg.trusted;
    if (!msg.trusted) {
        log_debug("Setting do_rewrite to", msg.trusted);
        d[msg.hash].do_rewrite = msg.trusted;
    }
    lsput("trustedSATLists", d);
    return true;
}

function onMessage_setSATDomainListEnabled(msg) {
    let d = lsget("trustedSATLists") || {};
    if (!(msg.hash in d)) {
        log_error("Asked to set SAT domain list is_enabled", msg.enabled,
            "for id", msg.hash, "but we don't know about that list");
        return false;
    }
    log_debug("Setting is_enabled to", msg.enabled);
    d[msg.hash].is_enabled = msg.enabled;
    if (!msg.enabled) {
        log_debug("Setting do_rewrite to", msg.enabled);
        d[msg.hash].do_rewrite = msg.enabled;
    }
    lsput("trustedSATLists", d);
    return true;
}

function onMessage_setSATDomainListRewrite(msg) {
    let d = lsget("trustedSATLists") || {};
    if (!(msg.hash in d)) {
        log_error("Asked to set SAT domain list do_rewrite", msg.rewrite,
            "for id", msg.hash, "but we don't know about that list");
        return false;
    }
    log_debug("Setting do_rewrite to", msg.rewrite);
    d[msg.hash].do_rewrite = msg.rewrite;
    lsput("trustedSATLists", d);
    return true;
}

function onMessage_deleteSATDomainList(msg) {
    let d = lsget("trustedSATLists") || {};
    if (!(msg.hash in d)) {
        log_error("Asked to delete SAT domain list id", msg.hash,
            "but we don't know about that list");
        return false;
    }
    delete d[msg.hash];
    lsput("trustedSATLists", d);
    return true;
}

function onMessage_giveCurrentSettings(msg) {
    let d = lsget("settings") || new Settings();
    return d;
}

function onMessage_setSetting(msg) {
    let d = lsget("settings") || new Settings();
    let v = msg['value'];
    switch (msg.key) {
        case "attestedSATDomainsOnly":
        case "wildcardSATDomainsAllowed":
        case "satAltSvcNotInTLSCertAllowed":
            log_debug("Set", msg.key, "to", v);
            d[msg.key] = v;
            break;
        default:
            log_debug("Unknown setting key:", msg.key);
            return false;
    }
    lsput("settings", d);
    return true;
}

function onMessage_setAltSvcTrusted(msg) {
    let sites = lsget("altsvcs") || {};
    let origin = msg.origin;
    let altstr = msg.altstr;
    let trusted = msg.trust;
    if (!(origin in sites)) {
        log_debug(
            "Unknown origin", origin, "cannot set trust of altsvc", altstr);
        return false;
    }
    if (!(altstr in sites[origin].alts)) {
        log_debug(
            "Unknown altsvc", altstr, "for origin", origin,
            "cannot set trust");
        return false;
    }
    sites[origin].alts[altstr].userTrusts = trusted;
    sites[origin].alts[altstr].userDistrusts = !trusted;
    lsput("altsvcs", sites);
    return true;
}

function onMessage_addPersonalSATListItem(msg) {
    let sat = msg.sat.trim();
    if (sat.startsWith("http://") || sat.startsWith("https://")) {
        // Remove first 7 chars (may be a leftover "/" if https)
        sat = sat.substring("http://".length);
        // Remove leading "/", if it exists
        if (sat.charAt(0) == "/") {
            sat = sat.substring(1);
        }
    }
    // Remove everything after the domain, if the user gave a URL.
    // So if we have aaaaonion.foo.com/index.html, remove /index.html
    if (sat.includes("/")) {
        sat = sat.substring(0, sat.indexOf("/"))
    }
    let is_sat = !!onion_v3extractFromPossibleSATDomain(sat);
    if (!is_sat) {
        log_error(sat, "is not a SAT domain");
        return;
    }
    let base = onion_extractBaseDomain(sat);
    if (!base) {
        log_error("Unabled to get base domain from", sat);
        return;
    }
    if (!sat.endsWith(base)) {
        log_error("SAT domain", sat, "does not end with", base);
        return;
    }
    let d = lsget("trustedSATLists") || {};
    let hash = PERSONAL_LIST_HASH;
    if (!log_assert(hash in d, "Cannot find personal SAT list")) {
        return;
    };
    let listObj = d[hash];
    let matches = listObj.list.filter(function(i) {
        return i.satName == sat && i.baseName == base;
    });
    if (matches.length > 0) {
        log_debug("Already have this personal sat list entry. Ignoring");
        return;
    }
    listObj.list.push({'satName': sat, 'baseName': base});
    d[hash] = listObj;
    lsput("trustedSATLists", d);
    return;
}

function onMessage_deletePersonalSATListItem(msg) {
    let d = lsget("trustedSATLists") || {};
    let hash = PERSONAL_LIST_HASH;
    if (!log_assert(hash in d, "Cannot find personal SAT list")) {
        return false;
    };
    let listObj = d[hash];
    listObj.list = listObj.list.filter(function (i) {
        return i.satName != msg.item.satName || i.baseName != msg.item.baseName;
    });
    d[hash] = listObj;
    lsput("trustedSATLists", d);
    return true;
}

async function onMessage_metaSatSignatureFound(msg) {
    // Abuse the onHeaderReceived listener
    let details = secInfoCache[msg.url];
    if (!details) {
        log_debug("Cached SecInfo not found");
        return;
    }
    details.satSig = msg.satSig;
    return onHeadersReceived_verifySelfAuthConnection(details);
}

async function onMessage_validateParseSattestation(msg) {
    let parsed = validateAndParseSattestation(msg);
    if (!parsed) {
        return;
    }
    let satSet = handleSattestations(parsed);
    if (!satSet) {
        return;
    }
    log_debug(onMessage_satDomainList(satSet));
}

async function onMessage_parseUrl(msg) {
    log_debug("in parseUrl: " + msg);
    let url = splitURL(msg.url);
    let onion = onion_v3extractFromPossibleSATUrl(url);
    if (!onion) {
        log_debug(`Self-authenticating url not found in ${url}`);
        onion = onion_v3extractFromPossibleSATDomain(url.hostname);
        if (!onion) {
            log_debug("Stopped considering", url.hostname, "because not",
                "a self-authenticating domain name");
            return;
        }
    }

    msg.onion = onion;
    return msg;
}

function onMessage(msg_obj, sender, responseFunc) {
    let id = msg_obj.id;
    let msg = msg_obj.msg;
    if (id == "giveAltSvcs") {
        responseFunc(onMessage_giveAltSvcs(msg));
    } else if (id == "giveTrustedSATLists") {
        responseFunc(onMessage_giveTrustedSATLists(msg));
    } else if (id == "giveTrustedSATListsContaining") {
        responseFunc(onMessage_giveTrustedSATListsContaining(msg));
    } else if (id == "giveCurrentSettings") {
        responseFunc(onMessage_giveCurrentSettings(msg));
    } else if (id == "setSetting") {
        responseFunc(onMessage_setSetting(msg));
    } else if (id == "satDomainList") {
        responseFunc(onMessage_satDomainList(msg));
    } else if (id == "setSATDomainListName") {
        responseFunc(onMessage_setSATDomainListName(msg));
    } else if (id == "setSATDomainListTrusted") {
        responseFunc(onMessage_setSATDomainListTrusted(msg));
    } else if (id == "setSATDomainListEnabled") {
        responseFunc(onMessage_setSATDomainListEnabled(msg));
    } else if (id == "setSATDomainListRewrite") {
        responseFunc(onMessage_setSATDomainListRewrite(msg));
    } else if (id == "deleteSATDomainList") {
        responseFunc(onMessage_deleteSATDomainList(msg));
    } else if (id == "setAltSvcTrusted") {
        responseFunc(onMessage_setAltSvcTrusted(msg));
    } else if (id == "addPersonalSATListItem") {
        responseFunc(onMessage_addPersonalSATListItem(msg));
    } else if (id == "deletePersonalSATListItem") {
        responseFunc(onMessage_deletePersonalSATListItem(msg));
    } else if (id == "metaSatSignature") {
        responseFunc(onMessage_metaSatSignatureFound(msg));
    } else if (id == "validateParseSattestation") {
        responseFunc(onMessage_validateParseSattestation(msg));
    } else if (id == "parseUrl") {
        responseFunc(onMessage_parseUrl(msg));
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
    //browser.webRequest.onHeadersReceived.addListener(
    //    onHeadersReceived_allowAttestedSATDomainsOnly,
    //    {urls: ["<all_urls>"]},
    //    ["blocking", "responseHeaders"]
    //);
    browser.webRequest.onHeadersReceived.addListener(
        onHeadersReceived_cacheSecurityInfo,
        {urls: ["<all_urls>"]},
        ["blocking", "responseHeaders"]
    );
    browser.webRequest.onBeforeRequest.addListener(
        onBeforeRequest_rewriteSATDomains,
        {urls: ["<all_urls>"]},
        ["blocking"]
    );
    //browser.webRequest.onBeforeRequest.addListener(
    //    onBeforeRequest_cacheOnionAddressConnection,
    //    {urls: ["<all_urls>"]},
    //    ["blocking"]
    //);
}

function updateSATList(hash) {
    let d = lsget("trustedSATLists") || {};
    if (!(hash in d)) {
        log_debug("List", hash, "not in trusted SAT list storage. "+
            "Nothing to do");
        return;
    }

    let listObj = d[hash];
    if (!log_assert(
            !listObj.is_personal,
            "Refusing to attempt update of personal list")) {
        return;
    }

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
        if (listObj.is_personal) {
            continue;
        }
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

function ensurePersonalSATList() {
    let d = lsget("trustedSATLists") || {};
    let hash = PERSONAL_LIST_HASH;
    if (!(hash in d)) {
        log_warn("Creating blank personal SAT mapping list");
        d[hash] = new SATList(
            "personal", [], true, true, true, 0, "Personal");
    }
    d[hash].is_personal = true;
    lsput("trustedSATLists", d);
}

//lsput("trustedSATLists", {});
//lsput("altsvcs", {});
addEventListeners();
scheduleSATUpdates();
ensurePersonalSATList();
browser.runtime.onMessage.addListener(onMessage);
nacl_factory.instantiate(function (nacl_) {
    nacl = nacl_;
});
