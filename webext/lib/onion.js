class Onion {
    constructor(onionstr) {
        if (!log_assert(onion_v3valid(onionstr), `invalid onion str ${onionstr}`))
            return;
        let o = onion_v3decode(onionstr);
        log_assert(o);
        this.pubkey = o.pubkey;
        this.checksum = o.checksum;
        this.version = o.version;
        this.str = o.str;
    }
}

/**
 * Takes a 56 char onion address (without the "onion" suffix)
 * and determines whether or not it is valid. If invalid, return null.
 * If valid, return the decoded info.
 */
function onion_v3decode(onionstr) {
    // "Assert" on these things because they should have been validated already
    if (!log_assert(onionstr.length == 56, "Invalid v3 onion string (length)"))
        return null;
    bytes = base32.decode(onionstr);
    if (!log_assert(bytes.length == 35, "Invalid v3 onion string (bytes length)"))
        return null;
    let pubkey = bytes.slice(0,32);
    let checksum1 = bytes.slice(32,34);
    let version = bytes.slice(34);
    // Last byte (version) must be three
    if (version != 3) {
        log_debug("Invalid version", bytes.slice(-1));
        return null;
    }
    // Checksum must be valid
    let checksum2 = sha3_256.create();
    checksum2.update(".onion checksum")
        .update(new Uint8Array(pubkey))
        .update(new Uint8Array(version));
    checksum2 = checksum2.array().slice(0, 2);
    if (checksum1[0] != checksum2[0] || checksum1[1] != checksum2[1]) {
        log_debug("Invalid v3 onion string (checksum)", checksum1, checksum2);
        return null;
    }
    return {
        pubkey: pubkey,
        checksum: checksum1,
        version: version,
        str: onionstr
    }
}

/**
 * Takes a 56 char onion address (without the "onion" suffix) and determines
 * whether or not it is valid. Returns true if valid, false otherwise
 */
function onion_v3valid(onionstr) {
    return !!onion_v3decode(onionstr);
}

/**
 * Given a domain name, extract the onion address (without the "onion" suffix)
 * from it, if any and if in the right position. Otherwise, return null.
 *
 * Returns [56chars] from domains like [56chars]onion.foo.com, otherwise
 * returns null.
 */
function onion_v3extractFromPossibleSATDomain(domain) {
    let rightNumPeriods = (domain.match(/\./g) || []).length >= 2;
    if (!rightNumPeriods)
        return null;
    let rightLength = domain.indexOf(".") == 56 + "onion".length;
    if (!rightLength)
        return null;
    let followedByDotOnion = domain.indexOf("onion.") == 56;
    if (!followedByDotOnion)
        return null;
    let onion = domain.substring(0, 56);
    let validOnion = onion_v3valid(onion);
    if (!validOnion)
        return null
    return onion;
}

/**
 * Given a URL including query strings, extract the onion address from it.
 *
 * Returns [56chars] from domains like [56chars]onion.foo.com, otherwise
 * returns null.
 */
function onion_v3extractFromPossibleSATUrl(url) {
    if (url.search === "") {
        return null;
    }

    if (url.search[0] !== "?") {
        return null;
    }

    const search = url.search.substring(1);
    if (search.length === 0) {
        return null;
    }

    const queries = search.split("&");
    for (let query of queries) {
        const kv = query.split("=");
        if (kv.length !== 2) {
            continue;
        }
        if (kv[0] !== "onion") {
            continue;
        }
        const onion = kv[1];
        if (!onion_v3valid(onion)) {
            continue;
        }
        return onion;
    }

    return null;
}

/**
 * Given a domain name, extract the onion address (without the ".onion" suffix)
 * from it. Otherwise return null.
 *
 * Returns [56chars] from domains like [56chars].onion, otherwise returns null.
 */
function onion_v3extractFromPossibleOnionDomain(domain) {
    let rightNumPeriods = (domain.match(/\./g) || []).length == 1;
    if (!rightNumPeriods)
        return null;
    let rightLength = domain.indexOf(".") == 56 && domain.length == 56 + ".onion".length;
    if (!rightLength)
        return null;
    let followedByDotOnion = domain.indexOf(".onion") == 56;
    if (!followedByDotOnion)
        return null;
    let onion = domain.substring(0, 56);
    let validOnion = onion_v3valid(onion);
    if (!validOnion)
        return null
    return onion;
}

/**
 * Given a satis domain name, extract the base part of the domain. For example,
 * given aaaabbbbbccccddddonion.example.com, return example.com. If not a
 * satis domain, return null.
 */
function onion_extractBaseDomain(domain) {
    if (!onion_v3extractFromPossibleSATDomain(domain)) {
        log_debug("Can't extract a base domain from a non-satis domain.");
        return null;
    }
    return domain.substring(56 + "onion.".length);
}

class OnionSig {
    constructor(nacl, onion, base64Value) {
        let ED25519_SIG_LEN = 64;
        let MAGIC = "satis-guard-----";
        let allAsBytes;
        try {
            allAsBytes = window.atob(base64Value);
        } catch (err) {
            log_debug("Exception in atob(): ", err);
            throw err;
        }
        allAsBytes = byteStringToUint8Array(allAsBytes);
        let dataBytes = allAsBytes.slice(0, -ED25519_SIG_LEN);
        let sigBytes = allAsBytes.slice(-ED25519_SIG_LEN);
        if (!log_assert(nacl != null, "NaCl wasn't initialized in time"))
            return;
        let validSig = nacl.crypto_sign_verify_detached(
            sigBytes, dataBytes, onion.pubkey);

        let offset = 0;

        let magic = parseStringFromByteBuffer(dataBytes.buffer, offset, MAGIC.length);
        offset += MAGIC.length;
        let timeCenter = parseUint64FromByteBuffer(dataBytes.buffer, offset);
        offset += 8;
        let timeWindow = parseUint64FromByteBuffer(dataBytes.buffer, offset);
        offset += 8;
        let nonce = parseUint32FromByteBuffer(dataBytes.buffer, offset);
        offset += 4;
        let domainLen = parseUint32FromByteBuffer(dataBytes.buffer, offset);
        offset += 4;
        let domain = parseStringFromByteBuffer(dataBytes.buffer, offset, domainLen);
        offset += domainLen;
        let fpLen = parseUint32FromByteBuffer(dataBytes.buffer, offset);
        offset += 4;
        let fp = parseStringFromByteBuffer(dataBytes.buffer, offset, fpLen);
        offset += fpLen;

        this.readAllBytes = offset + ED25519_SIG_LEN == allAsBytes.length;
        this.validSig = validSig;
        this.magic = magic;
        this.timeCenter = timeCenter;
        this.timeWindow = timeWindow;
        this.nonce = nonce;
        this.domain = domain;
        this.fingerprint = fp;
    }
}

function onionSigValidInTime(onionSig, secInfo) {
    let sigStart = onionSig.timeCenter - onionSig.timeWindow / 2;
    let sigEnd = onionSig.timeCenter + onionSig.timeWindow / 2;
    let now = Date.now() / 1000;
    if (secInfo != null) {
        let certValidity = getValidity(secInfo);
        let certStart = Date.parse(certValidity.startGMT) / 1000;
        let certEnd = Date.parse(certValidity.endGMT) / 1000;
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
    }
    //let secondsAfterStart = now - sigStart;
    //let secondsBeforeEnd = sigEnd - now;
    //log_debug("Signature been valid for", secondsAfterStart,
    //    "secs and will stop being valid in", secondsBeforeEnd, "secs")
    return now >= sigStart && now <= sigEnd;
}
