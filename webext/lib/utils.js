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
    let list = doc.getElementById("sat_domain_list");
    if (!list) {
        log_debug("There is no domain list in this page");
        return;
    }
    let out = new Set();
    for (let li of list.children) {
        let from_name = null;
        let to_name = null;
        for (ele of li.getElementsByTagName("span")) {
            if (ele.classList.contains("sat_domain_from")) {
                from_name = ele.textContent;
            } else if (ele.classList.contains("sat_domain_to")) {
                to_name = ele.textContent;
            }
        }
        if (from_name && to_name) {
            log_debug("Adding", from_name, "to", to_name);
            out.add({'from': from_name, 'to': to_name});
        } else {
            log_debug("Ignoring element:");
            log_object(ele);
        }
    }
    return out;
}

