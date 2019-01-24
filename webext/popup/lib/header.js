function _getHeader(headers, name) {
    for (let header of headers) {
        if (header.name == name.toLowerCase()) {
            return header.value;
        }
    }
    return null;
}

function _getHeaders(headers, name) {
    let ret = []
    for (let header of headers) {
        if (header.name == name.toLowerCase()) {
            ret.push(header.value);
        }
    }
    return ret;
}

function getOnionSigHeader(headers) {
    return _getHeader(headers, "X-Alliuminate");
}

function getOnionSigHeaders(headers) {
    return _getHeaders(headers, "X-Alliuminate");
}

function getAltSvcHeaders(headers) {
    return _getHeaders(headers, "Alt-Svc");
}
