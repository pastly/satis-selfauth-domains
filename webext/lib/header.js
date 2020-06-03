function _getHeader(headers, name) {
    for (let header of headers) {
        if (header.name.toLowerCase() == name.toLowerCase()) {
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
    return _getHeader(headers, "X-SAT-Sig");
}

function getOnionSigHeaders(headers) {
    return _getHeaders(headers, "X-SAT-Sig");
}

function getSatTokenHeader(headers) {
    return _getHeader(headers, "SAT-TOKEN");
}

function getSatTokenHeaders(headers) {
    return _getHeaders(headers, "SAT-TOKEN");
}

function getAltSvcHeaders(headers) {
    return _getHeaders(headers, "Alt-Svc");
}
