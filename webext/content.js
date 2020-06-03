function log_success_from_bg(resp) {
    log_debug("Got from background script:", resp);
}

function log_error_from_bg(resp) {
    log_error("Error from background script:", resp);
}

function redirect_sat_page(resp) {
    window.location = resp.redirectUrl;
    log_success_from_bg(resp);
}

function main() {
    let satSig = findSATSigInMetaTag(document);
    if (satSig) {
        let response = sendMessage(
            "metaSatSignatureFound", {
                "url": document.URL, "satSig": satSig });
        response.then(redirect_sat_page, log_error_from_bg);
    }
    let set = findSATDomainList(document);
    if (!set || set.size < 1) {
        return;
    }
    let response = sendMessage(
        "satDomainList", {
            "url": document.URL, "set": set, "wellknown": false, "satUrl": false });
    response.then(log_success_from_bg, log_error_from_bg);
    fetchSATDomainList(window);
}

main();
