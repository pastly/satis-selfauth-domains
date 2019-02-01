function log_success_from_bg(resp) {
    log_debug("Got from background script:", resp);
}

function log_error_from_bg(resp) {
    log_error("Error from background script:", resp);
}

function main() {
    let set = findSATDomainList(document);
    if (set.length < 1) {
        return;
    }
    let response = sendMessage(
        "satDomainList", {
            "url": document.URL, "set": set });
    response.then(log_success_from_bg, log_error_from_bg);
}

main();
