function setDomain(get) {
    let e = document.getElementById("domain");
    e.appendChild(document.createTextNode(get.domain));
}

function setLabelSet(get) {
    let e = document.getElementById("selfLabels");
    e.appendChild(document.createTextNode(get.selfLabels));
}

function setSatLabelSet(get) {
    let e = document.getElementById("satLabels");
    e.appendChild(document.createTextNode(get.satLabels));
}

function setErrorMessage(get) {
    let e = document.getElementById("errmsg");
    e.appendChild(document.createTextNode(decodeURIComponent(get.error)));
}

function addButtonTargets() {
    let elm = document.getElementById("satListButton");
    elm.href = browser.runtime.getURL("pages/satlists.html");
}

function main() {
    var get = {};
    location.search.replace('?', '').split('&').forEach(function (val) {
        split = val.split("=", 2);
        log_debug(split[0], split[1])
        get[split[0]] = split[1];
    });
    setDomain(get);
    setLabelSet(get);
    setSatLabelSet(get);
    setErrorMessage(get);
    addButtonTargets();
}

main();
