function setDomain(get) {
    let e = document.getElementById("domain");
    e.appendChild(document.createTextNode(get.domain));
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
    addButtonTargets();
}

main();
