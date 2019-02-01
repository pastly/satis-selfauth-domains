function setOrigin(s) {
    document.getElementById("origin").innerHTML = s;
}

function addAltSvc(domain, preload, onionsig) {
    document.getElementById("altsvccontainer").classList.remove("hide");
    //let ul = document.getElementById("altsvc");
    //let li = document.createElement("li");
    //li.appendChild(document.createTextNode(s));
    //ul.appendChild(li);
    let table = document.getElementById("altsvc");
    let tr = document.createElement("tr");

    let td = document.createElement("td");
    td.appendChild(document.createTextNode(domain));
    tr.appendChild(td);

    td = document.createElement("td");
    td.appendChild(document.createTextNode(preload ? "Yes" : "No"));
    td.classList.add(preload ? "good" : "bad");
    tr.appendChild(td);

    td = document.createElement("td");
    td.appendChild(document.createTextNode(onionsig ? "Yes" : "No"));
    td.classList.add(onionsig ? "good" : "bad");
    tr.appendChild(td);

    table.appendChild(tr);
}

function addSATList(listObj) {
    document.getElementById("satmaplistcontainer").classList.remove("hide");
    let theList = document.getElementById("satmaplist");

    let li_top = document.createElement("li");
    li_top.title = "Update URL: " + listObj.updateURL;
    li_top.appendChild(document.createTextNode(
        "List " + listObj.id + " last updated " +
        new Date(listObj.lastUpdate * 1000)));
        //new Date(listObj.lastUpdate * 1000).toDateString()));

    let ul = document.createElement("ul");
    for (map of listObj.list) {
        let li = document.createElement("li");
        let from_a = document.createElement("a");
        from_a.href = 'https://' + map.from;
        from_a.appendChild(document.createTextNode(map.from));
        let to_a = document.createElement("a");
        to_a.href = 'https://' + map.to;
        to_a.appendChild(document.createTextNode(map.to));
        li.appendChild(to_a);
        li.appendChild(document.createTextNode(" has SAT domain "));
        li.appendChild(from_a);
        ul.appendChild(li);
    }
    li_top.appendChild(ul);

    theList.appendChild(li_top);
}

function populatePopupWindow(tabs) {
    let origin = splitURL(tabs[0].url).hostname;
    setOrigin(origin);
    let response = sendMessage("giveAltSvcs", origin);
    response.then(populateAltSvc, log_error);
    response = sendMessage("giveTrustedSATLists", null);
    response.then(populateTrustedSATLists, log_error);
}

function populateAltSvc(alts) {
    for (alt in alts) {
        addAltSvc(alt, alts[alt]['onpreload'], alts[alt]['onionsig']);
    }
}

function populateTrustedSATLists(obj) {
    for (hash in obj) {
        addSATList(obj[hash]);
    }
}

function main() {
    browser.tabs.query({active: true, currentWindow: true})
        .then(populatePopupWindow)
        .catch(log_error);
}

main();
