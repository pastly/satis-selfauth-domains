function addButtonTargets() {
    let elm = document.getElementById("sat_list_button");
    elm.href = browser.runtime.getURL("pages/satlists.html");
}

function populateSettings(s) {
    let d = document;
    var e = d.getElementById("settingAttestedSATDomainsOnly");
    e.checked = s.attestedSATDomainsOnly;
    e = d.getElementById("settingWildcardSATDomainsAllowed");
    e.checked = s.wildcardSATDomainsAllowed;
    e = d.getElementById("settingSATAltSvcNotInTLSCertAllowed");
    e.checked = s.satAltSvcNotInTLSCertAllowed;
}

function addSettingsEvents() {
    let e1 = document.getElementById("settingAttestedSATDomainsOnly");
    e1.addEventListener("change", function() {
        let resp = sendMessage(
            "setSetting",
            {'key': 'attestedSATDomainsOnly', 'value': e1.checked});
        resp.then(function (it_worked) {
            if (!it_worked) e1.checked = !e1.checked;
        }, log_error);
    });
    let e2 = document.getElementById("settingWildcardSATDomainsAllowed");
    e2.addEventListener("change", function() {
        let resp = sendMessage(
            "setSetting",
            {'key': 'wildcardSATDomainsAllowed', 'value': e2.checked});
        resp.then(function (it_worked) {
            if (!it_worked) e2.checked = !e2.checked;
        }, log_error);
    });
    let e3 = document.getElementById("settingSATAltSvcNotInTLSCertAllowed");
    e3.addEventListener("change", function() {
        let resp = sendMessage(
            "setSetting",
            {'key': 'satAltSvcNotInTLSCertAllowed', 'value': e3.checked});
        resp.then(function (it_worked) {
            if (!it_worked) e3.checked = !e3.checked;
        }, log_error);
    });
}

//function setOrigin(s) {
//    document.getElementById("origin")
//        .appendChild(document.createTextNode(s));
//}

function addAltSvc(as, onionsig) {
    document.getElementById("altsvccontainer").classList.remove("hide");
    let domain = !!as.domain ? as.domain : as.str;
    let table = document.getElementById("altsvc");
    let tr = document.createElement("tr");

    let td = document.createElement("td");
    td.appendChild(document.createTextNode(domain));
    tr.appendChild(td);

    td = document.createElement("td");
    td.appendChild(document.createTextNode(onionsig ? "Yes" : "No"));
    td.classList.add(onionsig ? "good" : "bad");
    tr.appendChild(td);

    table.appendChild(tr);
}

function populatePopupWindow(tabs) {
    let origin = splitURL(tabs[0].url).hostname;
    //setOrigin(origin);
    let resp_altsvc = sendMessage("giveAltSvcs", origin);
    resp_altsvc.then(populateAltSvc, log_error);
    let resp_satlists = sendMessage("giveTrustedSATListsContaining", origin);
    resp_satlists.then(populateSATLists(origin), log_error);
    addButtonTargets();
    let resp_settings = sendMessage("giveCurrentSettings", {});
    resp_settings.then(populateSettings, log_error);
    addSettingsEvents();
}

function populateAltSvc(alts) {
    for (altstr in alts) {
        addAltSvc(alts[altstr]['alt'], alts[altstr]['onionsig']);
    }
}

function populateSATLists(origin) {
    return function(d) {
        let div = document.getElementById("existonsatlistcontainer");
        let ul = document.getElementById("existonsatlist");
        if (!onion_v3extractFromPossibleSATDomain(origin)) {
            div.classList.remove("add");
            return;
        }
        div.classList.remove("hide");
        if (Object.keys(d).length == 0) {
            let p = document.createElement("p");
            p.appendChild(document.createTextNode(
                "This domain is not on any of your enabled and trusted SAT " +
                "lists, or you do not have any enabled and trusted SAT lists."));
            div.appendChild(p);
            //let li = document.createElement("li");
            //li.appendChild(document.createTextNode("None"));
            //li.classList.add("warn");
            //ul.appendChild(li);
            return;
        }
        for (hash in d) {
            let listObj = d[hash];
            let li = document.createElement("li");
            li.appendChild(document.createTextNode(listObj.name));
            ul.appendChild(li);
        }
    }
}

function main() {
    browser.tabs.query({active: true, currentWindow: true})
        .then(populatePopupWindow)
        .catch(log_error);
}

main();
