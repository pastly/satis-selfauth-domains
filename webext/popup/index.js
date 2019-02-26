function addButtonTargets() {
    let elm = document.getElementById("satListButton");
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

function _buildTrustButton(origin, altstr, trust, longText) {
    let goodText = longText ? "Change ✓" : "✓" ;
    let badText = longText ? "Change ✘" : "✘" ;
    let d = document;
    let but = d.createElement("a");
    let textNode = d.createTextNode(trust ? goodText : badText);
    but.classList.add(trust ? "trustButton" : "distructButton");
    but.appendChild(textNode);
    but.addEventListener("click", function() {
        let resp = sendMessage(
            "setAltSvcTrusted",
            {"altstr": altstr, "origin": origin, "trust": trust});
        resp.then(function (it_worked) {
            if (it_worked) {
                textNode.nodeValue = "OK! Set to " + (trust ? "yes" : "no");
            } else {
                textNode.nodeValue = "Failed";
            }
        }, log_error);
    });
    return but;
}

function addAltSvc(origin, as, validOnionSig, userTrusts, userDistrusts) {
    let d = document;
    d.getElementById("altsvccontainer").classList.remove("hide");
    let domain = !!as.domain ? as.domain : as.str;
    let table = d.getElementById("altsvc");
    let tr = d.createElement("tr");

    let td = d.createElement("td");
    td.appendChild(d.createTextNode(domain));
    tr.appendChild(td);

    // onion sig
    td = d.createElement("td");
    td.appendChild(d.createTextNode(validOnionSig ? "Yes" : "No"));
    td.classList.add(validOnionSig ? "good" : "bad");
    tr.appendChild(td);

    // trust
    td = d.createElement("td");
    if (!userTrusts && !userDistrusts) {
        longText = false;
        let butTrust = _buildTrustButton(origin, as.str, true, longText);
        let butDistrust = _buildTrustButton(origin, as.str, false, longText);
        td.appendChild(butTrust);
        td.appendChild(butDistrust);
    } else if (userDistrusts) {
        let longText = true;
        td.appendChild(d.createTextNode("No"));
        td.classList.add("bad");
        let but = _buildTrustButton(origin, as.str, true, longText);
        td.appendChild(but);
    } else if (userTrusts) {
        let longText = true;
        td.appendChild(d.createTextNode("Yes"));
        td.classList.add("good");
        let but = _buildTrustButton(origin, as.str, false, longText);
        td.appendChild(but);
    }
    tr.appendChild(td);

    table.appendChild(tr);
}

function populatePopupWindow(tabs) {
    let origin = splitURL(tabs[0].url).hostname;
    //setOrigin(origin);
    let resp_altsvc = sendMessage("giveAltSvcs", origin);
    resp_altsvc.then(function(alts) {populateAltSvc(origin, alts);}, log_error);
    let resp_satlists = sendMessage("giveTrustedSATListsContaining", origin);
    resp_satlists.then(populateSATLists(origin), log_error);
    addButtonTargets();
    let resp_settings = sendMessage("giveCurrentSettings", {});
    resp_settings.then(populateSettings, log_error);
    addSettingsEvents();
}

function populateAltSvc(origin, alts) {
    for (altstr in alts) {
        addAltSvc(
            origin,
            alts[altstr].alt, alts[altstr].validOnionSig,
            alts[altstr].userTrusts, alts[altstr].userDistrusts,
        );
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
