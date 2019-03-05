function addSATList(listObj) {
    if (!log_assert(
            !listObj.is_personal,
            "Personal lists have their own addSATList function")) {
        return;
    }
    let doc = document;
    let div_top = doc.getElementById(
        (listObj.is_trusted ? "trustedlist" : "untrustedlist"));
    let div_new = doc.createElement("div");

    let h3 = doc.createElement("h3");
    h3.appendChild(doc.createTextNode(
        "List " +
        (listObj.name ? listObj.name : "(Unamed)") +
        (!listObj.is_enabled ? " (Disabled)" : "")));
    if (!listObj.is_enabled) {
        h3.classList.add("disabled");
    }
    div_new.appendChild(h3);

    let p = doc.createElement("p");
    p.appendChild(doc.createTextNode(
        "Last updated: " + new Date(listObj.lastUpdate * 1000)));
    div_new.appendChild(p);

    p = doc.createElement("p");
    let a = doc.createElement("a");
    a.href = listObj.updateURL;
    a.appendChild(doc.createTextNode(listObj.updateURL));
    p.appendChild(doc.createTextNode("Source URL: "));
    p.appendChild(a);
    div_new.appendChild(p);

    let form = doc.createElement("form");
    let label = doc.createElement("label");
    let input_name = doc.createElement("input");
    let button = doc.createElement("button");
    label.for = listObj.id + "-name";
    input_name.id =  listObj.id + "-name";
    input_name.type = "text";
    if (listObj.name) {
        input_name.value = listObj.name;
    }
    label.appendChild(doc.createTextNode("List name"));
    button.appendChild(doc.createTextNode("Set"));
    button.addEventListener("click", function() {
        let resp = sendMessage(
            "setSATDomainListName",
            {'hash': listObj.id, 'name': input_name.value});
        resp.then(function() {}, log_debug);
    });
    form.appendChild(label);
    form.appendChild(input_name);
    form.appendChild(button);
    div_new.appendChild(form);

    form = doc.createElement("form");
    label = doc.createElement("label");
    let input_trusted = doc.createElement("input");
    label.for = listObj.id + "-trusted";
    input_trusted.id = listObj.id + "-trusted";
    input_trusted.type = "checkbox";
    input_trusted.checked = listObj.is_trusted;
    label.appendChild(doc.createTextNode("Is trusted"));
    input_trusted.addEventListener("change", function() {
        let resp = sendMessage(
            "setSATDomainListTrusted",
            {'hash': listObj.id, 'trusted': input_trusted.checked});
        resp.then(function() {}, log_debug);
        window.location.reload(false); // false means don't make a web request
    });
    form.appendChild(label);
    form.appendChild(input_trusted);
    div_new.appendChild(form);

    if (listObj.is_trusted) {
        form = doc.createElement("form");
        label = doc.createElement("label");
        let input_enabled = doc.createElement("input");
        label.for = listObj.id + "-enabled";
        input_enabled.id = listObj.id + "-enabled";
        input_enabled.type = "checkbox";
        input_enabled.checked = listObj.is_enabled;
        label.appendChild(doc.createTextNode("Is enabled"));
        input_enabled.addEventListener("change", function() {
            let resp = sendMessage(
                "setSATDomainListEnabled",
                {'hash': listObj.id, 'enabled': input_enabled.checked});
            resp.then(function() {}, log_debug);
            window.location.reload(false); // false means don't make a web request
        });
        form.appendChild(label);
        form.appendChild(input_enabled);
        div_new.appendChild(form);
    }

    if (listObj.is_enabled) {
        form = doc.createElement("form");
        label = doc.createElement("label");
        let input_rewrite = doc.createElement("input");
        label.for = listObj.id + "-rewrite";
        input_rewrite.id = listObj.id + "-rewrite";
        input_rewrite.type = "checkbox";
        input_rewrite.checked = listObj.do_rewrite;
        label.appendChild(doc.createTextNode("Use rewrites"));
        input_rewrite.addEventListener("change", function() {
            let resp = sendMessage(
                "setSATDomainListRewrite",
                {'hash': listObj.id, 'rewrite': input_rewrite.checked});
            resp.then(function() {}, log_debug);
            window.location.reload(false); // false means don't make a web request
        });
        form.appendChild(label);
        form.appendChild(input_rewrite);
        div_new.appendChild(form);
    }

    form = doc.createElement("form");
    button = doc.createElement("button");
    button.appendChild(doc.createTextNode("Delete this list"));
    button.addEventListener("click", function() {
        let resp = sendMessage(
            "deleteSATDomainList",
            {'hash': listObj.id});
        resp.then(function() {}, log_debug);
    });
    form.appendChild(button);
    div_new.appendChild(form);

    let h4 = doc.createElement("h4");
    h4.appendChild(doc.createTextNode("Contents"));
    div_new.appendChild(h4);

    let ul = doc.createElement("ul");
    for (map of listObj.list) {
        let li = doc.createElement("li");
        let satName_a = doc.createElement("a");
        satName_a.href = 'https://' + map.satName;
        satName_a.appendChild(doc.createTextNode(map.satName));
        let baseName_a = doc.createElement("a");
        baseName_a.href = 'https://' + map.baseName;
        baseName_a.appendChild(doc.createTextNode(map.baseName));
        li.appendChild(baseName_a);
        li.appendChild(doc.createTextNode(" has SAT domain "));
        li.appendChild(satName_a);
        ul.appendChild(li);
    }
    div_new.appendChild(ul);
    div_new.classList.add("satmaplistentry");

    div_top.appendChild(div_new);
}

function addPersonalSATList(listObj) {
    if (!log_assert(
            listObj.is_personal,
            "Non-personal list in personal func")) {
        return;
    }
    log_assert(listObj.name, "Personal list should have a name");
    doc = document;
    let div_top = doc.getElementById("personallist");
    let div_new = doc.createElement("div");

    let form = doc.createElement("form");
    let label = doc.createElement("label");
    let input_rewrite = doc.createElement("input");
    label.for = listObj.id + "-rewrite";
    input_rewrite.id = listObj.id + "-rewrite";
    input_rewrite.type = "checkbox";
    input_rewrite.checked = listObj.do_rewrite;
    label.appendChild(doc.createTextNode("Use rewrites"));
    input_rewrite.addEventListener("change", function() {
        let resp = sendMessage(
            "setSATDomainListRewrite",
            {'hash': listObj.id, 'rewrite': input_rewrite.checked});
        resp.then(function() {}, log_debug);
        window.location.reload(false); // false means don't make a web request
    });
    form.appendChild(label);
    form.appendChild(input_rewrite);
    div_new.appendChild(form);

    let h3 = doc.createElement("h3");
    h3.appendChild(doc.createTextNode("Entries"));
    div_new.appendChild(h3);

    let tab = doc.createElement("table");
    let tr = doc.createElement("tr");
    let td;
    let button;

    tr = doc.createElement("tr");
    td = doc.createElement("th");
    td.appendChild(doc.createTextNode("Base domain"));
    tr.appendChild(td);
    td = doc.createElement("th");
    td.appendChild(doc.createTextNode("SAT domain"));
    tr.appendChild(td);
    tab.appendChild(tr);

    for (item of listObj.list) {
        let satName_a = doc.createElement("a");
        satName_a.href = "https://" + item.satName;
        satName_a.appendChild(doc.createTextNode(item.satName));
        let baseName_a = doc.createElement("a");
        baseName_a.href = "https://" + item.baseName;
        baseName_a.appendChild(doc.createTextNode(item.baseName));
        tr = doc.createElement("tr");
        td = doc.createElement("td");
        td.appendChild(baseName_a);
        tr.appendChild(td);
        td = doc.createElement("td");
        td.appendChild(satName_a);
        tr.appendChild(td);
        tab.appendChild(tr);

        td = doc.createElement("td");
        form = doc.createElement("form");
        button = doc.createElement("button");
        button.appendChild(doc.createTextNode("Delete ✘"));
        let mapping = item;
        button.addEventListener("click", function() {
            let resp = sendMessage(
                "deletePersonalSATListItem", {"item": mapping})
            resp.then(function() {}, log_debug);
        });
        form.appendChild(button);
        td.appendChild(form);
        tr.appendChild(td);
    }

    div_new.appendChild(tab);
    div_top.appendChild(div_new);
}

function addAddPersonalEntry() {
    doc = document;
    let div_top = doc.getElementById("personallist");
    let div_new = doc.createElement("div");
    let form = doc.createElement("form");
    let input = doc.createElement("input");
    let button = doc.createElement("button");
    input.id = "add-personal-entry";
    input.type = "text";
    input.placeholder = "aaaaaaaaonion.foo.com";
    button.appendChild(doc.createTextNode("Add"));
    button.addEventListener("click", function() {
        let resp = sendMessage(
            "addPersonalSATListItem", {"sat": input.value});
        resp.then(log_debug, log_error);
    });
    form.appendChild(input);
    form.appendChild(button);
    div_new.appendChild(form);
    div_top.appendChild(div_new);
}

function populateTrustedSATLists(obj) {
    for (hash in obj) {
        if (!obj[hash].is_personal) {
            addSATList(obj[hash]);
        } else {
            addPersonalSATList(obj[hash]);
        }
    }
    addAddPersonalEntry();
}

function main() {
    response = sendMessage("giveTrustedSATLists", null);
    response.then(populateTrustedSATLists, log_error);
}

main();
