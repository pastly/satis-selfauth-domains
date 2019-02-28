function addSATList(listObj) {
    let doc = document;
    let div_top = doc.getElementById(
        (listObj.is_trusted ? "trustedlist" : "untrustedlist"));
    let div_new = doc.createElement("div");

    let h2 = doc.createElement("h2");
    h2.appendChild(doc.createTextNode(
        "List " +
        (listObj.name ? listObj.name : "(Unamed)") +
        (!listObj.is_enabled ? " (Disabled)" : "")));
    if (!listObj.is_enabled) {
        h2.classList.add("disabled");
    }
    div_new.appendChild(h2);

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

    let h3 = doc.createElement("h3");
    h3.appendChild(doc.createTextNode("Contents"));
    div_new.appendChild(h3);

    let ul = doc.createElement("ul");
    for (map of listObj.list) {
        let li = doc.createElement("li");
        let from_a = doc.createElement("a");
        from_a.href = 'https://' + map.from;
        from_a.appendChild(doc.createTextNode(map.from));
        let to_a = doc.createElement("a");
        to_a.href = 'https://' + map.to;
        to_a.appendChild(doc.createTextNode(map.to));
        li.appendChild(to_a);
        li.appendChild(doc.createTextNode(" has SAT domain "));
        li.appendChild(from_a);
        ul.appendChild(li);
    }
    div_new.appendChild(ul);
    div_new.classList.add("satmaplistentry");

    div_top.appendChild(div_new);
}

function populateTrustedSATLists(obj) {
    for (hash in obj) {
        addSATList(obj[hash]);
    }
}

function main() {
    response = sendMessage("giveTrustedSATLists", null);
    response.then(populateTrustedSATLists, log_error);
}

main();
