function addSATList(listObj) {
    let doc = document;
    let div_top = doc.getElementById("satmaplistcontainer");
    let div_new = doc.createElement("div");

    let h2 = doc.createElement("h2");
    h2.appendChild(doc.createTextNode(
        "List " + (listObj.name ? listObj.name : "(Unamed)")));
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
    let input = doc.createElement("input");
    let button = doc.createElement("button");
    label.for = listObj.id + "-name";
    input.id =  listObj.id + "-name";
    input.type = "text";
    if (listObj.name) {
        input.value = listObj.name;
    }
    label.appendChild(doc.createTextNode("List name"));
    button.appendChild(doc.createTextNode("Set"));
    button.addEventListener("click", function() {
        let resp = sendMessage(
            "setSATDomainListName",
            {'hash': listObj.id, 'name': input.value});
        resp.then(log_debug, log_debug);
    });
    form.appendChild(label);
    form.appendChild(input);
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
