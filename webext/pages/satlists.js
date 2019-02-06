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
