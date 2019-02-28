class SATList {
    constructor(updateURL, list, trusted, enabled, rewrite, lastUpdate, name) {
        let hash = sha3_256.create().update(updateURL).hex();
        this.lastUpdate = // an int and measured in seconds
            (lastUpdate ? lastUpdate : Math.floor(Date.now() / 1000));
        this.id = hash;
        this.updateURL = updateURL;
        this.name = name;
        this.list = list;
        this.is_trusted = trusted;
        this.is_enabled = enabled;
        this.do_rewrite = rewrite;
    }
}
