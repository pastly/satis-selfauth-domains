class AltSvc {
    constructor(s) {
        this.str = s;
        let values = s.split(';');
        values = values.map(v => v.trim()).filter(v => v.length > 0);
        //log_object(values);
        for (let v of values) {
            if (!v.startsWith("h2="))
                continue;
            this.domain = v.substring(
                "h2=\"".length, v.indexOf(":"));
            //log_debug("Found alt-svc domain", this.domain);
        }
    }
}
