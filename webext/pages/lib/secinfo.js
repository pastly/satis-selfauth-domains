function getSubject(securityInfo) {
    let asn1 = ASN1.decode(securityInfo.certificates[0].rawDER);
    let item = asn1.sub[0].sub[5].sub[0].sub[0].sub[1];
    let pos = item.header + item.stream.pos;
    let str = "";
    for (let i = 0; i < item.length; i++) {
        str += String.fromCharCode(item.stream.enc[pos+i]);
    }
    //log_debug(str);
    return str;
}

function getSubjectAlts(securityInfo) {
    let alts = [];
    let asn1 = ASN1.decode(securityInfo.certificates[0].rawDER);
    let extensions = asn1.sub[0].sub[7].sub[0].sub;
    //log_object(extensions);
    for (let ext of extensions) {
        if (ext.sub.length != 2) {
            //log_debug("Not this one because " + ext.sub.length + " subs is not 2");
            continue;
        }
        //log_object(ext.sub[0]);
        let item = ext.sub[0];
        let pos = item.header + item.stream.pos;
        let key = "";
        for (let i = 0; i < item.length; i++) {
            key += item.stream.enc[pos+i].toString(16);
        }
        if (key != "551d11") {
            //log_debug("Not this one because key " + key + " is not 551d11");
            continue;
        }
        item = ext.sub[1].sub[0];
        let names = ext.sub[1].sub[0].sub;
        for (let i = 0; i < names.length; i++) {
            let name = names[i];
            pos = name.header + name.stream.pos;
            let str = "";
            for (let j = 0; j < name.length; j++) {
                str += String.fromCharCode(name.stream.enc[pos+j]);
        }
        alts.push(str);
    }
        //log_debug("Subject alts are: " + alts);
    }
    return alts;
}

function getFingerprint(securityInfo) {
    let fp = securityInfo.certificates[0].fingerprint.sha256;
    return fp.replace(/:/g, "");
}

function getTLSVersion(securityInfo) {
    return securityInfo.protocolVersion;
}

function getValidity(securityInfo) {
    /* See .startGMT and .endGMT and pass those strings to Date.parse */
    return securityInfo.certificates[0].validity;
}
