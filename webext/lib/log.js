let LOG_DEBUG = true;
let LOG_OBJECT = true;

/**
 * This doesn't actually prevent futher execution, however :(
 */
function log_assert(cond, msg) {
    if (!cond) {
        msg = msg || "Assertion failed";
        console.assert(cond, msg);
    }
    return cond;
}

function __dateStr() {
    let t = new Date();
    let h = t.getHours();
    let m = t.getMinutes();
    let s = t.getSeconds();
    let ms = t.getMilliseconds();
    h = "" + h;
    m = m < 10 ? "0" + m : "" + m;
    s = s < 10 ? "0" + s : "" + s;
    ms = ms < 100 ? ms < 10 ? "00" + ms : "0" + ms : "" + ms;
    return h + ":" + m + ":" + s + "." + ms;
}

function __funcStr() {
    let trace = new Error();
    let stack = new Error().stack;
    let stackLine = stack.split("\n")[3]; // 0 is __funcStr, 1 is __log, 2 is log_debug (or similar)
    let func = stackLine.substr(0, stackLine.indexOf("@"));
    let fileInfo = stackLine.substr(stackLine.lastIndexOf("/")+1);
    return func + "@" + fileInfo;
}

function __log(level) {

    return console.log(
        //"[SAT]",
        "[" + level + "]",
        "[" + __dateStr() + "]",
        "[" + __funcStr() + "]",
        [].slice.apply(arguments).slice(1).join(" "));
}

function log_object(o) {
    if (LOG_OBJECT)
        return console.log(o);
}

function log_debug() {
    if (LOG_DEBUG)
        return __log("D", [].slice.apply(arguments).join(" "));
}

function log_warn() {
    return __log("W", [].slice.apply(arguments).join(" "));
}

function log_error() {
    return __log("E", [].slice.apply(arguments).join(" "));
}
