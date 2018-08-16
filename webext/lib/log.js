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

/**
 * Log something to the console
 */
function log() {
    return console.log("[SATIS]", [].slice.apply(arguments).join(" "));
}

function log_object(o) {
    if (LOG_OBJECT)
        return console.log(o);
}

function log_debug() {
    if (LOG_DEBUG)
        return log("[DEBUG]", [].slice.apply(arguments).join(" "));
}

function log_warn() {
    return log("[WARN]", [].slice.apply(arguments).join(" "));
}

function log_error() {
    return log("[ERROR]", [].slice.apply(arguments).join(" "));
}
