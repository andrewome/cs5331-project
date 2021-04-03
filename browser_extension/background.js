"use strict";
// Module is from libyara-wasm.js
const yara = Module();

const REQUEST_MARKER = 'extension_marker_cbe72189b8663';

const runYara = (url, inp, yaraRule) => {
    let matchString = '';
    const resp = yara.run(new Uint8Array(inp), yaraRule); // apparently embind recognises std::string as Uint8Array
    
    // Add compile errors
    if (resp.compileErrors.size() > 0) {
        for (let i = 0; i < resp.compileErrors.size(); i++) {
            const compileError = resp.compileErrors.get(i);
            if (!compileError.warning) {
                matchString += `Error on line ${compileError.lineNumber}: ${compileError.message}`;
                break;
            } else {
                matchString += `Warning on line ${compileError.lineNumber}: ${compileError.message}`;
            }
        }
    }

    // Matched rules info
    const matchedRules = resp.matchedRules;
    for (let i = 0; i < matchedRules.size(); i++) {
        const rule = matchedRules.get(i);
        const matches = rule.resolvedMatches;

        let meta = "";
        if (rule.metadata.size() > 0) {
            meta += " [";
            for (let j = 0; j < rule.metadata.size(); j++) {
                meta += `${rule.metadata.get(j).identifier}: ${rule.metadata.get(j).data}, `;
            }
            meta = meta.slice(0, -2) + "]";
        }
        const countString = `${matches.size()} time${matches.size() > 1 ? "s" : ""}`;
        matchString += `Input from ${url} matches rule "${rule.ruleName}"${meta}${countString.length > 0 ? ` ${countString}`: ""}.\n`;
    }

    if (matchedRules.size()) // Only output if there's matched rules
        console.log(matchString);
    return resp.matchedRules.size() ? true : false;
}

const filter = async (requestDetails) => {
    const {requestId, method, url} = requestDetails;

    // Don't process URLs that contain our extension marker. Will create infinite loop
    if (url.includes(REQUEST_MARKER))
        return;

    // Only process GET reqs for convenience sake
    if (method.toUpperCase() !== 'GET')
        return;

    // Add a custom requestId to url so we know that it's a repeated request from this ext.
    console.log(`Fetching ${url}`)
    let toFetch = new URL(url);
    toFetch.searchParams.append(REQUEST_MARKER, requestId);
    
    // Fetch data, check it with YARA with input rules.
    // All rules must pass
    let cancel = true;
    const data = await (await fetch(toFetch)).arrayBuffer();
    for (let i = 0; i < yaraRules.length; i++) { // yaraRules is from rules.js.
        const yaraRule = yaraRules[i];
        if (!runYara(url, data, yaraRule)) {
            cancel = false;
            break;
        }
    }
    if (cancel)
        console.log(`Data from ${url} matches signatures from cryptonight miner. Cancelling request.`)
    return {cancel};
}

// Only add listener once yara is loaded
yara.onRuntimeInitialized = () => {
    console.log('YARA has loaded successfully.');
    browser.webRequest.onBeforeRequest.addListener(
        filter,
        {urls: ['<all_urls>']},
        ['blocking']
    );
};
