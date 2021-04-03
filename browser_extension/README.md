# Firefox Browser Extension
Only works with Firefox cause Chrome does not support async callbacks for `webRequest.onBeforeRequest`...

## What does it do
Scans incoming requests and uses Yara with input rules to detect if the file is a Cryptonight Cryptominer

## Credits
Yara WASM for compatibility with JavaScript - https://github.com/mattnotmitt/libyara-wasm