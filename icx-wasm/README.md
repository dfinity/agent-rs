# `icx-wasm`
A command line tool to transform Wasm modules running on the Internet Computer.

## Metadata

Usage: `icx-wasm <input.wasm> [-o output.wasm] metadata [name] [-d <text content> | -f <file content>] [-v <public|private>]`

Example:

```
// List current metadata sections
$ icx-wasm input.wasm metadata
// List a specific metadata content
$ icx-wasm input.wasm metadata candid:service
// Add/overwrite a private metadata section
$ icx-wasm input.wasm -o output.wasm metadata new_section -d "hello, world"
// Add/overwrite a public metadata section from file
$ icx-wasm input.wasm -o output.wasm metadata candid:service -f service.did -v public
```
