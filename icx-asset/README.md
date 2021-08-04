# `icx-asset`
A command line tool to manage an asset storage canister.

## icx-asset sync

Synchronize a directory to an asset canister.

Usage: `icx-asset sync <directory>`

Example:
```
# same asset synchronization as dfx deploy
$ icx-asset sync src/<project>/assets   
```

## icx-asset ls

List 

## icx-asset upload

Usage: `icx-asset upload [<destination>=]<file> [[<destination>=]<file> ...]`

Examples:

```
# upload a single file as /a.txt
$ icx-asset upload a.txt

# upload a single file, a.txt, under another name
$ icx-asset upload /b.txt=a.txt

# upload a directory and its contents as /some-dir/*
$ icx-asset upload some-dir

# Similar to synchronization with dfx deploy, but without deleting anything:
$ icx-asset upload /=src/<project>/assets


```