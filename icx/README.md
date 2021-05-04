# `icx`
A command line tool to use the `ic-agent` crate directly. It allows simple communication with
the Internet Computer.

## Installing `icx`
To install `icx` you will have to build it locally, using `cargo`. Make a clone of this repository,
then in it simply run `cargo build`:

```sh
git clone https://github.com/dfinity/agent-rust.git
cd agent-rust
cargo build
```

The output executable will be in `target/debug/icx`.

## Using `icx`
To get help, simply use `icx --help`.

### Identity
To read a PEM file, you can pass it with the `--pem` argument. The PEM file must be a valid
key that can be used for the Internet Computer signing and validation.

### Root Key
For non-IC networks, pass --fetch_root_key to fetch the root key.  If this argument is not present,
icx will use the hardcoded public key for the Internet Computer.

### Examples
To call the management canister's `create_canister` function, you can use the following:

```shell script
icx update aaaaa-aa create_canister
```

If you have a candid file, you can use it to validate arguments. Pass it in with the
`--candid=path/to/the/file.did` argument:

```shell script
icx query 75hes-oqbaa-aaaaa-aaaaa-aaaaa-aaaaa-aaaaa-q greet --candid=~/path/greet.did '("World")' 
```
