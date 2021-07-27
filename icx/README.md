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
For non-IC networks, pass `--fetch-root-key` to fetch the root key.  When this argument is not present,
icx uses the hard-coded public key.

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

#### Sign and Send Separation
Pass `--serialize` when use `icx update` and `icx query` will serialize the signed canister call message as json.
The output will print to stdout. When use `icx update`, a corresponding request_status message is also generated and printed to stderr.

In the default IC project generated with `dfx new` and the local emulator has started with `dfx start --background`.

##### Sign
```shell script
icx --fetch-root-key update --serialize rwlgt-iiaaa-aaaaa-aaaaa-cai greet '("everyone")' > output.txt
head -n 1 output.txt > update.json
tail -n 1 output.txt > request_status.json
```
> `rwlgt-iiaaa-aaaaa-aaaaa-cai` is the ID of hello canister in the default project.

##### Send
```shell script
cat update.json | icx send
...
RequestID: 0x1234....
```

##### Request status
```shell script
cat request_status.json | icx --fetch-root-key send
...
("Hello, everyone!")
```

When sending message to the IC main net, all `--fech-root-key` are not required. So the sign step can be executed on an air-gapped machine.