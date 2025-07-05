# CLI

The `cargo prove` CLI is useful for various tasks related to the Ziren project. Typically users will not need to interact with the CLI directly, but rather use the `zkmup` script to install the CLI.

## Development

To run the CLI locally, you can use the following command:

```bash
cargo run --bin cargo-prove -- --help
```

To test a particular subcommand, you can pass in `prove` and the subcommand you want to test along with the arguments you want to pass to it. For example, to test the `new` subcommand, you can run the following command:

```bash
cargo run --bin cargo-prove -- prove new --bare fibonacci
```

### Installing the CLI locally from source

You can install the CLI locally from source by running the following command:

```bash
cargo install --locked --force --path .
```

### Running the CLI after installing

After installing the CLI, you can run it by simply running the following command:

```bash
cargo prove
```
