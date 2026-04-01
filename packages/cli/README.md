# @clearproof/cli

Command-line tool for generating and verifying ZK compliance proofs.

## Install

```bash
npm install -g @clearproof/cli
```

## Usage

```bash
# Run the demo proof generation flow
npx @clearproof/cli demo
```

> **Note:** The CLI requires locally compiled circuit artifacts (WASM + zkey). You must compile circuits before running the demo:
>
> ```bash
> git clone https://github.com/clearproof/clearproof.git
> cd clearproof
> npm install
> bash scripts/compile_circuits.sh    # ~5 min, requires circom
> npx @clearproof/cli demo
> ```

## Links

- [Main repository](https://github.com/clearproof/clearproof)
- [Circuit documentation](https://github.com/clearproof/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
