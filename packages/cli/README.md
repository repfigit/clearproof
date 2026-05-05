# @clearproof/cli

Command-line tool for generating and verifying ZK compliance proofs.

## Install

```bash
npm install -g @clearproof/cli
```

## Usage

```bash
# Run the demo proof generation flow using bundled circuit artifacts
npx @clearproof/cli demo
```

To use locally compiled artifacts from a repo checkout:
>
> ```bash
> git clone https://github.com/repfigit/clearproof.git
> cd clearproof
> npm install
> bash scripts/compile_circuits.sh    # ~5 min, requires circom
> npx @clearproof/cli demo --artifacts ./artifacts
> ```

## Links

- [Main repository](https://github.com/repfigit/clearproof)
- [Circuit documentation](https://github.com/repfigit/clearproof/tree/main/packages/circuits)

## License

Apache-2.0
