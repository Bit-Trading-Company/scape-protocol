# MEME

**MEME** (_Multi-host Exchange for Media and Entities_) is the open protocol beneath [Scape](https://scape.com.de): self-certifying accounts, signed records, content-addressed files and portable scapes, so the network survives without any one host. The name is a placeholder; search for it to rename.

| Path                                   | What                                                                                   |
| -------------------------------------- | -------------------------------------------------------------------------------------- |
| [`spec/v0.md`](spec/v0.md)             | **The specification.** Where code and spec disagree, the spec wins                     |
| [`spec/v1-notes.md`](spec/v1-notes.md) | Design direction for v1: sync, key transparency, private data across hosts             |
| [`types/`](types/)                     | JSON Schemas of the core record types                                                  |
| [`src/`](src/)                         | The reference library: create and verify every v0 object                               |
| [`vectors/`](vectors/)                 | Test vectors any implementation, in any language, can run ([guide](vectors/README.md)) |
| [`conformance/`](conformance/)         | The vector runner, the vector builder, and live host checks                            |

## Use

```bash
make install
make check          # lint, types, unit tests, conformance
pnpm conformance    # every vector, with results
make vectors        # regenerate vectors/ after changing conformance/build-vectors.ts
```

Needs Node 24 and pnpm 10.

## Status

v0, approved 2026-10-17. Implemented here: key logs, records, the repository log and checkpoints, sign-in proofs, file refs and scape bundles, plus live host checks (`pnpm conformance --host URL --account ID`) for the descriptor, key logs, handles and errors. Checks for the record, log and checkpoint endpoints are written as hosts start serving them; until then they report as pending.

## License

Not chosen yet.
