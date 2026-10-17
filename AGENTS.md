# AGENTS.md

How to work in this repository. Read [`spec/v0.md`](spec/v0.md) before changing anything.

## Rules

1. **The spec wins.** If the code and the spec disagree, the code has a bug. If the spec is wrong or ambiguous, stop and ask the founder; the founder owns the protocol.
2. **Published formats don't change.** Within v0, only clarifications and additive changes allowed by the spec's [Evolution](spec/v0.md#evolution) rules. Anything else is a new `v`.
3. **Vectors are generated, never hand-edited.** Change [`conformance/build-vectors.ts`](conformance/build-vectors.ts), run `make vectors`, and commit both. A test fails if they drift.
4. **Never change the expected result of an existing vector** without the founder's approval: other implementations rely on it. Add new vectors instead.
5. **Every rule in the spec has a vector,** valid and invalid. A new rule ships with its vectors in the same change.
6. **MEME is a placeholder name.** Write it exactly as `MEME` in prose and `meme` in paths, so one search renames it. Never put it inside signed data.
7. **`make check` passes** before every commit.

## Layout

- `src/`: the reference library. No I/O, no clocks, no randomness except `generateKeyPair`.
- `conformance/build-vectors.ts`: builds every vector from fixed keys and times.
- `conformance/vectors.ts`: runs vectors through the library.
- `types/`: JSON Schemas. Open (no `additionalProperties: false`), additive only.

## Adding a record type

Follow the `scape-record-type` skill in `scape-app` once it exists. Until then: add `types/<type>.json`, register it in `src/schemas.ts`, add valid and invalid vectors, and add a row to the spec's core types table (founder approval needed).
