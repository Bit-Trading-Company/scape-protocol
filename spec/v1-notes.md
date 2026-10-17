# Design note: MEME v1

_Draft 0, 2026-10-17. Status: **direction, not a spec.** Approved as direction on 2026-10-17. What MEME needs beyond [v0](v0.md) to carry a network at the scale of the largest social apps, and how v0 already leaves room for each piece. Each item becomes a spec in `docs/specs/` before it is built. v1 is due with M6 ([../engineering/v1-plan.md](../../docs/engineering/v1-plan.md#m6-open-network)); some pieces land earlier, as noted._

## Where scale really bites

Protocols are rarely what limits a social network. **Indexers are:** the services that build feeds, search, counts and graphs from everyone's data. Bluesky's protocol is cheap to run; its feed and search servers are where the money goes. The same will hold here.

So MEME's job is to **never be the bottleneck**: let indexing be split across many machines and many operators, let any cache serve data without trust, and let Scape's own Postgres-based services be replaced behind the protocol seams when they outgrow it. The items below serve that goal.

## Partitioned sync and backfill

**Problem.** A single network-wide stream of changes (Bluesky's firehose) has to be carried in full by every consumer. That gets expensive fast, and most consumers want only a slice.

**Direction:**
- Each host publishes its changes as **partitions**, each partition an ordered stream with its own cursor. Accounts are assigned to partitions by hash, so one account's changes stay in order.
- Consumers **subscribe with filters**: by account set, record type, or partition. A music indexer reads only `file` and track types; a friend's feed reads only followed accounts.
- **Backfill from snapshots:** a host can export an account (or a partition) as one archive at a checkpoint, so a new indexer starts from a snapshot and then follows the stream, instead of replaying history.
- Streams carry repository log entries plus the records they point at, and periodic checkpoints, so consumers verify completeness as they go.

**v0 already has:** the per-account repository log, its cursors (`seq`), and signed checkpoints. Partitioning is a grouping of those logs.

## Inclusion proofs

**Problem.** The v0 hash chain proves a range of the log is complete, but proving that *one* entry is in the log means fetching everything before it.

**Direction:** a **Merkle mountain range** over the repository log, with its root added to checkpoints (as a new `v`). A host can then prove any single entry with a few dozen hashes, which lets light clients and caches verify a record's place in the log cheaply.

**v0 already has:** log entries hashed individually and chained, so an MMR can be built over the same hashes without changing them.

## Key transparency

**Problem.** In v0 a host or directory can **withhold** a key log's newest entry, or show different versions to different readers, and nobody can tell.

**Direction:**
- Every key log entry is also appended to a public, append-only **transparency log**, as with Certificate Transparency for the web and key transparency for WhatsApp and iMessage at billions of users.
- Independent **witnesses** co-sign the log's head, so a split view requires them to collude.
- Readers accept a key log entry only with proof that it is in the transparency log, and can ask whether a newer entry exists.
- **Recovery windows** ride on the same log: within a fixed period (72 hours, say), a higher-priority rotation key can override a newer entry. This is the defense for a user whose host key was stolen, and it is what self-custody (M6) needs.

**v0 already has:** self-verifying, hash-linked key log entries and prioritized rotation keys, which are exactly what a transparency log stores.

## Private data across hosts

**Problem.** The model has *followers* and *members* visibility, but v0 moves only public data. A followers-only post on one host can't be read by a follower on another. At Instagram's scale, with private accounts common, this is the biggest gap.

**Direction, in two stages:**
1. **Service authentication** (target M3, needed once a second host exists). A host asking another for private data presents a short-lived token signed by the requesting account's key, naming the target host and the request. The serving host checks the key log and its own access rules. This is the same mechanism as v0's sign-in proofs, with a different audience.
2. **Audience encryption** (later). Records for an audience are encrypted to a group key that rotates as the audience changes, using MLS, already chosen for chat ([../engineering/architecture.md](../../docs/engineering/architecture.md#d9-chat-on-postgres-and-websockets)). Any host or cache can then carry them, because only members can read them.

**v0 already has:** visibility kept outside the record, and the sign-in proof format.

## Chunked file hashes

**Problem.** A file named by one SHA-256 can only be checked once it has been downloaded in full. A 4 GB video can't be verified while streaming, or after a seek.

**Direction:**
- Large files get a second name: a **BLAKE3** root hash, whose tree structure lets each chunk be verified on its own (via Bao-style outboards).
- File refs gain an optional `blake3` key next to `sha256`. Small files and Blossom compatibility keep using SHA-256.
- Video delivered through Mux is a derivative and isn't covered; originals are.

**v0 already has:** file refs that name the algorithm by key, so `{ "sha256": …, "blake3": … }` is an additive change.

## Labels

**Problem.** At scale, abuse grows faster than users. Moderation decisions need to travel between hosts and apps, and people need to see why something was hidden.

**Direction:**
- A **label** is a signed statement by a labeler account about a record, file, scape or account: "spam", "nudity", "AI-generated", "verified human", and so on.
- Labelers publish labels on their own stream. Apps and users choose which labelers to subscribe to.
- Scape's moderation publishes its decisions as labels, with statements of reasons ([../company/legal-and-safety.md](../../docs/company/legal-and-safety.md)).

**When:** early. The labeler starts with the moderation queue in M1, as a core record type, and becomes a protocol layer in v1.

**v0 already has:** core record types, and record refs pinned by CID, which are what a label points at.

## A binary wire format

**Problem.** JSON is larger and slower to parse than a binary format, and at billions of records that costs bandwidth and storage.

**Direction:** offer **deterministic CBOR** (RFC 8949 §4.2) as an alternative encoding on sync streams and archives, negotiated per connection. Signatures and CIDs stay defined over the JCS bytes, so a reader converts to JSON to verify. JSON remains the default, because people and AI can read it, which matters for Scape.

**v0 already has:** integers-only signed JSON, which converts to and from CBOR without loss.

## Order

| Item | Lands |
|---|---|
| Labels (as a record type) | M1 |
| Service authentication | M3 |
| Partitioned sync and backfill | M3, when the first outside indexer or the Nostr bridge needs it |
| Chunked file hashes | M4, with music and video at scale |
| Key transparency and recovery windows | M6, with self-custody |
| Inclusion proofs | M6 |
| Audience encryption | After the testing phase |
| Binary wire format | When bandwidth costs justify it |
