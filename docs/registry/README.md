# Poseidon2 Domain Registry

This directory contains the machine-readable draft registry for protocol-visible
Poseidon2 domains.

This registry contains only Poseidon2 capacity domains: selectors used in
`[frame, selector, param0, param1]` to initialize Poseidon2 capacity. Transcript
labels are local to their transcript specification and are not part of this
global registry.

The central registry allocates top-level numeric ranges. The crypto repository
fills its maintained range here; delegated maintainer repositories maintain their
concrete domain entries inside their assigned ranges.

The registry is intentionally explicit. New consensus domains are assigned a
numeric `domain_id` from the assigned range, and `version` is encoded into the full
selector:

```text
selector = (domain_id << 8) | version
```

Human-readable names are for review and generated constants; the numeric
assignment is normative.

## Adding a Domain

1. Find the assigned range in `poseidon2-domains.toml`.
2. Pick the next unused `domain_id` in that range.
3. Add a `[[domains]]` entry with `version = 1`.
4. Describe the payload, frame rule, params, and rate layout.
5. Run the registry validation test:

```text
cargo test -p miden-crypto --test domain_registry
```
