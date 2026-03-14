## Schema Version Resolution

This repository stores the Execution Plan schema in versioned directories:

- `schemas/execution-plan/<semver>/schema.json`

### Runtime behavior (current)

The runtime does **not** auto-discover schema versions. The schema is selected by **path**, typically via configuration (e.g., `schema_path`) or by embedding the intended version in the caller.

This is intentional:
- schema upgrades can introduce breaking changes
- we want upgrades to be an explicit opt-in, not a silent “latest wins” behavior

### Recommended usage

- Pin to an explicit version in production:
  - `schemas/execution-plan/1.0.0/schema.json`
- Treat upgrades as a deliberate change:
  - bump the pinned version and update any dependent code/tests accordingly

### "latest" alias (optional)

For convenience in development, we may add a non-versioned alias:

- `schemas/execution-plan/latest/schema.json` (copy or symlink)

If present, `latest` is **not** recommended for production usage. Production callers should pin to a specific version.

### Future versions

When a new schema version (e.g., `1.1.0`) is added:
- it will live under its own directory
- no runtime behavior changes automatically
- callers migrate by switching the pinned schema path