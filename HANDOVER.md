# Handover: TIBX chain timeline and provenance

This branch hands work from a cloud Claude Code session to the local session that holds the
real TIBX test archives. The cloud session only ran synthetic tests, because its LFS data was
missing. Testing against real archives happens on the local bench.

The same file sits on the `handover/tibx-chain-timeline` branch of both
`falklindner/dissect.archive` and `falklindner/dissect.target`.

## Context

The use case is industrial (OT) security: running dissect over Acronis TIBX backups to find
threats, non-compliance and malware. Backup chains are the best sensor on hosts that cannot be
touched live, such as HMIs and engineering workstations.

The first feature built for this is the chain timeline and provenance:

- One archive opens as one target per backup.
- Every record says which backup it came from.
- A plugin lists the backups in an archive as a timeline.

## Branches

| Repository | Feature branch | Commit | Based on |
|---|---|---|---|
| dissect.archive | `claude/adoring-einstein-un7r6i` | `9b3fcec` | `main` at `8671dd4`, the merged parser |
| dissect.target | `claude/adoring-einstein-un7r6i` | `d6f3886` | `feature/tibx-loader` at `2979e36` |

The `handover/tibx-chain-timeline` branches are those feature branches plus this file. Do not
open pull requests from the handover branches. Open them from the feature branches, so this file
stays out of the history.

Merge order: dissect.archive first. The loader uses the new parser API. The dissect.target
pyproject pin is unchanged, at `dissect.archive>=1.9.dev3` with its release TODO.

## What changed

### dissect.archive

- `TIBX.recovery_point` returns the selected `RecoveryPoint`. While "latest" is selected it
  returns the newest backup, and without recorded backups it returns `None`.
- `TIBX.uuid` returns the archive UUID from the live ARCH root, read as `uuid.UUID(bytes_le=...)`.
  The mixed-endian layout is an assumption, taken from the slice GUIDs.
- `RecoveryPoint` gained `size`, `compressed_size`, `items_added`, `items_changed`, `items_removed`
  and `deleted`. They come straight from the slice record. `deleted` is bit `0x80` of its flags,
  exposed as the new constant `SLICE_DELETED`.
- `use_recovery_point()` also accepts a backup GUID, as a `uuid.UUID` or a string of 32 or more
  characters. An index shifts when Acronis deletes older backups, but a GUID does not.
- Synthetic tests are in `tests/tibx/test_recovery.py`.

### dissect.target

- In `dissect/target/loaders/tibx.py`, `recovery-point=all` makes `find_all` yield one URI per
  backup, oldest first. Each URI is keyed by GUID and keeps the other query parameters.
  - Without recorded backups, it yields `recovery-point=latest`.
  - If the archive cannot be opened, it yields the path unchanged, so loading reports the error.
  - A single-target open with `all` raises a `LoaderError` that explains why.
- `map()` sets `target.path` to `<archive>?recovery-point=<guid>`, the latest backup included.
  Every record's `_source` therefore names its backup, and prefixing `tibx://` reopens it.
  LocalLoader also sets `target.path`, so this has precedent.
- The new plugin `dissect/target/plugins/apps/backup/tibx.py` has the namespace `tibx`.
  - `tibx.recovery_points` yields `application/backup/tibx/recovery_point` records with these
    fields: `ts_created`, `ts_finished`, `index`, `guid`, `type`, `selected`, `deleted`, `size`,
    `compressed_size`, `items_added`, `items_changed`, `items_removed`, `archive_uuid` and `source`.
  - `tibx.backup` yields one `application/backup/tibx/backup` record. It describes the selected
    backup, with the fields `latest`, `recovery_points`, `encrypted`, `archive_uuid`, `source`
    and `parts`.
- Synthetic tests are in `tests/loaders/test_tibx.py` and `tests/plugins/apps/backup/test_tibx.py`.
  The loader tests use a `SyntheticTibx` stand-in.
- Two real-archive tests were changed without running them, because LFS data was absent:
  - `test_target_open` now expects the target path to start with
    `f"{path}?recovery-point=4b7e07ce-"`, the GUID prefix of the latest `t1_chain_inc` backup.
  - `test_split_archive_in_directory` now checks `target._loader.path.name`.

## Cloud results

All results are synthetic. The LFS files were pointers, not data.

- **dissect.archive:** every test that does not need LFS data passes. The failures are the 83
  tests in `test_tibx_acronis.py` and 7 VBK, VMA and WIM tests, all of them on LFS pointers.
- **dissect.target:** `tests/test_plugin.py` passes, including the source-field count of 81
  and the field type consistency check. The new synthetic tests pass, 16 for the loader and
  9 for the plugin.
- **Unchanged failures:** the 18 real-archive loader tests fail the same way before and after
  the change. So do the core and tools suites. Every failure comes from missing LFS data.
- **Suite guard:** dissect.target's suite refuses to start on LFS pointers. A local pytest
  plugin got around that in the cloud, and it was not committed.
- **End to end:** a synthetic chain of three backups with ext2 filesystems went through the real
  parser, loader, plugin and CLI. The commands used were target-query, target-shell and target-diff.

## To do on the bench

1. Check out the branches and pull the LFS data. Then install the four repos editable into one
   venv. The cloud needed pretended versions to satisfy the pins, which is likely unnecessary
   with real git tags:

   ```bash
   for r in dissect.archive dissect.target; do
       git -C $r fetch origin claude/adoring-einstein-un7r6i
       git -C $r checkout claude/adoring-einstein-un7r6i
       git -C $r lfs pull
   done

   uv venv .venv
   SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DISSECT_UTIL=3.25.dev99 \
   SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DISSECT_ARCHIVE=1.9.dev99 \
   SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DISSECT_VOLUME=3.18.dev99 \
   SETUPTOOLS_SCM_PRETEND_VERSION_FOR_DISSECT_TARGET=3.25.dev99 \
   uv pip install -e ./dissect.util -e "./dissect.archive[full]" -e ./dissect.volume \
       -e "./dissect.target[full]" pytest pexpect docutils
   ```

2. Run the tests:

   ```bash
   (cd dissect.archive && pytest tests/tibx)
   (cd dissect.target && pytest tests/loaders/test_tibx.py tests/plugins/apps/backup tests/test_plugin.py)
   ```

   If the GUID prefix or the path form is wrong, fix the two tests that were changed blind.

3. Check these against acrocmd or the Acronis console:
   1. Does `TIBX.uuid` match the archive ID Acronis shows? If it matches only reversed, the
      byte order assumption is wrong.
   2. Are `size`, `compressed_size` and the item counts per backup or cumulative? Check
      incremental and differential chains.
   3. Does retention set the deleted bit, or remove the slice record? Does a deleted backup still
      open, and does `recovery-point=all` cope with it?
   4. Does `recovery-point=all` work on split archives (`t1_chain_diff` with its `-0001` part),
      differential chains, encrypted archives (`-Kv dissect`) and multi-volume archives? Also try
      the user's real backups.

4. Try the CLI:

   ```bash
   target-query -f tibx.recovery_points path/to/archive.tibx -s
   target-query -f tibx.backup,hostname "tibx:///absolute/path/archive.tibx?recovery-point=all" -j
   ```

   Check that `_source` names a different backup for each target.

5. Report the results to the user. Push fixes to the feature branches only after the user agrees.

## Known limits

None of these come from this change.

- target-fs and target-inspect parse their target argument as a file path, so `tibx://` URIs
  do not work there. Use target-shell or target-query instead.
- `target-diff fs` counts a file as modified only when its size, mtime or ctime changes. A
  content change that keeps that metadata goes unnoticed, for example timestomped PLC logic.
  This matters for the next feature, change detection between backups.

## Synthetic chain builder

`handover_build_chain.py`, on the dissect.archive handover branch, builds the synthetic chain
used for the cloud's end-to-end check. It uses dissect.archive's own test builder and needs
`mke2fs`. Run it from the root of the dissect.archive checkout:

```bash
python handover_build_chain.py /tmp/plc-eng01.tibx
target-query -f walkfs "tibx:///tmp/plc-eng01.tibx?recovery-point=all" -j
target-shell "tibx:///tmp/plc-eng01.tibx?recovery-point=02020202-0202-0202-0202-020202020202" -c "cat /opt/project/line1.cfg"
```

Expected results:

- The dropped script `/tmp/dropper.sh` exists only in the newest backup.
- The setpoint file reads `setpoint=50` in backup `02020202-...` and `setpoint=80` in backup
  `03030303-...`.
- The backup type reads `unknown (0x0)`, because the builder writes no slice flags.
