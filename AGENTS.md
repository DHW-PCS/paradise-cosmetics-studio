# Repository Maintenance Guidelines

## Changes and verification

- Confirm the goal, acceptance criteria, and scope before making changes. Check Git status, then read the relevant code and documentation.
- Preserve unrelated work. Clarify module responsibilities, interfaces, and file ownership before implementing. Keep changes local and use clear names and simple control flow. Add fallbacks, retries, compatibility paths, or limits only when a concrete requirement or observed behavior justifies them.
- Choose the smallest check that covers the change. Review the diff for straightforward documentation changes and run the relevant `go test` checks for Go behavior changes.
- Review the diff, test results, and staged files before committing. Report which checks passed, failed, were skipped, or were not run. Keep credentials and unredacted production data out of source control and routine logs.

## Test containers

- Arrange cleanup when creating test containers, such as with a shell trap or a finally block. After testing, including after failure or interruption, stop and remove the containers created for the task. Verify that none remain unless retaining them was explicitly requested.
- Preserve named and anonymous data volumes unless deletion is authorized. Use `docker rm` without `-v`, and avoid `--rm` for containers whose volumes must be preserved. Do not remove other tasks' containers or run global prune commands.

## Terminology

- Use the full name Yggdrasil in project prose and new identifiers. Existing legacy or plugin identifiers, persisted names, and compatibility formats may remain unchanged.
