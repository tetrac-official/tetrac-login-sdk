# Project rules

## Git — NEVER commit

- **Never run `git commit`.** Not with `-m`, not `--amend`, never.
- **Never `git push`, `git merge`, `git rebase`, `git reset`, `git checkout -b`, `git branch`, or `git tag`.** Do not create, move, rename, or delete branches. Do not modify history.
- **Make file edits only.** Leave every change in the working tree, uncommitted.
- The user owns ALL git operations — staging, committing, branching, merging, tagging, and publishing to npm. Do not do any of these, even if it seems helpful or the user asks indirectly ("bump and publish", "put this on a branch"). Make the file changes and stop; report what changed and let the user run git.
- Read-only git is fine (`git status`, `git log`, `git diff`, `git branch --list`, `git show`).

## Publishing

- Never run `npm publish` (or `yarn publish`). The user publishes to npm themselves.
- You may bump the `version` field in `package.json` as a file edit when asked, but do not commit or tag it.
