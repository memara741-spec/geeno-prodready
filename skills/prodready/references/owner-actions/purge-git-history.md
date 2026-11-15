# Removing a secret from git history

What this covers: when it is worth rewriting history, the risks, and the steps. Read it for SEC-003. After reading you can decide and, if needed, do it safely. Rotation is still required either way.
Last checked: 2026-11-13.

**First, rotate the key** (`rotate-keys.md`). History rewriting does not undo exposure: forks, clones and caches may already hold the secret.

**Worth doing when** the repository is public or shared widely, or the history also holds other data you must remove. **Usually not worth it** for a private repository with a few collaborators once the key is rotated.

**Risks.** Every commit hash changes; collaborators must re-clone or reset; open pull requests break; a force push is irreversible on the remote.

**Steps.**
1. Tell collaborators and ask them to push everything first. Make a full backup copy of the repository folder.
2. Install `git-filter-repo` (the maintained history-rewriting tool).
3. In a fresh clone run `git filter-repo --invert-paths --path .env` to drop a file, or `git filter-repo --replace-text expressions.txt` to replace a value (the file lists `literal==>REMOVED`; do not paste the secret anywhere else).
4. Review with `git log --all -p -S"<first characters>"`.
5. Force-push all branches and tags: `git push --force --all` and `git push --force --tags`. Ask the host to purge cached views if offered.
6. Collaborators run a fresh clone. Do not merge old branches back.

Claude does not run history rewrites; they are owner actions.
