# Deployment and rollback

## Supported strategies

V1 supports configured Git deployments activated through either exact systemd restarts or a configured Docker Compose project directory. No agent-provided build command, path, ref, service, or Compose argument is accepted.

## Deploy transaction

`deploy_commit` performs the following bounded transaction:

1. Validate the exact 40-character commit and migration-risk acknowledgement.
2. Verify the configured repository and expected current release.
3. Reject dirty or conflicting repository state and unsafe/symlinked release paths.
4. Fetch only through the fixed Git invocation.
5. Verify the commit is reachable from at least one configured allowed ref.
6. Create an isolated release worktree.
7. Run only configured check and build executable/argument arrays.
8. Atomically switch the active symlink.
9. Restart only configured resources.
10. Run only configured health probes.
11. Restore the prior active release if activation verification fails.
12. Atomically record sanitized release evidence.

A dry-run performs validation and reports intended actions without creating a release, changing the symlink, restarting a resource, or writing release state.

## Rollback

`rollback_deployment` accepts only a commit already present in the deployment state ledger. It re-checks the expected current commit, activates that recorded release, restarts configured resources, runs probes, and restores the original current release if rollback verification fails.

## Database migrations

OpsHaven does not execute or reverse database migrations automatically. A deployment marked `manual-review` requires explicit acknowledgement. Before approval, determine whether the target commit is backward-compatible with the current schema and whether rollback remains safe. Refuse the operation when this is unknown.

## Failure recovery

If the client disconnects after mutation begins, treat completion as unknown. Inspect the deployed commit, service state, probes, release ledger, and audit log before retrying. Approval tokens are single-use; obtain a new request only after confirming current state.
