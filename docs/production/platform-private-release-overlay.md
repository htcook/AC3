# AC3 production platform release overlay

## Purpose

`ac3-production-platform-private` currently runs a distroless amd64 image whose
entrypoint is `runtime-bootstrap.mjs`. The production ECS task supplies RDS
connection information as the separate `DATABASE_HOST`, `DATABASE_PORT`,
`DATABASE_USERNAME`, `DATABASE_PASSWORD`, and `DATABASE_NAME` values rather
than `DATABASE_URL`.

The normal source Dockerfile rebuilds all Node dependencies. When the release
executor is not amd64-native, use `Dockerfile.aws.release-overlay` instead of
changing the production service to a locally emulated dependency rebuild. The
overlay starts from the exact digest used by the currently contained production
service and replaces only the reviewed built application and release artifacts.
It retains the base image's amd64 Node runtime and production dependency
closure.

## Security invariants

- Begin with `AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED=false`; do not enable it
  during migration or verification.
- Create and wait for an encrypted RDS snapshot before any DDL.
- Build from an immutable **base image digest** and publish an immutable,
  commit-addressable overlay image tag/digest.
- The overlay bootstrap derives `DATABASE_URL` only in the application process
  from complete split RDS variables. It never prints the URL or credentials.
- `RUN_DATABASE_MIGRATIONS=true` is rejected by the service bootstrap. Schema
  changes are permitted only from the controlled one-off task.
- One-off migration and verification commands resolve the same split RDS
  variables directly; they do not rely on a shell entrypoint.
- `AC3_RUNTIME_SCHEMA_MIGRATIONS_ENABLED` remains `false` on the service task.
- Promote the service only after both `run-migrations.mjs` and
  `verify-agent-tenant-isolation.mjs` exit successfully from the candidate
  image.

## IAM-role separation

Keep the ECS roles separate:

- **ECS execution role:** image pull, log delivery, and startup-only platform
  duties. Do not grant it application runtime permissions or use it for builds.
- **ECS task role:** runtime application access only. Do not use it as the
  execution role or as a CodeBuild role.
- **Build role:** a dedicated CodeBuild/ECR publication role only. Inspect its
  trust relationship and permissions before use. Do not repurpose an ECS role
  for an image build.

## Dedicated database migration principal

The platform application account is intentionally DDL-free. Before running a
schema migration, create or rotate the `ac3plus_schema_migrator` database
principal through the isolated provisioning task; do not grant `CREATE` or
`ALTER` to the platform account.

- Store its generated, 32+ character password as the JSON `password` field of
  the dedicated Secrets Manager migration credential.
- Start the provisioner with the managed RDS master credential injected only
  into the one-off task as `DATABASE_PASSWORD`, and the generated migration
  password injected as `AC3_MIGRATION_DB_PASSWORD`.
- Run `/nodejs/bin/node provision-migration-principal.mjs` with
  `AC3_MIGRATION_DB_USERNAME=ac3plus_schema_migrator`.
- The provisioner requires SSL and grants only `SELECT`, `INSERT`, `UPDATE`,
  `CREATE`, `ALTER`, `INDEX`, and `REFERENCES` on the application schema. It
  does not grant `DROP`, `DELETE`, global administration, or application IAM
  access.
- The subsequent migration and verifier tasks use this migration credential;
  the ECS service continues to use the DDL-free platform database account.

## Overlay build procedure

1. Read the contained service's task definition and resolve its current image
   digest from ECR. Record this as `BASE_IMAGE`.
2. Confirm the checked-out security branch is clean and build the source bundle:

   ```sh
   pnpm run build
   ```

3. Build the overlay for the production architecture. Replace the placeholders
   with the fixed base digest and current Git commit:

   ```sh
   docker build --platform linux/amd64 \
     --file Dockerfile.aws.release-overlay \
     --build-arg BASE_IMAGE='ACCOUNT.dkr.ecr.REGION.amazonaws.com/ac3-plus/platform@sha256:BASE' \
     --build-arg RELEASE_SHA='GIT_COMMIT' \
     --build-arg RELEASE_DATE="$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
     --tag 'ACCOUNT.dkr.ecr.REGION.amazonaws.com/ac3-plus/platform:prod-tenant-isolation-GIT_COMMIT' \
     .
   ```

4. Push the image, retrieve its ECR digest, and register a new ECS task
   definition that changes only the image reference from the contained task
   definition. Preserve secrets, both role ARNs, network configuration, and
   `AC3_LIVE_ENGAGEMENT_EXECUTION_ENABLED=false`.

## Controlled migration and verification

Use the new task definition but do **not** update the ECS service yet. Run a
one-off task in the service's private subnets and security groups with the
following commands, in this order:

```text
/nodejs/bin/node run-migrations.mjs
/nodejs/bin/node verify-agent-tenant-isolation.mjs
```

For each task, wait for `STOPPED`, require `exitCode=0`, and inspect the
CloudWatch log stream for the expected completed status. Any non-zero exit,
missing migration record, unresolved tenant ownership, missing physical
constraint, or failed foreign-key/index check blocks rollout.

## Service rollout and acceptance

1. Update `ac3-production-platform-private` to the verified candidate task
   definition and force a new deployment.
2. Wait for a completed rollout with `runningCount == desiredCount`.
3. Confirm the candidate task is healthy and logs show the bootstrap configured
   split ECS database values without printing a connection string.
4. Confirm tenant-isolation verifier output remains successful.
5. Keep the live-execution feature gate disabled pending an explicit separate
   authorization. Roll back to the recorded contained task definition if the
   service does not stabilize.
