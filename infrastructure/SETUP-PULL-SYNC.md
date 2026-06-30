# AC3 — Pull-Sync Setup Guide for AceofCloud Admin

**Author:** Harrison Cook  
**Last Updated:** April 28, 2026

This document explains how to set up automatic syncing from the developer repo (`hcook-aoc/AC3`) into the company repo (`aceofcloud/AC3`). The company repo **pulls** from the developer repo — no write access to `aceofcloud/AC3` is needed by the developer.

---

## How It Works

A GitHub Actions workflow runs daily (and on-demand) on `aceofcloud/AC3`. It uses a read-only PAT to fetch the latest code from `hcook-aoc/AC3` and fast-forward merges it into `aceofcloud/AC3`.

```
hcook-aoc/AC3  ──── pull (read-only PAT) ────►  aceofcloud/AC3
  (developer)         daily at 06:00 UTC           (company)
```

The developer never needs write access to the company repo. The company controls when and how code is synced.

---

## Setup Steps

### Step 1: Add the Workflow File

Copy `infrastructure/aceofcloud-sync-workflow.yml` into the company repo at:

```
aceofcloud/AC3/.github/workflows/sync-from-dev.yml
```

You can do this via the GitHub web UI (Add file → Create new file) or by cloning the repo locally.

### Step 2: Add the UPSTREAM_PAT Secret

The workflow needs a Personal Access Token that can **read** `hcook-aoc/AC3` (which is a private repo).

**PAT Value (read-only, scoped to hcook-aoc/AC3):**

```
<REDACTED_UPSTREAM_PAT>
```

Add it as a repository secret:

1. Go to `aceofcloud/AC3` → **Settings** → **Secrets and variables** → **Actions**
2. Click **New repository secret**
3. **Name:** `UPSTREAM_PAT`
4. **Value:** Paste the PAT above
5. Click **Add secret**

### Step 3: Verify

1. Go to `aceofcloud/AC3` → **Actions** tab
2. Click **"Sync from Developer Repo"** in the left sidebar
3. Click **"Run workflow"** → **"Run workflow"**
4. The workflow should complete in under a minute and sync all code

---

## Usage

### Automatic Sync

The workflow runs automatically every day at **06:00 UTC**. No action needed.

### Manual Sync

To sync immediately:

1. Go to `aceofcloud/AC3` → **Actions** → **Sync from Developer Repo**
2. Click **"Run workflow"**
3. Leave "Force sync" as `false` for safe fast-forward merge
4. Click **"Run workflow"**

### Force Sync (Overwrite)

If the company repo has diverged (local changes were made directly), you can force-overwrite:

1. Go to **Actions** → **Sync from Developer Repo** → **Run workflow**
2. Set "Force sync" to `true`
3. Click **"Run workflow"**

**Warning:** Force sync overwrites all changes in `aceofcloud/AC3` with the developer repo. Use only when you want to reset to the developer's version.

---

## Security Notes

The PAT used (`UPSTREAM_PAT`) has the following properties:

| Property | Value |
|---|---|
| Owner | `hcook-aoc` (Harrison Cook — AoC account) |
| Type | Fine-grained PAT |
| Scope | `hcook-aoc/AC3` only |
| Permissions | Contents: read-only, Metadata: read-only |
| Risk | Read-only — cannot modify the developer repo |

The PAT allows the company workflow to **read** the private developer repo. It cannot write, delete, or modify anything in `hcook-aoc/AC3`.

---

## Troubleshooting

**"Fast-forward not possible"** — The company repo has commits that don't exist in the developer repo. Either merge manually or use force sync to overwrite.

**"Resource not accessible by personal access token"** — The `UPSTREAM_PAT` secret may be expired or missing. Re-add it following Step 2.

**"Not Found" errors** — The PAT may have been revoked. Contact Harrison Cook for a new PAT.
