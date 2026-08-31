# CI workflow — staging location

`ci/ci.yml` is the finished GitHub Actions workflow for this repository. It lives here
**temporarily**: the automation account that authored it is a GitHub App installation that
does not (yet) hold the **Workflows: Read and write** permission, and GitHub refuses any
push, Contents API call, or Git tree that touches `.github/workflows/**` without it.

## Activate it

1. Grant the permission — GitHub → repository **Settings → Integrations → GitHub Apps** →
   the automation app → **Review request / Configure** → set **Workflows** to
   *Read and write*. (This is an App installation permission; a classic PAT's `workflow`
   scope is a different thing and will not unblock the App.)
2. Move the file into place and push:

   ```bash
   mkdir -p .github/workflows
   git mv ci/ci.yml .github/workflows/ci.yml
   git rm ci/README.md
   git commit -m "ci: activate GitHub Actions workflow"
   git push
   ```

Anyone pushing with their **own** GitHub account (including via the GitHub web UI:
*Add file → Create new file*) can skip step 1 — the restriction only applies to the App.

## What the workflow runs

| Job | What it does |
|-----|--------------|
| `backend` | `pytest -v` in `backend/` on Python 3.11 and 3.12, pip cache keyed on the requirements files, plus an app-import smoke check |
| `frontend` | `npm ci` + `npm run build` in `frontend/` on Node 20, uploads `frontend/dist` as an artifact |
| `docker` | Buildx builds of the `backend` and `frontend` images in parallel, with GitHub Actions layer caching |
| `compose` | `docker compose config` validation, then brings the stack up and smoke-tests `http://localhost:8000/api/health` and the UI on `:8080`, dumping container logs on failure |

Triggers: pushes to `main`, every pull request, and manual `workflow_dispatch`.
In-progress runs for the same ref are cancelled when a new commit arrives.

## Verified before commit

- Backend suite: **70 passed** locally (`pytest -q`).
- Frontend: `vite build` succeeds.
- Workflow YAML parses, and every action input used was checked against the live
  `action.yml` of each pinned action (`checkout@v7`, `setup-python@v7`, `setup-node@v7`,
  `upload-artifact@v7`, `setup-buildx-action@v4`, `build-push-action@v7`).
- The Docker image builds are the only steps not exercised locally — no Docker daemon is
  available in the authoring environment, so CI is their first real run.
