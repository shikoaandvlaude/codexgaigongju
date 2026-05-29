# HW Supplement Skills

These skills are optional helpers for authorized HW / blue-team style work.
They are not enabled by default because the main Bai workflow still focuses on bounty-oriented vulnerability hunting.

## Skills

- `exposed-surface`: management panels, Swagger/OpenAPI, actuator, debug, health, and metrics surfaces.
- `weak-credential`: default credentials, demo accounts, seed passwords, and leftover test credentials.
- `cloud-misconfig`: public bucket, object storage, CDN, ACL, IAM, and policy exposure.
- `cicd-exposure`: Jenkins, GitHub Actions, GitLab CI, runners, artifacts, and deployment secrets.
- `debug-backup`: logs, backup files, old archives, dumps, and public debug assets.

## How To Use

Open the discovery page and manually select the HW supplement skills when the authorized target or project scope calls for them.

Keep the validation light:

- Stay inside written scope.
- Prefer evidence from code, config, screenshots, or a single safe request.
- Do not brute force credentials.
- Do not run destructive checks.
- Treat these skills as triage helpers, then verify manually.
