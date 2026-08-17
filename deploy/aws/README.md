# AWS EC2 Deploy

This path runs the whole app on one EC2 instance: frontend, backend, and PostgreSQL.

Use `t3.small` for this repo. It is the safer choice on a 2 GB box because the backend image, PostgreSQL, and Playwright/Chromium stack are all x86_64-friendly. `t4g.small` can work only if you are happy to move everything to ARM and re-test the browser stack.

## Recommended layout

* EC2 instance: Ubuntu 22.04 or Amazon Linux 2023
* Instance type: `t3.small`
* Storage: at least 30 GB gp3
* Security group: allow `22` from your IP, `80` from the world, `443` if you later add TLS

## Files

* `deploy/aws/docker-compose.yml` runs PostgreSQL, the backend, and the frontend reverse proxy.
* `deploy/aws/.env.example` holds the deployment variables.
* `frontend/Dockerfile` builds the SPA and serves it through Nginx.
* `frontend/nginx.conf` sends `/api/*` to the backend container and serves the SPA for everything else.
* `SCAN_PROFILE=lite` keeps Chromium-driven discovery off by default so the stack fits smaller instances; change it to `balanced` on a bigger box.

## Bootstrap

1. Copy `deploy/aws/.env.example` to `deploy/aws/.env` and fill in the secrets.
2. On the EC2 box, install Docker and the Compose plugin.
3. Clone this repo.
4. Run:

```bash
cd deploy/aws
docker compose up -d --build
```

The backend runs its Alembic migrations on startup, so a fresh box comes up with the schema applied.

Use a URL-safe `POSTGRES_PASSWORD`, or URL-encode it before placing it in `deploy/aws/.env`, because that value is embedded in the backend's `DATABASE_URL`.

`FRONTEND_ORIGINS` must match the browser origin exactly, including scheme. For a plain EC2 public IP, that usually looks like `["http://<public-ip>"]`; for a domain with TLS, use `["https://<domain>"]`.

## IAM

For a simple SSH-based deploy, the instance itself does not need a broad IAM role. If you want Session Manager, attach `AmazonSSMManagedInstanceCore` to the instance profile. If you are creating a deploy user for console work, keep it limited to the AWS services you actually plan to touch.

## Notes

* The app keeps the frontend and backend on the same origin in this layout, so the existing `/api` client default still works.
* Add TLS at the edge if this will be reachable beyond private testing.
* If memory gets tight, keep the swap file on. On a 2 GB instance that helps more than trying to squeeze the containers harder.
