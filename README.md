# VICTORY DENTAL CLINIC — Stage 3 Cloud Deployment

This build runs the clinic web app and FastAPI backend from the same HTTPS service and uses PostgreSQL for shared data.

## What this stage solves
- One shared database for phone + computer.
- HTTPS deployment target.
- PostgreSQL instead of local SQLite for the production cloud database.
- Login sessions stored server-side.
- Patient, appointment, treatment, billing totals and audit data stored centrally.
- The existing browser interface is served by the backend, so there is one app URL.

## Deploy with Render
1. Create a GitHub repository and upload this project folder.
2. In Render, create a new Blueprint and select the repository containing `render.yaml`.
3. Render can create the web service and PostgreSQL database from the Blueprint.
4. The `ADMIN_PASSWORD` is generated as a secret. Save it before first use and use the generated value to log in with `ADMIN_EMAIL`.
5. Open the service URL. Test `/api/health`, then log in.
6. On Android, use the browser's Add to Home Screen / Install option. On a computer, bookmark or install the PWA where supported.

## Important production note
The whole-clinic `/api/state` sync endpoint is retained for compatibility with the first builds. Before using this for a real clinic, the next development stage should replace whole-state overwrite with record-level synchronization, add role permissions, password change, stronger session management, reminders, detailed reports, and more granular audit logging.

Never place database credentials or admin passwords in the frontend code or repository.
