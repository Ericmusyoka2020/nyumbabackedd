# Nyumba

## Run locally

1. Copy `.env.example` to `.env`.
2. Set `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` from your remote Turso database.
3. Set a private `ADMIN_PASSCODE`. A random `JWT_SECRET` of at least 32 characters is recommended; if omitted, it is derived from the server-only Turso auth token.
4. Run `npm install`, then `npm start` to start the API on port 4000.
5. Host `index.html` and `admin.html` separately as static frontend files. The API does not serve frontend pages.

The backend creates and updates the application tables in the configured Turso database when it starts. It does not create or use a local database. User profiles, listings and their photos, payment records, reports, plans, and system settings are persisted in Turso. The browser only keeps the signed-in session token; profile information is loaded from the server.

## Deploy API separately from the frontend

The Express application exports an API handler and includes Vercel function routes under `api/`; it does not start a listener when imported by Vercel. The backend is API-only on every host and never serves the frontend. Host `index.html` and `admin.html` separately. Set these server-side environment variables on the API host: `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `ADMIN_PASSCODE`, `JWT_SECRET`, `ALLOWED_ORIGINS`, and `PAYMENT_GATEWAY_URL`. Password-reset mail also requires all four `EMAILJS_SERVICE_ID`, `EMAILJS_PUBLIC_KEY`, `EMAILJS_PRIVATE_KEY`, and `EMAILJS_TEMPLATE_ID` variables on the API host; local `.env` values are not automatically available to a hosted API. Never place database or admin credentials in frontend files.

Both frontend pages currently point to `http://localhost:4000` in their `api-base` meta tag for local development. Before publishing, replace that value in `index.html` and `admin.html` with the deployed API's public origin, for example `<meta name="api-base" content="https://your-api.example.com" />`. This is the frontend build's backend link; leave off the trailing slash and rebuild/re-upload the static files after changing it. Alternatively, define `window.API_URL` before the page's main script. Set `ALLOWED_ORIGINS` on the API to the exact frontend origin(s), comma-separated, so browser API requests pass CORS checks. Open `https://your-api.example.com/api/health` to verify the API and Turso connection.

### Render

This repository includes `render.yaml` for the API web service. Create or update a Render Blueprint from the repository, then set the prompted `TURSO_DATABASE_URL`, `TURSO_AUTH_TOKEN`, `ADMIN_PASSCODE`, `JWT_SECRET`, and `ALLOWED_ORIGINS` values in Render's environment settings. The Render log shown when these are absent means those secrets have not been added to the service; `.env` is intentionally ignored by Git and is not uploaded to Render. Keep `TURSO_DATABASE_URL` and `TURSO_AUTH_TOKEN` from the same Turso database. Set `ALLOWED_ORIGINS` to the exact static frontend origins (comma-separated). Add the four `EMAILJS_*` values too if password reset email is enabled. Render supplies `PORT`; the server listens on it. The health check is `/api/health`.

For an existing Render web service, use build command `npm install`, start command `npm start`, and health check path `/api/health`, then add the required environment variables under **Environment** and redeploy. Do not copy secret values into `render.yaml`.

### Vercel

Set the same required server-side environment variables in the Vercel project's **Settings → Environment Variables**. Vercel's `api/` functions route API requests; do not configure this project to deploy the frontend. If a required variable is missing, the server reports its name at startup. The frontend remains a separate static deployment.

## Frontend and local preview

For local preview on ports 3000, 5173, 5500, or 5501, the pages connect to port 4000 on the same host name as the page (so another device on your network can reach the backend). Keep `.env` and all database/authentication credentials on the server; do not publish them in frontend code.

The admin passcode is exchanged for a short-lived signed session token and is never sent with admin data changes. Existing sessions expire after 12 hours.

For EmailJS password resets, configure the selected template's recipient field as `{{to_email}}`, subject as `{{subject}}`, and message body as `{{message}}`. The API also supplies `{{reset_code}}`, `{{verification_code}}`, `{{otp}}`, and `{{code}}` for templates using those code variable names. The API reports EmailJS errors instead of showing a successful “code sent” state, and removes reset codes when EmailJS rejects a send so a failed attempt does not consume the resend cooldown. A successful EmailJS API response confirms acceptance by EmailJS, not final inbox delivery; check the EmailJS activity log and the service's verified sender/delivery settings if a message is still missing.

The public listing search matches county names in the combined location search. A post can include multiple unit types in one building; these selections are saved in Turso and can be filtered, displayed, and edited. Existing single-type listings are migrated automatically. Listing results return only a cover image; remaining photos and full details are fetched when a listing is opened, reducing the initial response size. The cookie notice stores only the user's preference and the site does not use advertising or analytics cookies.

## Listing and payment workflows

Listings are editable from the signed-in user dashboard. Renewal plans, photo additions, and priority boosts are selected there and their changes are saved only after payment verification succeeds. Admins can inspect listing and report details, filter listing states, restore paused listings, and add days to expired listings.

The configured payment gateway must provide a status result tied to the specific STK prompt. The current `/api/status` integration returns a global status response, which cannot reliably identify the matching prompt when payments overlap. Until the gateway supports per-checkout verification or callbacks, do not treat concurrent payment prompts as safely verifiable.

Payment and email requests use bounded upstream timeouts. If the gateway closes a connection, the API reports an upstream availability error and marks an initiated payment as failed when it can; the gateway itself must be reachable and return valid JSON for payment prompts and status checks to complete.
