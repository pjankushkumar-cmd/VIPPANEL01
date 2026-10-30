# HACKII Full Server

Only one environment variable is required: `ADMIN_KEY` (minimum 24 characters).

## Render
- Build command: `npm install`
- Start command: `npm start`
- Environment: add only `ADMIN_KEY`
- Add a persistent disk mounted at `/opt/render/project/src/data` to retain `data/hackii.sqlite`.
- Open `/admin` for the admin panel.

The API URL, API key header (`X-API-Key`), database path (`./data/hackii.sqlite`) and session duration are configured inside `server.js`. Admin sets global/member API key values from the panel; they are stored server-side and never exposed to member browsers. Change the API header constant in `server.js` if the provider expects a different format.

Member keys are bcrypt-hashed. Device caps use a browser-generated localStorage identifier, not hardware attestation; clearing browser data can register a new device. Online status means activity in the last 90 seconds. SHA-256 estimates do not guarantee random external results. SQLite is for a single server instance.
