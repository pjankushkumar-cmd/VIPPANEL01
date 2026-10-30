# HACKII Full Server — Node 26 compatible

This build removes `better-sqlite3` and uses Node.js built-in `node:sqlite`. It avoids the `node-gyp` native addon compilation failure shown in Render logs.

## Render settings
- Build command: `npm install`
- Start command: `npm start`
- Node version: Render uses Node 26.13.0 in the reported build; this project requires Node >=26.11.0.
- Environment: only `ADMIN_KEY` (minimum 24 characters).
- Persistent disk: mount at `/opt/render/project/src/data` to retain `data/hackii.sqlite`.

The API URL, API key header (`X-API-Key`), database path and session duration remain configured in `server.js` / project code.


## Member key login fix
Keys are normalized with Unicode NFKC normalization and trimmed when saved and checked for both Global and Individual member logins. Matching remains case-sensitive. After deploying this update, recreate affected individual member keys and re-save the global member key in Admin Settings. Existing bcrypt hashes cannot be safely rewritten because the original key text is not stored.
