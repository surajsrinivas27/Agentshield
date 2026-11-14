# AgentShield frontend

React, TypeScript, and Vite dashboard for the AgentShield security workflow.

## Run locally

From this folder:

```powershell
npm install
npm run dev
```

Open the local URL printed by Vite, usually `http://localhost:5173`.

## Backend connection

Create `frontend/.env.local` from `.env.example`, then set the base URL to the
FastAPI host reachable from this computer. For a backend on another laptop, use
that laptop's local-network IP and port, for example:

```env
VITE_API_BASE_URL=http://192.168.1.25:8000
```

Restart Vite after changing `.env.local`. The backend must allow the frontend
origin through CORS. The dashboard uses the API endpoints in
`../docs/API_CONTRACTS.md`.

## Optional Spline visual

Publish a Spline scene using the web embed option and put its iframe URL in
`.env.local`:

```env
VITE_SPLINE_EMBED_URL=https://my.spline.design/your-published-scene/
```

Restart Vite after changing the URL. When the URL is empty, the dashboard uses
its CSS shield illustration instead.

## Checks

```powershell
npm run build
npm run lint
```

The overview metrics are illustrative demo values. API-driven results appear
after the backend is running. Raw source text and placeholder mappings are kept
in the AI Assistant's React memory; the workflow API receives masked content.
