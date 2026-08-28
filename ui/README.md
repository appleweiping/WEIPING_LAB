# WEIPING_LAB UI

React/Vite interface for discovery, extension, transfer, session inspection, and streamed progress.

## Local development

Start the API from the repository root:

```powershell
uvicorn api.server:app --reload --port 8001
```

Install and start the UI:

```powershell
npm ci --prefix ui
npm --prefix ui run dev
```

Vite serves `http://localhost:5174` and proxies `/api` to `http://localhost:8001`.

## Quality gates

```powershell
npm --prefix ui run lint
npm --prefix ui run build
```

The full repository gate is `powershell -ExecutionPolicy Bypass -File scripts\verify.ps1`.
