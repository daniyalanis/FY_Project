# 2026 HomePage Gateway

This folder hosts the main homepage and mounts tools under the `/tools/<ToolName>` path.

## What runs where

- Main homepage: http://localhost:8000
- ECA Tools: http://localhost:8000/tools/ECA_Tools

## Run locally (Docker)

From `2026/HomePage`:

```bash
docker compose up -d --build
```

Stop:

```bash
docker compose down
```

## Run locally (Python)

You need SageMath installed locally.

```bash
cd 2026/HomePage
python app.py
```

If needed, install dependencies:

```bash
sage -pip install -r Tools/ECA_Tools/WebApp/requirements.txt
```

## Deploy on Render

- Runtime: **Docker**
- Root Directory: `2026/HomePage`
- Render will inject `PORT`; the container defaults to `8000`.

## Tool migration checklist

1. Copy the tool into `2026/HomePage/Tools/<ToolName>/WebApp`.
2. Ensure the tool exposes a Flask `app` object in `WebApp/app.py`.
3. Make sure the tool builds URLs from `request.script_root` so it works when mounted.
4. Mount it in `app.py` (add to `DispatcherMiddleware`).
5. Add a button link in `home.html` to `/tools/<ToolName>`.

Example mount snippet in `app.py`:

```python
from Tools.MyTool.WebApp.app import app as my_tool_app

application = DispatcherMiddleware(home_app, {
    "/tools/ECA_Tools": eca_app,
    "/tools/MyTool": my_tool_app,
})
```

## Notes

- ECA Tools uses SageMath scripts under `Tools/ECA_Tools/WebApp/scripts`.
- The homepage gateway keeps tool apps isolated by URL prefix.
- Tool scripts are invoked via absolute paths so the gateway can mount the app without path issues.
