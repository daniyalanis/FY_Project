# Journey - Homepage Migration Notes

Changes made inside `2026/HomePage/Tools/ECA_Tools` to support migration:

- `WebApp/app.py` now prefers `request.script_root` when passing `base_path` to templates, so it works when mounted at `/tools/ECA_Tools`.
- `WebApp/app.py` now supports package-style imports (fallback to local import) when loaded from the homepage gateway.
- No changes to templates, scripts, or requirements were required.
- `WebApp/app.py` now resolves Sage script paths from the app directory to avoid missing-file errors when mounted.
