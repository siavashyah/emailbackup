# emailbackup

A small set of Python scripts to download and export emails for local backup and analysis.

## What this project does

- Downloads emails using settings in `config.ini` and stores them in `downloaded_emails/`.
- Provides a simple exporter to convert stored emails into Excel (CSV/XLSX) via `export_to_excel.py`.
- Uses `database.py` for lightweight local storage/lookup.

## Requirements

- Python 3.8 or newer

## Configuration

- Edit `config.ini` at the project root. The downloader scripts read connection/auth settings from this file.
- Make sure the `downloaded_emails/` directory exists and is writable by your user.

## Quick start (PowerShell)

Open PowerShell in the project folder and run:

```powershell
# create venv (optional)
python -m venv .venv
; .\.venv\Scripts\Activate.ps1

# run the email downloader (reads config.ini)
python .\email_downloader.py

# export downloaded emails to Excel/CSV
python .\export_to_excel.py
```

## Files

- `config.ini` — configuration for email access (credentials, server, folders).
- `email_downloader.py` — main downloader script.
- `database.py` — simple local DB helpers.
- `export_to_excel.py` — create Excel/CSV from downloaded emails.
- `downloaded_emails/` — directory where raw email files are stored.
