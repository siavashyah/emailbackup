import sqlite3
import pandas as pd
import os
import sys
import io
import re
import contextlib
from pathlib import Path

# --- Settings ---
DB_FILE = 'emails.db'
OUTPUT_EXCEL_FILE = 'Email_Report.xlsx'  # Make sure this file is saved in your main folder (the base of folder_path)
# ----------------


# ------------- Logging helpers (tee stdout/stderr to file) -------------
class Tee(io.TextIOBase):
    """A simple tee that writes to multiple streams (e.g., console and a file)."""
    def __init__(self, *streams):
        self.streams = streams
    def write(self, s):
        for st in self.streams:
            st.write(s)
            st.flush()
        return len(s)
    def flush(self):
        for st in self.streams:
            st.flush()

@contextlib.contextmanager
def tee_output(file_path, mode='a', encoding='utf-8'):
    """
    Context manager that duplicates stdout and stderr to a log file,
    while still showing output in the console.
    """
    f = open(file_path, mode, encoding=encoding)
    try:
        tee_out = Tee(sys.stdout, f)
        tee_err = Tee(sys.stderr, f)
        with contextlib.redirect_stdout(tee_out), contextlib.redirect_stderr(tee_err):
            yield
    finally:
        f.close()
# ----------------------------------------------------------------------


# -------------------------- Data cleaners -----------------------------
def clean_body_text(text, clip_to_excel_limit=True):
    """
    Clean up email body text:
      - Normalize newlines
      - Remove zero-width and non-breaking spaces
      - Collapse repeated horizontal spaces
      - Collapse multiple blank lines
      - Optionally clip to Excel's max cell length (32,767 chars)
    """
    if pd.isna(text):
        return text
    s = str(text)

    # Normalize line breaks
    s = s.replace('\r\n', '\n').replace('\r', '\n')

    # Remove non-breaking and zero-width spaces
    s = s.replace('\u00A0', ' ')
    s = re.sub(r'[\u200B-\u200D\uFEFF]', '', s)

    # Collapse repeated horizontal whitespace but keep line breaks
    s = re.sub(r'[ \t\f\v]+', ' ', s)

    # Collapse 3+ blank lines to 2
    s = re.sub(r'\n{3,}', '\n\n', s)

    # Clip to Excel cell char limit if requested
    if clip_to_excel_limit and len(s) > 32767:
        s = s[:32760] + '…'

    return s.strip()
# ----------------------------------------------------------------------


def get_excel_writer(output_path):
    """
    Create a Pandas ExcelWriter with XlsxWriter engine and disable automatic
    string-to-URL conversion to avoid UserWarning 1303 on long 'body_text' cells.
    Includes a backward-compatible fallback if engine_kwargs isn't supported.
    """
    options = {'strings_to_urls': False, 'strings_to_formulas': False}
    try:
        # Pandas >= 1.4
        return pd.ExcelWriter(output_path, engine='xlsxwriter', engine_kwargs={'options': options})
    except TypeError:
        # Fallback for older Pandas
        writer = pd.ExcelWriter(output_path, engine='xlsxwriter')
        try:
            writer.book.strings_to_urls = False
            writer.book.strings_to_formulas = False
        except Exception:
            pass
        return writer


def to_external_relative_folder_url(rel_path_str):
    """
    Build an Excel 'external:' hyperlink from a relative folder path.
    - rel_path_str must be relative to the workbook location (the main folder).
    - Use forward slashes for cross-platform compatibility.
    - Explicitly prefix with './' if it doesn't start with './' or '../'
    - Add a trailing '/' so Excel treats it as a folder link (opens folder).
    """
    if pd.isna(rel_path_str):
        return None

    p = str(rel_path_str).strip()
    if not p:
        return None

    # Normalize: remove accidental URL prefixes and normalize separators
    p = re.sub(r'^(?:external:|file:/{2,3})+', '', p, flags=re.I)
    p = p.replace('\\', '/')

    # If it is absolute (starts with drive, UNC, or root), we keep it,
    # but note: it won't be portable when moving drives
    is_abs = bool(re.match(r'^[A-Za-z]:/|^/|^//', p))
    if not is_abs:
        # Ensure explicit relative indicator
        if not p.startswith(('./', '../')):
            p = './' + p

    # Add trailing slash to indicate a folder
    if not p.endswith('/'):
        p += '/'

    return 'external:' + p


def export_db_to_excel(db_path, output_path):
    """
    Read data from SQLite, clean body_text, and write to Excel with relative folder links.
    Assumptions:
      - The workbook (output_path) is saved in the 'main folder'.
      - The database 'folder_path' column stores paths relative to that same main folder.
    Result:
      - Links remain valid after moving the whole main folder elsewhere.
    """
    if not Path(db_path).exists():
        print(f"✗ Database file '{db_path}' not found.")
        return

    try:
        # Resolve where the Excel file will be written.
        output_path = Path(output_path)
        try:
            excel_dir = output_path.resolve().parent
        except Exception:
            excel_dir = output_path.absolute().parent

        # 1) Read from DB
        print("Connecting to the database and reading data...")
        conn = sqlite3.connect(db_path)
        df = pd.read_sql_query("SELECT * FROM emails", conn)
        conn.close()
        print(f"✓ {len(df)} records read from the database.")

        # 2) Clean body_text
        if 'body_text' in df.columns:
            df['body_text'] = df['body_text'].apply(clean_body_text)

        # 3) Prepare link column
        if 'folder_path' in df.columns:
            df['link_display_text'] = "Open Folder"
        else:
            print("⚠ Column 'folder_path' not found in the database. Hyperlinks will not be created.")
            df['folder_path'] = ''
            df['link_display_text'] = 'N/A'

        # 4) Write to Excel
        print(f"Writing data to Excel file: {output_path} ...")

        log_path = Path(output_path).with_suffix('.log')
        with tee_output(log_path, mode='a'):
            with get_excel_writer(output_path) as writer:
                # Place the manual link column at the end
                cols = [c for c in df.columns if c not in ['link_display_text']]
                df = df.rename(columns={'link_display_text': 'Folder Link'})
                final_cols = cols + ['Folder Link']

                # Write the data
                df[final_cols].to_excel(writer, sheet_name='Emails', index=False, freeze_panes=(1, 0))

                workbook = writer.book
                worksheet = writer.sheets['Emails']
                url_format = workbook.add_format({'font_color': 'blue', 'underline': 1})

                try:
                    link_text_col_idx = final_cols.index('Folder Link')
                    folder_path_col_idx = df.columns.get_loc('folder_path')
                except ValueError:
                    print("⚠ Required columns for creating links were not found.")
                    return

                # Create 'external:' relative links for each row
                for row_num in range(1, len(df) + 1):
                    rel_folder_path = df.iloc[row_num - 1, folder_path_col_idx]
                    link_text = df.iloc[row_num - 1, df.columns.get_loc('Folder Link')]

                    if rel_folder_path and pd.notna(rel_folder_path):
                        url = to_external_relative_folder_url(rel_folder_path)
                        if url:
                            worksheet.write_url(row_num, link_text_col_idx, url, cell_format=url_format, string=str(link_text))

                # Auto-fit columns if available (newer XlsxWriter). Safe no-op otherwise.
                if hasattr(worksheet, 'autofit'):
                    worksheet.autofit()

            print(f"✓ Excel file created successfully at '{output_path}'.")

    except Exception as e:
        print(f"✗ An unexpected error occurred: {e}")


if __name__ == "__main__":
    # Important: Make sure OUTPUT_EXCEL_FILE points to your main folder (or run the script from the main folder)
    export_db_to_excel(DB_FILE, OUTPUT_EXCEL_FILE)