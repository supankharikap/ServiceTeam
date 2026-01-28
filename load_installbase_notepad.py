import os, sys
import pyodbc
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime

load_dotenv(Path(__file__).resolve().parent / ".env")

def must_env(k: str) -> str:
    v = os.getenv(k)
    if not v:
        raise RuntimeError(f"Missing env var: {k}")
    return v

SERVER = must_env("AZURE_SQL_SERVER")
DB     = must_env("AZURE_SQL_DB")
USER   = must_env("AZURE_SQL_USER")
PWD    = must_env("AZURE_SQL_PASSWORD")

CONN_STR = (
    "Driver={ODBC Driver 18 for SQL Server};"
    f"Server=tcp:{SERVER},1433;"
    f"Database={DB};"
    f"Uid={USER};"
    f"Pwd={PWD};"
    "Encrypt=yes;"
    "TrustServerCertificate=no;"
    "Connection Timeout=30;"
)

NA_VALUES = {"", "NA", "N/A", "NULL", "null", "na", "n/a"}

DATE_HEADERS = {
    "Invoice Date", "Installed On", "AMC Invoice Date", "AMC From", "AMC To",
    "AMC Due Date", "Filter Invoice Date", "Next Filter Due Date",
    "Cluster Visit Plan", "Actual Visit", "NEXT TER2 PLAN"
}

def clean(v):
    if v is None:
        return None
    v = v.strip()
    if v in NA_VALUES:
        return None
    return v

def parse_date(v):
    v = clean(v)
    if not v:
        return None
    for fmt in ("%d-%b-%y", "%d-%b-%Y"):
        try:
            return datetime.strptime(v, fmt).date()
        except ValueError:
            pass
    return None

def normalize(name: str) -> str:
    # Convert "Sales Invoice No" -> "SALES_INVOICE_NO" like variants
    x = name.strip()
    x = x.replace(".", "")
    x = x.replace("/", "_")
    x = x.replace("-", "_")
    x = x.replace("  ", " ")
    x = x.replace(" ", "_")
    x = x.replace("(", "").replace(")", "")
    return x.upper()

def load_rows_safely(filepath: str):
    # Handles cases where address field contains newline (no extra tab),
    # by joining lines until column count matches header count.
    raw = Path(filepath).read_text(encoding="utf-8-sig", errors="ignore")
    lines = [ln for ln in raw.splitlines() if ln.strip() != ""]

    if not lines:
        raise RuntimeError("File empty hai.")

    header_line = lines[0]
    headers = [h.strip() for h in header_line.split("\t")]
    col_count = len(headers)
    if col_count < 5:
        raise RuntimeError("Header me TAB delimiter nahi lag raha. (Columns bahut kam detect hue)")

    rows = []
    buf = ""

    for ln in lines[1:]:
        if not buf:
            buf = ln
        else:
            buf = buf + " " + ln  # join broken line with space

        parts = buf.split("\t")

        if len(parts) < col_count:
            continue  # still incomplete row, keep adding next line
        else:
            # If extra tabs happened, merge extras into last column
            if len(parts) > col_count:
                fixed = parts[:col_count-1] + [" ".join(parts[col_count-1:])]
                parts = fixed

            row = {headers[i]: parts[i] for i in range(col_count)}
            rows.append(row)
            buf = ""

    if buf.strip():
        print("⚠️ Last row incomplete lag raha hai, skip ho gaya:", buf[:120])

    return headers, rows

def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "installbase.txt"

    headers, rows = load_rows_safely(filepath)
    print(f"Headers: {len(headers)} | Rows found: {len(rows)}")

    with pyodbc.connect(CONN_STR) as conn:
        cur = conn.cursor()
        cur.fast_executemany = True

        # DB columns
        cur.execute("""
            SELECT name
            FROM sys.columns
            WHERE object_id = OBJECT_ID('dbo.InstallBase')
        """)
        db_cols = {r[0] for r in cur.fetchall()}

        # Build mapping: file header -> db column
        mapping = {}
        missing = []

        for h in headers:
            candidates = [
                h,                       # exact excel style
                normalize(h),            # normalized style
                normalize(h).title(),    # sometimes mixed
                normalize(h).lower(),    # lower
            ]
            chosen = None
            for c in candidates:
                if c in db_cols:
                    chosen = c
                    break
            if chosen:
                mapping[h] = chosen
            else:
                missing.append(h)

        if missing:
            print("⚠️ Ye headers DB me nahi mile, insert me skip honge:")
            for m in missing:
                print(" -", m)

        use_headers = [h for h in headers if h in mapping]
        if not use_headers:
            raise RuntimeError("Koi bhi header DB columns se match nahi hua. Table schema check karo.")

        insert_cols = [mapping[h] for h in use_headers]
        col_sql = ", ".join(f"[{c}]" for c in insert_cols)
        placeholders = ", ".join("?" for _ in insert_cols)
        sql = f"INSERT INTO dbo.InstallBase ({col_sql}) VALUES ({placeholders})"

        batch = []
        total = 0

        for r in rows:
            vals = []
            for h in use_headers:
                v = r.get(h)
                if h in DATE_HEADERS:
                    vals.append(parse_date(v))
                else:
                    vals.append(clean(v))
            batch.append(tuple(vals))

            if len(batch) >= 300:
                cur.executemany(sql, batch)
                conn.commit()
                total += len(batch)
                print("Inserted:", total)
                batch = []

        if batch:
            cur.executemany(sql, batch)
            conn.commit()
            total += len(batch)

        print("✅ DONE. Total inserted rows:", total)

        cur.execute("SELECT COUNT(*) FROM dbo.InstallBase;")
        print("DB total rows now:", cur.fetchone()[0])

if __name__ == "__main__":
    main()
