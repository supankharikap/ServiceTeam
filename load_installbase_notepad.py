import os, sys
import pyodbc
import pandas as pd
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime
from decimal import Decimal, InvalidOperation

# Load .env from same folder
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

NA_VALUES = {"", "NA", "N/A", "NULL", "null", "na", "n/a", "-", "--"}

# Put your exact date headers here (same as your file)
DATE_HEADERS = {
    "Invoice Date", "Installed On", "AMC Invoice Date", "AMC From", "AMC To",
    "AMC Due Date", "Filter Invoice Date", "Next Filter Due Date",
    "Cluster Visit Plan", "Actual Visit", "NEXT TER2 PLAN"
}

# ✅ FIX: empty string -> None
def clean(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    if s in NA_VALUES:
        return None
    return s

def parse_date(v):
    s = clean(v)
    if not s:
        return None
    for fmt in ("%d-%b-%y", "%d-%b-%Y", "%d/%m/%Y", "%d-%m-%Y", "%Y-%m-%d", "%d/%m/%y"):
        try:
            return datetime.strptime(s, fmt).date()
        except ValueError:
            pass
    return None

def parse_int(v):
    s = clean(v)
    if not s:
        return None
    s = s.replace(",", "").strip()
    try:
        if "." in s:
            return int(float(s))
        return int(s)
    except ValueError:
        return None

def parse_decimal(v):
    s = clean(v)
    if not s:
        return None
    s = s.replace(",", "").strip()
    s = s.replace("₹", "").replace("$", "").replace("INR", "").strip()
    try:
        return Decimal(s)
    except (InvalidOperation, ValueError):
        return None

def parse_float(v):
    s = clean(v)
    if not s:
        return None
    s = s.replace(",", "").strip()
    try:
        return float(s)
    except ValueError:
        return None

def parse_bit(v):
    s = clean(v)
    if not s:
        return None
    s = s.strip().lower()
    if s in {"1", "true", "t", "yes", "y"}:
        return 1
    if s in {"0", "false", "f", "no", "n"}:
        return 0
    return None

def normalize(name: str) -> str:
    x = str(name).strip()
    x = x.replace(".", "")
    x = x.replace("/", "_")
    x = x.replace("-", "_")
    x = " ".join(x.split())
    x = x.replace(" ", "_")
    x = x.replace("(", "").replace(")", "")
    return x.upper()

def read_csv(filepath: str) -> pd.DataFrame:
    p = Path(filepath)
    if not p.exists():
        raise RuntimeError(f"File not found: {filepath}")
    df = pd.read_csv(p, encoding="utf-8-sig", dtype=str, keep_default_na=False)
    df.columns = [str(c).strip() for c in df.columns]
    return df

def main():
    filepath = sys.argv[1] if len(sys.argv) > 1 else "INSTALL BASE.csv"
    df = read_csv(filepath)
    print("CSV Columns:", len(df.columns), "| Rows:", len(df))

    with pyodbc.connect(CONN_STR) as conn:
        cur = conn.cursor()

        # ✅ HY090 FIX: do NOT use fast_executemany
        cur.fast_executemany = False

        # Read DB column names + types
        cur.execute("""
           SELECT c.name, t.name AS type_name
           FROM sys.columns c
           JOIN sys.types t ON c.user_type_id = t.user_type_id
           WHERE c.object_id = OBJECT_ID('dbo.InstallBase')
           AND c.is_computed = 0
        """)

        db_info = cur.fetchall()
        db_cols = {r[0] for r in db_info}
        db_types = {r[0]: str(r[1]).lower() for r in db_info}
        db_cols_norm_map = {normalize(c): c for c in db_cols}

        # Mapping: CSV header -> DB column (skip ID)
        mapping = {}
        missing = []
        for h in df.columns:
            if normalize(h) == "ID":
                continue
                # ✅ Skip Filter Days (SQL will calculate / default)
            if normalize(h) in {"FILTER_DAYS"}:
              continue

            nh = normalize(h)
            chosen = None
            if h in db_cols:
                chosen = h
            elif nh in db_cols_norm_map:
                chosen = db_cols_norm_map[nh]
            if chosen:
                mapping[h] = chosen
            else:
                missing.append(h)

        if missing:
            print("⚠️ These CSV headers not found in DB. Skipping:")
            for m in missing:
                print(" -", m)

        use_headers = [h for h in df.columns if h in mapping]
        if not use_headers:
            raise RuntimeError("No CSV headers matched DB columns. Check table schema.")

        insert_cols = [mapping[h] for h in use_headers]
        print("✅ Columns to insert:", len(insert_cols))

        # Parser per DB type
        date_headers_norm = {normalize(x) for x in DATE_HEADERS}

        def parse_by_db_type(csv_header, v):
            db_col = mapping[csv_header]
            t = db_types.get(db_col, "")

            if normalize(csv_header) in date_headers_norm:
                return parse_date(v)

            if t in {"date", "datetime", "datetime2", "smalldatetime"}:
                return parse_date(v)
            if t in {"int", "bigint", "smallint", "tinyint"}:
                return parse_int(v)
            if t in {"decimal", "numeric", "money", "smallmoney"}:
                return parse_decimal(v)
            if t in {"float", "real"}:
                return parse_float(v)
            if t in {"bit"}:
                return parse_bit(v)
            return clean(v)
        
        # 🗑️ FULL REFRESH: delete all old rows
        #-------------------------------------

        cur.execute("DELETE FROM dbo.InstallBase;")
        conn.commit()
        print("🗑️ Deleted old rows from dbo.InstallBase")
        cur.execute("SELECT COUNT(*) FROM dbo.InstallBase;")
        print("✅ DB count after delete:", cur.fetchone()[0])
       




        # Create staging table
        stage_cols_sql = ", ".join(f"[{c}]" for c in insert_cols)
        cur.execute("IF OBJECT_ID('tempdb..#Stage') IS NOT NULL DROP TABLE #Stage;")
        cur.execute(f"SELECT TOP 0 {stage_cols_sql} INTO #Stage FROM dbo.InstallBase;")
        conn.commit()

        # Insert CSV -> #Stage (ROW BY ROW)
        col_sql = ", ".join(f"[{c}]" for c in insert_cols)
        placeholders = ", ".join("?" for _ in insert_cols)
        stage_insert_sql = f"INSERT INTO #Stage ({col_sql}) VALUES ({placeholders})"

        total_stage = 0
        for i, (_, row) in enumerate(df.iterrows()):
            vals = [parse_by_db_type(h, row.get(h, "")) for h in use_headers]
            try:
                cur.execute(stage_insert_sql, vals)
                total_stage += 1
                if total_stage % 200 == 0:
                    conn.commit()
            except pyodbc.Error as e:
                print("\n❌ BAD ROW FOUND at CSV row index:", i)
                print("Error:", e)
                for h, v in zip(use_headers, vals):
                    print(f"  {h}: {v!r}")
                raise

        conn.commit()
        print("✅ Staged rows:", total_stage)

        cur.execute("SELECT COUNT(*) FROM #Stage;")
        print("✅ #Stage count:", cur.fetchone()[0])

        # Final insert ALL rows to dbo.InstallBase (NO DELETE, NO NOT EXISTS)
        final_insert_sql = f"""
        INSERT INTO dbo.InstallBase ({col_sql})
        SELECT {col_sql}
        FROM #Stage;
        """
        cur.execute(final_insert_sql)
        conn.commit()
        print("✅ Insert completed")

        cur.execute("SELECT COUNT(*) FROM dbo.InstallBase;")
        print("✅ DB total rows now:", cur.fetchone()[0])

if __name__ == "__main__":
    main()
