from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import pyodbc
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, date, timedelta

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")


# ===================== DB HELPERS =====================
def _must_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Missing env var: {name}. Check your .env file.")
    return v

def get_conn():
    server = _must_env("AZURE_SQL_SERVER")   # e.g. kgkerpdb.database.windows.net
    db     = _must_env("AZURE_SQL_DB")       # e.g. kgkerdb
    user   = _must_env("AZURE_SQL_USER")
    pwd    = _must_env("AZURE_SQL_PASSWORD")

    conn_str = (
        "Driver={ODBC Driver 18 for SQL Server};"
        f"Server=tcp:{server},1433;"
        f"Database={db};"
        f"Uid={user};Pwd={pwd};"
        "Encrypt=yes;TrustServerCertificate=no;Connection Timeout=30;"
    )
    return pyodbc.connect(conn_str)

def _table_columns(schema_table: str):
    if "." not in schema_table:
        schema, table = "dbo", schema_table
    else:
        schema, table = schema_table.split(".", 1)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION
        """, (schema, table))
        return [r[0] for r in cur.fetchall()]

def _norm(s: str) -> str:
    return "".join(ch.lower() for ch in str(s) if ch.isalnum())

def _col_index(cols):
    # normalize => actual
    return {_norm(c): c for c in cols}

def _find_col(cols, aliases=None, must_contain=None):
    """
    Find actual column name from table columns.
    - aliases: list of possible names (space/underscore variations)
    - must_contain: list of tokens that must exist in normalized col (fuzzy)
    """
    aliases = aliases or []
    idx = _col_index(cols)

    # exact alias match by normalization
    for a in aliases:
        na = _norm(a)
        if na in idx:
            return idx[na]

    # fuzzy contains-all match
    if must_contain:
        tokens = [_norm(t) for t in must_contain if t]
        for c in cols:
            nc = _norm(c)
            ok = all(t in nc for t in tokens)
            if ok:
                return c

    return None

def _qcol(c: str) -> str:
    # safe bracket quoting for spaces etc.
    return f"[{c}]"

def _json_safe(v):
    if v is None:
        return ""
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return str(v)


# ===================== AUTH =====================
def get_user(username: str):
    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT Username, FullName, Zone, RoleName, Team, Password, IsActive
            FROM dbo.UserLogin
            WHERE Username = ?
        """, (username,))
        return cur.fetchone()

@app.get("/")
def home():
    return render_template("login.html", error=None)

@app.post("/login")
def login_post():
    username = (request.form.get("username") or "").strip()
    password = (request.form.get("password") or "").strip()

    if not username or not password:
        return render_template("login.html", error="Please enter username and password!")

    try:
        row = get_user(username)
    except Exception as e:
        return render_template("login.html", error=f"DB error: {e}")

    if not row:
        return render_template("login.html", error="Invalid user or inactive!")

    db_username = row[0]
    db_fullname = row[1]
    db_zone     = row[2]
    db_role     = row[3]
    db_team     = row[4]
    db_pass     = row[5]
    db_active   = row[6]

    if db_active in (0, False, None):
        return render_template("login.html", error="Invalid user or inactive!")

    if (db_pass or "") != password:
        return render_template("login.html", error="Invalid username or password!")

    session["user"] = db_username
    session["engineer"] = (db_fullname or db_username or "").strip()
    session["zone"] = (db_zone or "").strip()
    session["role"] = (db_role or "").strip()
    session["team"] = (db_team or "").strip()

    return redirect(url_for("dashboard"))

@app.get("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "dashboard.html",
        engineer=session.get("engineer", ""),
        zone=session.get("zone", ""),
        role=session.get("role", ""),
        team=session.get("team", "")
    )

@app.get("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))


# ===================== SCOPES =====================
def _is_manager_like(role: str) -> bool:
    r = (role or "").strip().lower()
    return ("manager" in r) or ("team leader" in r) or ("teamleader" in r) or ("team_leader" in r)

def _installbase_scope_where(install_cols):
    """
    Admin         => all rows
    Manager/TL    => zone only
    User/others   => zone + (service_eng OR sales_eng) == engineer
    """
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    eng  = (session.get("engineer") or "").strip()

    if role == "admin":
        return "", []

    zone_col = _find_col(install_cols, aliases=["ZONE"], must_contain=["zone"])
    svc_col  = _find_col(install_cols, aliases=["SERVICE_ENGR","SERVICE ENGR","SERVICE_ENGINEER","SERVICE ENGINEER"], must_contain=["service","engr"])
    sales_col= _find_col(install_cols, aliases=["SALES_ENGR","SALES ENGR","SALES_ENGINEER","SALES ENGINEER"], must_contain=["sales","engr"])

    where = []
    params = []

    # Manager-like => zone only
    if _is_manager_like(role):
        if zone and zone_col:
            where.append(f"{_qcol(zone_col)} = ?")
            params.append(zone)
        return (" WHERE " + " AND ".join(where)) if where else "", params

    # User => zone + own engineer (service or sales)
    if zone and zone_col:
        where.append(f"{_qcol(zone_col)} = ?")
        params.append(zone)

    # engineer filter
    if eng and (svc_col or sales_col):
        if svc_col and sales_col:
            where.append(f"({_qcol(svc_col)} = ? OR {_qcol(sales_col)} = ?)")
            params.extend([eng, eng])
        elif svc_col:
            where.append(f"{_qcol(svc_col)} = ?")
            params.append(eng)
        elif sales_col:
            where.append(f"{_qcol(sales_col)} = ?")
            params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params

def _wsr_scope_where(wsr_cols):
    """
    Admin         => all
    Manager/TL    => zone only
    User/others   => zone + engineer
    """
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    eng  = (session.get("engineer") or "").strip()

    if role == "admin":
        return "", []

    zone_col = _find_col(wsr_cols, aliases=["Zone","ZONE"], must_contain=["zone"])
    eng_col  = _find_col(wsr_cols, aliases=["EngineerName","Engineer Name","ENGINEER_NAME"], must_contain=["engineer","name"])

    where = []
    params = []

    if zone and zone_col:
        where.append(f"{_qcol(zone_col)} = ?")
        params.append(zone)

    if (not _is_manager_like(role)) and eng and eng_col:
        where.append(f"{_qcol(eng_col)} = ?")
        params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params


# ===================== SEARCH BUILDERS =====================
def _build_token_search_where(q: str, cols: list, preferred_cols: list):
    """
    multi-word search:
    "east supan cij" => AND across tokens, OR across columns
    Always uses CAST([col] AS NVARCHAR(MAX)) LIKE ?
    """
    q = (q or "").strip()
    if not q:
        return "", []

    tokens = [t.strip() for t in q.split() if t.strip()]
    if not tokens:
        return "", []

    # keep only existing columns (by normalization)
    idx = _col_index(cols)
    actual_search_cols = []
    for pc in preferred_cols:
        k = _norm(pc)
        if k in idx:
            actual_search_cols.append(idx[k])

    # fallback if preferred not found: use all columns (but capped)
    if not actual_search_cols:
        actual_search_cols = cols[:30]

    parts = []
    params = []
    for tok in tokens:
        ors = []
        for c in actual_search_cols:
            ors.append(f"CAST({_qcol(c)} AS NVARCHAR(MAX)) LIKE ?")
            params.append(f"%{tok}%")
        parts.append("(" + " OR ".join(ors) + ")")

    return "(" + " AND ".join(parts) + ")", params


# ===================== KPI =====================
@app.get("/api/kpi")
def api_kpi():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return jsonify({"error": "dbo.InstallBase not found"}), 400

    where_sql, params = _installbase_scope_where(install_cols)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            installbase_total = int(cur.fetchone()[0])

            # customer column auto detect
            cust_col = _find_col(install_cols, aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"], must_contain=["customer","name"])
            customers = 0
            if cust_col:
                cur.execute(f"SELECT COUNT(DISTINCT {_qcol(cust_col)}) FROM dbo.InstallBase{where_sql}", params)
                customers = int(cur.fetchone()[0])

    except Exception as e:
        return jsonify({"error": f"InstallBase KPI error: {e}"}), 500

    return jsonify({
        "installbase_total": installbase_total,
        "customers": customers,
        "this_month_reports": 0,
        "pending": 0
    })


# ===================== MASTER INSTALLBASE =====================
@app.get("/api/master/installbase")
def api_master_installbase():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))

    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"error": "dbo.InstallBase not found"}), 400

    base_where, base_params = _installbase_scope_where(cols)

    preferred = [
        "ZONE","SALES_ENGR","SERVICE_ENGR","Cluster_No","CUSTOMER_NAME","Location","Machine_Type","Model","Serial_No",
        # also allow space variants:
        "SALES ENGR","SERVICE ENGR","CLUSTER NO","CUSTOMER NAME","SERIAL NO"
    ]
    search_where, search_params = _build_token_search_where(q, cols, preferred)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params
    if search_where:
        where_parts.append(search_where)
        params += search_params

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    id_col = _find_col(cols, aliases=["Id","ID"], must_contain=["id"])
    order_by = f"{_qcol(id_col)} DESC" if id_col else f"{_qcol(cols[0])} DESC"
    select_cols = ", ".join([_qcol(c) for c in cols])

    sql = f"SELECT TOP {limit} {select_cols} FROM dbo.InstallBase{where_sql} ORDER BY {order_by}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()

        out_rows = []
        for r in rows:
            obj = {}
            for i, c in enumerate(cols):
                obj[c] = _json_safe(r[i])
            out_rows.append(obj)

        return jsonify({"columns": cols, "rows": out_rows})

    except Exception as e:
        return jsonify({"error": f"InstallBase API error: {e}"}), 500


@app.get("/api/master/installbase/suggest")
def api_master_installbase_suggest():
    """
    Suggestions for master search box.
    Returns top distinct matches from key columns.
    """
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _installbase_scope_where(cols)

    # key columns auto detect
    zone_col = _find_col(cols, aliases=["ZONE"], must_contain=["zone"])
    cust_col = _find_col(cols, aliases=["CUSTOMER_NAME","CUSTOMER NAME"], must_contain=["customer","name"])
    serial_col = _find_col(cols, aliases=["Serial_No","SERIAL NO","Serial No"], must_contain=["serial"])
    svc_col = _find_col(cols, aliases=["SERVICE_ENGR","SERVICE ENGR"], must_contain=["service","engr"])

    key_cols = [c for c in [cust_col, serial_col, svc_col, zone_col] if c]

    items = []
    seen = set()

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            for c in key_cols:
                where_parts = []
                params = []
                if base_where:
                    where_parts.append(base_where.replace(" WHERE ", "", 1))
                    params += base_params

                where_parts.append(f"CAST({_qcol(c)} AS NVARCHAR(200)) LIKE ?")
                params.append(f"%{q}%")

                where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""
                sql = f"""
                    SELECT DISTINCT TOP 10 CAST({_qcol(c)} AS NVARCHAR(200)) AS v
                    FROM dbo.InstallBase
                    {where_sql}
                    ORDER BY v
                """
                cur.execute(sql, params)
                for (v,) in cur.fetchall():
                    vv = (v or "").strip()
                    if not vv:
                        continue
                    if vv.lower() in seen:
                        continue
                    seen.add(vv.lower())
                    items.append(vv)
                    if len(items) >= 12:
                        break
                if len(items) >= 12:
                    break

    except Exception:
        return jsonify({"items": []})

    return jsonify({"items": items})

# ===================== INSTALLBASE (WSR AUTOFILL + CUSTOMER SUGGEST) =====================

@app.get("/api/installbase/customer_suggest")
def api_installbase_customer_suggest():
    """
    WSR form ke liye Customer Name suggestions (datalist).
    """
    if "user" not in session:
        return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    cust_col = _find_col(
        cols,
        aliases=["CUSTOMER_NAME", "CUSTOMER NAME", "CustomerName", "Customer Name"],
        must_contain=["customer", "name"]
    )
    if not cust_col:
        return jsonify({"items": []})

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"CAST({_qcol(cust_col)} AS NVARCHAR(200)) LIKE ?")
    params.append(f"%{q}%")

    where_sql = " WHERE " + " AND ".join(where_parts)

    sql = f"""
        SELECT DISTINCT TOP 12 CAST({_qcol(cust_col)} AS NVARCHAR(200)) AS v
        FROM dbo.InstallBase
        {where_sql}
        ORDER BY v
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            items = [(r[0] or "").strip() for r in cur.fetchall()]
            items = [x for x in items if x]
        return jsonify({"items": items})
    except Exception:
        return jsonify({"items": []})


@app.get("/api/installbase/details")
def api_installbase_details():
    """
    WSR form auto-fill:
    customer select होते ही location/contact/email/ink/machine-status etc return करेगा.
    """
    if "user" not in session:
        return jsonify({"ok": False, "message": "unauthorized"}), 401

    customer = (request.args.get("customer") or "").strip()
    if not customer:
        return jsonify({"ok": False, "message": "customer is required"}), 400

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.InstallBase not found"}), 400

    # detect needed columns safely
    id_col      = _find_col(cols, aliases=["ID", "Id"], must_contain=["id"])
    cust_col    = _find_col(cols, aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"], must_contain=["customer","name"])
    loc_col     = _find_col(cols, aliases=["LOCATION","Location"], must_contain=["location"])
    cp_col      = _find_col(cols, aliases=["Contact Person1","ContactPerson1","CONTACT_PERSON1"], must_contain=["contact","person"])
    des_col     = _find_col(cols, aliases=["Designation","DESIGNATION"], must_contain=["designation"])
    cn_col      = _find_col(cols, aliases=["Contact No.","Contact No","ContactNo","Contact Number","ContactNumber"], must_contain=["contact","no"])
    email_col   = _find_col(cols, aliases=["Email Id","Email","EMAIL"], must_contain=["email"])
    ink_col     = _find_col(cols, aliases=["Ink type","InkType"], must_contain=["ink"])
    active_col  = _find_col(cols, aliases=["Active Status","ActiveStatus"], must_contain=["active","status"])
    mc_col = _find_col(cols,aliases=["Mc Status","McStatus","Machine Status","MachineStatus"],must_contain=["mc","status"]) or _find_col(cols,aliases=["Machine Status","MachineStatus"], must_contain=["machine","status"])

    model_col   = _find_col(cols, aliases=["Model","MODEL"], must_contain=["model"])
    serial_col  = _find_col(cols, aliases=["Serial No.","Serial No","Serial_No","SERIAL NO"], must_contain=["serial"])
    mtype_col   = _find_col(cols, aliases=["Machine Type","Machine_Type"], must_contain=["machine","type"])

    if not cust_col:
        return jsonify({"ok": False, "message": "Customer column not found in InstallBase"}), 400

    # apply same scope rules (Admin/Manager/User)
    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_qcol(cust_col)} = ?")
    params.append(customer)

    where_sql = " WHERE " + " AND ".join(where_parts)

    # build select list
    select_cols = []
    keys = []

    def add(key, col):
        if col:
            keys.append(key)
            select_cols.append(_qcol(col))

    add("id", id_col)
    add("customer_name", cust_col)
    add("location", loc_col)
    add("contact_person", cp_col)
    add("designation", des_col)
    add("contact_no", cn_col)
    add("email", email_col)
    add("ink_type", ink_col)
    add("active_status", active_col)
    add("mc_status", mc_col)
    add("model", model_col)
    add("serial_no", serial_col)
    add("machine_type", mtype_col)

    if not select_cols:
        return jsonify({"ok": False, "message": "No usable columns to return"}), 400

    order_by = f" ORDER BY {_qcol(id_col)} DESC" if id_col else ""

    sql = f"""
        SELECT TOP (1) {", ".join(select_cols)}
        FROM dbo.InstallBase
        {where_sql}
        {order_by}
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            row = cur.fetchone()

        if not row:
            return jsonify({"ok": True, "found": False, "data": {}}), 200

        data = {}
        for i, k in enumerate(keys):
            data[k] = _json_safe(row[i])

        return jsonify({"ok": True, "found": True, "data": data})

    except Exception as e:
        return jsonify({"ok": False, "message": f"details error: {e}"}), 500

# ===================== REPORT VIEW (WSR) =====================
@app.get("/api/report")
def api_report():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))
    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"columns": [], "rows": []})

    base_where, base_params = _wsr_scope_where(cols)

    preferred = [
        "Zone","EngineerName","Engineer Name","CustomerName","Customer Name","Location","ServiceReportNo","Serial_No","Model","Machine_Type",
        "VisitDate","MMM-YY","MMM_YY"
    ]
    search_where, search_params = _build_token_search_where(q, cols, preferred)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params
    if search_where:
        where_parts.append(search_where)
        params += search_params

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    visit_col = _find_col(cols, aliases=["VisitDate","Visit Date"], must_contain=["visit","date"])
    id_col    = _find_col(cols, aliases=["Id","ID"], must_contain=["id"])
    order_by = f"{_qcol(visit_col)} DESC" if visit_col else (f"{_qcol(id_col)} DESC" if id_col else f"{_qcol(cols[0])} DESC")

    select_cols = ", ".join([_qcol(c) for c in cols])
    sql = f"SELECT TOP {limit} {select_cols} FROM dbo.WSR{where_sql} ORDER BY {order_by}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()

        out_rows = []
        for r in rows:
            obj = {}
            for i, c in enumerate(cols):
                obj[c] = _json_safe(r[i])
            out_rows.append(obj)

        return jsonify({"columns": cols, "rows": out_rows})

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/report/suggest")
def api_report_suggest():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _wsr_scope_where(cols)

    zone_col = _find_col(cols, aliases=["Zone","ZONE"], must_contain=["zone"])
    eng_col  = _find_col(cols, aliases=["EngineerName","Engineer Name"], must_contain=["engineer","name"])
    cust_col = _find_col(cols, aliases=["CustomerName","Customer Name"], must_contain=["customer","name"])
    rep_col  = _find_col(cols, aliases=["ServiceReportNo","Service report No","Service report No."], must_contain=["report"])

    key_cols = [c for c in [cust_col, rep_col, eng_col, zone_col] if c]

    items = []
    seen = set()

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            for c in key_cols:
                where_parts = []
                params = []
                if base_where:
                    where_parts.append(base_where.replace(" WHERE ", "", 1))
                    params += base_params

                where_parts.append(f"CAST({_qcol(c)} AS NVARCHAR(200)) LIKE ?")
                params.append(f"%{q}%")

                where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""
                sql = f"""
                    SELECT DISTINCT TOP 10 CAST({_qcol(c)} AS NVARCHAR(200)) AS v
                    FROM dbo.WSR
                    {where_sql}
                    ORDER BY v
                """
                cur.execute(sql, params)
                for (v,) in cur.fetchall():
                    vv = (v or "").strip()
                    if not vv:
                        continue
                    if vv.lower() in seen:
                        continue
                    seen.add(vv.lower())
                    items.append(vv)
                    if len(items) >= 12:
                        break
                if len(items) >= 12:
                    break
    except Exception:
        return jsonify({"items": []})

    return jsonify({"items": items})


# ===================== WSR INSERT =====================
def _parse_date(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
        return None
    for fmt in ("%Y-%m-%d", "%d-%b-%y", "%d-%b-%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    return None

@app.post("/api/wsr")
def api_wsr():
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}
    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.WSR table not found"}), 400

    # find real db columns (space/underscore auto)
    zone_col = _find_col(cols, aliases=["Zone","ZONE"], must_contain=["zone"])
    eng_col  = _find_col(cols, aliases=["EngineerName","Engineer Name"], must_contain=["engineer","name"])
    month_col= _find_col(cols, aliases=["MonthYear","MMM-YY","MMM_YY","MMM YY"], must_contain=["mmm"])
    rep_col  = _find_col(cols, aliases=["ServiceReportNo","Service report No","Service report No."], must_contain=["report"])
    cust_col = _find_col(cols, aliases=["CustomerName","Customer Name"], must_contain=["customer","name"])
    loc_col  = _find_col(cols, aliases=["Location"], must_contain=["location"])
    cp_col   = _find_col(cols, aliases=["ContactPerson","Contact Person"], must_contain=["contact","person"])
    des_col  = _find_col(cols, aliases=["Designation"], must_contain=["designation"])
    cn_col   = _find_col(cols, aliases=["ContactNumber","Contact No","Contact No."], must_contain=["contact","no"])
    email_col= _find_col(cols, aliases=["Email","Email Id"], must_contain=["email"])
    call_col = _find_col(cols, aliases=["CallLoggedDate","Call Logged Date"], must_contain=["call","date"])
    prob_col = _find_col(cols, aliases=["ProblemReported","Problem Reported"], must_contain=["problem"])
    ms_col   = _find_col(cols, aliases=["MachineStatus","Machine Status"], must_contain=["machine","status"])
    vc1_col  = _find_col(cols, aliases=["VisitCode1","Visit Code 1"], must_contain=["visit","code","1"])
    vc2_col  = _find_col(cols, aliases=["VisitCode2","Visit Code 2"], must_contain=["visit","code","2"])
    ink_col  = _find_col(cols, aliases=["InkType","Ink type"], must_contain=["ink"])
    visit_col= _find_col(cols, aliases=["VisitDate","Visit Date"], must_contain=["visit","date"])
    act_col  = _find_col(cols, aliases=["ActionTaken","Action Taken"], must_contain=["action"])
    rem_col  = _find_col(cols, aliases=["Remarks"], must_contain=["remark"])

    mapping = [
        ("zone", zone_col),
        ("engineerName", eng_col),
        ("monthYear", month_col),
        ("serviceReportNo", rep_col),
        ("customerName", cust_col),
        ("location", loc_col),
        ("contactPerson", cp_col),
        ("designation", des_col),
        ("contactNumber", cn_col),
        ("email", email_col),
        ("callLoggedDate", call_col),
        ("problemReported", prob_col),
        ("machineStatus", ms_col),
        ("visitCode1", vc1_col),
        ("visitCode2", vc2_col),
        ("inkType", ink_col),
        ("visitDate", visit_col),
        ("actionTaken", act_col),
        ("remarks", rem_col),
    ]

    insert_cols = []
    insert_vals = []
    params = []

    for key, dbcol in mapping:
        if not dbcol:
            continue
        val = payload.get(key)

        if dbcol == call_col or dbcol == visit_col:
            val = _parse_date(val)

        insert_cols.append(_qcol(dbcol))
        insert_vals.append("?")
        params.append(val)

    # optional CreatedAt column
    created_col = _find_col(cols, aliases=["CreatedAt","Created At"], must_contain=["created"])
    if created_col:
        insert_cols.append(_qcol(created_col))
        insert_vals.append("GETUTCDATE()")

    if not insert_cols:
        return jsonify({"ok": False, "message": "No matching columns found in dbo.WSR"}), 400

    sql = f"INSERT INTO dbo.WSR ({', '.join(insert_cols)}) VALUES ({', '.join(insert_vals)})"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            conn.commit()
        return jsonify({"ok": True, "message": "WSR saved successfully!"})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Insert error: {e}"}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
