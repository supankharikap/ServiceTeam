from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import pyodbc
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, date
from werkzeug.middleware.proxy_fix import ProxyFix

# Load .env from project root
load_dotenv(Path(__file__).resolve().parent / ".env")

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "change-me")

# ✅ Azure/Codespaces reverse-proxy => https detect + cookies work
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ✅ Cookie settings (IMPORTANT)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (os.environ.get("COOKIE_SECURE", "1") == "1")


# ===================== DB HELPERS =====================
def _must_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Missing env var: {name}. Check your .env file.")
    return v


def get_conn():
    server = _must_env("AZURE_SQL_SERVER")
    db     = _must_env("AZURE_SQL_DB")
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
    return {_norm(c): c for c in cols}


def _find_col(cols, aliases=None, must_contain=None):
    aliases = aliases or []
    idx = _col_index(cols)

    for a in aliases:
        na = _norm(a)
        if na in idx:
            return idx[na]

    if must_contain:
        tokens = [_norm(t) for t in must_contain if t]
        for c in cols:
            nc = _norm(c)
            if all(t in nc for t in tokens):
                return c
    return None


def _qcol(c: str) -> str:
    return f"[{c}]"


def _json_safe(v):
    if v is None:
        return ""
    if isinstance(v, (datetime, date)):
        return v.isoformat()
    return str(v)


def _parse_iso_date(v):
    """HTML <input type="date"> => YYYY-MM-DD"""
    if v is None:
        return None
    s = str(v).strip()
    if not s:
        return None
    try:
        return datetime.strptime(s, "%Y-%m-%d").date()
    except Exception:
        return None


def _json_err(msg, code=400):
    return jsonify({"error": msg}), code


def _require_login_json():
    if "user" not in session:
        return jsonify({"error": "unauthorized"}), 401
    return None


# ✅ helper: case-insensitive trim compare expression
def _cmp_ci_trim(colname: str) -> str:
    c = f"CAST({_qcol(colname)} AS NVARCHAR(200))"
    # remove NBSP (CHAR(160)) and tabs, then trim + upper
    return f"UPPER(LTRIM(RTRIM(REPLACE(REPLACE({c}, CHAR(160), ' '), CHAR(9), ''))))"


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

    db_username, db_fullname, db_zone, db_role, db_team, db_pass, db_active = row

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


@app.get("/installbase/update")
def installbase_update():
    if "user" not in session:
        return redirect(url_for("home"))
    return render_template("installbaseForm.html")


# ===================== SCOPES =====================
def _is_manager_like(role: str) -> bool:
    r = (role or "").strip().lower()
    return ("manager" in r) or ("team leader" in r) or ("teamleader" in r) or ("team_leader" in r)


# ✅✅ FINAL FIX: USER = zone + SERVICE ENGINEER ONLY (sales engineer removed)
def _installbase_scope_where(install_cols):
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    eng  = (session.get("engineer") or "").strip()

    if role == "admin":
        return "", []

    zone_col = _find_col(install_cols, aliases=["ZONE"], must_contain=["zone"])
    svc_col  = _find_col(
        install_cols,
        aliases=["SERVICE_ENGR", "SERVICE ENGR", "SERVICE_ENGINEER", "SERVICE ENGINEER"],
        must_contain=["service", "engr"]
    )

    where = []
    params = []

    # Manager/Team Leader => only zone
    if _is_manager_like(role):
        if zone and zone_col:
            where.append(f"{_cmp_ci_trim(zone_col)} = UPPER(?)")
            params.append(zone)
        return (" WHERE " + " AND ".join(where)) if where else "", params

    # User => zone + service engineer
    if eng and svc_col:
        where.append(f"{_cmp_ci_trim(svc_col)} = UPPER(?)")
        params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params


def _wsr_scope_where(wsr_cols):
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
        where.append(f"{_cmp_ci_trim(zone_col)} = UPPER(?)")
        params.append(zone)

    if (not _is_manager_like(role)) and eng and eng_col:
        where.append(f"{_cmp_ci_trim(eng_col)} = UPPER(?)")
        params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params


# ===================== SEARCH BUILDERS =====================
def _build_token_search_where(q: str, cols: list, preferred_cols: list):
    q = (q or "").strip()
    if not q:
        return "", []

    tokens = [t.strip() for t in q.split() if t.strip()]
    if not tokens:
        return "", []

    idx = _col_index(cols)
    actual_search_cols = []
    for pc in preferred_cols:
        k = _norm(pc)
        if k in idx:
            actual_search_cols.append(idx[k])

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
    need = _require_login_json()
    if need: return need

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return _json_err("dbo.InstallBase not found", 400)

    where_sql, params = _installbase_scope_where(install_cols)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            installbase_total = int(cur.fetchone()[0])

            cust_col = _find_col(
                install_cols,
                aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"],
                must_contain=["customer","name"]
            )
            customers = 0
            if cust_col:
                cur.execute(f"SELECT COUNT(DISTINCT {_qcol(cust_col)}) FROM dbo.InstallBase{where_sql}", params)
                customers = int(cur.fetchone()[0])

    except Exception as e:
        return _json_err(f"InstallBase KPI error: {e}", 500)

    return jsonify({
        "installbase_total": installbase_total,
        "customers": customers,
        "this_month_reports": 0,
        "pending": 0
    })


# ===================== MASTER INSTALLBASE =====================
@app.get("/api/master/installbase")
def api_master_installbase():
    need = _require_login_json()
    if need: return need

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))
    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return _json_err("dbo.InstallBase not found", 400)

    base_where, base_params = _installbase_scope_where(cols)

    preferred = [
        "ZONE","SERVICE_ENGR","Cluster_No","CUSTOMER_NAME","Location","Machine_Type","Model","Serial_No",
        "SERVICE ENGR","CLUSTER NO","CUSTOMER NAME","SERIAL NO"
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
        return _json_err(f"InstallBase API error: {e}", 500)


@app.get("/api/master/installbase/suggest")
def api_master_installbase_suggest():
    need = _require_login_json()
    if need: return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _installbase_scope_where(cols)

    zone_col   = _find_col(cols, aliases=["ZONE","Zone"], must_contain=["zone"])
    svc_col    = _find_col(cols, aliases=["SERVICE_ENGR","SERVICE ENGR"], must_contain=["service","engr"])
    cust_col   = _find_col(cols, aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"], must_contain=["customer","name"])
    serial_col = _find_col(cols, aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo"], must_contain=["serial"])
    cluster_col= _find_col(cols, aliases=["Cluster_No","CLUSTER NO","Cluster No"], must_contain=["cluster"])
    loc_col    = _find_col(cols, aliases=["LOCATION","Location"], must_contain=["location"])

    items = []
    seen = set()

    key_cols = [c for c in [cust_col, serial_col, loc_col, svc_col, zone_col, cluster_col] if c]

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
                    k = vv.lower()
                    if k in seen:
                        continue
                    seen.add(k)
                    items.append(vv)
                    if len(items) >= 12:
                        break

                if len(items) >= 12:
                    break

    except Exception:
        return jsonify({"items": []})

    return jsonify({"items": items})


# ===================== INSTALLBASE SUGGESTS =====================
@app.get("/api/installbase/customer_suggest")
def api_installbase_customer_suggest():
    need = _require_login_json()
    if need: return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()

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

    if q:
        where_parts.append(f"CAST({_qcol(cust_col)} AS NVARCHAR(200)) LIKE ?")
        params.append(f"%{q}%")

    where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""

    sql = f"""
        SELECT DISTINCT TOP 30 CAST({_qcol(cust_col)} AS NVARCHAR(200)) AS v
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


@app.get("/api/installbase/serial_suggest")
def api_installbase_serial_suggest():
    need = _require_login_json()
    if need: return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    serial_col = _find_col(cols, aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo"], must_contain=["serial"])
    if not serial_col:
        return jsonify({"items": []})

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    if q:
        where_parts.append(f"CAST({_qcol(serial_col)} AS NVARCHAR(200)) LIKE ?")
        params.append(f"%{q}%")

    where_sql = " WHERE " + " AND ".join(where_parts) if where_parts else ""

    sql = f"""
        SELECT DISTINCT TOP 30 CAST({_qcol(serial_col)} AS NVARCHAR(200)) AS v
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


@app.get("/api/installbase/rows")
def api_installbase_rows():
    need = _require_login_json()
    if need: return jsonify({"ok": False, "rows": []}), 401

    customer = (request.args.get("customer") or "").strip()
    if not customer:
        return jsonify({"ok": True, "rows": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "rows": [], "message": "dbo.InstallBase not found"}), 400

    cust_col = _find_col(cols, aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"], must_contain=["customer","name"])
    if not cust_col:
        return jsonify({"ok": False, "rows": [], "message": "Customer column not found"}), 400

    zone_col    = _find_col(cols, aliases=["ZONE","Zone"], must_contain=["zone"])
    svc_col     = _find_col(cols, aliases=["SERVICE_ENGR","SERVICE ENGR"], must_contain=["service","engr"])
    cluster_col = _find_col(cols, aliases=["Cluster_No","CLUSTER NO","Cluster No"], must_contain=["cluster"])
    loc_col     = _find_col(cols, aliases=["LOCATION","Location"], must_contain=["location"])
    state_col   = _find_col(cols, aliases=["STATE","State"], must_contain=["state"])
    addr_col    = _find_col(cols, aliases=["Address","ADDRESS"], must_contain=["address"])
    serial_col  = _find_col(cols, aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo"], must_contain=["serial"])
    ink_col     = _find_col(cols, aliases=["Ink type","InkType","INK TYPE"], must_contain=["ink"])
    active_col  = _find_col(cols, aliases=["Active Status","ActiveStatus"], must_contain=["active","status"])
    mc_status_col = _find_col(cols, aliases=["Mc Status","McStatus","Machine Status","MachineStatus"], must_contain=["status"])

    # ✅✅ FIX: model + machine type columns for JSON return
    model_col = _find_col(cols, aliases=["Model","MODEL","Printer Model","PrinterModel"], must_contain=["model"])
    mtype_col = _find_col(cols, aliases=["Machine Type","MachineType","Machine_Type"], must_contain=["machine","type"])

    cp_col   = _find_col(cols, aliases=["Contact Person","ContactPerson"], must_contain=["contact","person"])
    des_col  = _find_col(cols, aliases=["Designation"], must_contain=["designation"])
    cn_col   = _find_col(cols, aliases=["Contact No","ContactNumber","Contact Number"], must_contain=["contact","no"])
    email_col= _find_col(cols, aliases=["Email","Email Id"], must_contain=["email"])

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(cust_col)} = UPPER(?)")
    params.append(customer)

    where_sql = " WHERE " + " AND ".join(where_parts)

    def sel(col, alias):
        return f"{_qcol(col)} AS {alias}" if col else f"'' AS {alias}"

    select_sql = ", ".join([
        sel(cust_col, "customer_name"),
        sel(serial_col, "serial_no"),
        sel(model_col, "model"),            # ✅ added
        sel(mtype_col, "machine_type"),     # ✅ added
        sel(zone_col, "zone"),
        sel(svc_col, "service_engr"),
        sel(cluster_col, "cluster_no"),
        sel(loc_col, "location"),
        sel(state_col, "state"),
        sel(addr_col, "address"),
        sel(ink_col, "ink_type"),
        sel(active_col, "active_status"),
        sel(mc_status_col, "mc_status"),
        sel(cp_col, "contact_person"),
        sel(des_col, "designation"),
        sel(cn_col, "contact_no"),
        sel(email_col, "email"),
    ])

    order_by = f" ORDER BY {(_qcol(serial_col) if serial_col else _qcol(cust_col))}"

    sql = f"""
        SELECT TOP (500) {select_sql}
        FROM dbo.InstallBase
        {where_sql}
        {order_by}
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            data_cols = [d[0] for d in cur.description]
            fetched = cur.fetchall()

        out_rows = []
        for r in fetched:
            obj = {}
            for i, c in enumerate(data_cols):
                obj[c] = _json_safe(r[i])
            out_rows.append(obj)

        return jsonify({"ok": True, "rows": out_rows})
    except Exception as e:
        return jsonify({"ok": False, "rows": [], "message": str(e)}), 500


# ===================== REPORT VIEW (WSR TABLE VIEW) =====================
@app.get("/api/report")
def api_report():
    need = _require_login_json()
    if need: return need

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))
    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"columns": [], "rows": []})

    base_where, base_params = _wsr_scope_where(cols)

    preferred = ["Zone","EngineerName","CustomerName","Location","MMM-YY","Serial","Model","VisitDate"]
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
        return _json_err(str(e), 500)


@app.get("/api/report/suggest")
def api_report_suggest():
    need = _require_login_json()
    if need: return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _wsr_scope_where(cols)

    zone_col  = _find_col(cols, aliases=["Zone","ZONE"], must_contain=["zone"])
    eng_col   = _find_col(cols, aliases=["EngineerName","Engineer Name"], must_contain=["engineer","name"])
    cust_col  = _find_col(cols, aliases=["CustomerName","Customer Name"], must_contain=["customer","name"])
    month_col = _find_col(cols, aliases=["MonthYear","Month Year","MMM-YY","MMM_YY","MMM YY"], must_contain=["month"])

    key_cols = [c for c in [month_col, cust_col, eng_col, zone_col] if c]

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
                    k = vv.lower()
                    if k in seen:
                        continue
                    seen.add(k)
                    items.append(vv)
                    if len(items) >= 12:
                        break

                if len(items) >= 12:
                    break

    except Exception:
        return jsonify({"items": []})

    return jsonify({"items": items})



@app.get("/api/serial/details")
def api_serial_details():
    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "wsr": {}, "installbase": {}})

    # ---------------- WSR: latest row for this serial ----------------
    wsr_cols = _table_columns("dbo.WSR")
    wsr_data = {}

    if wsr_cols:
        wsr_serial_col = _find_col(
            wsr_cols,
            aliases=["Serial No", "SerialNo", "Serial_No", "SERIAL NO", "Serial"],
            must_contain=["serial"]
        )
        wsr_visit_col = _find_col(
            wsr_cols,
            aliases=["VisitDate", "Visit Date", "Last Visit Date"],
            must_contain=["visit", "date"]
        )

        # fields needed from WSR
        wsr_tot_col = _find_col(wsr_cols, aliases=["TOT", "Tot"], must_contain=["tot"])
        wsr_pot_col = _find_col(wsr_cols, aliases=["POT", "Pot"], must_contain=["pot"])
        wsr_ink_col = _find_col(wsr_cols, aliases=["INK", "Ink", "InkType", "Ink Type"], must_contain=["ink"])
        wsr_sol_col = _find_col(wsr_cols, aliases=["Solvent", "SOLVENT"], must_contain=["solvent"])
        wsr_cnc_col = _find_col(wsr_cols, aliases=["CNC"], must_contain=["cnc"])

        base_where, base_params = _wsr_scope_where(wsr_cols)

        if wsr_serial_col and wsr_visit_col:
            where_parts = []
            params = []

            if base_where:
                where_parts.append(base_where.replace(" WHERE ", "", 1))
                params += base_params

            where_parts.append(f"{_cmp_ci_trim(wsr_serial_col)} = UPPER(?)")
            params.append(serial)

            where_sql = " WHERE " + " AND ".join(where_parts)

            def sel(col, alias):
                return f"{_qcol(col)} AS {alias}" if col else f"'' AS {alias}"

            select_sql = ", ".join([
                sel(wsr_visit_col, "last_visit_date"),
                sel(wsr_tot_col, "tot"),
                sel(wsr_pot_col, "pot"),
                sel(wsr_ink_col, "ink"),
                sel(wsr_sol_col, "solvent"),
                sel(wsr_cnc_col, "cnc"),
            ])

            sql = f"""
                SELECT TOP 1 {select_sql}
                FROM dbo.WSR
                {where_sql}
                ORDER BY {_qcol(wsr_visit_col)} DESC
            """

            try:
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute(sql, params)
                    r = cur.fetchone()
                    if r:
                        keys = ["last_visit_date", "tot", "pot", "ink", "solvent", "cnc"]
                        for i, k in enumerate(keys):
                            v = r[i]
                            if isinstance(v, (datetime, date)):
                                wsr_data[k] = v.date().isoformat() if isinstance(v, datetime) else v.isoformat()
                            else:
                                wsr_data[k] = "" if v is None else str(v)
            except Exception:
                wsr_data = {}

    # ---------------- InstallBase: dates for this serial ----------------
    ib_cols = _table_columns("dbo.InstallBase")
    ib_data = {}

    if ib_cols:
        ib_serial_col = _find_col(
            ib_cols,
            aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo", "Serial"],
            must_contain=["serial"]
        )

        filter_due_col = _find_col(
            ib_cols,
            aliases=["Filter Due Date / Hrs", "Filter Due Date/Hrs", "Filter Kit Due Date/Hrs", "FilterKitDue", "FilterDue"],
            must_contain=["filter", "due"]
        )

        amc_due_col = _find_col(
            ib_cols,
            aliases=["AMC Due Date", "Amc Due Date", "AMC_DUE_DATE", "AMCDueDate"],
            must_contain=["amc", "due"]
        )

        base_where, base_params = _installbase_scope_where(ib_cols)

        if ib_serial_col:
            where_parts = []
            params = []

            if base_where:
                where_parts.append(base_where.replace(" WHERE ", "", 1))
                params += base_params

            where_parts.append(f"{_cmp_ci_trim(ib_serial_col)} = UPPER(?)")
            params.append(serial)

            where_sql = " WHERE " + " AND ".join(where_parts)

            def sel(col, alias):
                return f"{_qcol(col)} AS {alias}" if col else f"'' AS {alias}"

            select_sql = ", ".join([
                sel(filter_due_col, "filter_due"),
                sel(amc_due_col, "amc_due"),
            ])

            sql = f"""
                SELECT TOP 1 {select_sql}
                FROM dbo.InstallBase
                {where_sql}
            """

            try:
                with get_conn() as conn:
                    cur = conn.cursor()
                    cur.execute(sql, params)
                    r = cur.fetchone()
                    if r:
                        keys = ["filter_due", "amc_due"]
                        for i, k in enumerate(keys):
                            v = r[i]
                            if isinstance(v, (datetime, date)):
                                ib_data[k] = v.date().isoformat() if isinstance(v, datetime) else v.isoformat()
                            else:
                                ib_data[k] = "" if v is None else str(v)
            except Exception:
                ib_data = {}

    return jsonify({
        "ok": True,
        "wsr": wsr_data,
        "installbase": ib_data
    })



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


# ✅ time helper: keep HH:MM as text
def _parse_time_hhmm(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
        return None
    return s[:5]


@app.post("/api/wsr")
def api_wsr():
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}
    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.WSR table not found"}), 400

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
    ms_col   = _find_col(cols, aliases=["MachineStatus","Machine Status","Mc Status","McStatus"], must_contain=["status"])

    vc1_col  = _find_col(cols, aliases=["VisitCode1","Visit Code 1"], must_contain=["visit","code","1"])
    vc2_col  = _find_col(cols, aliases=["VisitCode2","Visit Code 2"], must_contain=["visit","code","2"])
    ink_col  = _find_col(cols, aliases=["InkType","Ink type"], must_contain=["ink"])
    visit_col= _find_col(cols, aliases=["VisitDate","Visit Date"], must_contain=["visit","date"])
    act_col  = _find_col(cols, aliases=["ActionTaken","Action Taken"], must_contain=["action"])
    rem_col  = _find_col(cols, aliases=["Remarks","Remark"], must_contain=["remark"])

    # ✅ extra columns for complete WSR table
    model_col  = _find_col(cols, aliases=["Printer Model","PrinterModel","Model"], must_contain=["printer","model"])
    mcno_col   = _find_col(cols, aliases=["M/C No","MC No","MCNo","Machine No","MachineNo"], must_contain=["mc","no"])
    serial_col = _find_col(cols, aliases=["Serial No","SerialNo","Serial_No","SERIAL NO"], must_contain=["serial"])

    turnon_col  = _find_col(cols, aliases=["Turn on Time","TurnOnTime"], must_contain=["turn","time"])
    printon_col = _find_col(cols, aliases=["Print on time","PrintOnTime"], must_contain=["print","time"])

    tstart_col = _find_col(cols, aliases=["Travel Start (HH:MM)","TravelStart","Travel Start"], must_contain=["travel","start"])
    tend_col   = _find_col(cols, aliases=["Travel End (HH:MM)","TravelEnd","Travel End"], must_contain=["travel","end"])
    ttime_col  = _find_col(cols, aliases=["TRAVE TIME","TRAVEL TIME","Travel Time","TravelTime"], must_contain=["travel","time"])

    wstart_col = _find_col(cols, aliases=["Work Start (HH:MM)","WorkStart","Work Start"], must_contain=["work","start"])
    wend_col   = _find_col(cols, aliases=["Work End (HH:MM)","WorkEnd","Work End"], must_contain=["work","end"])
    wtime_col  = _find_col(cols, aliases=["WORK TIME","Work Time","WorkTime"], must_contain=["work","time"])

    ink_col2    = _find_col(cols, aliases=["INK","Ink"], must_contain=["ink"])
    solvent_col = _find_col(cols, aliases=["Solvent"], must_contain=["solvent"])
    cnc_col     = _find_col(cols, aliases=["CNC"], must_contain=["cnc"])

    filterdue_col  = _find_col(cols, aliases=["Filter Kit Due Date/Hrs","FilterKitDue","Filter Kit Due"], must_contain=["filter","due"])
    feedback_col   = _find_col(cols, aliases=["Customer Feedback","CustomerFeedback"], must_contain=["customer","feedback"])
    callstatus_col = _find_col(cols, aliases=["Call Status","CallStatus"], must_contain=["call","status"])
    revisit_col    = _find_col(cols, aliases=["Re-visit Required","Revisit Required","RevisitRequired"], must_contain=["re","visit"])

    se_rem_col = _find_col(cols, aliases=["Service Engineer Remarks","ServiceEngineerRemarks"], must_contain=["service","engineer","remarks"])
    sm_rem_col = _find_col(cols, aliases=["Service Manager Remarks","ServiceManagerRemarks"], must_contain=["service","manager","remarks"])

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

        ("printerModel", model_col),
        ("mcNo", mcno_col),
        ("serialNo", serial_col),

        ("turnOnTime", turnon_col),
        ("printOnTime", printon_col),

        ("travelStart", tstart_col),
        ("travelEnd", tend_col),
        ("travelTime", ttime_col),

        ("workStart", wstart_col),
        ("workEnd", wend_col),
        ("workTime", wtime_col),

        ("ink", ink_col2),
        ("solvent", solvent_col),
        ("cnc", cnc_col),

        ("filterKitDue", filterdue_col),
        ("customerFeedback", feedback_col),
        ("callStatus", callstatus_col),
        ("revisitRequired", revisit_col),

        ("serviceEngineerRemarks", se_rem_col),
        ("serviceManagerRemarks", sm_rem_col),
    ]

    insert_cols = []
    insert_vals = []
    params = []

    # ✅✅ FIX: prevent same db column twice in insert
    seen_cols = set()

    for key, dbcol in mapping:
        if not dbcol:
            continue

        if dbcol in seen_cols:
            continue
        seen_cols.add(dbcol)

        val = payload.get(key)

        # dates
        if dbcol in (call_col, visit_col):
            val = _parse_date(val)

        # times (HH:MM)
        if dbcol in (turnon_col, printon_col, tstart_col, tend_col, wstart_col, wend_col):
            val = _parse_time_hhmm(val)

        insert_cols.append(_qcol(dbcol))
        insert_vals.append("?")
        params.append(val)

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
