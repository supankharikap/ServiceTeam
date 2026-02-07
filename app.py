from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import os
import pyodbc
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, date, timedelta
from werkzeug.middleware.proxy_fix import ProxyFix
from decimal import Decimal, InvalidOperation

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


def _clean_val(v):
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if s == "" or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
            return None
        return s
    return v


def _to_int(v):
    v = _clean_val(v)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except Exception:
        return None




def _to_decimal(v):
    v = _clean_val(v)
    if v is None:
        return None
    if isinstance(v, (int, float, Decimal)):
        return v
    try:
        return Decimal(str(v).strip())
    except (InvalidOperation, Exception):
        return None
    
def _parse_iso_date(v):
    """HTML <input type="date"> => YYYY-MM-DD"""
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
        return None

    # if ISO datetime came, keep only date part
    if "T" in s:
        s = s.split("T", 1)[0].strip()

    s = s.replace("/", "-")

    for fmt in ("%Y-%m-%d", "%d-%m-%Y", "%d-%m-%y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass

    return None



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


# ✅✅ FIX: get data types too (for robust parsing)
def _table_column_types(schema_table: str):
    if "." not in schema_table:
        schema, table = "dbo", schema_table
    else:
        schema, table = schema_table.split(".", 1)

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute("""
            SELECT COLUMN_NAME, DATA_TYPE
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
        """, (schema, table))
        out = {}
        for c, t in cur.fetchall():
            out[str(c)] = str(t).lower()
        return out


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

@app.get("/weekly-plan-report")
def weekly_plan_report_page():
    if "user" not in session:
        return redirect(url_for("home"))

    # ye template new tab me open hoga
    return render_template(
        "weeklyPlanReport.html",
        engineer=session.get("engineer", ""),
        zone=session.get("zone", ""),
        role=session.get("role", ""),
        team=session.get("team", ""),
        visitType=(request.args.get("visitType") or "").strip()
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

    zone_col = _find_col(wsr_cols, aliases=["Zone", "ZONE"], must_contain=["zone"])
    eng_col  = _find_col(wsr_cols, aliases=["EngineerName", "Engineer Name", "ENGINEER_NAME"], must_contain=["engineer", "name"])

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
# ===================== KPI =====================
@app.get("/api/kpi")
def api_kpi():
    need = _require_login_json()
    if need:
        return need

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return _json_err("dbo.InstallBase not found", 400)

    where_sql, params = _installbase_scope_where(install_cols)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # 1) InstallBase total
            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            installbase_total = int(cur.fetchone()[0] or 0)

            # 2) Customers count
            cust_col = _find_col(
                install_cols,
                aliases=["CUSTOMER_NAME", "CUSTOMER NAME", "CustomerName", "Customer Name"],
                must_contain=["customer", "name"]
            )
            customers = 0
            if cust_col:
                cur.execute(
                    f"SELECT COUNT(DISTINCT {_qcol(cust_col)}) FROM dbo.InstallBase{where_sql}",
                    params
                )
                customers = int(cur.fetchone()[0] or 0)

            # 3) This Month Cluster Plan (InstallBase -> Cluster Visit Plan)
            cluster_no_col = _find_col(
                install_cols,
                aliases=["Cluster No", "Cluster_No", "CLUSTER NO", "Cluster No."],
                must_contain=["cluster"]
            )
            plan_col = _find_col(
                install_cols,
                aliases=["Cluster Visit Plan", "ClusterVisitPlan", "CLUSTER VISIT PLAN"],
                must_contain=["cluster", "visit", "plan"]
            )

            this_month_cluster_plan = 0
            if cluster_no_col and plan_col:

                # ✅ text date -> date safe conversion (yyyy-mm-dd OR dd-mm-yyyy)
                plan_date_expr = (
                    f"COALESCE("
                    f"TRY_CONVERT(date, {_qcol(plan_col)}, 23),"   # yyyy-mm-dd
                    f"TRY_CONVERT(date, {_qcol(plan_col)}, 105),"  # dd-mm-yyyy
                    f"TRY_CONVERT(date, {_qcol(plan_col)})"
                    f")"
                )

                where_parts = []
                p = []

                # add scope
                if where_sql:
                    where_parts.append(where_sql.replace(" WHERE ", "", 1))
                    p += params

                # cluster not blank
                where_parts.append(
                    f"NULLIF(LTRIM(RTRIM(CAST({_qcol(cluster_no_col)} AS NVARCHAR(200)))), '') IS NOT NULL"
                )

                # plan date valid
                where_parts.append(f"{plan_date_expr} IS NOT NULL")

                # current month filter
                where_parts.append(
                    f"{plan_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
                )
                where_parts.append(
                    f"{plan_date_expr} <  DATEADD(month, 1, DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1))"
                )

                w = " WHERE " + " AND ".join(where_parts)

                cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{w}", p)
                this_month_cluster_plan = int(cur.fetchone()[0] or 0)

    except Exception as e:
        return _json_err(f"InstallBase KPI error: {e}", 500)

    return jsonify({
        "installbase_total": installbase_total,
        "customers": customers,
        "this_month_cluster_plan": this_month_cluster_plan,
        "pending": 0
    })


# ===================== MASTER INSTALLBASE =====================
@app.get("/api/master/installbase")
def api_master_installbase():
    need = _require_login_json()
    if need:
        return need

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))
    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return _json_err("dbo.InstallBase not found", 400)

    base_where, base_params = _installbase_scope_where(cols)

    preferred = [
        "ZONE", "SERVICE_ENGR", "Cluster_No", "CUSTOMER_NAME", "Location", "Machine_Type", "Model", "Serial_No",
        "SERVICE ENGR", "CLUSTER NO", "CUSTOMER NAME", "SERIAL NO"
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

    id_col = _find_col(cols, aliases=["Id", "ID"], must_contain=["id"])
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
    if need:
        return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _installbase_scope_where(cols)

    zone_col = _find_col(cols, aliases=["ZONE", "Zone"], must_contain=["zone"])
    svc_col = _find_col(cols, aliases=["SERVICE_ENGR", "SERVICE ENGR"], must_contain=["service", "engr"])
    cust_col = _find_col(cols, aliases=["CUSTOMER_NAME", "CUSTOMER NAME", "CustomerName", "Customer Name"], must_contain=["customer", "name"])
    serial_col = _find_col(cols, aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo"], must_contain=["serial"])
    cluster_col = _find_col(cols, aliases=["Cluster_No", "CLUSTER NO", "Cluster No"], must_contain=["cluster"])
    loc_col = _find_col(cols, aliases=["LOCATION", "Location"], must_contain=["location"])

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
    if need:
        return jsonify({"items": []}), 401

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
    if need:
        return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"items": []})

    serial_col = _find_col(cols, aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo"], must_contain=["serial"])
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
    if need:
        return jsonify({"ok": False, "rows": []}), 401

    customer = (request.args.get("customer") or "").strip()
    if not customer:
        return jsonify({"ok": True, "rows": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "rows": [], "message": "dbo.InstallBase not found"}), 400

    cust_col = _find_col(cols, aliases=["CUSTOMER_NAME", "CUSTOMER NAME", "CustomerName", "Customer Name"], must_contain=["customer", "name"])
    if not cust_col:
        return jsonify({"ok": False, "rows": [], "message": "Customer column not found"}), 400

    zone_col = _find_col(cols, aliases=["ZONE", "Zone"], must_contain=["zone"])
    svc_col = _find_col(cols, aliases=["SERVICE_ENGR", "SERVICE ENGR"], must_contain=["service", "engr"])
    cluster_col = _find_col(cols, aliases=["Cluster_No", "CLUSTER NO", "Cluster No"], must_contain=["cluster"])
    loc_col = _find_col(cols, aliases=["LOCATION", "Location"], must_contain=["location"])
    state_col = _find_col(cols, aliases=["STATE", "State"], must_contain=["state"])
    addr_col = _find_col(cols, aliases=["Address", "ADDRESS"], must_contain=["address"])
    serial_col = _find_col(cols, aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo"], must_contain=["serial"])
    ink_col = _find_col(cols, aliases=["Ink type", "InkType", "INK TYPE"], must_contain=["ink"])
    active_col = _find_col(cols, aliases=["Active Status", "ActiveStatus"], must_contain=["active", "status"])
    mc_status_col = _find_col(cols, aliases=["Mc Status", "McStatus", "Machine Status", "MachineStatus"], must_contain=["status"])

    # ✅✅ FIX: model + machine type columns for JSON return
    model_col = _find_col(cols, aliases=["Model", "MODEL", "Printer Model", "PrinterModel"], must_contain=["model"])
    mtype_col = _find_col(cols, aliases=["Machine Type", "MachineType", "Machine_Type"], must_contain=["machine", "type"])

    cp_col = _find_col(cols, aliases=["Contact Person", "ContactPerson"], must_contain=["contact", "person"])
    des_col = _find_col(cols, aliases=["Designation"], must_contain=["designation"])
    cn_col = _find_col(cols, aliases=["Contact No", "ContactNumber", "Contact Number"], must_contain=["contact", "no"])
    email_col = _find_col(cols, aliases=["Email", "Email Id"], must_contain=["email"])

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
        sel(model_col, "model"),
        sel(mtype_col, "machine_type"),
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
    if need:
        return need

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))
    q = (request.args.get("q") or "").strip()

    from_date = _parse_iso_date(request.args.get("from"))
    to_date = _parse_iso_date(request.args.get("to"))

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"columns": [], "rows": []})

    base_where, base_params = _wsr_scope_where(cols)

    preferred = ["Zone", "EngineerName", "CustomerName", "Location", "MMM-YY", "Serial", "Model", "VisitDate"]
    search_where, search_params = _build_token_search_where(q, cols, preferred)

    visit_col = _find_col(cols, aliases=["VisitDate", "Visit Date"], must_contain=["visit", "date"])

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    if search_where:
        where_parts.append(search_where)
        params += search_params

    if visit_col:
        if from_date:
            where_parts.append(f"{_qcol(visit_col)} >= ?")
            params.append(from_date)
        if to_date:
            where_parts.append(f"{_qcol(visit_col)} <= ?")
            params.append(to_date)

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    id_col = _find_col(cols, aliases=["Id", "ID"], must_contain=["id"])
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
    if need:
        return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"items": []})

    base_where, base_params = _wsr_scope_where(cols)

    zone_col = _find_col(cols, aliases=["Zone", "ZONE"], must_contain=["zone"])
    eng_col = _find_col(cols, aliases=["EngineerName", "Engineer Name"], must_contain=["engineer", "name"])
    cust_col = _find_col(cols, aliases=["CustomerName", "Customer Name"], must_contain=["customer", "name"])
    month_col = _find_col(cols, aliases=["MonthYear", "Month Year", "MMM-YY", "MMM_YY", "MMM YY"], must_contain=["month"])

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

# ===================== WEEKLY PLAN REPORT (VIEW) =====================
# ✅✅ WEEKLY PLAN AUTOFILL (DO NOT TOUCH WSR INSERT CODE)
# Paste this by REPLACING your current /api/serial/details function (same route)

@app.get("/api/serial/details")
def api_serial_details():
    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "wsr": {}, "installbase": {}})

    # ---------------- WSR: pick row with MAX(VisitDate) for this serial ----------------
    wsr_cols = _table_columns("dbo.WSR")
    wsr_data = {}

    if wsr_cols:
        wsr_serial_col = _find_col(
            wsr_cols,
              aliases=[
                  "Serial No", "SerialNo", "Serial_No", "SERIAL NO", "Serial",
                  "serialNo", "serial_no", "serial no", "Serial Number", "Machine SR. No.", "Printer SR. No."
                  ],
                  must_contain=["serial"])
        
        wsr_visit_col = _find_col( wsr_cols, aliases=["Visit Date", "VISIT DATE", "VisitDate", "Visit_Date", "visit_date"], must_contain=["visit", "date"])


        # ✅ weekly plan wants these (from dbo.WSR)
        wsr_tot_col = _find_col(wsr_cols,aliases=["Turn on Time", "TurnOnTime", "TURN ON TIME"], must_contain=["turn", "on", "time"])
        wsr_pot_col = _find_col(wsr_cols,aliases=["Print on time", "PrintOnTime", "PRINT ON TIME"],must_contain=["print", "on", "time"]
)

        wsr_ink_col = _find_col(wsr_cols, aliases=["INK", "Ink"], must_contain=["ink"])
        wsr_sol_col = _find_col(wsr_cols, aliases=["Solvent", "SOLVENT"], must_contain=["solvent"])
        wsr_cnc_col = _find_col(wsr_cols, aliases=["CNC"], must_contain=["cnc"])

        base_where, base_params = _wsr_scope_where(wsr_cols)

        if wsr_serial_col and wsr_visit_col:
            where_parts = []
            params = []

            # ✅ scope (zone/engineer) same as your report
            if base_where:
                where_parts.append(base_where.replace(" WHERE ", "", 1))
                params += base_params

            # ✅ serial match (trim+upper)
            where_parts.append(f"{_cmp_ci_trim(wsr_serial_col)} = UPPER(?)")
            params.append(serial)

            # ✅ ignore rows where VisitDate is NULL (so MAX visit date logic works)
            where_parts.append(f"{_qcol(wsr_visit_col)} IS NOT NULL")

            where_sql = " WHERE " + " AND ".join(where_parts)

            def sel(col, alias):
                return f"{_qcol(col)} AS {alias}" if col else f"NULL AS {alias}"

            select_sql = ", ".join([
                sel(wsr_visit_col, "last_visit_date"),
                sel(wsr_tot_col, "tot"),
                sel(wsr_pot_col, "pot"),
                sel(wsr_ink_col, "ink"),
                sel(wsr_sol_col, "solvent"),
                sel(wsr_cnc_col, "cnc"),
            ])

            # ✅✅ IMPORTANT: this picks MAX(VisitDate) row (NOT latest entry / ID)
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
                        if isinstance(v, datetime):
                            wsr_data[k] = v.date().isoformat()
                        elif isinstance(v, date):
                            wsr_data[k] = v.isoformat()
                        else:
                            wsr_data[k] = "" if v is None else str(v)
                else:
                    # ✅ no WSR data for this serial => keep blank
                    wsr_data = {}

            except Exception:
                wsr_data = {}

    # ---------------- InstallBase: get filter_due / amc_due for this serial ----------------
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
            aliases=[
                "Filter Due Date / Hrs", "Filter Due Date/Hrs",
                "Filter Kit Due Date/Hrs", "FilterKitDue", "FilterDue"
            ],
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
                return f"{_qcol(col)} AS {alias}" if col else f"NULL AS {alias}"

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
                        if isinstance(v, datetime):
                            ib_data[k] = v.date().isoformat()
                        elif isinstance(v, date):
                            ib_data[k] = v.isoformat()
                        else:
                            ib_data[k] = "" if v is None else str(v)
                else:
                    ib_data = {}

            except Exception:
                ib_data = {}

    return jsonify({
        "ok": True,
        "wsr": wsr_data,
        "installbase": ib_data
    })


@app.get("/api/weeklyplan/report/suggest")
@app.get("/api/weekly-plan/report/suggest")
@app.get("/api/weekly_plan/report/suggest")
def api_weekly_plan_report_suggest():
    need = _require_login_json()
    if need:
        return jsonify({"items": []}), 401

    q = (request.args.get("q") or "").strip()
    if len(q) < 2:
        return jsonify({"items": []})

    cols = _table_columns("dbo.Planning")
    if not cols:
        return jsonify({"items": []})

    # choose important columns for suggestions
    zone_col = _find_col(cols, aliases=["zone", "Zone", "ZONE"], must_contain=["zone"])
    eng_col  = _find_col(cols, aliases=["engineer_name", "EngineerName", "Engineer Name"], must_contain=["engineer", "name"])
    cust_col = _find_col(cols, aliases=["customer_name", "CustomerName", "Customer Name"], must_contain=["customer", "name"])
    loc_col  = _find_col(cols, aliases=["location", "Location"], must_contain=["location"])
    clus_col = _find_col(cols, aliases=["cluster_code", "Cluster", "ClusterCode"], must_contain=["cluster"])
    vdate_col = _find_col(cols, aliases=["visit_date", "VisitDate", "Visit Date"], must_contain=["visit", "date"])

    key_cols = [c for c in [cust_col, eng_col, zone_col, loc_col, clus_col, vdate_col] if c]

    items = []
    seen = set()

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            for c in key_cols:
                sql = f"""
                    SELECT DISTINCT TOP 10 CAST({_qcol(c)} AS NVARCHAR(200)) AS v
                    FROM dbo.Planning
                    WHERE CAST({_qcol(c)} AS NVARCHAR(200)) LIKE ?
                    ORDER BY v
                """
                cur.execute(sql, [f"%{q}%"])

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

# ===================== PLANNING / WEEKLY PLAN (FIX HTTP 404) =====================
# ✅ IMPORTANT: This is ONLY to fix 404 by providing the endpoint(s).
# It does NOT touch your WSR logic.


# ✅ robust time parser (accepts "18 : 16" too)
def _parse_time(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
        return None
    s = s.replace(" ", "")  # "18 : 16" -> "18:16"
    for fmt in ("%H:%M:%S", "%H:%M"):
        try:
            return datetime.strptime(s, fmt).time()
        except Exception:
            pass
    return None

   

def _insert_dynamic(schema_table: str, payload: dict):
    cols = _table_columns(schema_table)
    if not cols:
        return False, f"{schema_table} table not found"

    col_types = _table_column_types(schema_table)
    idx = _col_index(cols)

    payload = dict(payload or {})

    # ✅ FIX: normalize visit_date key from any frontend key
    if "visit_date" not in payload:
        payload["visit_date"] = (
            payload.get("visitDate")
            or payload.get("VisitDate")
            or payload.get("visit date")
            or payload.get("Visit Date")
        )

    # ✅ if ISO datetime came, keep only date part
    vd = payload.get("visit_date")
    if isinstance(vd, str) and "T" in vd:
        payload["visit_date"] = vd.split("T", 1)[0].strip()

    insert_cols = []
    insert_vals = []
    params = []

    # map payload keys -> db cols by normalized name match
    for k, raw_val in payload.items():
        nk = _norm(k)
        if nk not in idx:
            continue

        dbcol = idx[nk]
        val = _clean_val(raw_val)
        dtype = (col_types.get(dbcol) or "").lower()

        if dtype in ("date", "datetime", "datetime2", "smalldatetime"):
            val = _parse_iso_date(val)

        elif dtype == "time":
            val = _parse_time(val)
        elif dtype in ("int", "bigint", "smallint", "tinyint"):
            val = _to_int(val)
        elif dtype in ("decimal", "numeric", "float", "real", "money", "smallmoney"):
            val = _to_decimal(val)

        insert_cols.append(_qcol(dbcol))
        insert_vals.append("?")
        params.append(val)

    # optional created timestamp if exists
    created_col = _find_col(cols, aliases=["CreatedAt", "Created At"], must_contain=["created"])
    if created_col and created_col not in [c.strip("[]") for c in insert_cols]:
        insert_cols.append(_qcol(created_col))
        insert_vals.append("GETUTCDATE()")

    if not insert_cols:
        return False, "No matching columns found to insert"

    sql = f"INSERT INTO {schema_table} ({', '.join(insert_cols)}) VALUES ({', '.join(insert_vals)})"

    with get_conn() as conn:
        cur = conn.cursor()
        cur.execute(sql, params)
        conn.commit()

    return True, "Saved"




# ✅ Provide multiple endpoints to eliminate route mismatch (404 fix)
@app.post("/api/weekly-plan")
@app.post("/api/weeklyplan")
@app.post("/api/weekly_plan")
def api_weekly_plan_save():
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}

    # ✅ (optional) extra safety: normalize visit_date here also
    if "visit_date" not in payload:
        payload["visit_date"] = (
            payload.get("visitDate")
            or payload.get("VisitDate")
            or payload.get("visit date")
            or payload.get("Visit Date")
        )
    vd = payload.get("visit_date")
    if isinstance(vd, str) and "T" in vd:
        payload["visit_date"] = vd.split("T", 1)[0].strip()

    table_name = "dbo.Planning"

    try:
        ok, msg = _insert_dynamic(table_name, payload)
        if not ok:
            return jsonify({"ok": False, "message": msg}), 400
        return jsonify({"ok": True, "message": "Weekly Plan saved successfully!"})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Weekly Plan save error: {e}"}), 500


def _wsr_clean_val(v):
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if s == "" or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
            return None
        return s
    return v


def _wsr_to_int(v):
    v = _wsr_clean_val(v)
    if v is None:
        return None
    if isinstance(v, int):
        return v
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _wsr_to_decimal(v):
    v = _wsr_clean_val(v)
    if v is None:
        return None
    if isinstance(v, (int, float, Decimal)):
        return v
    try:
        return Decimal(str(v).strip())
    except (InvalidOperation, Exception):
        return None


def _wsr_parse_date(v):
    v = _wsr_clean_val(v)
    if v is None:
        return None
    s = str(v).strip()
    for fmt in ("%Y-%m-%d", "%d-%b-%y", "%d-%b-%Y", "%d-%m-%Y"):
        try:
            return datetime.strptime(s, fmt).date()
        except Exception:
            pass
    return None


def _wsr_parse_time_hhmm(v):
    v = _wsr_clean_val(v)
    if v is None:
        return None
    s = str(v).strip()
    if len(s) >= 5:
        return s[:5]  # keep "HH:MM" text
    return None


@app.post("/api/wsr")
@app.post("/api/wsr/")     # trailing slash support
@app.post("/wsr")          # if frontend sending /wsr
@app.post("/wsr/")         # slash support
def api_wsr():
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.WSR table not found"}), 400

    col_types = _table_column_types("dbo.WSR")

    # --- find columns dynamically (same pattern as your file) ---
    zone_col  = _find_col(cols, aliases=["Zone", "ZONE"], must_contain=["zone"])
    eng_col   = _find_col(cols, aliases=["EngineerName", "Engineer Name", "ENGINEER_NAME"], must_contain=["engineer", "name"])
    month_col = _find_col(cols, aliases=["MonthYear", "MMM-YY", "MMM_YY", "MMM YY"], must_contain=["mmm"])
    rep_col   = _find_col(cols, aliases=["ServiceReportNo", "Service report No", "Service report No."], must_contain=["report"])
    cust_col  = _find_col(cols, aliases=["CustomerName", "Customer Name"], must_contain=["customer", "name"])
    loc_col   = _find_col(cols, aliases=["Location"], must_contain=["location"])

    cp_col    = _find_col(cols, aliases=["ContactPerson", "Contact Person"], must_contain=["contact", "person"])
    des_col   = _find_col(cols, aliases=["Designation"], must_contain=["designation"])
    cn_col    = _find_col(cols, aliases=["ContactNumber", "Contact No", "Contact No."], must_contain=["contact", "no"])
    email_col = _find_col(cols, aliases=["Email", "Email Id"], must_contain=["email"])
    call_col  = _find_col(cols, aliases=["CallLoggedDate", "Call Logged Date"], must_contain=["call", "date"])
    prob_col  = _find_col(cols, aliases=["ProblemReported", "Problem Reported"], must_contain=["problem"])
    ms_col    = _find_col(cols, aliases=["MachineStatus", "Machine Status", "Mc Status", "McStatus"], must_contain=["status"])

    vc1_col   = _find_col(cols, aliases=["VisitCode1", "Visit Code 1"], must_contain=["visit", "code", "1"])
    vc2_col   = _find_col(cols, aliases=["VisitCode2", "Visit Code 2"], must_contain=["visit", "code", "2"])
    inkType_col = _find_col(cols, aliases=["InkType", "Ink type"], must_contain=["ink"])
    visit_col = _find_col(cols, aliases=["VisitDate", "Visit Date"], must_contain=["visit", "date"])
    act_col   = _find_col(cols, aliases=["ActionTaken", "Action Taken"], must_contain=["action"])
    rem_col   = _find_col(cols, aliases=["Remarks", "Remark"], must_contain=["remark"])

    model_col = _find_col(cols, aliases=["Printer Model", "PrinterModel", "Model"], must_contain=["model"])
    mcno_col  = _find_col(cols, aliases=["M/C No", "MC No", "MCNo", "Machine No", "MachineNo"], must_contain=["mc", "no"])
    serial_col= _find_col(cols, aliases=["Serial No", "SerialNo", "Serial_No", "SERIAL NO", "Serial"], must_contain=["serial"])

    turnon_col  = _find_col(cols, aliases=["Turn on Time", "TurnOnTime"])
    printon_col = _find_col(cols, aliases=["Print on time", "PrintOnTime"])

    tstart_col = _find_col(cols, aliases=["Travel Start (HH:MM)", "TravelStart", "Travel Start"], must_contain=["travel", "start"])
    tend_col   = _find_col(cols, aliases=["Travel End (HH:MM)", "TravelEnd", "Travel End"], must_contain=["travel", "end"])
    ttime_col  = _find_col(cols, aliases=["TRAVE TIME", "TRAVEL TIME", "Travel Time", "TravelTime"], must_contain=["travel", "time"])

    wstart_col = _find_col(cols, aliases=["Work Start (HH:MM)", "WorkStart", "Work Start"], must_contain=["work", "start"])
    wend_col   = _find_col(cols, aliases=["Work End (HH:MM)", "WorkEnd", "Work End"], must_contain=["work", "end"])
    wtime_col  = _find_col(cols, aliases=["WORK TIME", "Work Time", "WorkTime"], must_contain=["work", "time"])

    ink_col2    = _find_col(cols, aliases=["INK", "Ink"], must_contain=["ink"])
    solvent_col = _find_col(cols, aliases=["Solvent", "SOLVENT"], must_contain=["solvent"])
    cnc_col     = _find_col(cols, aliases=["CNC"], must_contain=["cnc"])

    filterdue_col  = _find_col(cols, aliases=["Filter Kit Due Date/Hrs", "FilterKitDue", "Filter Kit Due"], must_contain=["filter", "due"])
    feedback_col   = _find_col(cols, aliases=["Customer Feedback", "CustomerFeedback"], must_contain=["customer", "feedback"])
    callstatus_col = _find_col(cols, aliases=["Call Status", "CallStatus"], must_contain=["call", "status"])
    revisit_col    = _find_col(cols, aliases=["Re-visit Required", "Revisit Required", "RevisitRequired"], must_contain=["re", "visit"])

    se_rem_col = _find_col(cols, aliases=["Service Engineer Remarks", "ServiceEngineerRemarks"], must_contain=["service", "engineer", "remarks"])
    sm_rem_col = _find_col(cols, aliases=["Service Manager Remarks", "ServiceManagerRemarks"], must_contain=["service", "manager", "remarks"])

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
        ("inkType", inkType_col),
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

    seen_cols = set()

    for key, dbcol in mapping:
        if not dbcol:
            continue
        if dbcol in seen_cols:
            continue
        seen_cols.add(dbcol)

        val = payload.get(key)
        val = _wsr_clean_val(val)

        dtype = (col_types.get(dbcol) or "").lower()

        if dtype in ("date", "datetime", "datetime2", "smalldatetime"):
            val = _wsr_parse_date(val)
        elif dtype in ("time",):
            val = _wsr_parse_time_hhmm(val)
        elif dtype in ("int", "bigint", "smallint", "tinyint"):
            val = _wsr_to_int(val)
        elif dtype in ("decimal", "numeric", "float", "real", "money", "smallmoney"):
            val = _wsr_to_decimal(val)

        insert_cols.append(_qcol(dbcol))
        insert_vals.append("?")
        params.append(val)

    created_col = _find_col(cols, aliases=["CreatedAt", "Created At"], must_contain=["created"])
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



# ===================== INSTALLBASE: BY SERIAL / EXISTS / SAVE (INSERT/UPDATE) =====================

def _installbase_serial_where(cols, serial_value: str):
    """Scope + serial match WHERE builder"""
    base_where, base_params = _installbase_scope_where(cols)

    serial_col = _find_col(
        cols,
        aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo", "Serial"],
        must_contain=["serial"]
    )
    if not serial_col:
        return None, None, "Serial column not found"

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(serial_col)} = UPPER(?)")
    params.append((serial_value or "").strip())

    where_sql = " WHERE " + " AND ".join(where_parts)
    return where_sql, params, None


@app.get("/api/installbase/exists")
@app.get("/api/installbase/exists/")
def api_installbase_exists():
    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "exists": False})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "exists": False, "message": "dbo.InstallBase not found"}), 400

    where_sql, params, err = _installbase_serial_where(cols, serial)
    if err:
        return jsonify({"ok": False, "exists": False, "message": err}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(f"SELECT TOP 1 1 FROM dbo.InstallBase{where_sql}", params)
            exists = cur.fetchone() is not None
        return jsonify({"ok": True, "exists": exists})
    except Exception as e:
        return jsonify({"ok": False, "exists": False, "message": str(e)}), 500


@app.get("/api/installbase/by-serial")
@app.get("/api/installbase/by-serial/")
def api_installbase_by_serial():
    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "row": {}})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "row": {}, "message": "dbo.InstallBase not found"}), 400

    where_sql, params, err = _installbase_serial_where(cols, serial)
    if err:
        return jsonify({"ok": False, "row": {}, "message": err}), 400

    select_cols = ", ".join([_qcol(c) for c in cols])
    sql = f"SELECT TOP 1 {select_cols} FROM dbo.InstallBase{where_sql}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            r = cur.fetchone()

        if not r:
            return jsonify({"ok": True, "row": {}})

        obj = {}
        for i, c in enumerate(cols):
            obj[c] = _json_safe(r[i])

        return jsonify({"ok": True, "row": obj})
    except Exception as e:
        return jsonify({"ok": False, "row": {}, "message": str(e)}), 500


def _parse_time_any(v):
    """Accepts '18:16' or '18 : 16' etc -> HH:MM text (safe for NVARCHAR/time)"""
    if v is None:
        return None
    if isinstance(v, str):
        s = v.strip()
        if not s or s.upper() in ("NA", "N/A", "NULL", "#VALUE!"):
            return None
        s = s.replace(" ", "")
        return s[:8]
    return v


def _installbase_payload_to_db(cols, payload: dict):
    """
    payload (snake_case) -> db columns mapping by normalized match.
    returns: dict(dbcol -> value)
    """
    col_types = _table_column_types("dbo.InstallBase")
    idx = _col_index(cols)

    out = {}
    for k, raw_val in (payload or {}).items():
        nk = _norm(k)
        if nk not in idx:
            continue

        dbcol = idx[nk]
        val = _clean_val(raw_val)
        dtype = (col_types.get(dbcol) or "").lower()

        # type-safe conversions
        if dtype in ("date", "datetime", "datetime2", "smalldatetime"):
            val = _parse_iso_date(val)
        elif dtype in ("time",):
            val = _parse_time_any(val)
        elif dtype in ("int", "bigint", "smallint", "tinyint"):
            val = _to_int(val)
        elif dtype in ("decimal", "numeric", "float", "real", "money", "smallmoney"):
            val = _to_decimal(val)

        out[dbcol] = val

    return out


@app.post("/api/installbase/save")
@app.post("/api/installbase/save/")
def api_installbase_save():
    """
    Frontend expects:
    POST /api/installbase/save
    Body JSON: {customer_name, serial_no, ...}
    If serial exists => UPDATE else INSERT
    """
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}

    # required by frontend
    customer_name = (payload.get("customer_name") or "").strip()
    serial_no = (payload.get("serial_no") or "").strip()
    if not customer_name or not serial_no:
        return jsonify({"ok": False, "message": "Customer Name & Serial No required!"}), 400

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.InstallBase not found"}), 400

    # identify key columns in DB
    serial_col = _find_col(
        cols,
        aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo", "Serial"],
        must_contain=["serial"]
    )
    cust_col = _find_col(
        cols,
        aliases=["CUSTOMER_NAME", "CUSTOMER NAME", "CustomerName", "Customer Name"],
        must_contain=["customer", "name"]
    )
    if not serial_col:
        return jsonify({"ok": False, "message": "Serial column not found in dbo.InstallBase"}), 400
    if not cust_col:
        return jsonify({"ok": False, "message": "Customer column not found in dbo.InstallBase"}), 400

    # Convert payload -> db values (normalized mapping)
    db_vals = _installbase_payload_to_db(cols, payload)

    # Ensure customer/serial go in correct db columns (even if mapping missed)
    db_vals[cust_col] = customer_name
    db_vals[serial_col] = serial_no

    # scope + where for exists/update
    where_sql, where_params, err = _installbase_serial_where(cols, serial_no)
    if err:
        return jsonify({"ok": False, "message": err}), 400

    # do not update CreatedAt if present
    created_col = _find_col(cols, aliases=["CreatedAt", "Created At"], must_contain=["created"])
    updated_col = _find_col(cols, aliases=["UpdatedAt", "Updated At", "ModifiedAt", "Modified At"], must_contain=["updated"])

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # exists?
            cur.execute(f"SELECT TOP 1 1 FROM dbo.InstallBase{where_sql}", where_params)
            exists = cur.fetchone() is not None

            if exists:
                # UPDATE
                sets = []
                params = []

                for dbcol, val in db_vals.items():
                    # never change serial col in update (keep it as key)
                    if dbcol == serial_col:
                        continue
                    if created_col and dbcol == created_col:
                        continue
                    sets.append(f"{_qcol(dbcol)} = ?")
                    params.append(val)

                if updated_col:
                    sets.append(f"{_qcol(updated_col)} = GETUTCDATE()")

                if not sets:
                    return jsonify({"ok": False, "message": "Nothing to update"}), 400

                sql = f"UPDATE dbo.InstallBase SET {', '.join(sets)}{where_sql}"
                cur.execute(sql, params + where_params)
                conn.commit()

                return jsonify({"ok": True, "message": "InstallBase UPDATED successfully!"})

            else:
                # INSERT
                insert_cols = []
                insert_vals = []
                params = []

                for dbcol, val in db_vals.items():
                    insert_cols.append(_qcol(dbcol))
                    insert_vals.append("?")
                    params.append(val)

                if created_col and created_col not in db_vals:
                    insert_cols.append(_qcol(created_col))
                    insert_vals.append("GETUTCDATE()")

                sql = f"INSERT INTO dbo.InstallBase ({', '.join(insert_cols)}) VALUES ({', '.join(insert_vals)})"
                cur.execute(sql, params)
                conn.commit()

                return jsonify({"ok": True, "message": "InstallBase INSERTED successfully!"})

    except Exception as e:
        return jsonify({"ok": False, "message": f"InstallBase save error: {e}"}), 500
    

# ===================== INSTALLBASE DELETE =====================
@app.get("/api/installbase/delete")  
@app.post("/api/installbase/delete")         # main (frontend safe)
@app.delete("/api/installbase/delete")       # if browser supports DELETE
def api_installbase_delete():
    need = _require_login_json()
    if need:
        return need

    # serial can come via query (?serial=) or JSON body
    serial = (request.args.get("serial") or "").strip()
    if not serial:
        try:
            payload = request.get_json(force=True) or {}
        except Exception:
            payload = {}
        serial = (payload.get("serial_no") or payload.get("serial") or "").strip()

    if not serial:
        return jsonify({"ok": False, "message": "Serial No required!"}), 400

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.InstallBase not found"}), 400

    serial_col = _find_col(
        cols,
        aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo", "Serial"],
        must_contain=["serial"]
    )
    if not serial_col:
        return jsonify({"ok": False, "message": "Serial column not found in InstallBase"}), 400

    # ✅ scope protection (zone / engineer restriction)
    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    # exact serial match (trim + upper)
    where_parts.append(f"{_cmp_ci_trim(serial_col)} = UPPER(?)")
    params.append(serial)

    where_sql = " WHERE " + " AND ".join(where_parts)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # check exists first
            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            cnt = int(cur.fetchone()[0])
            if cnt == 0:
                return jsonify({"ok": False, "message": "Row not found (or you don't have access)."}), 404

            # delete
            cur.execute(f"DELETE FROM dbo.InstallBase{where_sql}", params)
            conn.commit()

        return jsonify({"ok": True, "message": f"Deleted Serial No: {serial}"})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Delete error: {e}"}), 500


# ===================== WEEKLY PLAN REPORT (dbo.Planning) =====================

def _planning_scope_where(cols):
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    eng  = (session.get("engineer") or "").strip()

    if role == "admin":
        return "", []

    zone_col = _find_col(cols, aliases=["Zone", "ZONE", "zone"], must_contain=["zone"])
    eng_col  = _find_col(cols, aliases=["EngineerName", "Engineer Name", "engineer_name", "engineer"], must_contain=["engineer", "name"])

    where = []
    params = []

    # Manager/Team Leader => only zone
    if _is_manager_like(role):
        if zone and zone_col:
            where.append(f"{_cmp_ci_trim(zone_col)} = UPPER(?)")
            params.append(zone)
        return (" WHERE " + " AND ".join(where)) if where else "", params

    # User => zone + engineer
    if zone and zone_col:
        where.append(f"{_cmp_ci_trim(zone_col)} = UPPER(?)")
        params.append(zone)

    if eng and eng_col:
        where.append(f"{_cmp_ci_trim(eng_col)} = UPPER(?)")
        params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params


@app.get("/api/weeklyplan/report", endpoint="weeklyplan_report")
@app.get("/api/weekly-plan/report", endpoint="weeklyplan_report")
@app.get("/api/weekly_plan/report", endpoint="weeklyplan_report")

def api_weeklyplan_report():
    need = _require_login_json()
    if need:
        return need

    limit = int(request.args.get("limit", "500"))
    limit = max(1, min(limit, 5000))

    q = (request.args.get("q") or "").strip()
    visit_type = (request.args.get("visitType") or "").strip()

    from_date = _parse_iso_date(request.args.get("from"))
    to_date   = _parse_iso_date(request.args.get("to"))

    cols = _table_columns("dbo.Planning")
    if not cols:
        return jsonify({"columns": [], "rows": []})

    base_where, base_params = _planning_scope_where(cols)

    preferred = [
        "zone", "engineer_name", "engineerName",
        "customer_name", "customerName",
        "location", "serial", "serial_no",
        "cluster", "cluster_code",
        "visit_type", "visitType",
        "visit_date", "visitDate"
    ]

    search_where, search_params = _build_token_search_where(q, cols, preferred)

    visit_col = _find_col(
        cols,
        aliases=["visit_date", "VisitDate", "Visit Date", "Planning Date"],
        must_contain=["visit", "date"]
    )

    type_col = _find_col(
        cols,
        aliases=["visitType", "VisitType", "visit_type", "Visit Type"],
        must_contain=["visit", "type"]
    )

    id_col = _find_col(cols, aliases=["Id", "ID"], must_contain=["id"])

    where_parts = []
    params = []

    # scope (zone / engineer)
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    # search
    if search_where:
        where_parts.append(search_where)
        params += search_params

    # date filter
    if visit_col:
        if from_date:
            where_parts.append(f"{_qcol(visit_col)} >= ?")
            params.append(from_date)
        if to_date:
            where_parts.append(f"{_qcol(visit_col)} <= ?")
            params.append(to_date)

    # ✅ visitType filter (Cluster / Breakdown / Sales Support / Other)
    if visit_type and type_col:
        vt = visit_type.strip().lower()
        # normalize DB value: trim + lower
        tc = f"LOWER(LTRIM(RTRIM(COALESCE(CAST({_qcol(type_col)} AS NVARCHAR(200)), ''))))"
        if vt in ("other", "others", "__other__"):
            where_parts.append(
                f"({tc} = '' OR {tc} LIKE '%other%' OR "
                f"({tc} NOT LIKE '%cluster%' AND {tc} NOT LIKE '%break%' AND {tc} NOT LIKE '%sales%'))"
            )
        elif "sales" in vt:
            where_parts.append(f"{tc} LIKE '%sales%'")
        elif "break" in vt:
            where_parts.append(f"{tc} LIKE '%break%'")
        elif "cluster" in vt:
            where_parts.append(f"{tc} LIKE '%cluster%'")
        else:
            where_parts.append(f"{tc} LIKE ?")
            params.append(f"%{vt}%")



    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    order_by = (
        f"{_qcol(visit_col)} DESC"
        if visit_col
        else (f"{_qcol(id_col)} DESC" if id_col else f"{_qcol(cols[0])} DESC")
    )

    select_cols = ", ".join([_qcol(c) for c in cols])
    sql = f"""
        SELECT TOP {limit} {select_cols}
        FROM dbo.Planning
        {where_sql}
        ORDER BY {order_by}
    """

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
        return _json_err(f"WeeklyPlan report error: {e}", 500)

@app.get("/api/weeklyplan/summary")
@app.get("/api/weekly-plan/summary")
@app.get("/api/weekly_plan/summary")
def api_weeklyplan_summary():
    need = _require_login_json()
    if need:
        return need

    cols = _table_columns("dbo.Planning")
    if not cols:
        return _json_err("dbo.Planning not found", 400)

    base_where, base_params = _planning_scope_where(cols)

    visit_col = _find_col(cols, aliases=["visit_date","VisitDate","Visit Date","Planning Date"], must_contain=["visit","date"])
    type_col  = _find_col(cols, aliases=["visitType","VisitType","visit_type","Visit Type"], must_contain=["visit","type"])
    eng_col   = _find_col(cols, aliases=["engineer_name","EngineerName","Engineer Name","engineer"], must_contain=["engineer","name"])

    if not visit_col:
        return _json_err("visit_date column not found in dbo.Planning", 400)
    if not type_col:
        return _json_err("visitType column not found in dbo.Planning", 400)

    # optional engineer filter
    engineer = (request.args.get("engineer") or "").strip()

    # scope where
    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    if engineer and eng_col:
        where_parts.append(f"{_cmp_ci_trim(eng_col)} = UPPER(?)")
        params.append(engineer)

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # prev7: today-7 to yesterday
            sql_prev = f"""
                SELECT COUNT(*) 
                FROM dbo.Planning
                {where_sql}
                {" AND " if where_sql else " WHERE "}
                {_qcol(visit_col)} >= DATEADD(day,-7, CAST(GETDATE() AS date))
                AND {_qcol(visit_col)} <  CAST(GETDATE() AS date)
            """
            cur.execute(sql_prev, params)
            prev7 = int(cur.fetchone()[0] or 0)

            # next7: today to today+6
            sql_next = f"""
                SELECT COUNT(*) 
                FROM dbo.Planning
                {where_sql}
                {" AND " if where_sql else " WHERE "}
                {_qcol(visit_col)} >= CAST(GETDATE() AS date)
                AND {_qcol(visit_col)} <  DATEADD(day,7, CAST(GETDATE() AS date))
            """
            cur.execute(sql_next, params)
            next7 = int(cur.fetchone()[0] or 0)

            # by type: last7 + next7 total 14 days window
            sql_type = f"""
                SELECT CAST({_qcol(type_col)} AS NVARCHAR(200)) AS t, COUNT(*) AS c
                FROM dbo.Planning
                {where_sql}
                {" AND " if where_sql else " WHERE "}
                {_qcol(visit_col)} >= DATEADD(day,-7, CAST(GETDATE() AS date))
                AND {_qcol(visit_col)} <  DATEADD(day,7, CAST(GETDATE() AS date))
                GROUP BY CAST({_qcol(type_col)} AS NVARCHAR(200))
            """
            cur.execute(sql_type, params)
            rows = cur.fetchall()

        by_type = {"breakdown": 0, "cluster": 0, "sales_support": 0, "other": 0}

        for t, c in rows:
            tt = (t or "").strip().lower()
            c = int(c or 0)

            if "break" in tt:
                by_type["breakdown"] += c
            elif "cluster" in tt:
                by_type["cluster"] += c
            elif "sales" in tt:
                by_type["sales_support"] += c
            else:
                if tt:   # ✅ only non-blank
                    by_type["other"] += c

        total14 = prev7 + next7

        return jsonify({
            "prev7": prev7,
            "next7": next7,
            "total14": total14,
            "by_type": by_type
        })

    except Exception as e:
        return _json_err(f"Weeklyplan summary error: {e}", 500)

@app.get("/api/wsr/summary_month")
def api_wsr_summary_month():
    need = _require_login_json()
    if need:
        return need

    cols = _table_columns("dbo.WSR")
    if not cols:
        return _json_err("dbo.WSR not found", 400)

    visit_col = _find_col(cols, aliases=["VisitDate", "Visit Date"], must_contain=["visit", "date"])
    vc1_col   = _find_col(cols, aliases=["VisitCode1", "Visit Code 1"], must_contain=["visit", "code", "1"])

    if not visit_col:
        return _json_err("VisitDate column not found in dbo.WSR", 400)
    if not vc1_col:
        return _json_err("VisitCode1 column not found in dbo.WSR", 400)

    base_where, base_params = _wsr_scope_where(cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    # ✅ current month filter ALWAYS apply
    where_parts.append(f"{_qcol(visit_col)} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)")
    where_parts.append(f"{_qcol(visit_col)} <  DATEADD(month, 1, DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1))")

    where_sql = " WHERE " + " AND ".join(where_parts)

    sql = f"""
        SELECT CAST({_qcol(vc1_col)} AS NVARCHAR(200)) AS t, COUNT(*) AS c
        FROM dbo.WSR
        {where_sql}
        GROUP BY CAST({_qcol(vc1_col)} AS NVARCHAR(200))
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()

        counts = {"Cluster": 0, "Breakdown": 0, "Sales Support": 0, "Other": 0}

        for t, c in rows:
            tt = (t or "").strip().lower()
            c = int(c or 0)

            if "break" in tt:
                counts["Breakdown"] += c
            elif "cluster" in tt:
                counts["Cluster"] += c
            elif "sales" in tt:
                counts["Sales Support"] += c
            else:
                counts["Other"] += c

        total = sum(counts.values())
        return jsonify({"ok": True, "total": total, "counts": counts})

    except Exception as e:
        return _json_err(f"WSR summary month error: {e}", 500)
    

    

from datetime import datetime

@app.get("/api/weeklyplan/summary_range")
def weeklyplan_summary_range():
    need = _require_login_json()
    if need:
        return need

    from_s = (request.args.get("from") or "").strip()
    to_s   = (request.args.get("to") or "").strip()

    try:
        from_d = datetime.strptime(from_s, "%Y-%m-%d").date()
        to_d   = datetime.strptime(to_s, "%Y-%m-%d").date()
    except Exception:
        return jsonify({"ok": False, "error": "Invalid from/to. Use YYYY-MM-DD"}), 400

    cols = _table_columns("dbo.Planning")
    if not cols:
        return jsonify({"ok": False, "error": "dbo.Planning not found"}), 400

    # ✅ apply same scope logic (zone/engineer/manager/admin)
    base_where, base_params = _planning_scope_where(cols)

    visit_col = _find_col(cols, aliases=["visit_date","VisitDate","Visit Date","Planning Date"], must_contain=["visit","date"])
    type_col  = _find_col(cols, aliases=["visitType","VisitType","visit_type","Visit Type"], must_contain=["visit","type"])

    if not visit_col:
        return jsonify({"ok": False, "error": "visit_date column not found"}), 400
    if not type_col:
        return jsonify({"ok": False, "error": "visitType column not found"}), 400

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    # ✅ date range
    where_parts.append(f"CAST({_qcol(visit_col)} AS date) >= ?")
    params.append(from_d)
    where_parts.append(f"CAST({_qcol(visit_col)} AS date) <= ?")
    params.append(to_d)

    where_sql = " WHERE " + " AND ".join(where_parts)

    sql = f"""
        SELECT
          COALESCE(CAST({_qcol(type_col)} AS NVARCHAR(200)),'') AS visitType,
          COUNT(*) AS cnt
        FROM dbo.Planning
        {where_sql}
        GROUP BY COALESCE(CAST({_qcol(type_col)} AS NVARCHAR(200)),'')
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()

        by = {"cluster": 0, "breakdown": 0, "sales_support": 0, "other": 0}

        for vt, cnt in rows:
            vt = (vt or "").strip().lower()
            c  = int(cnt or 0)

            if "cluster" in vt:
                by["cluster"] += c
            elif "break" in vt:
                by["breakdown"] += c
            elif "sales" in vt:
                by["sales_support"] += c
            else:
                by["other"] += c

        total = sum(by.values())
        return jsonify({"ok": True, "total": total, "by_type": by, "from": from_s, "to": to_s})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

@app.get("/api/wsr-report")
@app.get("/api/wsr_report")
@app.get("/api/wsrreport")
def api_wsr_report():
    need = _require_login_json()
    if need:
        return need

    limit = int(request.args.get("limit", "2000"))
    limit = max(1, min(limit, 5000))

    visit_type = (request.args.get("visitType") or "").strip()
    q = (request.args.get("q") or "").strip()

    from_date = _parse_iso_date(request.args.get("from"))
    to_date   = _parse_iso_date(request.args.get("to"))

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"columns": [], "rows": []})

    base_where, base_params = _wsr_scope_where(cols)

    # find columns
    visit_col = _find_col(cols, aliases=["VisitDate", "Visit Date"], must_contain=["visit", "date"])
    vc1_col   = _find_col(cols, aliases=["VisitCode1", "Visit Code 1"], must_contain=["visit", "code", "1"])

    # ✅ ROBUST date expression (TEXT date ko bhi date bana dega)
    visit_date_expr = None
    if visit_col:
        visit_date_expr = (
            f"COALESCE("
            f"TRY_CONVERT(date, {_qcol(visit_col)}, 23),"   # yyyy-mm-dd
            f"TRY_CONVERT(date, {_qcol(visit_col)}, 105),"  # dd-mm-yyyy
            f"TRY_CONVERT(date, {_qcol(visit_col)}, 103),"  # dd/mm/yyyy
            f"TRY_CONVERT(date, {_qcol(visit_col)})"
            f")"
        )

    preferred = ["Zone", "EngineerName", "CustomerName", "Location", "MMM-YY", "Serial", "Model", "VisitDate"]
    search_where, search_params = _build_token_search_where(q, cols, preferred)

    where_parts = []
    params = []

    # scope
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    # search
    if search_where:
        where_parts.append(search_where)
        params += search_params

    # ✅ DATE FILTER (works even if VisitDate text)
    if visit_date_expr:
        where_parts.append(f"{visit_date_expr} IS NOT NULL")
        if from_date:
            where_parts.append(f"{visit_date_expr} >= ?")
            params.append(from_date)
        if to_date:
            where_parts.append(f"{visit_date_expr} <= ?")
            params.append(to_date)

    # ✅ Visit Type filter (case-insensitive, partial match safe)
    if visit_type and vc1_col:
        where_parts.append(f"{_cmp_ci_trim(vc1_col)} LIKE ?")
        params.append(f"%{visit_type.strip().upper()}%")

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    id_col = _find_col(cols, aliases=["Id", "ID"], must_contain=["id"])

    # ✅ order by converted date
    order_by = (
        f"{visit_date_expr} DESC"
        if visit_date_expr
        else (f"{_qcol(id_col)} DESC" if id_col else f"{_qcol(cols[0])} DESC")
    )

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

@app.get("/wsr-report")
def wsr_report_page():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "WSRReport.html",   # ✅ yaha aapki template file ka exact naam
        engineer=session.get("engineer", ""),
        zone=session.get("zone", ""),
        role=session.get("role", ""),
        team=session.get("team", ""),
        visitType=(request.args.get("visitType") or "").strip(),
        from_date=(request.args.get("from") or "").strip(),
        to_date=(request.args.get("to") or "").strip(),
    )


# ===================== RUN =====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
