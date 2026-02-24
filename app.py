from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_from_directory
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

# ✅ Cookie settings
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = (os.environ.get("COOKIE_SECURE", "0") == "1")


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
@app.get("/api/kpi")
def api_kpi():

    need = _require_login_json()
    if need:
        return need

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return _json_err("InstallBase not found", 400)

    wsr_cols = _wsr_cols()
    if not wsr_cols:
        return _json_err("WSR not found", 400)

    # ---------------- InstallBase Scope ----------------
    where_sql, params = _installbase_scope_where(install_cols)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # ================= 1️⃣ TOTAL INSTALLBASE =================
            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            installbase_total = int(cur.fetchone()[0] or 0)

            # ================= 2️⃣ ACTIVE / INACTIVE / DEAD =================
            active_col = _find_col(
                install_cols,
                aliases=["Active Status", "ActiveStatus"],
                must_contain=["active", "status"]
            )

            active_total = 0
            inactive_total = 0
            dead_total = 0

            if active_col:

                active_expr = _cmp_ci_trim(active_col)

                status_where_parts = []
                status_params = []

                if where_sql:
                    status_where_parts.append(where_sql.replace(" WHERE ", "", 1))
                    status_params += params

                status_where_sql = (
                    " WHERE " + " AND ".join(status_where_parts)
                    if status_where_parts else ""
                )

                sql_status = f"""
                    SELECT
                        SUM(CASE WHEN {active_expr} = 'ACTIVE' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN {active_expr} = 'INACTIVE' THEN 1 ELSE 0 END),
                        SUM(CASE WHEN {active_expr} = 'DEAD' THEN 1 ELSE 0 END)
                    FROM dbo.InstallBase
                    {status_where_sql}
                """

                cur.execute(sql_status, status_params)
                row = cur.fetchone()

                if row:
                    active_total = int(row[0] or 0)
                    inactive_total = int(row[1] or 0)
                    dead_total = int(row[2] or 0)

            # ================= 3️⃣ CUSTOMERS =================
            cust_col = _find_col(install_cols, must_contain=["customer","name"])
            customers = 0
            if cust_col:
                cur.execute(
                    f"SELECT COUNT(DISTINCT {_qcol(cust_col)}) FROM dbo.InstallBase{where_sql}",
                    params
                )
                customers = int(cur.fetchone()[0] or 0)

            # ================= 4️⃣ THIS MONTH CLUSTER PLAN =================
            plan_col = _find_col(install_cols, must_contain=["cluster","visit","plan"])
            this_month_cluster_plan = 0

            if plan_col:

                plan_date_expr = f"i.{_qcol(plan_col)}"
                plan_where_parts = []
                plan_params = []

                if where_sql:
                    plan_where_parts.append(where_sql.replace(" WHERE ", "", 1))
                    plan_params += params

                plan_where_parts.append(
                    f"{plan_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
                )
                plan_where_parts.append(
                    f"{plan_date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))"
                )

                plan_where_sql = " WHERE " + " AND ".join(plan_where_parts)

                plan_sql = f"""
                    SELECT COUNT(DISTINCT {_cmp_ci_trim(_find_col(install_cols, must_contain=['serial']))})
                    FROM dbo.InstallBase
                    {plan_where_sql}
                """

                cur.execute(plan_sql, plan_params)
                this_month_cluster_plan = int(cur.fetchone()[0] or 0)

            # ================= 5️⃣ THIS MONTH CLUSTER VISITED =================
            dcol = _wsr_date_col(wsr_cols)
            vcol = _wsr_visit_code1_col(wsr_cols)
            serial_col = _find_col(wsr_cols, must_contain=["serial"])

            this_month_cluster_visited = 0

            if dcol and vcol and serial_col:

                base_where_wsr, base_params_wsr = _wsr_scope_where(wsr_cols)

                date_expr = f"""
                    COALESCE(
                        TRY_CONVERT(date, {_qcol(dcol)}, 23),
                        TRY_CONVERT(date, {_qcol(dcol)}, 105),
                        TRY_CONVERT(date, {_qcol(dcol)})
                    )
                """

                where_parts2 = []
                params2 = []

                if base_where_wsr:
                    where_parts2.append(base_where_wsr.replace(" WHERE ", "", 1))
                    params2 += base_params_wsr

                where_parts2.append(f"{_cmp_ci_trim(vcol)} = 'CLUSTER'")
                where_parts2.append(
                    f"{date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
                )
                where_parts2.append(
                    f"{date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))"
                )

                where_sql2 = " WHERE " + " AND ".join(where_parts2)

                sql2 = f"""
                    SELECT COUNT(DISTINCT {_cmp_ci_trim(serial_col)})
                    FROM dbo.WSR
                    {where_sql2}
                """

                cur.execute(sql2, params2)
                this_month_cluster_visited = int(cur.fetchone()[0] or 0)

        return jsonify({
            "installbase_total": installbase_total,
            "active_total": active_total,
            "inactive_total": inactive_total,
            "dead_total": dead_total,
            "customers": customers,
            "this_month_cluster_plan": this_month_cluster_plan,
            "this_month_cluster_visited": this_month_cluster_visited
        })

    except Exception as e:
        return _json_err(f"KPI error: {e}", 500)



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
    select_cols = """
    [ID],[ZONE],[SALES ENGR],[SERVICE ENGR],[Cluster No],[CUSTOMER NAME],[LOCATION],
    [STATE],[Address],[Contact Person1],[Designation],[Contact No.],[Email Id],
    [Contact Person2],[Designation (2)],[Contact No. (2)],[Email Id (2)],
    [Segment],[Sub-Segment],[Machine Type],[Model],[Serial No.],[Ink type],[Active Status],
    [Mc Status],[Sales Invoice No],[Invoice Date],[Installed On],
    [AMC Invoice Date],[AMC From],[AMC To],[No. of Visits],[AMC Amount],
    [AMC Due Date],[AMC Days Remaining],[Filter Invoice Date],
    [Next Filter Due Date],[Filter Days Remaining],[Cluster Visit Plan],
    [Actual Visit],[Cluster],[Remarks],[Teritory No],[NEXT TER2 PLAN]
    """
    sql = f"SELECT TOP {limit} {select_cols} FROM dbo.InstallBase{where_sql} ORDER BY {order_by}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()



        fixed_columns = [
            "ID","ZONE","SALES ENGR","SERVICE ENGR","Cluster No","CUSTOMER NAME","LOCATION",
            "STATE","Address","Contact Person1","Designation","Contact No.","Email Id",
            "Contact Person2","Designation (2)","Contact No. (2)","Email Id (2)",
            "Segment","Sub-Segment","Machine Type","Model","Serial No.","Ink type",
            "Active Status","Mc Status","Sales Invoice No","Invoice Date","Installed On",
            "AMC Invoice Date","AMC From","AMC To","No. of Visits","AMC Amount",
            "AMC Due Date","AMC Days Remaining","Filter Invoice Date",
            "Next Filter Due Date","Filter Days Remaining",
            "Cluster Visit Plan","Actual Visit","Cluster","Remarks",
            "Teritory No","NEXT TER2 PLAN"
            ]
        out_rows = []
        for r in rows:
            obj = {}
            for i, col_name in enumerate(fixed_columns):
                obj[col_name] = _json_safe(r[i])
            out_rows.append(obj)
        return jsonify({"columns": fixed_columns, "rows": out_rows})
    except Exception as e:
        return _json_err(f"InstallBase API error: {e}", 500)


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

        if dtype in ("date", "datetime", "datetime2", "smalldatetime"):
            val = _parse_iso_date(val)

        elif dtype in ("time",):
            val = _parse_time_any(val)
        elif dtype in ("int", "bigint", "smallint", "tinyint"):
            val = _to_int(val)
        elif dtype in ("decimal", "numeric", "float", "real", "money", "smallmoney"):
            val = _to_decimal(val)
        if _norm(dbcol) == "filterduedatehrs":
            parsed = _parse_iso_date(val)
        if parsed:
            val = parsed.strftime("%Y-%m-%d")   # always store same format   

        out[dbcol] = val

    return out


# ✅✅✅ FINAL FIXED SAVE (UPDATE whitelist + no ID update + formula columns not updated)
@app.post("/api/installbase/save")
@app.post("/api/installbase/save/")
def api_installbase_save():
    if "user" not in session:
        return jsonify({"ok": False, "message": "Unauthorized"}), 401

    payload = request.get_json(force=True) or {}

    customer_name = (payload.get("customer_name") or "").strip()
    serial_no = (payload.get("serial_no") or "").strip()
    if not customer_name or not serial_no:
        return jsonify({"ok": False, "message": "Customer Name & Serial No required!"}), 400

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.InstallBase not found"}), 400

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

    db_vals = _installbase_payload_to_db(cols, payload)
    db_vals[cust_col] = customer_name
    db_vals[serial_col] = serial_no

    where_sql, where_params, err = _installbase_serial_where(cols, serial_no)
    if err:
        return jsonify({"ok": False, "message": err}), 400

    created_col = _find_col(cols, aliases=["CreatedAt", "Created At"], must_contain=["created"])
    updated_col = _find_col(cols, aliases=["UpdatedAt", "Updated At", "ModifiedAt", "Modified At"], must_contain=["updated"])

    # ✅ UPDATE ONLY THESE DB COLUMNS (your list)
    UPDATE_ALLOWED = set(_norm(x) for x in [
        "ZONE",
        "SALES ENGR",
        "SERVICE ENGR",
        "Cluster No",
        "CUSTOMER NAME",
        "LOCATION",
        "STATE",
        "Address",
        "Contact Person1",
        "Designation",
        "Contact No.",
        "Email Id",
        "Contact Person2",
        "Designation (2)",
        "Contact No. (2)",
        "Email Id (2)",
        "Segment",
        "Sub-Segment",
        "Machine Type",
        "Model",
        "Serial No.",
        "Ink type",
        "Active Status",
        "Mc Status",
        "Sales Invoice No",
        "Invoice Date",
        "Installed On",
        "AMC Invoice Date",
        "AMC From",
        "AMC To",
        "No. of Visits",
        "AMC Amount",
        "Filter Invoice Date",
        "Cluster Visit Plan",
        "Actual Visit",
        "Remarks",
        "Teritory No",
        "NEXT TER2 PLAN",
    ])

    # ✅ NEVER UPDATE (formula/identity columns)
    NEVER_UPDATE = set(_norm(x) for x in [
        "ID",
        "AMC Due Date",
        "AMC Days Remaining",
        "Next Filter Due Date",
        "Filter Days Remaining",
        "Cluster",
    ])

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute(f"SELECT TOP 1 1 FROM dbo.InstallBase{where_sql}", where_params)
            exists = cur.fetchone() is not None

            if exists:
                sets = []
                params = []

                for dbcol, val in db_vals.items():
                    ndb = _norm(dbcol)

                    # ❌ never update these
                    if ndb in NEVER_UPDATE:
                        continue

                    # ❌ do not update serial key / createdAt
                    if dbcol == serial_col:
                        continue
                    if created_col and dbcol == created_col:
                        continue

                    # ✅ allow only whitelist
                    if ndb not in UPDATE_ALLOWED:
                        continue

                    # ✅ skip blank/null updates
                    if val is None:
                        continue
                    if isinstance(val, str) and val.strip() == "":
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
                # INSERT: skip identity + computed columns
                SKIP_INSERT = set(_norm(x) for x in [
                    "ID",
                    "AMC Due Date",
                    "AMC Days Remaining",
                    "Next Filter Due Date",
                    "Filter Days Remaining",
                    "Cluster",
                    ])
                insert_cols = []
                insert_vals = []
                params = []
                for dbcol, val in db_vals.items():
                    ndb = _norm(dbcol)
                    if ndb in SKIP_INSERT:
                        continue
                    if val is None:
                        continue
                    if isinstance(val, str) and val.strip() == "":
                        continue
                    insert_cols.append(_qcol(dbcol))
                    insert_vals.append("?")
                    params.append(val)
                if created_col and created_col not in db_vals:
                    insert_cols.append(_qcol(created_col))
                    insert_vals.append("GETUTCDATE()")
                if not insert_cols:
                    return jsonify({"ok": False, "message": "No valid data to insert"}), 400
                sql = f"""
                INSERT INTO dbo.InstallBase
                ({', '.join(insert_cols)})
                VALUES
                ({', '.join(insert_vals)})
                """
                cur.execute(sql, params)
                conn.commit()
                return jsonify({"ok": True, "message": "InstallBase INSERTED successfully!"})

    except Exception as e:
        return jsonify({"ok": False, "message": f"InstallBase save error: {e}"}), 500


# ===================== INSTALLBASE DELETE =====================
@app.get("/api/installbase/delete")
@app.post("/api/installbase/delete")
@app.delete("/api/installbase/delete")
def api_installbase_delete():
    need = _require_login_json()
    if need:
        return need

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

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(serial_col)} = UPPER(?)")
    params.append(serial)

    where_sql = " WHERE " + " AND ".join(where_parts)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute(f"SELECT COUNT(*) FROM dbo.InstallBase{where_sql}", params)
            cnt = int(cur.fetchone()[0])
            if cnt == 0:
                return jsonify({"ok": False, "message": "Row not found (or you don't have access)."}), 404

            cur.execute(f"DELETE FROM dbo.InstallBase{where_sql}", params)
            conn.commit()

        return jsonify({"ok": True, "message": f"Deleted Serial No: {serial}"})
    except Exception as e:
        return jsonify({"ok": False, "message": f"Delete error: {e}"}), 500




WEEKLY_TABLE = "dbo.Planning"


def _weekly_cols():
    cols = _table_columns(WEEKLY_TABLE)
    if not cols:
        return []
    return cols


def _weekly_scope_where(cols):
    """
    Same scope rule:
    - Admin => all
    - Manager/Team Leader => zone only
    - User => zone + engineer
    """
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    eng  = (session.get("engineer") or "").strip()

    if role == "admin":
        return "", []

    zone_col = _find_col(cols, aliases=["zone", "Zone", "ZONE"], must_contain=["zone"])
    eng_col  = _find_col(cols, aliases=["engineer_name", "EngineerName", "Engineer Name", "ENGINEER_NAME"], must_contain=["engineer", "name"])

    where = []
    params = []

    if zone and zone_col:
        where.append(f"{_cmp_ci_trim(zone_col)} = UPPER(?)")
        params.append(zone)

    if (not _is_manager_like(role)) and eng and eng_col:
        where.append(f"{_cmp_ci_trim(eng_col)} = UPPER(?)")
        params.append(eng)

    return (" WHERE " + " AND ".join(where)) if where else "", params


def _weekly_date_col(cols):
    """
    Find Planning/Visit date column from dbo.Planning
    Your table shows: visit_date
    """
    return _find_col(
        cols,
        aliases=["visit_date", "VisitDate", "Visit Date", "Planning Date", "PlanningDate", "PLAN_DATE", "Plan Date"],
        must_contain=["visit", "date"]
    )


def _weekly_visit_type_col(cols):
    """
    Find Visit Type column from dbo.Planning
    Your table shows: visit_type
    """
    return _find_col(
    cols,
    aliases=["visit_type","visittype","Visit_Type","VISIT_TYPE","VisitType","Visit Type"],
    must_contain=["visit", "type"]
)


def _weekly_payload_to_db(cols, payload: dict):
    """
    payload keys come from form/json
    We map by normalized matching to dbo.Planning column names.
    """
    col_types = _table_column_types(WEEKLY_TABLE)
    idx = _col_index(cols)

    out = {}
    for k, raw_val in (payload or {}).items():
        nk = _norm(k)
        if nk not in idx:
            continue

        dbcol = idx[nk]
        val = _clean_val(raw_val)
        dtype = (col_types.get(dbcol) or "").lower()

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



@app.get("/api/weeklyplan/report")
@app.get("/api/weeklyplan/report/")
def api_weeklyplan_report():
    need = _require_login_json()
    if need:
        return need

    limit = int(request.args.get("limit", "2000"))
    limit = max(1, min(limit, 5000))

    q = (request.args.get("q") or "").strip()
    from_s = (request.args.get("from") or "").strip()
    to_s   = (request.args.get("to") or "").strip()
    visit_type = (request.args.get("visitType") or request.args.get("visit_type") or "").strip()

    cols = _weekly_cols()
    if not cols:
        return _json_err(f"{WEEKLY_TABLE} not found", 400)

    dcol = _weekly_date_col(cols)
    tcol = _weekly_visit_type_col(cols)

    where_parts = []
    params = []

    # scope filter
    scope_where, scope_params = _weekly_scope_where(cols)
    if scope_where:
        where_parts.append(scope_where.replace(" WHERE ", "", 1))
        params += scope_params

    # date filter
    if dcol and (from_s or to_s):
        fd = _parse_iso_date(from_s) if from_s else None
        td = _parse_iso_date(to_s) if to_s else None

        date_expr = (
            f"COALESCE("
            f"TRY_CONVERT(date, {_qcol(dcol)}, 23),"
            f"TRY_CONVERT(date, {_qcol(dcol)}, 105),"
            f"TRY_CONVERT(date, {_qcol(dcol)})"
            f")"
        )

        if fd:
            where_parts.append(f"{date_expr} >= ?")
            params.append(fd)
        if td:
            where_parts.append(f"{date_expr} <= ?")
            params.append(td)

    # visit type filter
    if visit_type and tcol:
        where_parts.append(f"{_cmp_ci_trim(tcol)} = UPPER(?)")
        params.append(visit_type)

    # text search
    if q:
        preferred = [
            "customer_name", "customerName", "Customer Name",
            "engineer_name", "engineerName", "Engineer Name",
            "zone", "Zone",
            "location", "Location",
            "printer_sr_no", "Serial No", "Serial No.",
            "printer_model", "Model",
            "visit_type", "visitType", "Visit Type",
        ]
        search_where, search_params = _build_token_search_where(q, cols, preferred)
        if search_where:
            where_parts.append(search_where)
            params += search_params

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    order_by = f" ORDER BY {_qcol(dcol)} DESC" if dcol else f" ORDER BY {_qcol(cols[0])} DESC"
    select_cols = ", ".join([_qcol(c) for c in cols])

    sql = f"SELECT TOP {limit} {select_cols} FROM {WEEKLY_TABLE}{where_sql}{order_by}"

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
        return _json_err(f"Weekly plan report error: {e}", 500)


@app.get("/api/weeklyplan/summary")
@app.get("/api/weeklyplan/summary/")
def api_weeklyplan_summary_14():
    need = _require_login_json()
    if need:
        return need

    cols = _weekly_cols()
    if not cols:
        return _json_err(f"{WEEKLY_TABLE} not found", 400)

    dcol = _weekly_date_col(cols)
    tcol = _weekly_visit_type_col(cols)
    if not dcol:
        return _json_err("Planning date column not found in dbo.Planning", 400)
    if not tcol:
        return _json_err("Visit type column not found in dbo.Planning", 400)

    scope_where, scope_params = _weekly_scope_where(cols)

    date_expr = (
        f"COALESCE("
        f"TRY_CONVERT(date, {_qcol(dcol)}, 23),"
        f"TRY_CONVERT(date, {_qcol(dcol)}, 105),"
        f"TRY_CONVERT(date, {_qcol(dcol)})"
        f")"
    )

    sql_where_parts = []
    params = []

    if scope_where:
        sql_where_parts.append(scope_where.replace(" WHERE ", "", 1))
        params += scope_params

    sql_where_parts.append(f"{date_expr} >= DATEADD(day, -7, CAST(GETDATE() AS date))")
    sql_where_parts.append(f"{date_expr} <= DATEADD(day, 17, CAST(GETDATE() AS date))")

    where_sql = " WHERE " + " AND ".join(sql_where_parts)

    bucket_expr = f"""
      CASE
        WHEN UPPER(LTRIM(RTRIM(CAST({_qcol(tcol)} AS NVARCHAR(200))))) IN ('CLUSTER') THEN 'cluster'
        WHEN UPPER(LTRIM(RTRIM(CAST({_qcol(tcol)} AS NVARCHAR(200))))) IN ('BREAKDOWN') THEN 'breakdown'
        WHEN UPPER(LTRIM(RTRIM(CAST({_qcol(tcol)} AS NVARCHAR(200))))) IN ('SALES SUPPORT','SALES SUPPORTS') THEN 'sales_support'
        ELSE 'other'
      END
    """

    sql = f"""
      SELECT {bucket_expr} AS bucket, COUNT(*) AS cnt
      FROM {WEEKLY_TABLE}
      {where_sql}
      GROUP BY {bucket_expr}
    """

    try:
        by = {"cluster": 0, "breakdown": 0, "sales_support": 0, "other": 0}

        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            for b, c in cur.fetchall():
                b = (b or "").strip().lower()
                if b in by:
                    by[b] = int(c or 0)

        total = sum(by.values())
        return jsonify({"ok": True, "total14": total, "by_type": by})

    except Exception as e:
        return _json_err(f"Weekly plan summary error: {e}", 500)

# NOTE: Your Azure screenshot shows weekly plan table name = dbo.Planning



@app.post("/api/weeklyplan")
@app.post("/api/weeklyplan/")
def api_weeklyplan_save():
    if "user" not in session:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    if request.is_json:
        payload = request.get_json() or {}
    else:
        payload = request.form.to_dict() or {}
        print("WEEKLY PAYLOAD:", payload)


    cols = _weekly_cols()
    if not cols:
        return jsonify({"ok": False, "error": f"{WEEKLY_TABLE} not found"}), 400

    # ✅ force engineer/zone from session
    payload["engineer_name"] = (session.get("engineer") or "").strip()
    payload["zone"] = (session.get("zone") or "").strip()

    # ✅ visit_date required
    visit_date = (payload.get("visit_date") or "").strip()
    if not visit_date:
        return jsonify({"ok": False, "error": "Planning Date (visit_date) required"}), 400

    visit_dt = _parse_iso_date(visit_date)
    if not visit_dt:
        return jsonify({"ok": False, "error": "Invalid Planning Date"}), 400

    # ✅ build db values after payload is ready
    db_vals = _weekly_payload_to_db(cols, payload)

    # ✅ ensure date column is filled correctly
    dcol = _weekly_date_col(cols)
    if dcol:
        db_vals[dcol] = visit_dt

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            insert_cols = []
            insert_vals = []
            params = []

            for c in cols:
                # ✅ IMPORTANT: id is IDENTITY => never insert id
                if _norm(c) == "id":
                    continue

                if c in db_vals:
                    v = db_vals.get(c)
                    if v is None:
                        continue
                    if isinstance(v, str) and v.strip() == "":
                        continue

                    insert_cols.append(_qcol(c))
                    insert_vals.append("?")
                    params.append(v)

            if not insert_cols:
                return jsonify({"ok": False, "error": "No data to insert"}), 400

            sql = f"INSERT INTO {WEEKLY_TABLE} ({', '.join(insert_cols)}) VALUES ({', '.join(insert_vals)})"
            cur.execute(sql, params)
            conn.commit()

        return jsonify({"ok": True, "message": "Weekly Plan saved!"})

    except Exception as e:
        return jsonify({"ok": False, "error": f"Weekly Plan save error: {e}"}), 500
    
    

# ===================== WEEKLY PLAN: LAST WSR AUTO FILL =====================




# ===================== WSR (dbo.WSR) =====================

WSR_TABLE = "dbo.WSR"


def _wsr_cols():
    cols = _table_columns(WSR_TABLE)
    return cols or []

def _wsr_payload_to_db(cols, payload: dict):

    col_types = _table_column_types(WSR_TABLE)

    FIELD_MAP = {
        "zone": "ZONE",
        "engineer_name": "Engineer Name",
        "monthYear": "MMM-YY",
        "serviceReportNo": "Service report Number",
        "customerName": "Customer name",
        "location": "Location",
        "contactPerson": "Contact Person Name",
        "designation": "Designation",
        "contactNumber": "Contact Number",
        "email": "E-mail id",
        "callLoggedDate": "Call Logged Date",
        "problemReported": "Problem reported",
        "machineStatus": "Machine Status",
        "visitCode1": "Visit Code 1",
        "visitCode2": "Visit Code 2",
        "printerModel": "Printer Model",
        "mcNo": "M/C No",
        "serialNo": "Serial No",
        "inkType": "Ink Type",
        "turnOnTime": "Turn on Time",
        "printOnTime": "Print on time",
        "visitDate": "Visit Date",
        "travelStart": "Travel Start (HH:MM)",
        "travelEnd": "Travel End (HH:MM)",
        "travelTime": "TRAVE TIME",
        "workStart": "Work Start (HH:MM)",
        "workEnd": "Work End (HH:MM)",
        "workTime": "WORK TIME",
        "actionTaken": "Action Taken (in brief)",

        # 🔥 CRITICAL FIX
        "ink": "INK",
        "solvent": "Solvent",
        "cnc": "CNC",
        "filterKitDue": "Filter Kit Due Date/Hrs",
        "customerFeedback": "Customer Feedback",
        "callStatus": "Call Status",
        "revisitRequired": "Re-visit Required",
        "serviceEngineerRemarks": "Service Engineer Remarks",
        "serviceManagerRemarks": "Service Manager Remarks",
    }

    out = {}

    for form_key, raw_val in payload.items():

        if form_key not in FIELD_MAP:
            continue

        dbcol = FIELD_MAP[form_key]
        val = _clean_val(raw_val)

        dtype = (col_types.get(dbcol) or "").lower()

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



def _wsr_date_col(cols):
    return _find_col(
        cols,
        aliases=["VisitDate", "Visit Date", "visitDate", "visit_date"],
        must_contain=["visit", "date"]
    )

def _wsr_visit_code1_col(cols):
    return _find_col(
        cols,
        aliases=["VisitCode1", "Visit Code 1", "visitCode1", "visit_code1"],
        must_contain=["visit", "code", "1"]
    )




# ===================== WEEKLY PLAN: LAST WSR AUTO FILL =====================
@app.get("/api/wsr/latest-by-serial")
@app.get("/api/wsr/latest-by-serial/")
def api_wsr_latest_by_serial():
    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "row": {}})

    cols = _table_columns("dbo.WSR")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.WSR not found"}), 400

    # find important columns
    serial_col = _find_col(cols, aliases=["Serial No", "Serial_No", "SERIAL NO"], must_contain=["serial"])
    visit_date_col = _find_col(cols, aliases=["Visit Date", "VisitDate"], must_contain=["visit", "date"])
    tot_col = _find_col(cols, aliases=["Turn on Time"], must_contain=["turn"])
    pot_col = _find_col(cols, aliases=["Print on time"], must_contain=["print"])
    ink_col = _find_col(cols, aliases=["INK"], must_contain=["ink"])
    solvent_col = _find_col(cols, aliases=["Solvent"], must_contain=["solvent"])
    cnc_col = _find_col(cols, aliases=["CNC"], must_contain=["cnc"])

    if not serial_col or not visit_date_col:
        return jsonify({"ok": False, "message": "Required columns not found in WSR"}), 400

    # ✅ NO ENGINEER / ZONE RESTRICTION
    where_sql = f" WHERE {_cmp_ci_trim(serial_col)} = UPPER(?)"
    params = [serial]

    sql = f"""
        SELECT TOP 1
            {_qcol(visit_date_col)} AS visit_date,
            {_qcol(tot_col)} AS last_tot,
            {_qcol(pot_col)} AS last_pot,
            {_qcol(ink_col)} AS ink,
            {_qcol(solvent_col)} AS solvent,
            {_qcol(cnc_col)} AS cnc
        FROM dbo.WSR
        {where_sql}
        ORDER BY {_qcol(visit_date_col)} DESC
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            r = cur.fetchone()

        if not r:
            return jsonify({})

        data = {
            "visit_date": _json_safe(r[0]),
            "last_tot": _json_safe(r[1]),
            "last_pot": _json_safe(r[2]),
            "ink": _json_safe(r[3]),
            "solvent": _json_safe(r[4]),
            "cnc": _json_safe(r[5]),
        }

        return jsonify(data)

    except Exception as e:
        return jsonify({"ok": False, "message": str(e)}), 500




@app.get("/api/wsr-report")
@app.get("/api/wsr-report/")
def api_wsr_report():
    need = _require_login_json()
    if need:
        return need

    limit = int(request.args.get("limit", "2000"))
    limit = max(1, min(limit, 5000))

    q = (request.args.get("q") or "").strip()
    from_s = (request.args.get("from") or "").strip()
    to_s   = (request.args.get("to") or "").strip()
    visit_type = (request.args.get("visitType") or request.args.get("visit_type") or "").strip()

    cols = _wsr_cols()
    if not cols:
        return _json_err(f"{WSR_TABLE} not found", 400)

    dcol = _wsr_date_col(cols)
    vcol = _wsr_visit_code1_col(cols)

    where_parts = []
    params = []

    # scope (zone/engineer)
    scope_where, scope_params = _wsr_scope_where(cols)
    if scope_where:
        where_parts.append(scope_where.replace(" WHERE ", "", 1))
        params += scope_params

    # date filter
    if dcol and (from_s or to_s):
        fd = _parse_iso_date(from_s) if from_s else None
        td = _parse_iso_date(to_s) if to_s else None

        date_expr = (
            f"COALESCE("
            f"TRY_CONVERT(date, {_qcol(dcol)}, 23),"
            f"TRY_CONVERT(date, {_qcol(dcol)}, 105),"
            f"TRY_CONVERT(date, {_qcol(dcol)})"
            f")"
        )

        if fd:
            where_parts.append(f"{date_expr} >= ?")
            params.append(fd)
        if td:
            where_parts.append(f"{date_expr} <= ?")
            params.append(td)

    # visit type filter (VisitCode1)
    if visit_type and vcol:
        where_parts.append(f"{_cmp_ci_trim(vcol)} = UPPER(?)")
        params.append(visit_type)

    # search (tokens)
    if q:
        preferred = [
            "CustomerName","Customer Name","customerName",
            "EngineerName","Engineer Name","engineerName",
            "Zone","zone",
            "monthYear","MonthYear","MMM-YY",
            "VisitCode1","visitCode1",
            "Location","location",
            "SerialNo","serialNo","Serial No",
            "printerModel","Model",
        ]
        search_where, search_params = _build_token_search_where(q, cols, preferred)
        if search_where:
            where_parts.append(search_where)
            params += search_params

    where_sql = (" WHERE " + " AND ".join(where_parts)) if where_parts else ""

    order_by = f" ORDER BY {_qcol(dcol)} DESC" if dcol else f" ORDER BY {_qcol(cols[0])} DESC"
    select_cols = ", ".join([_qcol(c) for c in cols])

    sql = f"SELECT TOP {limit} {select_cols} FROM {WSR_TABLE}{where_sql}{order_by}"

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
        return _json_err(f"WSR report error: {e}", 500)



@app.get("/api/wsr/summary_month")
@app.get("/api/wsr/summary_month/")
def api_wsr_summary_month():
    need = _require_login_json()
    if need:
        return need

    cols = _wsr_cols()
    if not cols:
        return jsonify({"ok": False, "error": f"{WSR_TABLE} not found"}), 400

    dcol = _wsr_date_col(cols)
    vcol = _wsr_visit_code1_col(cols)

    serial_col = _find_col(
        cols,
        aliases=["Serial No", "Serial_No", "SERIAL NO"],
        must_contain=["serial"]
    )

    if not dcol or not vcol or not serial_col:
        return jsonify({"ok": False, "error": "WSR VisitDate / VisitCode1 / Serial column not found"}), 400

    scope_where, scope_params = _wsr_scope_where(cols)

    date_expr = (
        f"COALESCE("
        f"TRY_CONVERT(date, {_qcol(dcol)}, 23),"
        f"TRY_CONVERT(date, {_qcol(dcol)}, 105),"
        f"TRY_CONVERT(date, {_qcol(dcol)})"
        f")"
    )

    where_parts = []
    params = []

    if scope_where:
        where_parts.append(scope_where.replace(" WHERE ", "", 1))
        params += scope_params

    # ✅ Current month filter
    where_parts.append(
        f"{date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
    )
    where_parts.append(
        f"{date_expr} < DATEADD(month, 1, DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1))"
    )

    where_sql = " WHERE " + " AND ".join(where_parts)

    # ✅ COUNT DISTINCT SERIAL (VERY IMPORTANT FIX)
    sql = f"""
      SELECT 
        UPPER(LTRIM(RTRIM(CAST({_qcol(vcol)} AS NVARCHAR(200))))) AS vt,
        COUNT(DISTINCT {_cmp_ci_trim(serial_col)}) AS cnt
      FROM {WSR_TABLE}
      {where_sql}
      GROUP BY UPPER(LTRIM(RTRIM(CAST({_qcol(vcol)} AS NVARCHAR(200)))))
    """

    counts = {"Cluster": 0, "Breakdown": 0, "Sales Support": 0, "Other": 0}

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)

            for vt, cnt in cur.fetchall():
                vt = (vt or "").strip().upper()
                n = int(cnt or 0)

                if vt == "CLUSTER":
                    counts["Cluster"] += n
                elif vt == "BREAKDOWN":
                    counts["Breakdown"] += n
                elif vt in ("SALES SUPPORT", "SALES SUPPORTS"):
                    counts["Sales Support"] += n
                else:
                    counts["Other"] += n

        total = sum(counts.values())

        return jsonify({
            "ok": True,
            "total": total,
            "counts": counts
        })

    except Exception as e:
        return jsonify({"ok": False, "error": f"WSR summary error: {e}"}), 500
# ===================== WSR SAVE =====================
@app.post("/api/wsr")
@app.post("/api/wsr/")
def api_wsr_save():

    if "user" not in session:
        return jsonify({"ok": False, "error": "unauthorized"}), 401

    # accept JSON & FormData
    if request.is_json:
        payload = request.get_json() or {}
    else:
        payload = request.form.to_dict() or {}

    print("WSR PAYLOAD:", payload)

    cols = _wsr_cols()
    if not cols:
        return jsonify({"ok": False, "error": "WSR table not found"}), 400

    payload["engineer_name"] = (session.get("engineer") or "").strip()
    payload["zone"] = (session.get("zone") or "").strip()

    db_vals = _wsr_payload_to_db(cols, payload)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            insert_cols = []
            insert_vals = []
            params = []

            for c in cols:
                if _norm(c) == "id":
                    continue

                if c in db_vals:
                    v = db_vals.get(c)
                    if v is None:
                        continue
                    if isinstance(v, str) and v.strip() == "":
                        continue

                    insert_cols.append(_qcol(c))
                    insert_vals.append("?")
                    params.append(v)

            if not insert_cols:
                return jsonify({"ok": False, "error": "No data to insert"}), 400

            sql = f"""
                INSERT INTO {WSR_TABLE}
                ({', '.join(insert_cols)})
                VALUES ({', '.join(insert_vals)})
            """

            cur.execute(sql, params)

            # ================= UPDATE INSTALLBASE IF CLUSTER =================
            visit_code = (payload.get("visitCode1") or "").strip().upper()
            serial_no = (payload.get("serialNo") or "").strip()
            visit_date_raw = payload.get("visitDate")
            visit_date = _parse_iso_date(visit_date_raw)

            if visit_code == "CLUSTER" and serial_no and visit_date:

                install_cols = _table_columns("dbo.InstallBase")

                serial_col = _find_col(
                    install_cols,
                    aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo"],
                    must_contain=["serial"]
                )

                actual_visit_col = _find_col(
                    install_cols,
                    aliases=["Actual Visit", "ActualVisit"],
                    must_contain=["actual", "visit"]
                )

                if serial_col and actual_visit_col:

                    update_sql = f"""
                        UPDATE dbo.InstallBase
                        SET {_qcol(actual_visit_col)} = ?
                        WHERE {_cmp_ci_trim(serial_col)} = UPPER(?)
                    """

                    cur.execute(update_sql, (visit_date, serial_no))

            # ✅ ONE SINGLE COMMIT (best practice)
            conn.commit()

        return jsonify({"ok": True, "message": "WSR Saved Successfully"})

    except Exception as e:
        print("WSR SAVE ERROR:", str(e))
        return jsonify({"ok": False, "error": str(e)}), 500


@app.get("/wsr-report")
def wsr_report_page():
    if "user" not in session:
        return redirect(url_for("home"))

    return render_template(
        "WSRReport.html",
        engineer=session.get("engineer", ""),
        zone=session.get("zone", ""),
        role=session.get("role", ""),
        team=session.get("team", ""),
        visitType=(request.args.get("visitType") or "").strip(),
        fromDate=(request.args.get("from") or "").strip(),
        toDate=(request.args.get("to") or "").strip(),
        q=(request.args.get("q") or "").strip(),
    )

    # ===================== USERS API (dbo.UserLogin) =====================

def _require_admin_json():
    need = _require_login_json()
    if need:
        return need
    role = (session.get("role") or "").strip().lower()
    if role != "admin":
        return jsonify({"error": "forbidden"}), 403
    return None


@app.get("/api/users")
def api_users_list():
    need = _require_admin_json()
    if need:
        return need

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("""
                SELECT UserId, Username, FullName, Zone, RoleName, Team, IsActive, CreatedAt
                FROM dbo.UserLogin
                ORDER BY UserId DESC
            """)
            rows = cur.fetchall()

        out = []
        for r in rows:
            out.append({
                "UserId": int(r[0]) if r[0] is not None else 0,
                "Username": (r[1] or "").strip(),
                "FullName": (r[2] or "").strip(),
                "Zone": (r[3] or "").strip(),
                "RoleName": (r[4] or "").strip(),
                "Team": (r[5] or "").strip(),
                "IsActive": bool(r[6]),
                "CreatedAt": _json_safe(r[7]),
            })
        return jsonify(out)

    except Exception as e:
        return jsonify({"error": f"Users list error: {e}"}), 500


@app.post("/api/users")
def api_users_create():
    need = _require_admin_json()
    if need:
        return need

    payload = request.get_json(force=True) or {}

    username = (payload.get("Username") or "").strip()
    fullname = (payload.get("FullName") or "").strip()
    zone     = (payload.get("Zone") or "").strip()
    role     = (payload.get("RoleName") or "").strip()
    team     = (payload.get("Team") or "").strip()
    password = (payload.get("Password") or "").strip()

    if not username or not fullname or not zone or not role or not team or not password:
        return jsonify({"message": "All fields required"}), 400

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # unique username check
            cur.execute("SELECT TOP 1 1 FROM dbo.UserLogin WHERE Username = ?", (username,))
            if cur.fetchone():
                return jsonify({"message": "Username already exists"}), 409

            # insert
            cur.execute("""
                INSERT INTO dbo.UserLogin
                    (Username, FullName, Zone, RoleName, Team, Password, IsActive, CreatedAt)
                VALUES
                    (?, ?, ?, ?, ?, ?, 1, GETUTCDATE())
            """, (username, fullname, zone, role, team, password))

            conn.commit()

        return jsonify({"message": "User created successfully"}), 200

    except Exception as e:
        return jsonify({"message": f"Create user error: {e}"}), 500


@app.patch("/api/users/<int:user_id>/active")
def api_users_toggle_active(user_id: int):
    need = _require_admin_json()
    if need:
        return need

    payload = request.get_json(force=True) or {}
    is_active = payload.get("IsActive", None)
    if is_active is None:
        return jsonify({"message": "IsActive required"}), 400

    # allow true/false/1/0
    new_state = 1 if bool(is_active) else 0

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute("UPDATE dbo.UserLogin SET IsActive = ? WHERE UserId = ?", (new_state, user_id))
            if cur.rowcount == 0:
                return jsonify({"message": "User not found"}), 404
            conn.commit()

        return jsonify({"message": "User status updated"}), 200

    except Exception as e:
        return jsonify({"message": f"Toggle active error: {e}"}), 500

@app.route('/google0832a92ac05f82f8.html')
def google_verification():
    return send_from_directory('.', 'google0832a92ac05f82f8.html')
@app.get("/api/installbase/mc-summary")
def api_installbase_mc_summary():
    need = _require_login_json()
    if need:
        return need

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return jsonify({"error": "InstallBase not found"}), 400

    base_where, base_params = _installbase_scope_where(install_cols)

    active_col = _find_col(install_cols,aliases=["Active Status", "ActiveStatus"],must_contain=["active", "status"])
    mc_col = _find_col(install_cols,aliases=["Mc Status", "McStatus"],must_contain=["status"])
    
    if not active_col or not mc_col:
        return jsonify({"error": "Required columns not found"}), 400
    
    active_expr = f"UPPER({_qcol(active_col)})"
    mc_expr = f"UPPER({_qcol(mc_col)})"
    active_expr = _cmp_ci_trim(active_col)
    mc_expr = _cmp_ci_trim(mc_col)
    where_parts = []
    params = []

    # Always filter active
    where_parts.append(f"{active_expr} = 'ACTIVE'")

    # Add role-based scope
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_sql = " WHERE " + " AND ".join(where_parts)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            sql = f"""
                SELECT 
                    SUM(CASE WHEN {mc_expr} = 'AMC' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN {mc_expr} = 'NON AMC' THEN 1 ELSE 0 END),
                    SUM(CASE WHEN {mc_expr} = 'WARRANTY' THEN 1 ELSE 0 END)
                FROM dbo.InstallBase
                {where_sql}
            """

            cur.execute(sql, params)
            row = cur.fetchone()

        return jsonify({
            "amc": int(row[0] or 0),
            "non_amc": int(row[1] or 0),
            "warranty": int(row[2] or 0)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500



@app.get("/api/installbase/month-cluster-summary")
def month_cluster_summary():

    need = _require_login_json()
    if need:
        return need

    install_cols = _table_columns("dbo.InstallBase")
    wsr_cols = _wsr_cols()

    if not install_cols or not wsr_cols:
        return jsonify({"error": "Tables not found"}), 400

    # 🔍 Detect Columns Dynamically
    serial_ib = _find_col(
        install_cols,
        aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO"],
        must_contain=["serial"]
    )

    plan_col = _find_col(
        install_cols,
        aliases=["Cluster Visit Plan", "ClusterVisitPlan"],
        must_contain=["cluster", "visit", "plan"]
    )

    serial_wsr = _find_col(
        wsr_cols,
        aliases=["Serial No", "Serial_No", "SERIAL NO"],
        must_contain=["serial"]
    )

    visit_date_col = _wsr_date_col(wsr_cols)
    visit_code_col = _wsr_visit_code1_col(wsr_cols)

    if not all([serial_ib, plan_col, serial_wsr, visit_date_col, visit_code_col]):
        return jsonify({"error": "Required columns missing"}), 400

    # 🔄 Date Expressions (robust parsing)
    plan_date_expr = f"""
        COALESCE(
            TRY_CONVERT(date, {_qcol(plan_col)}, 23),
            TRY_CONVERT(date, {_qcol(plan_col)}, 105),
            TRY_CONVERT(date, {_qcol(plan_col)})
        )
    """

    visit_date_expr = f"""
        COALESCE(
            TRY_CONVERT(date, {_qcol(visit_date_col)}, 23),
            TRY_CONVERT(date, {_qcol(visit_date_col)}, 105),
            TRY_CONVERT(date, {_qcol(visit_date_col)})
        )
    """

    # 🔐 Role Based Scope
    base_where_ib, base_params_ib = _installbase_scope_where(install_cols)
    base_where_wsr, base_params_wsr = _wsr_scope_where(wsr_cols)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # ================= PLAN COUNT =================
            plan_where_parts = []
            plan_params = []

            if base_where_ib:
                plan_where_parts.append(base_where_ib.replace(" WHERE ", "", 1))
                plan_params += base_params_ib

            plan_where_parts.append(
                f"{plan_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
            )
            plan_where_parts.append(
                f"{plan_date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))"
            )

            plan_where_sql = " WHERE " + " AND ".join(plan_where_parts)

            plan_sql = f"""
                SELECT COUNT(DISTINCT {_cmp_ci_trim(serial_ib)})
                FROM dbo.InstallBase
                {plan_where_sql}
            """

            cur.execute(plan_sql, plan_params)
            total = int(cur.fetchone()[0] or 0)

            # ================= VISITED COUNT =================
            visit_where_parts = []
            visit_params = []

            if base_where_wsr:
                visit_where_parts.append(base_where_wsr.replace(" WHERE ", "", 1))
                visit_params += base_params_wsr

            visit_where_parts.append(
                f"{_cmp_ci_trim(visit_code_col)} = 'CLUSTER'"
            )
            visit_where_parts.append(
                f"{visit_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)"
            )
            visit_where_parts.append(
                f"{visit_date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))"
            )

            visit_where_sql = " WHERE " + " AND ".join(visit_where_parts)

            visit_sql = f"""
                SELECT COUNT(DISTINCT {_cmp_ci_trim(serial_wsr)})
                FROM dbo.WSR
                {visit_where_sql}
            """

            cur.execute(visit_sql, visit_params)
            completed = int(cur.fetchone()[0] or 0)

        return jsonify({
            "total": total,
            "completed": completed
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.get("/api/installbase/month-cluster-details")
def month_cluster_details():

    need = _require_login_json()
    if need:
        return need

    engineer_filter = (request.args.get("engineer") or "").strip()
    customer_filter = (request.args.get("customer") or "").strip()
    status_filter   = (request.args.get("status") or "").strip().upper()

    install_cols = _table_columns("dbo.InstallBase")
    wsr_cols = _wsr_cols()

    serial_ib = _find_col(install_cols, must_contain=["serial"])
    engineer_col = _find_col(install_cols, must_contain=["service", "engr"])
    customer_col = _find_col(install_cols, must_contain=["customer", "name"])
    plan_col = _find_col(install_cols, must_contain=["cluster", "visit", "plan"])
    active_col = _find_col(install_cols, must_contain=["active", "status"])

    serial_wsr = _find_col(wsr_cols, must_contain=["serial"])
    visit_date_col = _wsr_date_col(wsr_cols)
    visit_code_col = _wsr_visit_code1_col(wsr_cols)

    if not all([serial_ib, engineer_col, customer_col, plan_col,
                serial_wsr, visit_date_col, visit_code_col]):
        return jsonify({"error": "Required columns missing"}), 400

    # -------- Date Expressions --------
    plan_date_expr = f"""
        COALESCE(
            TRY_CONVERT(date, {_qcol(plan_col)}, 23),
            TRY_CONVERT(date, {_qcol(plan_col)}, 105),
            TRY_CONVERT(date, {_qcol(plan_col)})
        )
    """

    visit_date_expr = f"""
        COALESCE(
            TRY_CONVERT(date, w.{_qcol(visit_date_col)}, 23),
            TRY_CONVERT(date, w.{_qcol(visit_date_col)}, 105),
            TRY_CONVERT(date, w.{_qcol(visit_date_col)})
        )
    """

    base_where, base_params = _installbase_scope_where(install_cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(active_col)} = 'ACTIVE'")
    where_parts.append(f"{plan_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)")
    where_parts.append(f"{plan_date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))")

    if engineer_filter and engineer_filter != "All":
        where_parts.append(f"{_cmp_ci_trim(engineer_col)} = UPPER(?)")
        params.append(engineer_filter)

    if customer_filter and customer_filter != "All":
        where_parts.append(f"CAST({_qcol(customer_col)} AS NVARCHAR(300)) LIKE ?")
        params.append(f"%{customer_filter}%")

    where_sql = " WHERE " + " AND ".join(where_parts)

    sql = f"""
        SELECT 
            i.{_qcol(engineer_col)} AS engineer,
            i.{_qcol(customer_col)} AS customer,
            i.{_qcol(serial_ib)} AS serial_no,
            CONVERT(varchar(10), {plan_date_expr}, 23) AS cluster_visit_plan,
            CASE               
                WHEN EXISTS (
                    SELECT 1 
                    FROM dbo.WSR w
                    WHERE UPPER(LTRIM(RTRIM(w.{_qcol(serial_wsr)}))) =
                        UPPER(LTRIM(RTRIM(i.{_qcol(serial_ib)})))
                    AND UPPER(LTRIM(RTRIM(w.{_qcol(visit_code_col)}))) = 'CLUSTER'
                    AND {visit_date_expr} >= DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()), 1)
                    AND {visit_date_expr} < DATEADD(month,1,DATEFROMPARTS(YEAR(GETDATE()), MONTH(GETDATE()),1))
                )
                THEN 'COMPLETED'
                ELSE 'PENDING'            
            END AS status
        FROM dbo.InstallBase i
        {where_sql}
        ORDER BY cluster_visit_plan ASC
    """

    if status_filter in ["COMPLETED", "PENDING"]:
        sql = f"SELECT * FROM ({sql}) x WHERE UPPER(status) = ?"
        params.append(status_filter)

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            rows = cur.fetchall()
            columns = [d[0] for d in cur.description]

        out = []
        for r in rows:
            obj = {}
            for i, c in enumerate(columns):
                obj[c] = _json_safe(r[i])
            out.append(obj)

        return jsonify({"columns": columns, "rows": out})

    except Exception as e:
        return jsonify({"error": str(e)}), 500
       

@app.get("/api/engineers")
def get_engineers():

    need = _require_login_json()
    if need:
        return need

    install_cols = _table_columns("dbo.InstallBase")
    if not install_cols:
        return jsonify([])

    engineer_col = _find_col(
        install_cols,
        aliases=["SERVICE_ENGR", "SERVICE ENGR", "SERVICE ENGINEER"],
        must_contain=["service", "engr"]
    )

    if not engineer_col:
        return jsonify([])

    base_where, base_params = _installbase_scope_where(install_cols)

    where_sql = base_where if base_where else ""

    sql = f"""
        SELECT DISTINCT {_qcol(engineer_col)} AS engineer
        FROM dbo.InstallBase
        {where_sql}
        ORDER BY {_qcol(engineer_col)}
    """

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, base_params)
            rows = cur.fetchall()

        engineers = [(r[0] or "").strip() for r in rows if r[0]]
        return jsonify(engineers)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    


# ===================== SMS EXCEL UPLOAD =====================

@app.route("/api/sms/upload", methods=["POST"])
def api_sms_upload():

    need = _require_login_json()
    if need:
        return need

    role = (session.get("role") or "").strip().lower()
    if "admin" not in role:
        return jsonify({"error": "Only Admin allowed"}), 403

    if "excel_file" not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files["excel_file"]

    try:
        import pandas as pd
        from datetime import timedelta

        df = pd.read_excel(file)

        if df.empty:
            return jsonify({"error": "Excel is empty"}), 400

        # Normalize column names
        df.columns = df.columns.str.strip().str.upper()

        rename_map = {
            "S.NO": "SNO",
            "DATE": "DATE",
            "CUSTOMER NAME": "CUSTOMER_NAME",
            "M/C S,NO": "MC_SERIAL_NO",
            "INK": "INK",
            "DAYS": "DAYS",
            "ENGINEER": "ENGINEER",
            "REG": "REG"
        }

        df.rename(columns=rename_map, inplace=True)

        insert_sql = """
        INSERT INTO dbo.sms
        ([SNO],[DATE],[CUSTOMER_NAME],[MC_SERIAL_NO],
         [INK],[DAYS],[ENGINEER],[REG],[END_DAY])
        VALUES (?,?,?,?,?,?,?,?,?)
        """

        data = []

        for _, row in df.iterrows():

            if row.isnull().all():
                continue

            # ✅ ROBUST DATE PARSER (FIXED)
            excel_date = row.get("DATE")
            start_date = None

            if pd.notna(excel_date):
                start_date = pd.to_datetime(excel_date, errors="coerce")
                if pd.notna(start_date):
                    start_date = start_date.date()

            # Days
            days_val = None
            if pd.notna(row.get("DAYS")):
                try:
                    days_val = int(row.get("DAYS"))
                except:
                    days_val = None

            # Calculate END_DAY properly
            end_day = None
            if start_date and days_val is not None:
                end_day = start_date + timedelta(days=days_val)

            data.append([
                int(row.get("SNO")) if pd.notna(row.get("SNO")) else None,
                start_date,
                row.get("CUSTOMER_NAME"),
                row.get("MC_SERIAL_NO"),
                row.get("INK"),
                days_val,
                row.get("ENGINEER"),
                row.get("REG"),
                end_day
            ])

        if not data:
            return jsonify({"error": "No valid rows found"}), 400

        with get_conn() as conn:
            cur = conn.cursor()

            # Delete old data
            cur.execute("DELETE FROM dbo.sms")

            cur.fast_executemany = True
            cur.executemany(insert_sql, data)
            conn.commit()

        return jsonify({"message": f"{len(data)} rows uploaded successfully ✅"})

    except Exception as e:
        print("UPLOAD ERROR:", str(e))
        return jsonify({"error": str(e)}), 500    


# ================= EXPIRY FILTER API =================

@app.get("/api/expiry/engineers")
def get_all_engineers():

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute("""
                SELECT DISTINCT [SERVICE ENGR] FROM dbo.installbase
                WHERE [SERVICE ENGR] IS NOT NULL
                UNION
                SELECT DISTINCT ENGINEER FROM dbo.sms
                WHERE ENGINEER IS NOT NULL
                ORDER BY 1
            """)

            rows = cur.fetchall()

        engineers = [(r[0] or "").strip() for r in rows if r[0]]
        return jsonify(engineers)

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# =========================
# SMS EXPIRY BY SERIAL
# =========================
@app.get("/api/sms/by-serial")
def api_sms_by_serial():

    need = _require_login_json()
    if need:
        return need

    serial = (request.args.get("serial") or "").strip()

    if not serial:
        return jsonify({"ok": True, "expiry_date": ""})

    try:
        sql = """
            SELECT TOP 1 END_DAY
            FROM dbo.sms
            WHERE UPPER(LTRIM(RTRIM(MC_SERIAL_NO))) = UPPER(?)
            ORDER BY END_DAY DESC
        """

        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, (serial,))
            row = cur.fetchone()

        if row and row[0]:
            return jsonify({
                "ok": True,
                "expiry_date": row[0].strftime("%Y-%m-%d")
            })

        return jsonify({"ok": True, "expiry_date": ""})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})
# ================= EXPIRY FILTER MAIN API =================

@app.get("/api/expiry/filter")
def api_expiry_filter():

    need = _require_login_json()
    if need:
        return need

    filter_type = (request.args.get("type") or "").strip()
    engineer = (request.args.get("engineer") or "").strip()

    # 🔐 Session Info
    role = (session.get("role") or "").strip().lower()
    zone = (session.get("zone") or "").strip()
    logged_engineer = (session.get("engineer") or "").strip()

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            # ================= SMS (15 DAYS) =================
            if filter_type == "sms_15":

                query = """
                SELECT 
                    ENGINEER,
                    CUSTOMER_NAME,
                    MC_SERIAL_NO,
                    END_DAY AS EXPIRY_DATE,
                    DATEDIFF(DAY, CAST(GETDATE() AS DATE), END_DAY) AS REM_DAYS
                FROM dbo.sms
                WHERE END_DAY IS NOT NULL
                  AND DATEDIFF(DAY, CAST(GETDATE() AS DATE), END_DAY)
                      BETWEEN 0 AND 15
                """

                params = []

                # ✅ SMS → Full Zone Access (non-admin)
                if role != "admin":
                    query += " AND UPPER(REG) = UPPER(?)"
                    params.append(zone)

                if engineer:
                    query += " AND UPPER(ENGINEER) = UPPER(?)"
                    params.append(engineer)

                query += " ORDER BY END_DAY ASC"

                cur.execute(query, params)


            # ================= AMC (60 DAYS) =================
            elif filter_type == "amc_60":

                query = """
                SELECT 
                    [SERVICE ENGR] AS ENGINEER,
                    [CUSTOMER NAME] AS CUSTOMER_NAME,
                    [Serial No.] AS MC_SERIAL_NO,
                    [AMC Due Date] AS EXPIRY_DATE,
                    DATEDIFF(DAY, CAST(GETDATE() AS DATE), [AMC Due Date]) AS REM_DAYS
                FROM dbo.InstallBase
                WHERE [AMC Due Date] IS NOT NULL
                  AND DATEDIFF(DAY, CAST(GETDATE() AS DATE), [AMC Due Date])
                      BETWEEN 0 AND 60
                """

                params = []

                # 🔒 ROLE BASED CONTROL
                if role != "admin":

                    # Zone restriction
                    query += " AND UPPER([ZONE]) = UPPER(?)"
                    params.append(zone)

                    # Engineer restriction (only for normal users)
                    if role not in ["manager", "team leader"]:
                        query += " AND UPPER([SERVICE ENGR]) = UPPER(?)"
                        params.append(logged_engineer)

                if engineer:
                    query += " AND UPPER([SERVICE ENGR]) = UPPER(?)"
                    params.append(engineer)

                query += " ORDER BY [AMC Due Date] ASC"

                cur.execute(query, params)


            # ================= FILTER (60 DAYS) =================
            elif filter_type == "filter_60":

                query = """
                SELECT 
                    [SERVICE ENGR] AS ENGINEER,
                    [CUSTOMER NAME] AS CUSTOMER_NAME,
                    [Serial No.] AS MC_SERIAL_NO,
                    [Next Filter Due Date] AS EXPIRY_DATE,
                    DATEDIFF(DAY, CAST(GETDATE() AS DATE), [Next Filter Due Date]) AS REM_DAYS
                FROM dbo.InstallBase
                WHERE [Next Filter Due Date] IS NOT NULL
                  AND DATEDIFF(DAY, CAST(GETDATE() AS DATE), [Next Filter Due Date])
                      BETWEEN 0 AND 60
                """

                params = []

                # 🔒 ROLE BASED CONTROL
                if role != "admin":

                    query += " AND UPPER([ZONE]) = UPPER(?)"
                    params.append(zone)

                    if role not in ["manager", "team leader"]:
                        query += " AND UPPER([SERVICE ENGR]) = UPPER(?)"
                        params.append(logged_engineer)

                if engineer:
                    query += " AND UPPER([SERVICE ENGR]) = UPPER(?)"
                    params.append(engineer)

                query += " ORDER BY [Next Filter Due Date] ASC"

                cur.execute(query, params)

            else:
                return jsonify([])

            columns = [column[0] for column in cur.description]
            rows = [dict(zip(columns, row)) for row in cur.fetchall()]

        return jsonify(rows)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ================= INSTALLBASE EXCEL UPLOAD =================

@app.route("/api/installbase/excel-upload", methods=["POST"])
def api_installbase_excel_upload():

    need = _require_login_json()
    if need:
        return need

    role = (session.get("role") or "").strip().lower()

    
    if "excel_file" not in request.files:
        return jsonify({"error": "No file selected"}), 400

    file = request.files["excel_file"]

    try:
        import pandas as pd

        df = pd.read_excel(file)

        if df.empty:
            return jsonify({"error": "Excel is empty"}), 400

        df.columns = df.columns.str.strip()

        install_cols = _table_columns("dbo.InstallBase")
        col_types = _table_column_types("dbo.InstallBase")

        # 🔎 Serial column detect
        serial_col = _find_col(
            install_cols,
            aliases=["Serial No.", "Serial No", "Serial_No", "SERIAL NO", "SerialNo"],
            must_contain=["serial"]
        )

        if not serial_col:
            return jsonify({"error": "Serial column not found in InstallBase"}), 400

        inserted = 0
        skipped_duplicates = 0

        with get_conn() as conn:
            cur = conn.cursor()

            for _, row in df.iterrows():

                if row.isnull().all():
                    continue

                serial_value = str(row.get(serial_col, "")).strip()

                if not serial_value:
                    continue

                # 🔎 Duplicate Check
                cur.execute(
                    f"SELECT TOP 1 1 FROM dbo.InstallBase WHERE {_cmp_ci_trim(serial_col)} = UPPER(?)",
                    (serial_value,)
                )

                if cur.fetchone():
                    skipped_duplicates += 1
                    continue

                # 🔄 Build Insert Data
                insert_cols = []
                insert_vals = []
                params = []

                for col in install_cols:

                    # ❌ Skip identity & computed columns
                    if _norm(col) in [
                        "id",
                        "amcduedate",
                        "amcdaysremaining",
                        "nextfilterduedate",
                        "filterdaysremaining",
                        "cluster"
                    ]:
                        continue

                    if col not in df.columns:
                        continue

                    value = row.get(col)

                    if pd.isna(value):
                        continue

                    dtype = (col_types.get(col) or "").lower()

                    if dtype in ("date", "datetime", "datetime2", "smalldatetime"):
                        try:
                            value = pd.to_datetime(value).date()
                        except:
                            value = None

                    insert_cols.append(f"[{col}]")
                    insert_vals.append("?")
                    params.append(value)

                if not insert_cols:
                    continue

                sql = f"""
                    INSERT INTO dbo.InstallBase
                    ({', '.join(insert_cols)})
                    VALUES ({', '.join(insert_vals)})
                """

                cur.execute(sql, params)
                inserted += 1

            conn.commit()

        return jsonify({
            "message": "InstallBase Excel Uploaded Successfully ✅",
            "inserted": inserted,
            "skipped_duplicates": skipped_duplicates
        })

    except Exception as e:
        print("INSTALLBASE UPLOAD ERROR:", str(e))
        return jsonify({"error": str(e)}), 500

# ===================== RUN =====================
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
