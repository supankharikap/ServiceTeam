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


# ===================== INSTALLBASE ROWS (FULL) =====================
@app.get("/api/installbase/rows")
def api_installbase_rows():
    need = _require_login_json()
    if need:
        return jsonify({"ok": False, "rows": [], "message": "unauthorized"}), 401

    customer = (request.args.get("customer") or "").strip()
    if not customer:
        return jsonify({"ok": True, "rows": []})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "rows": [], "message": "dbo.InstallBase not found"}), 400

    cust_col = _find_col(
        cols,
        aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"],
        must_contain=["customer","name"]
    )
    if not cust_col:
        return jsonify({"ok": False, "rows": [], "message": "Customer column not found"}), 400

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(cust_col)} = UPPER(?)")
    params.append(customer)

    where_sql = " WHERE " + " AND ".join(where_parts)

    select_cols = ", ".join([_qcol(c) for c in cols])

    serial_col = _find_col(
        cols,
        aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo","Serial"],
        must_contain=["serial"]
    )
    order_by = f" ORDER BY {_qcol(serial_col)}" if serial_col else ""

    sql = f"SELECT TOP (500) {select_cols} FROM dbo.InstallBase{where_sql}{order_by}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            fetched = cur.fetchall()

        out_rows = []
        for r in fetched:
            obj = {}
            for i, c in enumerate(cols):
                obj[c] = _json_safe(r[i])
            out_rows.append(obj)

        return jsonify({"ok": True, "rows": out_rows})
    except Exception as e:
        return jsonify({"ok": False, "rows": [], "message": str(e)}), 500


# ===================== INSTALLBASE BY SERIAL (FULL) =====================
@app.get("/api/installbase/by-serial")
def api_installbase_by_serial():
    need = _require_login_json()
    if need:
        return jsonify({"ok": False, "row": None, "message": "unauthorized"}), 401

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "row": None})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "row": None, "message": "dbo.InstallBase not found"}), 400

    serial_col = _find_col(
        cols,
        aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo","Serial"],
        must_contain=["serial"]
    )
    if not serial_col:
        return jsonify({"ok": False, "row": None, "message": "Serial column not found"}), 400

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []

    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(serial_col)} = UPPER(?)")
    params.append(serial)

    where_sql = " WHERE " + " AND ".join(where_parts)

    select_cols = ", ".join([_qcol(c) for c in cols])

    id_col = _find_col(cols, aliases=["Id","ID"], must_contain=["id"])
    order_by = f" ORDER BY {_qcol(id_col)} DESC" if id_col else ""

    sql = f"SELECT TOP 1 {select_cols} FROM dbo.InstallBase{where_sql}{order_by}"

    try:
        with get_conn() as conn:
            cur = conn.cursor()
            cur.execute(sql, params)
            r = cur.fetchone()
            if not r:
                return jsonify({"ok": True, "row": None})

            row_obj = {}
            for i, c in enumerate(cols):
                row_obj[c] = _json_safe(r[i])

        return jsonify({"ok": True, "row": row_obj})
    except Exception as e:
        return jsonify({"ok": False, "row": None, "message": str(e)}), 500


# ===================== INSTALLBASE EXISTS (ASK BEFORE UPDATE) ✅ ADDED =====================
@app.get("/api/installbase/exists")
def api_installbase_exists():
    need = _require_login_json()
    if need:
        return jsonify({"ok": False, "exists": False, "message": "unauthorized"}), 401

    serial = (request.args.get("serial") or "").strip()
    if not serial:
        return jsonify({"ok": True, "exists": False})

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "exists": False, "message": "dbo.InstallBase not found"}), 400

    serial_col = _find_col(
        cols,
        aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo","Serial"],
        must_contain=["serial"]
    )
    if not serial_col:
        return jsonify({"ok": False, "exists": False, "message": "Serial column not found"}), 400

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
            cur.execute(f"SELECT TOP 1 1 FROM dbo.InstallBase{where_sql}", params)
            exists = cur.fetchone() is not None
        return jsonify({"ok": True, "exists": exists})
    except Exception as e:
        return jsonify({"ok": False, "exists": False, "message": str(e)}), 500


# ===================== INSTALLBASE SAVE (INSERT/UPDATE) ✅ ADDED =====================
@app.post("/api/installbase/save")
def api_installbase_save():
    need = _require_login_json()
    if need:
        return jsonify({"ok": False, "message": "unauthorized"}), 401

    payload = request.get_json(force=True) or {}

    cols = _table_columns("dbo.InstallBase")
    if not cols:
        return jsonify({"ok": False, "message": "dbo.InstallBase not found"}), 400

    id_col = _find_col(cols, aliases=["Id","ID"], must_contain=["id"])
    serial_col = _find_col(
        cols,
        aliases=["Serial No.","Serial No","Serial_No","SERIAL NO","SerialNo","Serial"],
        must_contain=["serial"]
    )
    cust_col = _find_col(
        cols,
        aliases=["CUSTOMER_NAME","CUSTOMER NAME","CustomerName","Customer Name"],
        must_contain=["customer","name"]
    )

    if not serial_col:
        return jsonify({"ok": False, "message": "Serial column not found in dbo.InstallBase"}), 400

    serial_val = (payload.get("serial_no") or payload.get("Serial No.") or payload.get("Serial No") or payload.get("Serial_No") or payload.get("SERIAL NO") or "").strip()
    cust_val = (payload.get("customer_name") or payload.get("CUSTOMER NAME") or payload.get("Customer Name") or "").strip()

    if not serial_val or not cust_val:
        return jsonify({"ok": False, "message": "Customer Name & Serial No required!"}), 400

    idx = _col_index(cols)

    def resolve_col(key: str):
        nk = _norm(key)
        return idx.get(nk)

    data = {}
    for k, v in payload.items():
        dbcol = resolve_col(k)
        if not dbcol:
            continue
        if id_col and _norm(dbcol) == _norm(id_col):
            continue
        data[dbcol] = v

    data[serial_col] = serial_val
    if cust_col:
        data[cust_col] = cust_val

    for k in list(data.keys()):
        if data[k] is None:
            continue
        if isinstance(data[k], str) and data[k].strip() == "":
            data[k] = None

    base_where, base_params = _installbase_scope_where(cols)

    where_parts = []
    params = []
    if base_where:
        where_parts.append(base_where.replace(" WHERE ", "", 1))
        params += base_params

    where_parts.append(f"{_cmp_ci_trim(serial_col)} = UPPER(?)")
    params.append(serial_val)

    where_sql = " WHERE " + " AND ".join(where_parts)

    sel_id = _qcol(id_col) if id_col else _qcol(serial_col)

    try:
        with get_conn() as conn:
            cur = conn.cursor()

            cur.execute(f"SELECT TOP 1 {sel_id} FROM dbo.InstallBase{where_sql}", params)
            existing = cur.fetchone()

            if existing:
                target_id = existing[0]

                sets = []
                upd_params = []

                for c, v in data.items():
                    if id_col and _norm(c) == _norm(id_col):
                        continue
                    sets.append(f"{_qcol(c)} = ?")
                    upd_params.append(v)

                if not sets:
                    return jsonify({"ok": True, "message": "Nothing to update."})

                if id_col:
                    upd_sql = f"UPDATE dbo.InstallBase SET {', '.join(sets)} WHERE {_qcol(id_col)} = ?"
                    upd_params.append(target_id)
                else:
                    upd_sql = f"UPDATE dbo.InstallBase SET {', '.join(sets)} WHERE {_cmp_ci_trim(serial_col)} = UPPER(?)"
                    upd_params.append(serial_val)

                cur.execute(upd_sql, upd_params)
                conn.commit()
                return jsonify({"ok": True, "message": "Updated successfully!"})

            else:
                ins_cols = []
                ins_vals = []
                ins_params = []

                for c, v in data.items():
                    if id_col and _norm(c) == _norm(id_col):
                        continue
                    ins_cols.append(_qcol(c))
                    ins_vals.append("?")
                    ins_params.append(v)

                if not ins_cols:
                    return jsonify({"ok": False, "message": "No valid columns to insert"}), 400

                ins_sql = f"INSERT INTO dbo.InstallBase ({', '.join(ins_cols)}) VALUES ({', '.join(ins_vals)})"
                cur.execute(ins_sql, ins_params)
                conn.commit()
                return jsonify({"ok": True, "message": "Inserted successfully!"})

    except Exception as e:
        return jsonify({"ok": False, "message": f"Save error: {e}"}), 500


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


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
