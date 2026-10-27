"""
FastAPI Server for SQL Injection Detection, Exploitation & Mitigation Platform.
Hosts REST endpoints for interactive lab testbed, SAST code scanner, and query token analyzer.
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List

from ..config import STATIC_DIR, PROJECT_TITLE, PROJECT_VERSION
from ..database.db import init_db, reset_db
from ..core.vulnerable_service import VulnerableService
from ..core.mitigated_service import MitigatedService
from ..core.query_analyzer import QueryAnalyzer
from ..core.sast_scanner import SASTScanner

# Ensure database exists on import
init_db()

app = FastAPI(
    title=PROJECT_TITLE,
    version=PROJECT_VERSION,
    description="Interactive Laboratory and SAST Auditor for CWE-89 (SQL Injection) Analysis & Defense"
)

# Startup Hook
@app.on_event("startup")
def on_startup():
    init_db()


# Request Models
class LoginRequest(BaseModel):
    username: str
    password: str
    mode: str = Field(default="vulnerable", description="'vulnerable' or 'mitigated'")

class SearchRequest(BaseModel):
    keyword: str
    mode: str = Field(default="vulnerable", description="'vulnerable' or 'mitigated'")

class ProfileRequest(BaseModel):
    user_id: str
    mode: str = Field(default="vulnerable", description="'vulnerable' or 'mitigated'")

class ScanCodeRequest(BaseModel):
    code: str

class TokenizeRequest(BaseModel):
    sql: str

# 1. Lab Endpoints
@app.post("/api/lab/login")
def lab_login(payload: LoginRequest):
    """Execute login authentication in either vulnerable or mitigated mode."""
    mode = payload.mode.lower()
    
    if mode == "mitigated":
        result = MitigatedService.login(payload.username, payload.password)
        # Compare token structures for educational visualization
        constructed_dynamic = f"SELECT id, username, role, email, full_name, account_balance FROM users WHERE username = '{payload.username}' AND password_hash = '{payload.password}';"
        template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE username = ? AND password_hash = ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=constructed_dynamic,
            parameterized_template=template,
            bound_params={"username": payload.username, "password": payload.password}
        )
    else:
        result = VulnerableService.login(payload.username, payload.password)
        template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE username = ? AND password_hash = ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=result["constructed_query"],
            parameterized_template=template,
            bound_params={"username": payload.username, "password": payload.password}
        )

    return {
        "execution": result,
        "query_analysis": analysis
    }

@app.post("/api/lab/search")
def lab_search(payload: SearchRequest):
    """Execute product catalog search in either vulnerable or mitigated mode."""
    mode = payload.mode.lower()
    
    if mode == "mitigated":
        result = MitigatedService.search_products(payload.keyword)
        constructed_dynamic = f"SELECT id, sku, name, category, price, stock_quantity, description FROM products WHERE name LIKE '%{payload.keyword}%' OR category LIKE '%{payload.keyword}%';"
        template = "SELECT id, sku, name, category, price, stock_quantity, description FROM products WHERE name LIKE ? OR category LIKE ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=constructed_dynamic,
            parameterized_template=template,
            bound_params={"pattern": f"%{payload.keyword}%"}
        )
    else:
        result = VulnerableService.search_products(payload.keyword)
        template = "SELECT id, sku, name, category, price, stock_quantity, description FROM products WHERE name LIKE ? OR category LIKE ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=result["constructed_query"],
            parameterized_template=template,
            bound_params={"pattern": f"%{payload.keyword}%"}
        )

    return {
        "execution": result,
        "query_analysis": analysis
    }

@app.post("/api/lab/profile")
def lab_profile(payload: ProfileRequest):
    """Execute user profile lookup by ID in either vulnerable or mitigated mode."""
    mode = payload.mode.lower()
    
    if mode == "mitigated":
        result = MitigatedService.get_user_profile(payload.user_id)
        constructed_dynamic = f"SELECT id, username, role, email, full_name, account_balance FROM users WHERE id = {payload.user_id};"
        template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE id = ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=constructed_dynamic,
            parameterized_template=template,
            bound_params={"user_id": payload.user_id}
        )
    else:
        result = VulnerableService.get_user_profile(payload.user_id)
        template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE id = ?;"
        analysis = QueryAnalyzer.compare_query_structures(
            vulnerable_sql=result["constructed_query"],
            parameterized_template=template,
            bound_params={"user_id": payload.user_id}
        )

    return {
        "execution": result,
        "query_analysis": analysis
    }

# 2. Query Lexical Tokenizer Endpoint
@app.post("/api/lab/tokenize")
def lab_tokenize(payload: TokenizeRequest):
    """Tokenize arbitrary SQL for lexical inspector."""
    tokens = QueryAnalyzer.tokenize(payload.sql)
    return {
        "sql": payload.sql,
        "token_count": len(tokens),
        "tokens": tokens
    }

# 3. SAST Static Application Security Testing Endpoints
@app.post("/api/sast/scan")
def sast_scan(payload: ScanCodeRequest):
    """Run AST-based static code analysis for CWE-89 detection."""
    result = SASTScanner.scan_code(payload.code)
    return result

@app.get("/api/sast/presets")
def sast_presets():
    """Return realistic code presets demonstrating vulnerable vs mitigated Python patterns."""
    return {
        "presets": [
            {
                "id": "vuln_fstring_login",
                "title": "Vulnerable Flask Route (f-string Dynamic Query)",
                "description": "Flask authentication handler concatenating request parameters directly into raw SQL.",
                "code": (
                    "@app.route('/login', methods=['POST'])\n"
                    "def login():\n"
                    "    user = request.form['username']\n"
                    "    pwd = request.form['password']\n"
                    "    cursor = db.cursor()\n"
                    "    # CRITICAL: Dynamic SQL construction via f-string\n"
                    "    query = f\"SELECT * FROM users WHERE username = '{user}' AND password = '{pwd}'\"\n"
                    "    cursor.execute(query)\n"
                    "    return cursor.fetchall()\n"
                )
            },
            {
                "id": "vuln_concat_search",
                "title": "Vulnerable Search Filter (String Concatenation with '+')",
                "description": "Product search function concatenating user input directly with SQL clauses.",
                "code": (
                    "def search_catalog(search_term):\n"
                    "    cursor = connection.cursor()\n"
                    "    # CRITICAL: String concatenation operator creates injection vector\n"
                    "    sql = \"SELECT id, name, price FROM products WHERE name LIKE '%\" + search_term + \"%';\"\n"
                    "    cursor.execute(sql)\n"
                    "    return cursor.fetchall()\n"
                )
            },
            {
                "id": "vuln_percent_format",
                "title": "Vulnerable Legacy Formatting ('%' Operator)",
                "description": "Legacy Python code using string interpolation `%s` without parameter binding.",
                "code": (
                    "def get_account_details(account_id):\n"
                    "    cursor = db.cursor()\n"
                    "    # CRITICAL: String interpolation formats input directly into query syntax\n"
                    "    stmt = \"SELECT * FROM accounts WHERE id = %s\" % account_id\n"
                    "    cursor.execute(stmt)\n"
                    "    return cursor.fetchone()\n"
                )
            },
            {
                "id": "mitigated_parameterized",
                "title": "Secure Parameterized Query (Prepared Statement)",
                "description": "Compliant Python code using prepared statements and native parameter tuples.",
                "code": (
                    "@app.route('/login', methods=['POST'])\n"
                    "def secure_login():\n"
                    "    user = request.form['username']\n"
                    "    pwd = request.form['password']\n"
                    "    cursor = db.cursor()\n"
                    "    # SECURE: Query structure is fixed; parameters passed as distinct tuple\n"
                    "    cursor.execute(\n"
                    "        \"SELECT id, username, role FROM users WHERE username = ? AND password = ?;\",\n"
                    "        (user, pwd)\n"
                    "    )\n"
                    "    return cursor.fetchall()\n"
                )
            },
            {
                "id": "mitigated_type_enforced",
                "title": "Defense-in-Depth (Type Enforcement + Parameterization)",
                "description": "Combining strict input validation with parameterized queries.",
                "code": (
                    "def get_user_profile(user_id_raw: str):\n"
                    "    # Defense-in-depth: Validate integer boundary before database interaction\n"
                    "    try:\n"
                    "        validated_id = int(user_id_raw)\n"
                    "    except ValueError:\n"
                    "        raise ValueError('Invalid user identifier')\n"
                    "    \n"
                    "    cursor = db.cursor()\n"
                    "    cursor.execute(\"SELECT * FROM users WHERE id = ?;\", (validated_id,))\n"
                    "    return cursor.fetchone()\n"
                )
            }
        ]
    }

# 4. Database Reset Endpoint
@app.post("/api/db/reset")
def api_reset_db():
    """Reset the database to initial clean state."""
    reset_db()
    return {"status": "SUCCESS", "message": "Database successfully reset and re-seeded with pristine records."}

# 5. Project Metadata & Academic Report Data Endpoint
@app.get("/api/project/meta")
def project_meta():
    """Return academic minor project metadata and theoretical foundations."""
    return {
        "title": PROJECT_TITLE,
        "version": PROJECT_VERSION,
        "cwe": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
        "owasp_rank": "A03:2021 - Injection",
        "theoretical_model": "Chomsky Hierarchy Type-2 Context-Free Grammar parser failure caused by Code-Data Ambiguity.",
        "detection_mechanisms": [
            "AST-based Static Application Security Testing (SAST)",
            "Lexical Grammar Token Differential Analysis",
            "Runtime Input Anomaly Inspection"
        ],
        "mitigation_hierarchy": [
            {"tier": "Primary Defense", "method": "Parameterized Queries / Prepared Statements", "efficacy": "100% against syntax mutation"},
            {"tier": "Secondary Defense", "method": "Object-Relational Mapping (ORM) Abstractions", "efficacy": "High (when raw queries avoided)"},
            {"tier": "Tertiary Defense", "method": "Input Validation & Strict Type Coercion", "efficacy": "Defense-in-Depth layer"},
            {"tier": "Systemic Defense", "method": "Principle of Least Privilege (DB Roles)", "efficacy": "Blast radius containment"}
        ]
    }

# Static file serving
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(STATIC_DIR / "index.html")
