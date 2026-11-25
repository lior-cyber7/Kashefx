"""Stage 04 (University Sandbox PoC Stress Benchmark) & Stage 05 (Iraqi Universities SaaS Engine)."""

from __future__ import annotations

import hashlib
import time
from typing import Any

from academic_analyzer import analyze_academic_text, scan_dlp_content
from analyzer import analyze_message
from db import db_transaction, init_db, open_db

OFFICIAL_IQD_PER_USD = 1310

PLAN_RATES_USD: dict[str, tuple[float, float]] = {
    "starter": (2.2, 4.0),
    "campus": (1.5, 3.0),
    "national": (0.95, 2.0),
}

FOREIGN_BENCHMARK_PER_STUDENT_USD = 14.0
FOREIGN_BENCHMARK_PER_FACULTY_USD = 25.0

SANDBOX_ACADEMIC_SAMPLES = [
    (
        "قمنا في مختبر الأمن السيبراني في الجامعة التكنولوجية بتجربة ثلاث تقنيات لرصد الروابط "
        "المشبوهة. أظهرت الاختبارات الميدانية تبايناً واضحاً في استجابة الطلبة للرسائل القصيرة "
        "غير المألوفة، مما يؤكد أهمية التوعية العملية مع الفحص الآلي السريع."
    ),
    (
        "مما لا شك فيه أن الذكاء الاصطناعي يلعب دورا حيويا في عصرنا الحالي. علاوة على ذلك، "
        "تجدر الإشارة إلى أهمية توظيف التقنيات الحديثة. في الختام، بناء على ما سبق، تعد هذه "
        "الأدوات ركيزة أساسية في التعليم العالي."
    ),
    (
        "تعتمد هجمات التصيد الإلكتروني على انتحال صفة المصارف والمؤسسات الرسمية عبر نطاقات "
        "مشابهة للخداع البصري ومطالبة الضحية بإرسال رموز التحقق المؤقتة أو بيانات البطاقة."
    ),
]

SANDBOX_CYBER_SAMPLES = [
    "تنبيه من مصرف الرافدين: سيتم إيقاف حسابك خلال 24 ساعة عبر http://rafidain-verify.xyz/auth أرسل OTP",
    "مرحباً، تم نشر جدول المحاضرات الجديد على موقع القسم الرسمي اليوم صباحاً.",
    "Student portal leak test: student@uotechnology.edu.iq phone=+9647701234567 link=http://paypa1-secure.xyz/login",
]


def _init_platform_tables(db_path: str | None = None) -> None:
    """Create sandbox benchmark and university SaaS tenant tables if missing."""
    init_db(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sandbox_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                department TEXT NOT NULL,
                load_size INTEGER NOT NULL,
                elapsed_ms REAL NOT NULL,
                avg_latency_ms REAL NOT NULL,
                throughput_per_sec REAL NOT NULL,
                ai_flagged INTEGER NOT NULL,
                cyber_threats_caught INTEGER NOT NULL,
                dlp_leaks_caught INTEGER NOT NULL,
                sla_status TEXT NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS saas_tenants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                tenant_code TEXT UNIQUE NOT NULL,
                university_name TEXT NOT NULL,
                student_count INTEGER NOT NULL,
                faculty_count INTEGER NOT NULL,
                plan_tier TEXT NOT NULL,
                api_key_prefix TEXT NOT NULL,
                annual_local_usd INTEGER NOT NULL,
                foreign_benchmark_usd INTEGER NOT NULL,
                annual_savings_usd INTEGER NOT NULL,
                savings_pct INTEGER NOT NULL,
                status TEXT NOT NULL,
                ts REAL NOT NULL
            )
            """
        )
        conn.commit()


def _serialize_sandbox_run(row: Any) -> dict[str, Any]:
    return {
        "id": int(row["id"]),
        "department": str(row["department"]),
        "load_size": int(row["load_size"]),
        "elapsed_ms": float(row["elapsed_ms"]),
        "avg_latency_ms": float(row["avg_latency_ms"]),
        "throughput_per_sec": float(row["throughput_per_sec"]),
        "ai_flagged": int(row["ai_flagged"]),
        "cyber_threats_caught": int(row["cyber_threats_caught"]),
        "dlp_leaks_caught": int(row["dlp_leaks_caught"]),
        "sla_status": str(row["sla_status"]),
        "ts": float(row["ts"]),
    }


def _serialize_tenant(row: Any) -> dict[str, Any]:
    return {
        "tenant_code": str(row["tenant_code"]),
        "university_name": str(row["university_name"]),
        "student_count": int(row["student_count"]),
        "faculty_count": int(row["faculty_count"]),
        "plan_tier": str(row["plan_tier"]),
        "api_key_prefix": str(row["api_key_prefix"]),
        "annual_local_usd": int(row["annual_local_usd"]),
        "foreign_benchmark_usd": int(row["foreign_benchmark_usd"]),
        "annual_savings_usd": int(row["annual_savings_usd"]),
        "savings_pct": int(row["savings_pct"]),
        "status": str(row["status"]),
        "ts": float(row["ts"]),
    }


def _execute_stress_batch(count: int) -> tuple[int, int, int, float]:
    ai_flagged = 0
    cyber_threats_caught = 0
    dlp_leaks_caught = 0

    start = time.perf_counter()
    for idx in range(count):
        acad_text = SANDBOX_ACADEMIC_SAMPLES[idx % len(SANDBOX_ACADEMIC_SAMPLES)]
        acad_res = analyze_academic_text(acad_text)
        if (acad_res.get("ai_probability") or 0) >= 45 or acad_res["plagiarism_pct"] >= 30:
            ai_flagged += 1

        cyber_text = SANDBOX_CYBER_SAMPLES[idx % len(SANDBOX_CYBER_SAMPLES)]
        msg_res = analyze_message(cyber_text)
        if msg_res["verdict"] in {"suspicious", "dangerous"}:
            cyber_threats_caught += 1

        dlp_res = scan_dlp_content(cyber_text)
        if dlp_res["dlp_findings"]:
            dlp_leaks_caught += 1

    elapsed_ms = round((time.perf_counter() - start) * 1000.0, 2)
    return ai_flagged, cyber_threats_caught, dlp_leaks_caught, elapsed_ms


def run_sandbox_benchmark(
    department: str,
    load_size: int = 30,
    db_path: str | None = None,
) -> dict[str, Any]:
    """Execute a real multi-engine stress benchmark across Academic, Cyber, and DLP Python modules."""
    _init_platform_tables(db_path)
    clean_dept = (department or "").strip()[:140] or "الجامعة التكنولوجية — قسم علوم الحاسوب"
    count = max(6, min(90, int(load_size)))

    ai_flagged, cyber_threats_caught, dlp_leaks_caught, elapsed_ms = _execute_stress_batch(count)
    total_ops = count * 3
    avg_latency_ms = round(elapsed_ms / max(1, total_ops), 2)
    throughput = round(total_ops / max(0.001, elapsed_ms / 1000.0), 1)
    sla_status = "optimal" if avg_latency_ms <= 15.0 else "acceptable"
    ts = time.time()

    with open_db(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO sandbox_runs
            (department, load_size, elapsed_ms, avg_latency_ms, throughput_per_sec,
             ai_flagged, cyber_threats_caught, dlp_leaks_caught, sla_status, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                clean_dept,
                total_ops,
                elapsed_ms,
                avg_latency_ms,
                throughput,
                ai_flagged,
                cyber_threats_caught,
                dlp_leaks_caught,
                sla_status,
                ts,
            ),
        )
        conn.commit()
        run_id = cursor.lastrowid

    run_record = {
        "id": run_id,
        "department": clean_dept,
        "load_size": total_ops,
        "elapsed_ms": elapsed_ms,
        "avg_latency_ms": avg_latency_ms,
        "throughput_per_sec": throughput,
        "ai_flagged": ai_flagged,
        "cyber_threats_caught": cyber_threats_caught,
        "dlp_leaks_caught": dlp_leaks_caught,
        "sla_status": sla_status,
        "ts": ts,
    }
    return {"run": run_record, "history": list_sandbox_runs(db_path=db_path)}


def list_sandbox_runs(limit: int = 6, db_path: str | None = None) -> list[dict[str, Any]]:
    """Return recent stress-benchmark runs stored in SQLite."""
    _init_platform_tables(db_path)
    with open_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM sandbox_runs ORDER BY id DESC LIMIT ?",
            (max(1, min(20, limit)),),
        ).fetchall()
    return [_serialize_sandbox_run(r) for r in rows]


def calculate_saas_economics(
    student_count: int,
    faculty_count: int,
    plan_tier: str = "campus",
) -> dict[str, int]:
    """Compute annual Iraqi university SaaS pricing vs foreign platform license benchmark."""
    students = max(50, min(500000, int(student_count)))
    faculty = max(5, min(50000, int(faculty_count)))
    tier = plan_tier if plan_tier in PLAN_RATES_USD else "campus"
    s_rate, f_rate = PLAN_RATES_USD[tier]

    local_usd = round(students * s_rate + faculty * f_rate)
    foreign_usd = round(
        students * FOREIGN_BENCHMARK_PER_STUDENT_USD
        + faculty * FOREIGN_BENCHMARK_PER_FACULTY_USD
    )
    savings_usd = max(0, foreign_usd - local_usd)
    savings_pct = round((savings_usd / max(1, foreign_usd)) * 100)

    return {
        "annual_local_usd": local_usd,
        "foreign_benchmark_usd": foreign_usd,
        "annual_savings_usd": savings_usd,
        "annual_savings_iqd": savings_usd * OFFICIAL_IQD_PER_USD,
        "savings_pct": savings_pct,
    }


def register_saas_tenant(
    university_name: str,
    student_count: int,
    faculty_count: int,
    plan_tier: str = "campus",
    db_path: str | None = None,
) -> dict[str, Any]:
    """Onboard a university tenant into SQLite SaaS registry with issued API prefix & ROI."""
    _init_platform_tables(db_path)
    clean_name = (university_name or "").strip()[:140]
    if len(clean_name) < 2:
        raise ValueError("University name is required")

    tier = plan_tier if plan_tier in PLAN_RATES_USD else "campus"
    students = max(50, min(500000, int(student_count)))
    faculty = max(5, min(50000, int(faculty_count)))
    econ = calculate_saas_economics(students, faculty, tier)
    ts = time.time()

    digest = hashlib.sha256(f"{clean_name}:{ts}".encode("utf-8")).hexdigest()
    api_prefix = f"acad_live_{digest[:12]}"
    status = "sandbox" if tier == "starter" else "active"

    with db_transaction(db_path) as conn:
        last_row = conn.execute(
            "SELECT COALESCE(MAX(id), 0) AS max_id FROM saas_tenants"
        ).fetchone()
        next_num = (int(last_row["max_id"]) + 1) if last_row else 1
        tenant_code = f"IQ-UNI-{next_num:03d}"

        conn.execute(
            """
            INSERT INTO saas_tenants
            (tenant_code, university_name, student_count, faculty_count, plan_tier,
             api_key_prefix, annual_local_usd, foreign_benchmark_usd, annual_savings_usd,
             savings_pct, status, ts)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                tenant_code,
                clean_name,
                students,
                faculty,
                tier,
                api_prefix,
                econ["annual_local_usd"],
                econ["foreign_benchmark_usd"],
                econ["annual_savings_usd"],
                econ["savings_pct"],
                status,
                ts,
            ),
        )

    return list_saas_tenants(db_path=db_path)


def delete_saas_tenant(tenant_code: str, db_path: str | None = None) -> dict[str, Any]:
    """Remove a registered university tenant by tenant_code and return updated list."""
    _init_platform_tables(db_path)
    with open_db(db_path) as conn:
        conn.execute(
            "DELETE FROM saas_tenants WHERE tenant_code = ?",
            ((tenant_code or "").strip(),),
        )
        conn.commit()
    return list_saas_tenants(db_path=db_path)


def list_saas_tenants(db_path: str | None = None) -> dict[str, Any]:
    """Return registered university SaaS tenants and aggregate student/savings totals."""
    _init_platform_tables(db_path)
    with open_db(db_path) as conn:
        rows = conn.execute(
            "SELECT * FROM saas_tenants ORDER BY id DESC LIMIT 20"
        ).fetchall()
        totals = conn.execute(
            """
            SELECT COUNT(*) AS cnt,
                   COALESCE(SUM(student_count), 0) AS total_students,
                   COALESCE(SUM(annual_savings_usd), 0) AS total_savings_usd
            FROM saas_tenants
            """
        ).fetchone()

    tenants = [_serialize_tenant(r) for r in rows]

    return {
        "tenants": tenants,
        "summary": {
            "tenant_count": int(totals["cnt"]) if totals else 0,
            "total_students": int(totals["total_students"]) if totals else 0,
            "total_savings_usd": int(totals["total_savings_usd"]) if totals else 0,
        },
    }
