"""FastAPI Web Application for NetScope Network Scanner & Audit Engine."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from scanner.engine import engine
from scanner.exporters import export_to_csv, export_to_html_report, export_to_json
from scanner.host_discovery import get_local_interfaces_info
from scanner.models import ScanJobConfig, ScanProgressEvent

app = FastAPI(
    title="NetScope Network Scanner & Audit API",
    description="Cybersecurity reconnaissance, software versioning, and compliance audit engine.",
    version="2.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

BASE_DIR = Path(__file__).resolve().parent.parent
STATIC_DIR = BASE_DIR / "static"


@app.get("/api/info")
async def get_system_info() -> Dict[str, Any]:
    """Retrieve local network interface information for UI auto-fill."""
    return get_local_interfaces_info()


@app.post("/api/scan")
async def start_scan(config: ScanJobConfig) -> Dict[str, Any]:
    """Start a new background network scan job."""
    try:
        job = engine.start_job(config)
        return {
            "status": "started",
            "job_id": job.job_id,
            "target": config.target,
        }
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.get("/api/scan/{job_id}")
async def get_scan_report(job_id: str) -> Dict[str, Any]:
    """Get the current scan report for a job ID."""
    report = engine.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return report.model_dump()


@app.post("/api/scan/{job_id}/cancel")
async def cancel_scan(job_id: str) -> Dict[str, Any]:
    """Cancel a running scan job."""
    success = engine.cancel_job(job_id)
    if not success:
        raise HTTPException(status_code=400, detail="Job cannot be cancelled (not running or not found)")
    return {"status": "cancelled", "job_id": job_id}


@app.get("/api/scan/{job_id}/stream")
async def stream_scan_events(job_id: str):
    """Server-Sent Events (SSE) endpoint providing live scan progress to the dashboard."""
    job = engine.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")

    async def event_generator():
        if job.report.status in ("completed", "cancelled", "failed"):
            final_evt = ScanProgressEvent(
                type="complete" if job.report.status == "completed" else job.report.status,
                message=f"Scan {job.report.status}",
                percent=100.0,
                payload=job.report.model_dump(),
            )
            yield f"data: {final_evt.model_dump_json()}\n\n"
            return

        queue: asyncio.Queue[ScanProgressEvent] = asyncio.Queue()
        loop = asyncio.get_running_loop()

        def on_event(evt: ScanProgressEvent):
            loop.call_soon_threadsafe(queue.put_nowait, evt)

        job.add_listener(on_event)
        try:
            while True:
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=20.0)
                    yield f"data: {evt.model_dump_json()}\n\n"
                    if evt.type in ("complete", "cancelled", "error"):
                        break
                except asyncio.TimeoutError:
                    yield ": keep-alive\n\n"
        finally:
            job.remove_listener(on_event)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/api/scan/{job_id}/export/csv")
async def export_csv(job_id: str):
    """Download scan findings as a CSV file."""
    report = engine.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    csv_data = export_to_csv(report)
    filename = f"scan_{report.target.replace('/', '_')}_{job_id}.csv"
    return Response(
        content=csv_data,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{job_id}/export/json")
async def export_json(job_id: str):
    """Download scan findings as a JSON file."""
    report = engine.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    json_data = export_to_json(report)
    filename = f"scan_{report.target.replace('/', '_')}_{job_id}.json"
    return Response(
        content=json_data,
        media_type="application/json",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/scan/{job_id}/export/html", response_class=HTMLResponse)
async def export_html(job_id: str):
    """View and print Executive Cybersecurity Audit Report."""
    report = engine.get_report(job_id)
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return export_to_html_report(report)


@app.get("/api/history")
async def get_history():
    """Retrieve history of previous scans."""
    history = engine.get_history()
    return [
        {
            "job_id": r.job_id,
            "target": r.target,
            "started_at": r.started_at,
            "duration_seconds": r.duration_seconds,
            "active_hosts": r.active_hosts_count,
            "open_ports": r.total_open_ports,
            "overall_grade": r.overall_posture_grade,
            "security_score": r.average_security_score,
            "status": r.status,
        }
        for r in history
    ]


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(str(index_file))
    return HTMLResponse("<h1>NetScope Dashboard Frontend Loading...</h1>")
