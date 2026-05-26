"""VPNTunel Billing — Landing page & registrasi ISP."""
from __future__ import annotations
import logging
import sqlite3
import time
from pathlib import Path

import yaml
from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

logging.basicConfig(level=logging.INFO)

cfg        = yaml.safe_load((Path(__file__).parent.parent / "vpntunel-panel" / "configs" / "panel.yaml").read_text())
ADMIN_WA   = cfg["admin_wa"]
WA_URL     = cfg.get("wuzapi", {}).get("url", "")
WA_TOKEN   = cfg.get("wuzapi", {}).get("token", "")
BILLING_DB = "/home/ubuntu/projects/billing-web/data/billing.db"

app       = FastAPI()
templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))


# ── WuzAPI helper ─────────────────────────────────────────────────────────────

def _wa(nomor: str, pesan: str):
    if not WA_URL or not nomor:
        return
    try:
        import requests as _req
        _req.post(
            f"{WA_URL}/chat/send/text",
            json={"phone": nomor, "body": pesan},
            headers={"Token": WA_TOKEN},
            timeout=8,
        )
    except Exception as e:
        logging.warning("WA send error: %s", e)


# ── DB helper ─────────────────────────────────────────────────────────────────

def _normalize_wa(nomor: str) -> str:
    n = nomor.strip().replace("-", "").replace(" ", "")
    if n.startswith("0"):
        n = "62" + n[1:]
    return n

def _save_registrasi(nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi, catatan):
    try:
        con = sqlite3.connect(BILLING_DB)
        con.execute(
            "INSERT INTO tenant_registrasi "
            "(nama_isp,nama_pemilik,nomor_wa,kota,paket,estimasi_pelanggan,catatan,created_at) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi, catatan, int(time.time()))
        )
        con.commit()
        con.close()
    except Exception as e:
        logging.error("Gagal simpan registrasi ke billing DB: %s", e)


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def landing(request: Request):
    return templates.TemplateResponse(request=request, name="landing.html", context={})


@app.get("/daftar", response_class=HTMLResponse)
async def daftar_form(request: Request):
    return templates.TemplateResponse(request=request, name="daftar.html", context={})


@app.post("/daftar", response_class=HTMLResponse)
async def daftar_submit(
    request: Request,
    nama_isp: str = Form(...),
    nama_pemilik: str = Form(...),
    nomor_wa: str = Form(...),
    kota: str = Form(...),
    paket: str = Form("Pro"),
    estimasi_pelanggan: str = Form(""),
    catatan: str = Form(""),
):
    nomor_wa = _normalize_wa(nomor_wa)
    _save_registrasi(nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi_pelanggan, catatan)
    _wa(ADMIN_WA,
        f"🔔 *Pendaftaran ISP Baru — VPNTunel Billing*\n\n"
        f"🏢 ISP: *{nama_isp}*\n"
        f"👤 Pemilik: {nama_pemilik}\n"
        f"📱 WA: {nomor_wa}\n"
        f"📍 Kota: {kota}\n"
        f"📦 Paket: {paket}\n"
        f"👥 Est. Pelanggan: {estimasi_pelanggan or '-'}\n"
        f"📝 Catatan: {catatan or '-'}\n\n"
        f"Lihat & proses di: https://admin.vpntunel.my.id/registrasi"
    )
    return templates.TemplateResponse(request=request, name="daftar.html", context={
        "success": True, "nama_isp": nama_isp, "nama_pemilik": nama_pemilik,
    })
