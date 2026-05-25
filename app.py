"""VPNTunel — Public website + customer portal."""
from __future__ import annotations
import sys
import logging
import calendar
import sqlite3
from datetime import date, timedelta
from pathlib import Path

import hashlib
import hmac
import random
import string

import yaml
import midtransclient
from fastapi import FastAPI, Form, Request, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import TimestampSigner, BadSignature

sys.path.insert(0, "/home/ubuntu/projects/vpntunel-panel")
from storage import Storage
from whatsapp import WuzAPIClient
import wg_manager
import l2tp_manager

def _build_vpn_connections(p: dict, vpn_connections: list[dict]) -> list[dict]:
    for vc in vpn_connections:
        if vc["protocol"] == "l2tp":
            vc["script"] = l2tp_manager.generate_client_script(vc["l2tp_user"], vc["l2tp_password"])
            vc["proto_label"] = "L2TP/IPSec"
        else:
            vc["script"] = wg_manager.generate_client_script(p["subdomain"], vc["wg_private_key"], vc["vpn_ip"])
            vc["proto_label"] = "WireGuard"
    return vpn_connections

logging.basicConfig(level=logging.INFO)

cfg = yaml.safe_load(Path("/home/ubuntu/projects/vpntunel-panel/configs/panel.yaml").read_text())
BILLING_DB = "/home/ubuntu/projects/billing-web/data/billing.db"


def _save_registrasi(nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi, catatan):
    import time as _time
    try:
        con = sqlite3.connect(BILLING_DB)
        con.execute(
            "INSERT INTO tenant_registrasi (nama_isp,nama_pemilik,nomor_wa,kota,paket,estimasi_pelanggan,catatan,created_at) VALUES (?,?,?,?,?,?,?,?)",
            (nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi, catatan, int(_time.time()))
        )
        con.commit()
        con.close()
    except Exception as e:
        logging.error("Gagal simpan registrasi ke billing DB: %s", e)

storage    = Storage(cfg["db_path"])
wa         = WuzAPIClient(cfg["wuzapi"]["url"], cfg["wuzapi"]["token"])
ADMIN_WA   = cfg["admin_wa"]
PAKET_LIST = cfg["paket"]
VPN_DOMAIN = cfg["frp"]["subdomain_host"]
SECRET_KEY = cfg["admin"]["secret_key"]
MT_CFG     = cfg.get("midtrans", {})
MT_SERVER_KEY = MT_CFG.get("server_key", "")
MT_CLIENT_KEY = MT_CFG.get("client_key", "")
MT_IS_PROD    = MT_CFG.get("is_production", False)

snap = midtransclient.Snap(
    is_production=MT_IS_PROD,
    server_key=MT_SERVER_KEY,
)

signer = TimestampSigner(SECRET_KEY)

def format_rupiah(n): return f"Rp {n:,.0f}".replace(",",".")

def get_expire_date(p: dict) -> str:
    today     = date.today()
    tgl_bayar = p["tanggal_bayar"]
    if today.day <= tgl_bayar:
        expire = today.replace(day=tgl_bayar)
    else:
        next_month = (today.replace(day=1) + timedelta(days=32)).replace(day=1)
        try:
            expire = next_month.replace(day=tgl_bayar)
        except ValueError:
            last_day = calendar.monthrange(next_month.year, next_month.month)[1]
            expire = next_month.replace(day=last_day)
    return expire.strftime("%-d %B %Y")

def get_client_script(p: dict) -> tuple[str, str]:
    proto = p.get("protocol", "wireguard")
    if proto == "l2tp":
        return l2tp_manager.generate_client_script(p["l2tp_user"], p["l2tp_password"]), "L2TP/IPSec"
    return wg_manager.generate_client_script(p["subdomain"], p["wg_private_key"], p["vpn_ip"]), "WireGuard"

def make_session(pid: str) -> str:
    return signer.sign(pid).decode()

def get_session_pid(session: str | None) -> str | None:
    if not session:
        return None
    try:
        return signer.unsign(session, max_age=86400 * 30).decode()
    except BadSignature:
        return None


app = FastAPI()
templates = Jinja2Templates(directory="templates")
templates.env.globals["format_rupiah"] = format_rupiah
templates.env.globals["FRP_SUBDOMAIN"] = VPN_DOMAIN
templates.env.globals["VPN_DOMAIN"]    = VPN_DOMAIN
templates.env.globals["FRP_SERVER"]    = cfg["frp"]["server_addr"]
templates.env.globals["PAKET_LIST"]    = PAKET_LIST
templates.env.globals["enumerate"]     = enumerate
templates.env.globals["min"]           = min


# ── Public routes ─────────────────────────────────────────────────────────────

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
    _save_registrasi(nama_isp, nama_pemilik, nomor_wa, kota, paket, estimasi_pelanggan, catatan)
    wa.send(ADMIN_WA,
        f"🔔 *Pendaftaran ISP Baru — VPNTunel Billing*\n\n"
        f"🏢 ISP: *{nama_isp}*\n"
        f"👤 Pemilik: {nama_pemilik}\n"
        f"📱 WA: {nomor_wa}\n"
        f"📍 Kota: {kota}\n"
        f"📦 Paket: {paket}\n"
        f"👥 Est. Pelanggan: {estimasi_pelanggan or '-'}\n"
        f"📝 Catatan: {catatan or '-'}\n\n"
        f"Lihat & proses di: https://billing.vpntunel.my.id/registrasi"
    )
    return templates.TemplateResponse(request=request, name="daftar.html", context={
        "success": True, "nama_isp": nama_isp, "nama_pemilik": nama_pemilik,
    })


# ── Auth routes ───────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, session: str | None = Cookie(default=None)):
    # Kalau sudah login, langsung ke portal
    if get_session_pid(session):
        return RedirectResponse("/portal", status_code=302)
    return templates.TemplateResponse(request=request, name="login.html", context={"error": ""})


@app.post("/login")
async def login_submit(
    request: Request,
    nomor_wa: str = Form(...),
    pin: str = Form(...),
):
    pelanggan = storage.get_by_wa_and_pin(nomor_wa, pin)
    if not pelanggan:
        return templates.TemplateResponse(request=request, name="login.html", context={
            "error": "Nomor WA atau PIN salah. Hubungi admin jika lupa PIN.",
        })
    token = make_session(pelanggan["id"])
    resp  = RedirectResponse("/portal", status_code=302)
    resp.set_cookie("portal_session", token, httponly=True, samesite="lax", max_age=86400 * 30)
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("portal_session")
    return resp


# ── Protected portal routes ───────────────────────────────────────────────────

def _get_pelanggan(session: str | None) -> dict | None:
    pid = get_session_pid(session)
    if not pid:
        return None
    return storage.get(pid)


@app.get("/portal", response_class=HTMLResponse)
async def portal(request: Request, portal_session: str | None = Cookie(default=None)):
    p = _get_pelanggan(portal_session)
    if not p:
        return RedirectResponse("/login?error=session", status_code=302)
    bulan   = date.today().strftime("%Y-%m")
    tagihan = storage.get_or_create_tagihan(p["id"], bulan)
    riwayat = storage.get_riwayat_bayar(p["id"])
    vpn_connections = _build_vpn_connections(p, storage.get_vpn_connections(p["id"]))
    # Fallback ke data lama kalau vpn_connections kosong
    if not vpn_connections:
        script, proto_label = get_client_script(p)
        vpn_connections = [{"id": 0, "label": "VPN 1", "protocol": p.get("protocol","wireguard"),
                            "proto_label": proto_label, "script": script,
                            "vpn_ip": p.get("vpn_ip",""), "l2tp_user": p.get("l2tp_user",""),
                            "status": "aktif"}]
    paket_data  = next((pk for pk in PAKET_LIST if pk["name"] == p["paket"]), {"ports": 1})
    vpn_limit   = p.get("vpn_limit") or paket_data["ports"]
    return templates.TemplateResponse(request=request, name="portal.html", context={
        "p": p,
        "vpn_connections": vpn_connections,
        "vpn_limit": vpn_limit,
        "tagihan": tagihan,
        "bulan": bulan,
        "riwayat": riwayat,
        "expire_date": get_expire_date(p),
    })


@app.post("/tambah-vpn-mandiri", response_class=JSONResponse)
async def tambah_vpn_mandiri(
    request: Request,
    label: str = Form(""),
    protocol: str = Form("wireguard"),
    portal_session: str | None = Cookie(default=None),
):
    p = _get_pelanggan(portal_session)
    if not p:
        return JSONResponse({"ok": False, "msg": "Session tidak valid."}, status_code=401)
    paket_data = next((pk for pk in PAKET_LIST if pk["name"] == p["paket"]), {"ports": 1})
    vpn_limit = int(p.get("vpn_limit") or paket_data.get("ports") or 1)
    current_count = storage.count_vpn_connections(p["id"])
    if current_count >= vpn_limit:
        return JSONResponse({"ok": False, "msg": f"Slot VPN penuh ({current_count}/{vpn_limit}). Upgrade paket untuk menambah slot."})
    auto_label = label.strip() or f"VPN {current_count + 1}"
    wg_priv = wg_pub = vpn_ip = l2tp_user = l2tp_pass = ""
    if protocol == "wireguard":
        wg_priv, wg_pub = wg_manager.gen_keypair()
        vpn_ip = storage.assign_next_vpn_ip()
        script = wg_manager.generate_client_script(p["subdomain"], wg_priv, vpn_ip)
        try:
            wg_manager.add_peer(wg_pub, vpn_ip)
        except Exception as e:
            logging.error("Gagal add WG peer: %s", e)
        proto_label = "WireGuard"
    else:
        l2tp_user = f"{p['subdomain']}-{current_count + 1}"
        l2tp_pass = "".join(random.choices(string.ascii_letters + string.digits, k=10))
        l2tp_manager.add_user(l2tp_user, l2tp_pass)
        script = l2tp_manager.generate_client_script(l2tp_user, l2tp_pass)
        proto_label = "L2TP/IPSec"
    storage.create_vpn_connection(
        p["id"], auto_label, protocol, wg_priv, wg_pub, vpn_ip, l2tp_user, l2tp_pass
    )
    wa.send(p["nomor_wa"],
        f"✅ *Koneksi VPN Baru Berhasil Dibuat!*\n\n"
        f"Halo {p['nama']}, koneksi VPN baru sudah siap.\n\n"
        f"📛 Label: *{auto_label}*\n"
        f"🔧 Protokol: {proto_label}\n\n"
        f"*Script Konfigurasi:*\n```\n{script}\n```\n\n"
        f"Buka Winbox → New Terminal → paste script → Enter"
    )
    return {"ok": True, "reload": True,
            "msg": f"VPN '{auto_label}' berhasil dibuat! Script sudah dikirim ke WhatsApp Anda."}


# ── Midtrans Payment Routes ───────────────────────────────────────────────────

def _snap_create(order_id: str, amount: int, p: dict, item_name: str) -> dict:
    return snap.create_transaction({
        "transaction_details": {
            "order_id": order_id,
            "gross_amount": amount,
        },
        "item_details": [{"id": order_id, "price": amount, "quantity": 1, "name": item_name}],
        "customer_details": {
            "first_name": p["nama"],
            "phone": p["nomor_wa"],
        },
        "callbacks": {
            "finish": f"https://vpntunel.my.id/portal?bayar=selesai",
        },
    })


@app.post("/bayar/tagihan", response_class=JSONResponse)
async def bayar_tagihan(
    request: Request,
    portal_session: str | None = Cookie(default=None),
):
    p = _get_pelanggan(portal_session)
    if not p:
        return JSONResponse({"ok": False, "msg": "Session tidak valid."}, status_code=401)
    bulan = date.today().strftime("%Y-%m")
    tagihan = storage.get_or_create_tagihan(p["id"], bulan)
    if tagihan["lunas"]:
        return JSONResponse({"ok": False, "msg": "Tagihan bulan ini sudah lunas."})
    # Cek apakah ada order pending yang masih valid
    existing = storage.get_pending_order(p["id"], "tagihan", bulan)
    if existing and existing["snap_token"]:
        return {"ok": True, "snap_token": existing["snap_token"], "client_key": MT_CLIENT_KEY}
    order_id = storage.create_order(p["id"], "tagihan", p["harga"],
                                    {"bulan": bulan, "ref": bulan})
    try:
        result = _snap_create(order_id, p["harga"], p,
                              f"Tagihan VPN {p['paket']} — {bulan}")
        storage.update_order_snap(order_id, result["token"], result.get("redirect_url", ""))
        return {"ok": True, "snap_token": result["token"], "client_key": MT_CLIENT_KEY}
    except Exception as e:
        logging.error("Midtrans create tagihan error: %s", e)
        return JSONResponse({"ok": False, "msg": f"Gagal membuat transaksi: {e}"}, status_code=500)


@app.post("/bayar/upgrade-paket", response_class=JSONResponse)
async def bayar_upgrade_paket(
    request: Request,
    target_paket: str = Form(...),
    portal_session: str | None = Cookie(default=None),
):
    p = _get_pelanggan(portal_session)
    if not p:
        return JSONResponse({"ok": False, "msg": "Session tidak valid."}, status_code=401)
    paket_data = next((pk for pk in PAKET_LIST if pk["name"] == target_paket), None)
    if not paket_data:
        return JSONResponse({"ok": False, "msg": "Paket tidak valid."})
    current = next((pk for pk in PAKET_LIST if pk["name"] == p["paket"]), {"ports": 0, "harga": 0})
    if paket_data["ports"] <= current["ports"]:
        return JSONResponse({"ok": False, "msg": "Pilih paket yang lebih tinggi dari paket Anda sekarang."})
    amount = paket_data["harga"]
    ref = f"upgrade-{target_paket}"
    existing = storage.get_pending_order(p["id"], "upgrade_paket", ref)
    if existing and existing["snap_token"]:
        return {"ok": True, "snap_token": existing["snap_token"], "client_key": MT_CLIENT_KEY}
    order_id = storage.create_order(p["id"], "upgrade_paket", amount,
                                    {"target_paket": target_paket,
                                     "target_harga": paket_data["harga"],
                                     "target_ports": paket_data["ports"],
                                     "ref": ref})
    try:
        result = _snap_create(order_id, amount, p,
                              f"Upgrade Paket VPN → {target_paket}")
        storage.update_order_snap(order_id, result["token"], result.get("redirect_url", ""))
        return {"ok": True, "snap_token": result["token"], "client_key": MT_CLIENT_KEY}
    except Exception as e:
        logging.error("Midtrans create upgrade error: %s", e)
        return JSONResponse({"ok": False, "msg": f"Gagal membuat transaksi: {e}"}, status_code=500)


@app.post("/midtrans/notification")
async def midtrans_notification(request: Request):
    body = await request.json()
    order_id    = body.get("order_id", "")
    status_code = body.get("status_code", "")
    gross       = body.get("gross_amount", "0")
    trx_status  = body.get("transaction_status", "")
    fraud       = body.get("fraud_status", "")

    # Verifikasi signature
    raw = f"{order_id}{status_code}{gross}{MT_SERVER_KEY}"
    sig = hashlib.sha512(raw.encode()).hexdigest()
    if sig != body.get("signature_key", ""):
        return JSONResponse({"ok": False}, status_code=403)

    paid = (trx_status == "capture" and fraud == "accept") or trx_status == "settlement"
    failed = trx_status in ("cancel", "deny", "expire")

    order = storage.get_order(order_id)
    if not order:
        return {"ok": True}

    if paid and order["status"] == "pending":
        storage.update_order_status(order_id, "paid")
        p = storage.get(order["pelanggan_id"])
        if not p:
            return {"ok": True}

        if order["type"] == "tagihan":
            bulan = order["metadata"]["bulan"]
            storage.tandai_lunas(p["id"], bulan)
            wa.send(p["nomor_wa"],
                f"✅ *Pembayaran Diterima!*\n\n"
                f"Halo {p['nama']}, pembayaran tagihan VPN bulan *{bulan}* "
                f"sebesar *{format_rupiah(order['amount'])}* telah dikonfirmasi.\n\n"
                f"Terima kasih 🙏"
            )
            wa.send(ADMIN_WA,
                f"💰 *Pembayaran Otomatis (Midtrans)*\n\n"
                f"Nama: {p['nama']}\nBulan: {bulan}\n"
                f"Jumlah: {format_rupiah(order['amount'])}"
            )

        elif order["type"] == "upgrade_paket":
            meta = order["metadata"]
            storage.update_paket(p["id"], meta["target_paket"],
                                 meta["target_harga"], meta["target_ports"])
            wa.send(p["nomor_wa"],
                f"✅ *Upgrade Paket Berhasil!*\n\n"
                f"Halo {p['nama']}, paket VPN Anda telah diupgrade ke "
                f"*{meta['target_paket']}* ({meta['target_ports']} slot VPN).\n\n"
                f"Pembayaran: {format_rupiah(order['amount'])}\n\n"
                f"Silakan login ke portal untuk menambah VPN baru:\n"
                f"https://vpntunel.my.id/portal"
            )
            wa.send(ADMIN_WA,
                f"⬆️ *Upgrade Paket (Midtrans)*\n\n"
                f"Nama: {p['nama']}\n"
                f"Paket baru: {meta['target_paket']}\n"
                f"Jumlah: {format_rupiah(order['amount'])}"
            )

    elif failed:
        storage.update_order_status(order_id, "failed")

    return {"ok": True}
