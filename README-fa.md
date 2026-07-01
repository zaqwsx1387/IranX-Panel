# ⚡ IranX Panel

[![Python](https://img.shields.io/badge/Python-3.11-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-green)](https://fastapi.tiangolo.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow)](LICENSE)

> یک پنل سبک و قدرتمند برای مدیریت اشتراک‌های VLESS over WebSocket + TLS  
> ساخته‌شده در یک فایل Python، بر پایه FastAPI و SQLite

---

## ✨ قابلیت‌ها

### 🔐 احراز هویت
- لاگین JWT با کوکی امن
- لاگ ثبت تلاش‌های ورود

### 📡 مدیریت کاربران
- ایجاد، ویرایش، حذف کاربران
- تعیین حجم ترافیک (GB) — ۰ = نامحدود
- تعیین تاریخ انقضا (روز) — ۰ = بدون انقضا
- حداکثر اتصال همزمان
- پرچم کشور برای کاربران
- غیرفعال/فعال کردن فوری
- ریست ترافیک

### 🔗 لینک اشتراک
- لینک Subscription URL برای همه کلاینت‌ها (v2rayNG، Nekobox، هشت‌پا)
- لینک VLESS مستقیم
- پشتیبانی از چند IP تمیز در یک اشتراک

### 🌐 IP های تمیز
- افزودن تکی یا انبوه
- برچسب‌گذاری IP ها
- فعال/غیرفعال کردن هر IP
- استفاده خودکار در لینک‌های اشتراک

### 📊 داشبورد
- آمار کلی کاربران
- نمودار توزیع کاربران
- مانیتورینگ CPU، RAM، Disk، شبکه
- کاربران در حال انقضا

### 🤖 نوتیفیکیشن تلگرام
- اعلام ورود به پنل
- اعلام انقضای کاربران
- اعلام ایجاد کاربر جدید
- دوزبانه (فارسی / انگلیسی)

### ⚡ Keep-Alive
- دو حالت Simple و Advanced
- برای جلوگیری از sleep شدن سرویس

---

## 🚀 راه‌اندازی سریع

### ۱. Fork کردن ریپو

ریپو را Fork کنید به اکانت GitHub خودتان.

### ۲. Deploy روی Railway

1. به [railway.app](https://railway.app) بروید
2. **New Project** → **Deploy from GitHub repo**
3. ریپو Fork شده را انتخاب کنید
4. Railway به طور خودکار Dockerfile را شناسایی می‌کند
5. متغیرهای محیطی را تنظیم کنید:

| متغیر | مثال | توضیح |
|-------|------|-------|
| `ADMIN_USERNAME` | `admin` | نام کاربری ادمین |
| `ADMIN_PASSWORD` | `Admin@12345` | رمز عبور (حداقل ۸ کاراکتر) |
| `SECRET_KEY` | `random_string` | کلید رمزنگاری JWT |
| `DOMAIN` | `xyz.up.railway.app` | دامنه عمومی |
| `DB_PATH` | `/data/panel.db` | مسیر دیتابیس |
| `TG_BOT_TOKEN` | `123:ABC...` | توکن ربات تلگرام (اختیاری) |
| `TG_CHAT_ID` | `-100...` | Chat ID تلگرام (اختیاری) |

6. یک Volume با mount path `/data` اضافه کنید (برای ماندگاری دیتابیس)
7. دسترسی به پنل: `https://your-domain/panel`

### ۳. Deploy روی Render

از فایل `render.yaml` موجود استفاده کنید یا دستی تنظیم کنید.

---

## 📁 ساختار ریپو

| فایل | توضیح |
|------|-------|
| `main.py` | **هسته اصلی** — FastAPI backend + HTML/JS frontend |
| `Dockerfile` | ساخت image Docker |
| `requirements.txt` | وابستگی‌های Python |
| `render.yaml` | Blueprint برای Render |
| `Procfile` | دستور اجرا برای Railway/Heroku |
| `panel-config.toml` | راهنمای تنظیمات |
| `.gitignore` | قوانین git ignore |

---

## 🔧 تنظیمات VLESS

پس از deploy، در تنظیمات پنل:

- **WS Path**: مسیر WebSocket (پیش‌فرض: `/vless-ws`)
- **Domain/SNI**: دامنه شما
- **TLS Fingerprint**: `chrome` توصیه می‌شود
- **Fragment**: برای دور زدن DPI (اختیاری)

---

## ⚖️ سلب مسئولیت

این نرم‌افزار صرفاً برای اهداف شخصی، آموزشی و تحقیقاتی است.  
استفاده تجاری یا فروش دسترسی مجاز نیست.  
توسعه‌دهنده هیچ مسئولیتی در قبال سوء استفاده ندارد.

---

## 📖 README

[English](README.md) | [فارسی](README-fa.md)
