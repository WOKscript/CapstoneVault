from pathlib import Path
import os
import socket
import dj_database_url
from dotenv import load_dotenv
from urllib.parse import urlparse

# ===== Base setup =====
BASE_DIR = Path(__file__).resolve().parent.parent  # points to /backend

# Try to load /backend/.env first (local), else fallback to root .env (Render)
local_env = BASE_DIR / ".env"
global_env = BASE_DIR.parent / ".env"

if local_env.exists():
    load_dotenv(local_env)
    print("💾 Loaded local .env (backend/.env)")
elif global_env.exists():
    load_dotenv(global_env)
    print("🌍 Loaded global .env (project root)")
else:
    print("⚠️ No .env file found — using defaults.")


# ===== Security =====
SECRET_KEY = os.getenv("SECRET_KEY", "fallback-key")
DEBUG = os.getenv("DEBUG", "False") == "True"

ALLOWED_HOSTS = ["localhost", "127.0.0.1", "capstonevault.onrender.com"]
CSRF_TRUSTED_ORIGINS = ["https://capstonevault.onrender.com"]

# ===== Installed apps =====
INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "whitenoise.runserver_nostatic",
    "widget_tweaks",
    "core",
    "colorfield",
]

# ===== Middleware =====
MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",  # must be right after SecurityMiddleware
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    "core.middleware.NoCacheForAuthMiddleware",
]

# ===== URL / WSGI =====
ROOT_URLCONF = "backend.urls"
WSGI_APPLICATION = "backend.wsgi.application"

# ===== Templates =====
TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "core" / "templates"],  # /backend/core/templates
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.debug",
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
            ],
        },
    },
]

# ===== Database (auto-switch between local & Render) =====
LOCAL_DB_URL = "postgresql://postgres:1234@localhost:5432/capstonevault_db"
DATABASE_URL = os.getenv("DATABASE_URL")

# Render sets these automatically for web services / static sites
IS_RENDER = bool(os.getenv("RENDER_EXTERNAL_HOSTNAME") or os.getenv("RENDER_EXTERNAL_URL"))

if DATABASE_URL:
    # Helpful log (safe): shows host only, not password
    try:
        print("🧩 DATABASE_URL host:", urlparse(DATABASE_URL).hostname)
    except Exception:
        pass

    if IS_RENDER:
        print("🔗 Using Render PostgreSQL (SSL enabled).")
        DATABASES = {
            "default": dj_database_url.config(
                default=DATABASE_URL,
                conn_max_age=600,
                ssl_require=True,
            )
        }
    else:
        # Local machine but DATABASE_URL provided (optional)
        print("💾 Using DATABASE_URL locally (no SSL).")
        DATABASES = {
            "default": dj_database_url.config(
                default=DATABASE_URL,
                conn_max_age=0,
                ssl_require=False,
            )
        }
else:
    print("💾 Using local PostgreSQL fallback (no SSL).")
    DATABASES = {
        "default": dj_database_url.config(
            default=LOCAL_DB_URL,
            conn_max_age=0,
            ssl_require=False,
        )
    }
# ===== Static and Media =====
# Since manage.py is inside /backend, BASE_DIR = /backend
STATIC_URL = "/static/"
STATICFILES_DIRS = [BASE_DIR / "core" / "static"]  # points to /backend/core/static
STATIC_ROOT = BASE_DIR / "staticfiles"            # /backend/staticfiles (auto-created)

MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR / "media"

# WhiteNoise - enable compressed static files for production
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

# ===== Email Configuration =====
EMAIL_BACKEND = "django.core.mail.backends.smtp.EmailBackend"
EMAIL_HOST = "smtp.gmail.com"
EMAIL_PORT = 587
EMAIL_USE_TLS = True
EMAIL_HOST_USER = os.getenv("EMAIL_HOST_USER")
EMAIL_HOST_PASSWORD = os.getenv("EMAIL_HOST_PASSWORD")
DEFAULT_FROM_EMAIL = os.getenv("DEFAULT_FROM_EMAIL")

# ===== Other settings =====
LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Manila"
USE_I18N = True
USE_TZ = True

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"
