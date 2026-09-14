import os
import shutil
import subprocess
import threading
import uuid
import re
import secrets
import string
import json
import zipfile
import tempfile
import base64
import hashlib
import plistlib
import platform
from functools import wraps
from datetime import datetime, timedelta
import sqlite3
from urllib.parse import urlparse
from flask import Flask, render_template, request, jsonify, send_file, send_from_directory, redirect, url_for, session, Response
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from werkzeug.exceptions import HTTPException
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from dotenv import load_dotenv
load_dotenv()

# Firebase
import firebase_admin
from firebase_admin import credentials, auth as firebase_auth, firestore, storage as firebase_storage

# Logging & Swagger
import logging
from flasgger import Swagger
import requests
import time

# ---------------- Logging Configuration ----------------
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()

logging.basicConfig(
    level=LOG_LEVEL,
    format="%(asctime)s | %(levelname)s | %(name)s | %(message)s",
)

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Initialize Firebase Admin SDK
firebase_initialized = False
db = None

def init_firebase():
    global firebase_initialized, db
    if not firebase_initialized:
        try:
            cred = None
            # 1. Check for raw JSON string in environment variable (useful for cloud deployments)
            service_account_json = os.getenv('FIREBASE_SERVICE_ACCOUNT_JSON', '').strip()
            if service_account_json:
                try:
                    cred_dict = json.loads(service_account_json)
                    cred = credentials.Certificate(cred_dict)
                    logger.info("Loaded Firebase credentials from FIREBASE_SERVICE_ACCOUNT_JSON")
                except Exception as e:
                    logger.warning("Failed to parse FIREBASE_SERVICE_ACCOUNT_JSON: %s", e)

            # 2. Check for service account JSON file
            if not cred:
                cred_path = os.getenv('FIREBASE_SERVICE_ACCOUNT_PATH') or os.getenv('GOOGLE_APPLICATION_CREDENTIALS', 'serviceAccount.json')
                if not os.path.isabs(cred_path):
                    cred_path = os.path.join(BASE_DIR, cred_path)

                if os.path.exists(cred_path):
                    cred = credentials.Certificate(cred_path)
                    logger.info("Loaded Firebase credentials from file: %s", cred_path)

            if cred:
                app_options = {}
                storage_bucket = os.getenv('FIREBASE_STORAGE_BUCKET', '').strip()
                if storage_bucket:
                    app_options['storageBucket'] = storage_bucket

                if not firebase_admin._apps:
                    firebase_admin.initialize_app(cred, app_options if app_options else None)

                db = firestore.client()
                firebase_initialized = True
                logger.info("Firebase Admin SDK & Firestore initialized successfully")
                print("[Firebase] Admin SDK & Firestore initialized successfully")
            else:
                logger.info("Firebase credentials not found. Running in local SQLite mode.")
                print("[Firebase] Credentials not found. Running in local SQLite mode.")
        except Exception as e:
            logger.warning("Failed to initialize Firebase Admin SDK: %s", e)
            print(f"[Firebase] Warning: Failed to initialize Firebase Admin SDK: {e}")
            firebase_initialized = False
            db = None

def is_firebase_enabled():
    """Returns True if Firebase Admin SDK and Firestore are active"""
    return firebase_initialized and db is not None

# Try to initialize Firebase on module load
init_firebase()

# Firebase configuration for client-side
def get_firebase_config():
    return {
        'api_key': os.getenv('FIREBASE_API_KEY', ''),
        'auth_domain': os.getenv('FIREBASE_AUTH_DOMAIN', ''),
        'project_id': os.getenv('FIREBASE_PROJECT_ID', ''),
        'storage_bucket': os.getenv('FIREBASE_STORAGE_BUCKET', ''),
        'messaging_sender_id': os.getenv('FIREBASE_MESSAGING_SENDER_ID', ''),
        'app_id': os.getenv('FIREBASE_APP_ID', ''),
        'measurement_id': os.getenv('FIREBASE_MEASUREMENT_ID', '')
    }

# Get Firebase Storage bucket
def get_storage_bucket():
    """Get Firebase Storage bucket for file operations"""
    bucket_name = os.getenv('FIREBASE_STORAGE_BUCKET', '').strip()
    if bucket_name and firebase_initialized:
        try:
            return firebase_storage.bucket(bucket_name)
        except Exception as e:
            logger.warning("Failed to get Firebase Storage bucket %s: %s", bucket_name, e)
    return None

# Authentication decorator supporting both Flask session & Bearer tokens
def firebase_auth_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Check Flask session (Built-in Native Authentication)
        if 'user_id' in session:
            request.user = {
                'uid': session['user_id'],
                'user_id': session['user_id'],
                'name': session.get('user_name', 'User'),
                'email': session.get('user_email', '')
            }
            return f(*args, **kwargs)

        # 2. Check Bearer Token (Firebase Auth fallback if configured)
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            id_token = auth_header.split('Bearer ')[1]
            if firebase_initialized:
                try:
                    decoded_token = firebase_auth.verify_id_token(id_token)
                    request.user = decoded_token
                    return f(*args, **kwargs)
                except Exception as e:
                    logger.warning("Invalid Firebase token: %s", e)

        # If not authenticated
        return jsonify({'error': 'Authentication required. Please sign in.'}), 401

    return decorated_function

# ==================== APPLE SIGNING SECURITY ====================

class SecureAppleSigning:
    """Secure handler for Apple code signing credentials"""

    def __init__(self, build_id):
        self.build_id = build_id
        self.keychain_name = None
        self.keychain_password = None
        self.profile_uuid = None
        self.temp_files = []

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Cleanup all sensitive data on exit"""
        self.cleanup()

    def cleanup(self):
        """Securely cleanup keychain and temporary files"""
        # Delete temporary keychain
        if self.keychain_name:
            try:
                subprocess.run(
                    ['security', 'delete-keychain', self.keychain_name],
                    capture_output=True,
                    timeout=30
                )
            except Exception:
                pass

        # Remove provisioning profile from system
        if self.profile_uuid:
            try:
                profile_path = os.path.expanduser(
                    f'~/Library/MobileDevice/Provisioning Profiles/{self.profile_uuid}.mobileprovision'
                )
                if os.path.exists(profile_path):
                    os.remove(profile_path)
            except Exception:
                pass

        # Securely delete temporary files
        for temp_file in self.temp_files:
            try:
                if os.path.exists(temp_file):
                    # Overwrite with random data before deletion for security
                    with open(temp_file, 'wb') as f:
                        f.write(secrets.token_bytes(os.path.getsize(temp_file)))
                    os.remove(temp_file)
            except Exception:
                pass

        # Clear sensitive data from memory
        self.keychain_password = None

    def create_temporary_keychain(self):
        """Create a temporary keychain for this build"""
        self.keychain_name = f"swab-build-{self.build_id}.keychain-db"
        self.keychain_password = secrets.token_hex(32)

        # Create the keychain
        result = subprocess.run(
            ['security', 'create-keychain', '-p', self.keychain_password, self.keychain_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise Exception(f"Failed to create keychain: {result.stderr}")

        # Set keychain settings (no auto-lock, no timeout)
        subprocess.run(
            ['security', 'set-keychain-settings', self.keychain_name],
            capture_output=True,
            timeout=30
        )

        # Unlock the keychain
        subprocess.run(
            ['security', 'unlock-keychain', '-p', self.keychain_password, self.keychain_name],
            capture_output=True,
            timeout=30
        )

        # Add to search list (required for codesign to find it)
        result = subprocess.run(
            ['security', 'list-keychains', '-d', 'user'],
            capture_output=True,
            text=True,
            timeout=30
        )

        current_keychains = result.stdout.strip().replace('"', '').split('\n')
        current_keychains = [k.strip() for k in current_keychains if k.strip()]

        subprocess.run(
            ['security', 'list-keychains', '-d', 'user', '-s', self.keychain_name] + current_keychains,
            capture_output=True,
            timeout=30
        )

        return self.keychain_name

    def import_certificate(self, cert_path, cert_password):
        """Import a .p12 certificate into the temporary keychain"""
        if not self.keychain_name:
            self.create_temporary_keychain()

        # Validate certificate file
        if not os.path.exists(cert_path):
            raise Exception("Certificate file not found")

        if not cert_path.endswith(('.p12', '.pfx')):
            raise Exception("Invalid certificate format. Use .p12 or .pfx file")

        # Import certificate with codesign access
        result = subprocess.run(
            [
                'security', 'import', cert_path,
                '-k', self.keychain_name,
                '-P', cert_password,
                '-T', '/usr/bin/codesign',
                '-T', '/usr/bin/security',
                '-T', '/usr/bin/productbuild'
            ],
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.returncode != 0:
            if 'incorrect password' in result.stderr.lower() or 'mac verify failure' in result.stderr.lower():
                raise Exception("Invalid certificate password")
            raise Exception(f"Failed to import certificate: {result.stderr}")

        # Set key partition list to allow codesign access without prompts
        subprocess.run(
            [
                'security', 'set-key-partition-list',
                '-S', 'apple-tool:,apple:,codesign:',
                '-s', '-k', self.keychain_password,
                self.keychain_name
            ],
            capture_output=True,
            timeout=30
        )

        return True

    def validate_provisioning_profile(self, profile_path):
        """Validate and extract info from provisioning profile"""
        if not os.path.exists(profile_path):
            raise Exception("Provisioning profile not found")

        if not profile_path.endswith('.mobileprovision'):
            raise Exception("Invalid provisioning profile format")

        # Extract plist from provisioning profile
        plist_data = None
        if shutil.which('security'):
            try:
                result = subprocess.run(
                    ['security', 'cms', '-D', '-i', profile_path],
                    capture_output=True,
                    timeout=30
                )
                if result.returncode == 0:
                    plist_data = plistlib.loads(result.stdout)
            except Exception:
                pass

        if plist_data is None:
            try:
                with open(profile_path, 'rb') as pf:
                    content = pf.read()
                start = content.find(b'<?xml')
                if start == -1:
                    start = content.find(b'<plist')
                end = content.find(b'</plist>')
                if start != -1 and end != -1:
                    end += len(b'</plist>')
                    plist_data = plistlib.loads(content[start:end])
            except Exception as pe:
                raise Exception(f"Failed to parse provisioning profile: {pe}")

        if not plist_data:
            raise Exception("Invalid provisioning profile format")

        # Extract relevant information
        profile_info = {
            'uuid': plist_data.get('UUID'),
            'name': plist_data.get('Name'),
            'team_id': plist_data.get('TeamIdentifier', [None])[0],
            'bundle_id': plist_data.get('Entitlements', {}).get('application-identifier', ''),
            'expiration_date': plist_data.get('ExpirationDate'),
            'creation_date': plist_data.get('CreationDate'),
            'platform': plist_data.get('Platform', ['iOS']),
            'is_development': 'get-task-allow' in str(plist_data.get('Entitlements', {})),
        }

        # Check if profile is expired
        from datetime import datetime
        if profile_info['expiration_date']:
            if isinstance(profile_info['expiration_date'], datetime):
                if profile_info['expiration_date'] < datetime.now():
                    raise Exception("Provisioning profile has expired")

        # Extract app bundle ID (remove team prefix)
        if profile_info['bundle_id']:
            parts = profile_info['bundle_id'].split('.')
            if len(parts) > 1 and parts[0] == profile_info['team_id']:
                profile_info['app_bundle_id'] = '.'.join(parts[1:])
            else:
                profile_info['app_bundle_id'] = profile_info['bundle_id']

        self.profile_uuid = profile_info['uuid']
        return profile_info

    def install_provisioning_profile(self, profile_path):
        """Install provisioning profile to system location"""
        profile_info = self.validate_provisioning_profile(profile_path)

        # Create provisioning profiles directory if needed
        profiles_dir = os.path.expanduser('~/Library/MobileDevice/Provisioning Profiles')
        os.makedirs(profiles_dir, exist_ok=True)

        # Copy profile with UUID as filename
        dest_path = os.path.join(profiles_dir, f"{profile_info['uuid']}.mobileprovision")
        shutil.copy(profile_path, dest_path)

        self.temp_files.append(dest_path)  # Track for cleanup

        return profile_info

    def get_signing_identity(self):
        """Get the signing identity from the keychain"""
        if not self.keychain_name:
            raise Exception("No keychain created")

        result = subprocess.run(
            ['security', 'find-identity', '-v', '-p', 'codesigning', self.keychain_name],
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode != 0:
            raise Exception("Failed to find signing identity")

        # Parse the output to get identity
        lines = result.stdout.strip().split('\n')
        for line in lines:
            if 'Apple Distribution' in line or 'iPhone Distribution' in line or 'Mac Developer' in line or 'Apple Development' in line:
                # Extract the identity hash
                parts = line.split('"')
                if len(parts) >= 2:
                    return parts[1]

        raise Exception("No valid signing identity found in certificate")

    def create_export_options_plist(self, build_dir, config, profile_info):
        """Create ExportOptions.plist for xcodebuild"""

        # Determine export method based on profile type
        if profile_info.get('is_development'):
            method = 'development'
        elif 'app-store' in profile_info.get('name', '').lower():
            method = 'app-store'
        else:
            method = 'ad-hoc'

        export_options = {
            'method': method,
            'teamID': config.get('team_id') or profile_info.get('team_id'),
            'signingStyle': 'manual',
            'provisioningProfiles': {
                config.get('package_name'): profile_info.get('name') or profile_info.get('uuid')
            }
        }

        # Add additional options for App Store
        if method == 'app-store':
            export_options['uploadSymbols'] = True
            export_options['uploadBitcode'] = False

        plist_path = os.path.join(build_dir, 'ExportOptions.plist')
        with open(plist_path, 'wb') as f:
            plistlib.dump(export_options, f)

        self.temp_files.append(plist_path)
        return plist_path


def validate_apple_certificate(cert_path, password):
    """Validate a .p12 certificate file cross-platform without needing openssl/security"""
    if not os.path.exists(cert_path):
        return {'valid': False, 'error': 'Certificate file not found'}

    try:
        from cryptography.hazmat.primitives.serialization import pkcs12
        from cryptography import x509
        with open(cert_path, 'rb') as f:
            data = f.read()

        pass_bytes = password.encode('utf-8') if password else None
        key, cert, additional_certs = pkcs12.load_key_and_certificates(data, pass_bytes)

        if cert is None:
            return {'valid': False, 'error': 'No certificate found in .p12 file'}

        subject_str = cert.subject.rfc4514_string()
        cn = ""
        for attr in cert.subject:
            if attr.oid == x509.NameOID.COMMON_NAME:
                cn = attr.value
                break

        expires_str = ""
        try:
            expires_str = cert.not_valid_after_utc.strftime('%b %d, %Y')
        except AttributeError:
            expires_str = cert.not_valid_after.strftime('%b %d, %Y')

        cert_info = {
            'subject': cn or subject_str,
            'expires': expires_str
        }
        return {'valid': True, 'info': cert_info}
    except Exception as e:
        err_msg = str(e).lower()
        if 'mac' in err_msg or 'password' in err_msg or 'pkcs12' in err_msg:
            return {'valid': False, 'error': 'Invalid certificate password'}

    # Fallback to openssl CLI if available
    try:
        result = subprocess.run(
            ['openssl', 'pkcs12', '-in', cert_path, '-passin', f'pass:{password}', '-noout'],
            capture_output=True,
            text=True,
            timeout=15
        )
        if result.returncode != 0:
            if 'mac verify failure' in result.stderr.lower():
                return {'valid': False, 'error': 'Invalid password'}
            return {'valid': False, 'error': 'Invalid certificate file'}

        return {'valid': True, 'info': {'subject': 'Apple Certificate', 'expires': ''}}
    except Exception:
        return {'valid': False, 'error': 'Invalid password or corrupted .p12 certificate'}


def is_macos():
    """Check if running on macOS (required for Apple signing)"""
    return platform.system() == 'Darwin'

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, 'templates', 'ui'))
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET_KEY', 'iewebnative-secret-key-2026-prod-auth-system')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['UPLOAD_FOLDER'] = os.path.join(BASE_DIR, 'uploads')
app.config['BUILD_FOLDER'] = os.path.join(BASE_DIR, 'builds')
app.config['FLUTTER_TEMPLATE'] = os.path.join(BASE_DIR, 'templates', 'webview_app')
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file size

# ===== SQLite Database Setup (Built-in Auth & Local Project Storage) =====
SQLITE_DB_PATH = os.path.join(BASE_DIR, 'app.db')

def get_db_connection():
    """Get connection to SQLite database with Row factory"""
    conn = sqlite3.connect(SQLITE_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_sqlite_db():
    """Create SQLite tables for users, projects, and builds if they don't exist"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS projects (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                web_url TEXT,
                description TEXT,
                app_version TEXT DEFAULT '1.0.0',
                build_number INTEGER DEFAULT 1,
                package_name TEXT,
                icon_url TEXT,
                splash_url TEXT,
                settings_json TEXT,
                keystore_json TEXT,
                apple_json TEXT,
                builds_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        ''')
        # Ensure builds_json and error_url columns exist if projects table was previously created without them
        try:
            cols = [col[1] for col in cursor.execute('PRAGMA table_info(projects)').fetchall()]
            if 'builds_json' not in cols:
                cursor.execute('ALTER TABLE projects ADD COLUMN builds_json TEXT')
            if 'error_url' not in cols:
                cursor.execute('ALTER TABLE projects ADD COLUMN error_url TEXT')
        except Exception as col_err:
            logger.debug(f"Column check notice: {col_err}")

        # Ensure picture column exists in users table
        try:
            user_cols = [col[1] for col in cursor.execute('PRAGMA table_info(users)').fetchall()]
            if 'picture' not in user_cols:
                cursor.execute('ALTER TABLE users ADD COLUMN picture TEXT')
        except Exception as user_col_err:
            logger.debug(f"User column check notice: {user_col_err}")

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS builds (
                id TEXT PRIMARY KEY,
                project_id TEXT,
                user_id TEXT NOT NULL,
                app_name TEXT,
                platform TEXT NOT NULL,
                status TEXT NOT NULL,
                outputs_json TEXT,
                artifacts_json TEXT,
                created_at TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("SQLite database initialized at %s", SQLITE_DB_PATH)
    except Exception as e:
        logger.error("Failed to initialize SQLite database: %s", e)

init_sqlite_db()

# ===== Webhook Helper =====

def send_webhook_notification(webhook_url, payload):
    """Send webhook notification in a safe, non-blocking way."""
    if not webhook_url:
        return

    try:
        response = requests.post(
            webhook_url,
            json=payload,
            timeout=5
        )
        response.raise_for_status()
    except Exception as e:
        app.logger.warning(f"Webhook notification failed: {e}")

# ---------------- Swagger Configuration ----------------

swagger_config = {
    "headers": [],
    "specs": [
        {
            "endpoint": "apispec",
            "route": "/apispec.json",
            "rule_filter": lambda rule: True,
            "model_filter": lambda tag: True,
        }
    ],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/",
}

Swagger(app, config=swagger_config)

# ---------------- Global Error Handlers ----------------

@app.errorhandler(Exception)
def handle_exception(e):
    if isinstance(e, HTTPException):
        return e
    logger.exception("Unhandled exception occurred")
    return jsonify({
        "success": False,
        "error": "Internal server error"
    }), 500

@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(BASE_DIR, 'static', 'images'), 'logo.png', mimetype='image/png')

# Ensure directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['BUILD_FOLDER'], exist_ok=True)

# Store build progress
build_progress = {}
ACTIVE_BUILD_PROCESSES = {}  # build_id -> list of subprocess.Popen

class BuildCancelledException(Exception):
    """Raised when a build is cancelled by the user."""
    pass

def is_build_cancelled(build_id):
    """Check if cancellation was requested for build_id"""
    bp = build_progress.get(build_id, {})
    return bp.get('cancel_requested') is True or bp.get('status') == 'cancelled'

def check_build_cancelled(build_id):
    """Raise BuildCancelledException if cancellation was requested"""
    if is_build_cancelled(build_id):
        raise BuildCancelledException("Build cancelled by user.")

def set_build_progress(build_id, status=None, progress=None, message=None, **kwargs):
    """Safely update build progress dictionary without losing metadata or overwriting cancellation"""
    if build_id not in build_progress:
        build_progress[build_id] = {}
    bp = build_progress[build_id]
    if bp.get('cancel_requested') is True or bp.get('status') == 'cancelled':
        return
    if status is not None:
        bp['status'] = status
    if progress is not None:
        bp['progress'] = progress
    if message is not None:
        bp['message'] = message
    bp.update(kwargs)

# SWAB file encryption key derived from machine-specific identifier
SWAB_SALT = b'swab_project_file_v1'

def get_machine_key():
    """Generate a machine-specific encryption key"""
    # Combine multiple machine identifiers for uniqueness
    machine_id = f"{os.getenv('USER', 'user')}_{os.path.expanduser('~')}_{BASE_DIR}"
    machine_hash = hashlib.sha256(machine_id.encode()).digest()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SWAB_SALT,
        iterations=480000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(machine_hash))
    return Fernet(key)

def encrypt_data(data: bytes) -> bytes:
    """Encrypt data using machine-specific key"""
    fernet = get_machine_key()
    return fernet.encrypt(data)

def decrypt_data(data: bytes) -> bytes:
    """Decrypt data using machine-specific key"""
    fernet = get_machine_key()
    return fernet.decrypt(data)

def sanitize_package_name(name):
    """Sanitize package name for Android/iOS"""
    return re.sub(r'[^a-zA-Z0-9_.]', '', name).lower()

def generate_password(length=16):
    """Generate a secure random password"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def generate_keystore(build_dir, config):
    """Generate a new Android keystore using keytool"""
    keystore_dir = os.path.join(build_dir, 'keystore')
    os.makedirs(keystore_dir, exist_ok=True)

    keystore_path = os.path.join(keystore_dir, 'release-keystore.jks')
    keystore_password = generate_password()
    key_alias = 'release'
    key_password = keystore_password  # Using same password for simplicity

    # Get app details for the certificate
    app_name = config.get('app_name', 'App')
    package_name = config.get('package_name', 'com.example.app')

    # Extract organization from package name
    package_parts = package_name.split('.')
    org_name = package_parts[1] if len(package_parts) > 1 else 'example'

    # Build the keytool command
    dname = f"CN={app_name}, OU=Mobile, O={org_name.capitalize()}, L=Unknown, ST=Unknown, C=US"

    keytool_cmd = [
        'keytool',
        '-genkeypair',
        '-v',
        '-keystore', keystore_path,
        '-keyalg', 'RSA',
        '-keysize', '2048',
        '-validity', '10000',
        '-alias', key_alias,
        '-storepass', keystore_password,
        '-keypass', key_password,
        '-dname', dname
    ]

    try:
        result = subprocess.run(
            keytool_cmd,
            capture_output=True,
            text=True,
            timeout=30
        )

        if result.returncode == 0 and os.path.exists(keystore_path):
            # Save keystore info to a file for user reference
            info_path = os.path.join(keystore_dir, 'keystore-info.txt')
            with open(info_path, 'w') as f:
                f.write("=== Android Keystore Information ===\n\n")
                f.write("IMPORTANT: Save this information securely!\n")
                f.write("You will need these credentials to update your app in the future.\n\n")
                f.write(f"Keystore File: release-keystore.jks\n")
                f.write(f"Keystore Password: {keystore_password}\n")
                f.write(f"Key Alias: {key_alias}\n")
                f.write(f"Key Password: {key_password}\n")
                f.write(f"\nGenerated for: {app_name} ({package_name})\n")

            return {
                'path': keystore_path,
                'password': keystore_password,
                'alias': key_alias,
                'key_password': key_password,
                'info_path': info_path
            }
    except subprocess.TimeoutExpired:
        pass
    except FileNotFoundError:
        # keytool not found
        pass

    return None

def setup_app_icon(project_dir, icon_path, build_id):
    """Setup app icon using icons_launcher package"""
    if not icon_path or not os.path.exists(icon_path):
        return False

    try:
        # Copy icon to project assets
        assets_dir = os.path.join(project_dir, 'assets')
        os.makedirs(assets_dir, exist_ok=True)

        icon_dest = os.path.join(assets_dir, 'icon.png')
        shutil.copy(icon_path, icon_dest)

        # Create icons_launcher.yaml configuration
        icons_config = f"""icons_launcher:
  image_path: "assets/icon.png"
  platforms:
    android:
      enable: true
    ios:
      enable: true
    macos:
      enable: true
    windows:
      enable: true
    linux:
      enable: true
    web:
      enable: true
"""
        config_path = os.path.join(project_dir, 'icons_launcher.yaml')
        with open(config_path, 'w') as f:
            f.write(icons_config)

        # Add icons_launcher to dev_dependencies in pubspec.yaml
        pubspec_path = os.path.join(project_dir, 'pubspec.yaml')
        with open(pubspec_path, 'r') as f:
            pubspec_content = f.read()

        # Add icons_launcher if not present
        if 'icons_launcher:' not in pubspec_content:
            pubspec_content = pubspec_content.replace(
                'dev_dependencies:',
                'dev_dependencies:\n  icons_launcher: ^3.0.0'
            )
            with open(pubspec_path, 'w') as f:
                f.write(pubspec_content)

        # Try local Pillow generation first (instant, works without Flutter SDK)
        try:
            from PIL import Image
            img = Image.open(icon_path).convert('RGBA')
            sizes = {
                'mipmap-mdpi': (48, 48),
                'mipmap-hdpi': (72, 72),
                'mipmap-xhdpi': (96, 96),
                'mipmap-xxhdpi': (144, 144),
                'mipmap-xxxhdpi': (192, 192)
            }
            res_dir = os.path.join(project_dir, 'android', 'app', 'src', 'main', 'res')
            for folder, size in sizes.items():
                target_dir = os.path.join(res_dir, folder)
                os.makedirs(target_dir, exist_ok=True)
                resized = img.resize(size, Image.Resampling.LANCZOS)
                resized.save(os.path.join(target_dir, 'ic_launcher.png'), 'PNG')

            # Windows icon (.ico)
            win_res_dir = os.path.join(project_dir, 'windows', 'runner', 'resources')
            if os.path.exists(win_res_dir):
                win_ico_path = os.path.join(win_res_dir, 'app_icon.ico')
                img.save(win_ico_path, format='ICO', sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
                logger.info("Successfully generated Windows app_icon.ico using Pillow")

            logger.info("Successfully generated Android and Windows icons using Pillow")
        except Exception as pe:
            logger.info(f"Pillow icon generation skipped or failed: {pe}")

        # If local flutter is available, run icons_launcher
        if shutil.which('flutter'):
            subprocess.run(
                ['flutter', 'pub', 'get'],
                cwd=project_dir,
                capture_output=True,
                timeout=120
            )
            subprocess.run(
                ['dart', 'run', 'icons_launcher:create'],
                cwd=project_dir,
                capture_output=True,
                text=True,
                timeout=120
            )

        return True
    except Exception as e:
        print(f"Icon setup error: {e}")
        return False

def rename_app(project_dir, app_name, package_name):
    """Rename app using the rename package"""
    try:
        # Add rename to dev_dependencies
        pubspec_path = os.path.join(project_dir, 'pubspec.yaml')
        with open(pubspec_path, 'r') as f:
            pubspec_content = f.read()

        if 'rename:' not in pubspec_content:
            pubspec_content = pubspec_content.replace(
                'dev_dependencies:',
                'dev_dependencies:\n  rename: ^3.0.2'
            )
            with open(pubspec_path, 'w') as f:
                f.write(pubspec_content)

        # Run flutter pub get
        subprocess.run(
            ['flutter', 'pub', 'get'],
            cwd=project_dir,
            capture_output=True,
            timeout=120
        )

        # Rename app name for all platforms
        subprocess.run(
            ['dart', 'run', 'rename', 'setAppName', '--value', app_name],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        # Rename bundle ID/package name for all platforms
        subprocess.run(
            ['dart', 'run', 'rename', 'setBundleId', '--value', package_name],
            cwd=project_dir,
            capture_output=True,
            text=True,
            timeout=60
        )

        return True
    except Exception as e:
        print(f"Rename error: {e}")
        return False

def build_via_github_actions(build_id, project_dir, build_dir, config, target_platform='android'):
    """Trigger GitHub Actions cloud build and download the resulting APK or Windows Zip"""
    github_token = os.getenv('GITHUB_TOKEN')
    github_owner = os.getenv('GITHUB_OWNER', 'ieenterprises')
    github_repo = os.getenv('GITHUB_REPO', 'iewebnative-builds')

    if not github_token:
        raise RuntimeError("GitHub Token is not configured in .env for cloud builds.")

    headers = {
        'Authorization': f'Bearer {github_token}',
        'Accept': 'application/vnd.github.v3+json'
    }

    if target_platform == 'windows':
        branch_name = f"build-windows-{build_id[:8]}"
        platform_label = "Windows Application"
    elif target_platform == 'ios':
        branch_name = f"build-ios-{build_id[:8]}"
        platform_label = "iOS Application (.ipa)"
    elif target_platform == 'macos':
        branch_name = f"build-macos-{build_id[:8]}"
        platform_label = "macOS Application (.dmg)"
    elif target_platform == 'linux':
        branch_name = f"build-linux-{build_id[:8]}"
        platform_label = "Linux Application"
    elif target_platform == 'android_aab':
        branch_name = f"build-android-{build_id[:8]}"
        platform_label = "Android App Bundle (.aab)"
    else:
        branch_name = f"build-android-{build_id[:8]}"
        platform_label = "Android APK"

    # Attach Apple credentials if building iOS with signing
    if target_platform == 'ios':
        cert_path = config.get('apple_certificate_path')
        profile_path = config.get('apple_provisioning_profile_path')
        cert_pass = config.get('apple_certificate_password', '')
        if cert_path and os.path.exists(cert_path) and profile_path and os.path.exists(profile_path):
            signing_dir = os.path.join(project_dir, 'ios_signing')
            os.makedirs(signing_dir, exist_ok=True)
            shutil.copy(cert_path, os.path.join(signing_dir, 'certificate.p12'))
            shutil.copy(profile_path, os.path.join(signing_dir, 'profile.mobileprovision'))
            if cert_pass:
                with open(os.path.join(signing_dir, 'password.txt'), 'w', encoding='utf-8') as pf:
                    pf.write(cert_pass)
            logger.info(f"Attached Apple signing credentials to iOS cloud build {build_id}.")

    # Attach Google Play publishing credentials if configured
    is_android_build = (target_platform in ('android', 'android_aab') or
                        'android' in config.get('platforms', []) or
                        'android_aab' in config.get('platforms', []))
    if is_android_build and config.get('enable_google_play_publish'):
        play_key_path = config.get('play_service_account_path')
        if play_key_path and os.path.exists(play_key_path):
            publishing_dir = os.path.join(project_dir, 'store_publishing')
            os.makedirs(publishing_dir, exist_ok=True)
            shutil.copy(play_key_path, os.path.join(publishing_dir, 'google_play_key.json'))
            play_config = {
                'track': config.get('play_track', 'internal'),
                'status': config.get('play_status', 'draft'),
                'package_name': config.get('package_name', '')
            }
            with open(os.path.join(publishing_dir, 'play_config.json'), 'w', encoding='utf-8') as pf:
                json.dump(play_config, pf, indent=2)
            logger.info(f"Attached Google Play publishing credentials to cloud build {build_id}.")

    # Attach App Store Connect publishing credentials if configured
    if target_platform == 'ios' and config.get('enable_app_store_publish'):
        app_store_key_path = config.get('app_store_key_path')
        app_store_key_id = config.get('app_store_key_id')
        app_store_issuer_id = config.get('app_store_issuer_id')
        if app_store_key_path and os.path.exists(app_store_key_path) and app_store_key_id and app_store_issuer_id:
            publishing_dir = os.path.join(project_dir, 'store_publishing')
            os.makedirs(publishing_dir, exist_ok=True)
            shutil.copy(app_store_key_path, os.path.join(publishing_dir, 'app_store_key.p8'))
            app_store_config = {
                'key_id': app_store_key_id,
                'issuer_id': app_store_issuer_id
            }
            with open(os.path.join(publishing_dir, 'app_store_config.json'), 'w', encoding='utf-8') as af:
                json.dump(app_store_config, af, indent=2)
            logger.info(f"Attached App Store Connect publishing credentials to cloud build {build_id}.")

    remote_url = f"https://x-access-token:{github_token}@github.com/{github_owner}/{github_repo}.git"

    check_build_cancelled(build_id)
    set_build_progress(
        build_id,
        status='building',
        progress=25,
        message=f'Preparing {platform_label} build in Cloud Builder...'
    )

    # Ensure git is initialized in project_dir
    subprocess.run(['git', 'init'], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.name', 'ieWebNative Cloud Builder'], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'config', 'user.email', 'iewebnative-cloud@build.local'], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'checkout', '-b', branch_name], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'add', '-A'], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'commit', '-m', f"Build {config['app_name']} ({build_id}) for {platform_label}"], cwd=project_dir, check=True, capture_output=True)
    subprocess.run(['git', 'remote', 'add', 'origin', remote_url], cwd=project_dir, check=True, capture_output=True)

    check_build_cancelled(build_id)
    push_res = subprocess.run(['git', '-c', 'credential.helper=', 'push', '-u', 'origin', branch_name, '--force'], cwd=project_dir, capture_output=True, text=True)
    if push_res.returncode != 0:
        raise RuntimeError(f"Failed to push build branch to remote: {push_res.stderr}")

    logger.info(f"Pushed branch {branch_name} to remote. Waiting for workflow run...")
    check_build_cancelled(build_id)
    set_build_progress(
        build_id,
        status='building',
        progress=35,
        message='Cloud build server queued...'
    )

    # Wait for workflow run to start on branch
    run_id = None
    start_wait = time.time()
    while time.time() - start_wait < 60:
        check_build_cancelled(build_id)
        time.sleep(3)
        try:
            r = requests.get(
                f"https://api.github.com/repos/{github_owner}/{github_repo}/actions/runs?branch={branch_name}",
                headers=headers,
                timeout=15
            )
            if r.status_code == 200:
                runs = r.json().get('workflow_runs', [])
                if runs:
                    run_id = runs[0]['id']
                    break
        except Exception as e:
            if isinstance(e, BuildCancelledException):
                raise
            logger.warning(f"Error checking workflow runs: {e}")

    check_build_cancelled(build_id)
    if not run_id:
        raise RuntimeError("Cloud build workflow run did not start within 60 seconds.")

    logger.info(f"Workflow run {run_id} started for branch {branch_name}.")
    if build_id in build_progress:
        build_progress[build_id]['github_run_id'] = run_id

    # Poll workflow run until completion (timeout 25 mins)
    start_run = time.time()
    while time.time() - start_run < 1500:
        check_build_cancelled(build_id)
        time.sleep(5)
        try:
            # Check if cancellation was requested
            if is_build_cancelled(build_id):
                try:
                    requests.post(
                        f"https://api.github.com/repos/{github_owner}/{github_repo}/actions/runs/{run_id}/cancel",
                        headers=headers,
                        timeout=10
                    )
                except Exception:
                    pass
                raise BuildCancelledException("Build cancelled by user.")

            r = requests.get(
                f"https://api.github.com/repos/{github_owner}/{github_repo}/actions/runs/{run_id}",
                headers=headers,
                timeout=15
            )
            if r.status_code != 200:
                continue

            run_data = r.json()
            run_status = run_data.get('status')
            run_conclusion = run_data.get('conclusion')

            if run_status == 'in_progress':
                elapsed = time.time() - start_run
                current_pct = min(88, int(40 + (elapsed / 240.0) * 45))
                set_build_progress(
                    build_id,
                    status='building',
                    progress=current_pct,
                    message=f"Compiling {platform_label} on Cloud Server... ({int(elapsed)}s)"
                )
            elif run_status == 'completed':
                if run_conclusion == 'success':
                    set_build_progress(
                        build_id,
                        status='building',
                        progress=92,
                        message=f'Build succeeded! Downloading {platform_label} files...'
                    )
                    break
                else:
                    raise RuntimeError(f"Cloud build failed (conclusion: {run_conclusion}).")
        except Exception as e:
            if isinstance(e, BuildCancelledException) or "Cloud build failed" in str(e) or "Build cancelled by user" in str(e):
                raise
            logger.warning(f"Polling error: {e}")

    output_dir = os.path.join(build_dir, 'outputs')
    os.makedirs(output_dir, exist_ok=True)
    if target_platform == 'windows':
        final_output_path = os.path.join(output_dir, f"{config['app_name']}_windows.zip")
    elif target_platform == 'ios':
        final_output_path = os.path.join(output_dir, f"{config['app_name']}.ipa")
        xcode_output_path = os.path.join(output_dir, f"{config['app_name']}_xcode_project.zip")
    elif target_platform == 'macos':
        final_output_path = os.path.join(output_dir, f"{config['app_name']}_macos.dmg")
    elif target_platform == 'linux':
        final_output_path = os.path.join(output_dir, f"{config['app_name']}_linux.tar.gz")
    elif target_platform == 'android_aab':
        final_output_path = os.path.join(output_dir, f"{config['app_name']}.aab")
    else:
        final_output_path = os.path.join(output_dir, f"{config['app_name']}.apk")

    downloaded = False
    # Method 1: Check GitHub Releases
    try:
        r_rel = requests.get(
            f"https://api.github.com/repos/{github_owner}/{github_repo}/releases",
            headers=headers,
            timeout=15
        )
        if r_rel.status_code == 200:
            releases = r_rel.json()
            for rel in releases:
                if branch_name in rel.get('tag_name', ''):
                    for asset in rel.get('assets', []):
                        name_lower = asset['name'].lower()
                        match = False
                        if target_platform == 'windows':
                            match = name_lower.endswith('.zip') or 'windows' in name_lower
                        elif target_platform == 'macos':
                            match = name_lower.endswith('.dmg') or 'macos' in name_lower
                            if name_lower.endswith('.zip') and not name_lower.endswith('.dmg'):
                                final_output_path = os.path.join(output_dir, f"{config['app_name']}_macos.zip")
                        elif target_platform == 'linux':
                            match = name_lower.endswith('.tar.gz') or 'linux' in name_lower
                            if name_lower.endswith('.zip'):
                                final_output_path = os.path.join(output_dir, f"{config['app_name']}_linux.zip")
                        elif target_platform == 'ios':
                            match = name_lower.endswith('.ipa')
                            # Also check for companion Xcode project zip
                            if 'xcode' in name_lower and name_lower.endswith('.zip'):
                                if build_id in build_progress:
                                    build_progress[build_id].setdefault('github_download_urls', {})['ios_xcode'] = asset['browser_download_url']
                                try:
                                    with requests.get(asset['browser_download_url'], stream=True, timeout=120) as r_xc:
                                        r_xc.raise_for_status()
                                        with open(xcode_output_path, 'wb') as f_xc:
                                            for chunk in r_xc.iter_content(chunk_size=65536):
                                                if chunk:
                                                    f_xc.write(chunk)
                                    logger.info(f"Downloaded companion Xcode project: {xcode_output_path}")
                                except Exception as xce:
                                    logger.warning(f"Could not download Xcode project release asset: {xce}")
                        elif target_platform == 'android_aab':
                            match = name_lower.endswith('.aab')
                        else:
                            match = name_lower.endswith('.apk')
                            if name_lower.endswith('.aab'):
                                if build_id in build_progress:
                                    build_progress[build_id].setdefault('github_download_urls', {})['android_aab'] = asset['browser_download_url']
                                try:
                                    aab_path = os.path.join(output_dir, f"{config['app_name']}.aab")
                                    with requests.get(asset['browser_download_url'], stream=True, timeout=120) as r_aab:
                                        r_aab.raise_for_status()
                                        with open(aab_path, 'wb') as f_aab:
                                            for chunk in r_aab.iter_content(chunk_size=65536):
                                                if chunk:
                                                    f_aab.write(chunk)
                                    logger.info(f"Downloaded companion AAB: {aab_path}")
                                except Exception as aabe:
                                    logger.warning(f"Could not download AAB release asset: {aabe}")

                        if match:
                            download_url = asset['browser_download_url']
                            if build_id in build_progress:
                                build_progress[build_id].setdefault('github_download_urls', {})[target_platform] = download_url
                            with requests.get(download_url, stream=True, timeout=120) as r_file:
                                r_file.raise_for_status()
                                with open(final_output_path, 'wb') as f_out:
                                    for chunk in r_file.iter_content(chunk_size=65536):
                                        if chunk:
                                            f_out.write(chunk)
                            downloaded = True
                            if target_platform != 'ios' and target_platform != 'android':
                                break
                    if downloaded:
                        break
    except Exception as e:
        logger.warning(f"Could not download release asset: {e}")

    # Method 2: Check Actions Artifacts
    if not downloaded:
        try:
            r_art = requests.get(
                f"https://api.github.com/repos/{github_owner}/{github_repo}/actions/runs/{run_id}/artifacts",
                headers=headers,
                timeout=15
            )
            if r_art.status_code == 200:
                artifacts = r_art.json().get('artifacts', [])
                for art in artifacts:
                    name_lower = art['name'].lower()
                    art_match = False
                    if target_platform == 'windows':
                        art_match = 'windows' in name_lower
                    elif target_platform == 'macos':
                        art_match = 'macos' in name_lower
                    elif target_platform == 'linux':
                        art_match = 'linux' in name_lower
                    elif target_platform == 'ios':
                        art_match = 'ipa' in name_lower
                    elif target_platform == 'android_aab':
                        art_match = 'bundle' in name_lower or 'aab' in name_lower
                    else:
                        art_match = 'apk' in name_lower or 'app-release' in name_lower
                        if 'bundle' in name_lower or 'aab' in name_lower:
                            try:
                                art_zip_url = art['archive_download_url']
                                art_res = requests.get(art_zip_url, headers=headers, stream=True, timeout=120)
                                art_res.raise_for_status()
                                aab_zip = os.path.join(output_dir, 'aab_artifact.zip')
                                with open(aab_zip, 'wb') as f_aabz:
                                    for chunk in art_res.iter_content(chunk_size=65536):
                                        if chunk:
                                            f_aabz.write(chunk)
                                aab_path = os.path.join(output_dir, f"{config['app_name']}.aab")
                                with zipfile.ZipFile(aab_zip, 'r') as zf:
                                    for m in zf.namelist():
                                        if m.endswith('.aab'):
                                            with zf.open(m) as src, open(aab_path, 'wb') as dst:
                                                shutil.copyfileobj(src, dst)
                                            break
                                if os.path.exists(aab_zip):
                                    os.remove(aab_zip)
                            except Exception as aab_err:
                                logger.warning(f"Could not extract AAB from artifact: {aab_err}")

                    if art_match:
                        art_zip_url = art['archive_download_url']
                        art_res = requests.get(art_zip_url, headers=headers, stream=True, timeout=120)
                        art_res.raise_for_status()
                        zip_temp_path = os.path.join(output_dir, 'artifact.zip')
                        with open(zip_temp_path, 'wb') as f_zip:
                            for chunk in art_res.iter_content(chunk_size=65536):
                                if chunk:
                                    f_zip.write(chunk)

                        if target_platform == 'windows':
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                names = zip_ref.namelist()
                                zip_members = [m for m in names if m.endswith('.zip')]
                                if zip_members:
                                    with zip_ref.open(zip_members[0]) as source, open(final_output_path, 'wb') as target:
                                        shutil.copyfileobj(source, target)
                                    downloaded = True
                                else:
                                    shutil.copyfile(zip_temp_path, final_output_path)
                                    downloaded = True
                        elif target_platform == 'macos':
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                for member in zip_ref.namelist():
                                    if member.endswith('.dmg'):
                                        with zip_ref.open(member) as source, open(final_output_path, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        downloaded = True
                                        break
                                    elif member.endswith('.zip'):
                                        zip_out = os.path.join(output_dir, f"{config['app_name']}_macos.zip")
                                        with zip_ref.open(member) as source, open(zip_out, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        final_output_path = zip_out
                                        downloaded = True
                                        break
                        elif target_platform == 'linux':
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                for member in zip_ref.namelist():
                                    if member.endswith('.tar.gz') or member.endswith('.zip'):
                                        with zip_ref.open(member) as source, open(final_output_path, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        downloaded = True
                                        break
                        elif target_platform == 'ios':
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                for member in zip_ref.namelist():
                                    if member.endswith('.ipa'):
                                        with zip_ref.open(member) as source, open(final_output_path, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        downloaded = True
                                        break
                        elif target_platform == 'android_aab':
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                for member in zip_ref.namelist():
                                    if member.endswith('.aab'):
                                        with zip_ref.open(member) as source, open(final_output_path, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        downloaded = True
                                        break
                        else:
                            with zipfile.ZipFile(zip_temp_path, 'r') as zip_ref:
                                for member in zip_ref.namelist():
                                    if member.endswith('.apk'):
                                        with zip_ref.open(member) as source, open(final_output_path, 'wb') as target:
                                            shutil.copyfileobj(source, target)
                                        downloaded = True
                                        break
                        if os.path.exists(zip_temp_path):
                            os.remove(zip_temp_path)
                        if downloaded and target_platform != 'ios' and target_platform != 'android':
                            break

                # Also look for xcode project artifact in iOS builds
                if target_platform == 'ios':
                    for art in artifacts:
                        if 'xcode' in art['name'].lower():
                            try:
                                art_zip_url = art['archive_download_url']
                                art_res = requests.get(art_zip_url, headers=headers, stream=True, timeout=120)
                                art_res.raise_for_status()
                                with open(xcode_output_path, 'wb') as f_xc:
                                    for chunk in art_res.iter_content(chunk_size=65536):
                                        if chunk:
                                            f_xc.write(chunk)
                                logger.info(f"Downloaded companion Xcode project artifact: {xcode_output_path}")
                            except Exception as xce:
                                logger.warning(f"Could not download Xcode artifact: {xce}")
        except Exception as e:
            logger.warning(f"Could not download artifact: {e}")

    if not downloaded or not os.path.exists(final_output_path):
        raise RuntimeError(f"Cloud build finished, but could not download the {platform_label} artifact.")

    # Clean up remote branch
    try:
        requests.delete(
            f"https://api.github.com/repos/{github_owner}/{github_repo}/git/refs/heads/{branch_name}",
            headers=headers,
            timeout=10
        )
    except Exception as e:
        logger.warning(f"Failed to delete remote branch {branch_name}: {e}")

    return final_output_path

def record_completed_build(build_id, config, final_status):
    """
    Saves completed build outputs (.apk, .aab, .ipa, windows, macos, linux)
    and associates them with the user project in Firestore and SQLite.
    Also uploads the binary to Firebase Storage if configured.
    """
    try:
        user_id = config.get('user_id')
        project_id = config.get('project_id')
        app_name = config.get('app_name', 'Untitled App')
        outputs = final_status.get('outputs', {})
        if not outputs:
            return

        now_iso = datetime.utcnow().isoformat()

        # If project_id not given, try to find or create project for this user
        if not project_id and user_id:
            web_url = config.get('web_url', '')
            if db:
                try:
                    p_query = db.collection('projects').where('userId', '==', user_id).stream()
                    for doc in p_query:
                        p_data = doc.to_dict()
                        if p_data.get('name') == app_name or (web_url and p_data.get('webUrl') == web_url):
                            project_id = doc.id
                            break
                except Exception as e:
                    logger.warning(f"Error finding existing project in Firestore: {e}")

            if not project_id:
                try:
                    conn = get_db_connection()
                    row = conn.execute(
                        'SELECT id FROM projects WHERE user_id = ? AND (name = ? OR (web_url != "" AND web_url = ?))',
                        (user_id, app_name, web_url)
                    ).fetchone()
                    conn.close()
                    if row:
                        project_id = row['id']
                except Exception as e:
                    logger.warning(f"Error finding existing project in SQLite: {e}")

            # If still no project, auto-create one
            if not project_id and user_id:
                project_id = str(uuid.uuid4())
                if db:
                    try:
                        new_proj = {
                            'userId': user_id,
                            'name': app_name,
                            'webUrl': web_url,
                            'description': config.get('app_description', ''),
                            'appVersion': config.get('app_version', '1.0.0'),
                            'buildNumber': config.get('build_number', 1),
                            'packageName': config.get('package_name', ''),
                            'iconUrl': config.get('icon_path', ''),
                            'settings': {},
                            'builds': {},
                            'createdAt': firestore.SERVER_TIMESTAMP,
                            'updatedAt': firestore.SERVER_TIMESTAMP
                        }
                        db.collection('projects').document(project_id).set(new_proj)
                    except Exception as e:
                        logger.warning(f"Error auto-creating project in Firestore: {e}")

                try:
                    conn = get_db_connection()
                    conn.execute('''
                        INSERT INTO projects (id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, settings_json, created_at, updated_at)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (project_id, user_id, app_name, web_url, config.get('app_description', ''), config.get('app_version', '1.0.0'), config.get('build_number', 1), config.get('package_name', ''), config.get('icon_path', ''), '{}', now_iso, now_iso))
                    conn.commit()
                    conn.close()
                except Exception as e:
                    logger.warning(f"Error auto-creating project in SQLite: {e}")

        # Extract GitHub release download URLs if available
        gh_urls = final_status.get('github_download_urls') or (build_progress.get(build_id, {}).get('github_download_urls') if build_id in build_progress else {}) or {}

        # Construct platform build artifacts
        platform_artifacts = {}
        for plat, output_path in outputs.items():
            if not output_path or output_path.startswith('Error:'):
                continue

            file_name = os.path.basename(output_path)
            file_size = 0
            human_size = ''
            if os.path.exists(output_path):
                file_size = os.path.getsize(output_path)
                if file_size < 1024 * 1024:
                    human_size = f"{file_size / 1024:.1f} KB"
                else:
                    human_size = f"{file_size / (1024 * 1024):.1f} MB"

            artifact = {
                'buildId': build_id,
                'platform': plat,
                'fileName': file_name,
                'fileSize': file_size,
                'fileSizeFormatted': human_size,
                'downloadUrl': f"/api/build/{build_id}/download/{plat}",
                'builtAt': now_iso,
                'status': 'completed'
            }
            if gh_urls.get(plat):
                artifact['githubDownloadUrl'] = gh_urls[plat]

            platform_artifacts[plat] = artifact

        if not platform_artifacts:
            return

        # 1. Update SQLite
        try:
            conn = get_db_connection()
            # Save build record
            conn.execute('''
                INSERT OR REPLACE INTO builds (id, project_id, user_id, app_name, platform, status, outputs_json, artifacts_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                build_id,
                project_id or '',
                user_id or '',
                app_name,
                list(platform_artifacts.keys())[0] if platform_artifacts else 'unknown',
                'completed',
                json.dumps(outputs),
                json.dumps(platform_artifacts),
                now_iso
            ))

            # Update project's builds_json if project exists (merging)
            if project_id:
                proj_row = conn.execute('SELECT builds_json FROM projects WHERE id = ?', (project_id,)).fetchone()
                existing_builds = {}
                if proj_row and proj_row['builds_json']:
                    try:
                        existing_builds = json.loads(proj_row['builds_json'])
                    except Exception:
                        existing_builds = {}
                existing_builds.update(platform_artifacts)
                conn.execute('UPDATE projects SET builds_json = ?, updated_at = ? WHERE id = ?', (json.dumps(existing_builds), now_iso, project_id))
            conn.commit()
            conn.close()
            logger.info(f"Recorded completed build {build_id} in SQLite for project {project_id}")
        except Exception as sqle:
            logger.warning(f"Error saving build to SQLite: {sqle}")

        # 2. Update Firestore
        if db:
            try:
                # Save to builds collection
                build_doc = {
                    'id': build_id,
                    'projectId': project_id or '',
                    'userId': user_id or '',
                    'appName': app_name,
                    'platforms': list(platform_artifacts.keys()),
                    'status': 'completed',
                    'outputs': outputs,
                    'artifacts': platform_artifacts,
                    'createdAt': firestore.SERVER_TIMESTAMP
                }
                db.collection('builds').document(build_id).set(build_doc)

                # Update project doc with new platform builds (merging so other platforms are preserved!)
                if project_id:
                    proj_ref = db.collection('projects').document(project_id)
                    proj_snap = proj_ref.get()
                    proj_builds = {}
                    if proj_snap.exists:
                        proj_builds = (proj_snap.to_dict() or {}).get('builds') or {}
                    proj_builds.update(platform_artifacts)
                    proj_ref.set({'builds': proj_builds, 'updatedAt': firestore.SERVER_TIMESTAMP}, merge=True)
                logger.info(f"Recorded completed build {build_id} in Firestore for project {project_id}")
            except Exception as fse:
                logger.warning(f"Error saving build to Firestore: {fse}")

        # 3. Background upload to Firebase Storage
        def _bg_upload_to_storage():
            try:
                bucket = get_storage_bucket()
                if not bucket or not user_id:
                    return
                for plat, output_path in outputs.items():
                    if not output_path or not os.path.exists(output_path):
                        continue
                    fname = os.path.basename(output_path)
                    storage_path = f"builds/{user_id}/{project_id or 'general'}/{plat}_{fname}"
                    blob = bucket.blob(storage_path)
                    blob.upload_from_filename(output_path)
                    try:
                        blob.make_public()
                        public_url = blob.public_url
                    except Exception:
                        public_url = blob.generate_signed_url(timedelta(days=365), method='GET')

                    # Update download url in Firestore builds & projects collections
                    if db:
                        try:
                            db.collection('builds').document(build_id).update({
                                f'artifacts.{plat}.storageUrl': public_url,
                                f'artifacts.{plat}.storagePath': storage_path
                            })
                        except Exception:
                            pass
                    if db and project_id:
                        try:
                            p_ref = db.collection('projects').document(project_id)
                            p_snap = p_ref.get()
                            if p_snap.exists:
                                pb = (p_snap.to_dict() or {}).get('builds') or {}
                                if plat in pb:
                                    pb[plat]['storageUrl'] = public_url
                                    pb[plat]['storagePath'] = storage_path
                                    p_ref.set({'builds': pb}, merge=True)
                        except Exception:
                            pass
                    logger.info(f"Uploaded build {build_id} ({plat}) to Firebase Storage: {storage_path}")
            except Exception as st_err:
                logger.warning(f"Note: Cloud storage upload skipped/deferred: {st_err}")

        threading.Thread(target=_bg_upload_to_storage, daemon=True).start()

    except Exception as e:
        logger.exception(f"Error in record_completed_build: {e}")

def run_build(build_id, config):
    """Run the Flutter build in a background thread"""
    try:
        check_build_cancelled(build_id)
        set_build_progress(build_id, status='preparing', progress=5, message='Preparing build environment...')

        # Create a unique build directory
        build_dir = os.path.join(app.config['BUILD_FOLDER'], build_id)
        os.makedirs(build_dir, exist_ok=True)

        check_build_cancelled(build_id)
        # Copy template to build directory
        project_dir = os.path.join(build_dir, 'project')
        shutil.copytree(app.config['FLUTTER_TEMPLATE'], project_dir)

        check_build_cancelled(build_id)
        set_build_progress(build_id, status='configuring', progress=10, message='Configuring app...')

        # Update main.dart with app details and feature options
        main_dart_path = os.path.join(project_dir, 'lib', 'main.dart')
        with open(main_dart_path, 'r') as f:
            content = f.read()

        content = content.replace('{{APP_NAME}}', config['app_name'])
        content = content.replace('{{APP_URL}}', config['web_url'])

        # Replace WebView feature options
        def bool_to_dart(value):
            return 'true' if value else 'false'

        content = re.sub(
            r'static const bool ALLOW_ZOOM = \w+;',
            f'static const bool ALLOW_ZOOM = {bool_to_dart(config["allow_zoom"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_JAVASCRIPT = \w+;',
            f'static const bool ENABLE_JAVASCRIPT = {bool_to_dart(config["enable_javascript"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_DOM_STORAGE = \w+;',
            f'static const bool ENABLE_DOM_STORAGE = {bool_to_dart(config["enable_dom_storage"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_GEOLOCATION = \w+;',
            f'static const bool ENABLE_GEOLOCATION = {bool_to_dart(config["enable_geolocation"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_PULL_TO_REFRESH = \w+;',
            f'static const bool ENABLE_PULL_TO_REFRESH = {bool_to_dart(config["enable_pull_refresh"])};',
            content
        )
        content = re.sub(
            r'static const bool SHOW_NAVIGATION_BAR = \w+;',
            f'static const bool SHOW_NAVIGATION_BAR = {bool_to_dart(config["show_navigation"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_FILE_ACCESS = \w+;',
            f'static const bool ENABLE_FILE_ACCESS = {bool_to_dart(config["enable_file_access"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_CACHE = \w+;',
            f'static const bool ENABLE_CACHE = {bool_to_dart(config["enable_cache"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_MEDIA_AUTOPLAY = \w+;',
            f'static const bool ENABLE_MEDIA_AUTOPLAY = {bool_to_dart(config["enable_media_autoplay"])};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_CAMERA = \w+;',
            f'static const bool ENABLE_CAMERA = {bool_to_dart(config.get("enable_camera", False))};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_MICROPHONE = \w+;',
            f'static const bool ENABLE_MICROPHONE = {bool_to_dart(config.get("enable_microphone", False))};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_SSL_PINNING = \w+;',
            f'static const bool ENABLE_SSL_PINNING = {bool_to_dart(config.get("enable_ssl_pinning", False))};',
            content
        )
        ssl_pins_str = str(config.get("ssl_pins", "")).replace("'", "\\'")
        content = re.sub(
            r'static const String SSL_PINS = [^;]+;',
            f"static const String SSL_PINS = '{ssl_pins_str}';",
            content
        )
        content = re.sub(
            r'static const bool ENABLE_BIOMETRIC_AUTH = \w+;',
            f'static const bool ENABLE_BIOMETRIC_AUTH = {bool_to_dart(config.get("enable_biometric_auth", config.get("enable_biometrics", False)))};',
            content
        )
        content = re.sub(
            r'static const bool ENABLE_APP_LOCK = \w+;',
            f'static const bool ENABLE_APP_LOCK = {bool_to_dart(config.get("enable_app_lock", False))};',
            content
        )
        app_lock_pin_str = str(config.get("app_lock_pin", "")).replace("'", "\\'")
        content = re.sub(
            r'static const String APP_LOCK_PIN = [^;]+;',
            f"static const String APP_LOCK_PIN = '{app_lock_pin_str}';",
            content
        )
        content = re.sub(
            r'static const bool ENABLE_SECURE_STORAGE = \w+;',
            f'static const bool ENABLE_SECURE_STORAGE = {bool_to_dart(config.get("enable_secure_storage", False))};',
            content
        )

        # Splash Screen Configuration
        content = re.sub(
            r'static const bool ENABLE_SPLASH_SCREEN = \w+;',
            f'static const bool ENABLE_SPLASH_SCREEN = {bool_to_dart(config.get("enable_splash_screen", False))};',
            content
        )
        splash_title_str = str(config.get("splash_title", config.get("app_name", ""))).replace("'", "\\'")
        content = re.sub(
            r'static const String SPLASH_TITLE = [^;]+;',
            f"static const String SPLASH_TITLE = '{splash_title_str}';",
            content
        )
        splash_subtitle_str = str(config.get("splash_subtitle", "")).replace("'", "\\'")
        content = re.sub(
            r'static const String SPLASH_SUBTITLE = [^;]+;',
            f"static const String SPLASH_SUBTITLE = '{splash_subtitle_str}';",
            content
        )
        splash_bg_color = str(config.get("splash_bg_color", "#FFFFFF")).strip() or "#FFFFFF"
        content = re.sub(
            r'static const String SPLASH_BG_COLOR = [^;]+;',
            f"static const String SPLASH_BG_COLOR = '{splash_bg_color}';",
            content
        )
        splash_text_color = str(config.get("splash_text_color", "#1E293B")).strip() or "#1E293B"
        content = re.sub(
            r'static const String SPLASH_TEXT_COLOR = [^;]+;',
            f"static const String SPLASH_TEXT_COLOR = '{splash_text_color}';",
            content
        )
        try:
            splash_duration = int(config.get("splash_duration", 2))
        except (ValueError, TypeError):
            splash_duration = 2
        content = re.sub(
            r'static const int SPLASH_DURATION_SECONDS = \d+;',
            f'static const int SPLASH_DURATION_SECONDS = {splash_duration};',
            content
        )
        has_custom_splash = bool(
            (config.get("splash_image_path") and os.path.exists(config.get("splash_image_path", ""))) or
            config.get("splash_image_url") or config.get("splashUrl") or config.get("splashImageUrl")
        )
        content = re.sub(
            r'static const bool HAS_CUSTOM_SPLASH_IMAGE = \w+;',
            f'static const bool HAS_CUSTOM_SPLASH_IMAGE = {bool_to_dart(has_custom_splash)};',
            content
        )

        # Error / Offline Page Configuration
        content = re.sub(
            r'static const bool ENABLE_ERROR_PAGE = \w+;',
            f'static const bool ENABLE_ERROR_PAGE = {bool_to_dart(config.get("enable_error_page", False))};',
            content
        )
        error_title_str = str(config.get("error_title", "No Internet Connection")).replace("'", "\\'")
        content = re.sub(
            r'static const String ERROR_TITLE = [^;]+;',
            f"static const String ERROR_TITLE = '{error_title_str}';",
            content
        )
        error_msg_str = str(config.get("error_message", "Please check your connection and try again")).replace("'", "\\'")
        content = re.sub(
            r'static const String ERROR_MESSAGE = [^;]+;',
            f"static const String ERROR_MESSAGE = '{error_msg_str}';",
            content
        )
        error_button_str = str(config.get("error_button_text", "Retry")).replace("'", "\\'")
        content = re.sub(
            r'static const String ERROR_BUTTON_TEXT = [^;]+;',
            f"static const String ERROR_BUTTON_TEXT = '{error_button_str}';",
            content
        )
        error_bg_color = str(config.get("error_bg_color", "#FFFFFF")).strip() or "#FFFFFF"
        content = re.sub(
            r'static const String ERROR_BG_COLOR = [^;]+;',
            f"static const String ERROR_BG_COLOR = '{error_bg_color}';",
            content
        )
        error_text_color = str(config.get("error_text_color", "#334155")).strip() or "#334155"
        content = re.sub(
            r'static const String ERROR_TEXT_COLOR = [^;]+;',
            f"static const String ERROR_TEXT_COLOR = '{error_text_color}';",
            content
        )
        has_custom_error = bool(
            (config.get("error_image_path") and os.path.exists(config.get("error_image_path", ""))) or
            config.get("error_image_url") or config.get("errorUrl") or config.get("errorImageUrl")
        )
        content = re.sub(
            r'static const bool HAS_CUSTOM_ERROR_IMAGE = \w+;',
            f'static const bool HAS_CUSTOM_ERROR_IMAGE = {bool_to_dart(has_custom_error)};',
            content
        )

        with open(main_dart_path, 'w') as f:
            f.write(content)

        # Update pubspec.yaml
        pubspec_path = os.path.join(project_dir, 'pubspec.yaml')
        with open(pubspec_path, 'r') as f:
            pubspec = f.read()

        # Handle placeholders from template
        pubspec = pubspec.replace('{{APP_PACKAGE_NAME}}', sanitize_package_name(config['app_name']))
        pubspec = pubspec.replace('{{APP_DESCRIPTION}}', config['app_description'])
        pubspec = pubspec.replace('{{APP_VERSION}}', config['app_version'])
        pubspec = pubspec.replace('{{APP_BUILD_NUMBER}}', str(config['build_number']))

        # Also handle old-style replacements for backwards compatibility
        pubspec = pubspec.replace('name: webview_app', f"name: {sanitize_package_name(config['app_name'])}")
        pubspec = pubspec.replace('description: "A new Flutter project."', f"description: \"{config['app_description']}\"")
        pubspec = pubspec.replace('version: 1.0.0+1', f"version: {config['app_version']}+{config['build_number']}")

        with open(pubspec_path, 'w') as f:
            f.write(pubspec)

        # Track if we generated a keystore
        keystore_generated = False
        keystore_info = None

        # Check if we need to generate a keystore for Android builds
        is_android = 'android' in config['platforms'] or 'android_aab' in config['platforms']
        has_keystore = config.get('keystore_path') and os.path.exists(config.get('keystore_path', ''))

        if is_android and not has_keystore:
            check_build_cancelled(build_id)
            set_build_progress(build_id, status='keystore', progress=12, message='Generating signing keystore...')
            keystore_info = generate_keystore(build_dir, config)
            if keystore_info:
                config['keystore_path'] = keystore_info['path']
                config['keystore_password'] = keystore_info['password']
                config['key_alias'] = keystore_info['alias']
                config['key_password'] = keystore_info['key_password']
                keystore_generated = True

        # Use rename package to set app name and bundle ID
        check_build_cancelled(build_id)
        set_build_progress(build_id, status='renaming', progress=15, message='Setting app name and bundle ID...')
        rename_app(project_dir, config['app_name'], config['package_name'])

        # Setup app icon if provided
        icon_path = config.get('icon_path')
        if (not icon_path or not os.path.exists(icon_path)) and (config.get('icon_url') or config.get('iconUrl')):
            remote_icon_url = config.get('icon_url') or config.get('iconUrl')
            try:
                r_icon = requests.get(remote_icon_url, timeout=10)
                if r_icon.status_code == 200:
                    local_icon = os.path.join(app.config['UPLOAD_FOLDER'], f"icon_{build_id}.png")
                    with open(local_icon, 'wb') as f:
                        f.write(r_icon.content)
                    icon_path = local_icon
            except Exception as dl_icon_err:
                logger.warning(f"Could not download remote icon for build {build_id}: {dl_icon_err}")

        if icon_path and os.path.exists(icon_path):
            check_build_cancelled(build_id)
            set_build_progress(build_id, status='icons', progress=18, message='Generating app icons...')
            setup_app_icon(project_dir, icon_path, build_id)

        # Setup splash and error assets if provided
        assets_dir = os.path.join(project_dir, 'assets')
        os.makedirs(assets_dir, exist_ok=True)
        splash_image_path = config.get('splash_image_path')
        if splash_image_path and os.path.exists(splash_image_path):
            shutil.copy(splash_image_path, os.path.join(assets_dir, 'splash.png'))
        elif config.get('splash_image_url') or config.get('splashUrl') or config.get('splashImageUrl'):
            splash_remote = config.get('splash_image_url') or config.get('splashUrl') or config.get('splashImageUrl')
            try:
                r_splash = requests.get(splash_remote, timeout=10)
                if r_splash.status_code == 200:
                    with open(os.path.join(assets_dir, 'splash.png'), 'wb') as f:
                        f.write(r_splash.content)
            except Exception as dl_splash_err:
                logger.warning(f"Could not download remote splash image for build {build_id}: {dl_splash_err}")

        error_image_path = config.get('error_image_path')
        if error_image_path and os.path.exists(error_image_path):
            shutil.copy(error_image_path, os.path.join(assets_dir, 'error.png'))
        elif config.get('error_image_url') or config.get('errorUrl') or config.get('errorImageUrl'):
            error_remote = config.get('error_image_url') or config.get('errorUrl') or config.get('errorImageUrl')
            try:
                r_err = requests.get(error_remote, timeout=10)
                if r_err.status_code == 200:
                    with open(os.path.join(assets_dir, 'error.png'), 'wb') as f:
                        f.write(r_err.content)
            except Exception as dl_err_img:
                logger.warning(f"Could not download remote error image for build {build_id}: {dl_err_img}")

        # Update Android config (for keystore)
        if 'android' in config['platforms'] or 'android_aab' in config['platforms']:
            update_android_config(project_dir, config)

        # Update iOS bundle ID
        if 'ios' in config['platforms']:
            update_ios_config(project_dir, config)

        # Update macOS bundle ID
        if 'macos' in config['platforms']:
            update_macos_config(project_dir, config)

        # Update Windows config
        if 'windows' in config['platforms']:
            update_windows_config(project_dir, config)

        # Update Linux config
        if 'linux' in config['platforms']:
            update_linux_config(project_dir, config)

        # Check if local Flutter is available, or use Cloud Builder
        has_flutter = bool(shutil.which('flutter'))
        github_token = os.getenv('GITHUB_TOKEN')
        is_android = 'android' in config['platforms'] or 'android_aab' in config['platforms']
        is_windows = 'windows' in config['platforms']
        is_ios = 'ios' in config['platforms']
        is_macos_target = 'macos' in config['platforms']
        is_linux_target = 'linux' in config['platforms']

        if not has_flutter or (is_ios and not is_macos()) or (is_macos_target and not is_macos()) or (is_linux_target and not is_linux()):
            if (is_android or is_windows or is_ios or is_macos_target or is_linux_target) and github_token:
                if is_windows:
                    target_platform = 'windows'
                elif is_ios:
                    target_platform = 'ios'
                elif is_macos_target:
                    target_platform = 'macos'
                elif is_linux_target:
                    target_platform = 'linux'
                elif 'android_aab' in config['platforms'] and 'android' not in config['platforms']:
                    target_platform = 'android_aab'
                else:
                    target_platform = 'android'

                check_build_cancelled(build_id)
                logger.info(f"Routing build {build_id} to GitHub Actions Cloud Builder for {target_platform}.")
                cloud_output_path = build_via_github_actions(build_id, project_dir, build_dir, config, target_platform=target_platform)
                outputs = {}
                if is_windows:
                    outputs['windows'] = cloud_output_path
                if is_macos_target:
                    outputs['macos'] = cloud_output_path
                if is_linux_target:
                    outputs['linux'] = cloud_output_path
                if is_android:
                    if 'android' in config['platforms']:
                        apk_path = os.path.join(build_dir, 'outputs', f"{config['app_name']}.apk")
                        outputs['android'] = apk_path if os.path.exists(apk_path) else cloud_output_path
                    if 'android_aab' in config['platforms']:
                        aab_path = os.path.join(build_dir, 'outputs', f"{config['app_name']}.aab")
                        outputs['android_aab'] = aab_path if os.path.exists(aab_path) else cloud_output_path
                if is_ios:
                    outputs['ios'] = cloud_output_path
                    xcode_zip = os.path.join(build_dir, 'outputs', f"{config['app_name']}_xcode_project.zip")
                    if os.path.exists(xcode_zip):
                        outputs['ios_xcode'] = xcode_zip

                final_status = {
                    'status': 'completed',
                    'progress': 100,
                    'message': 'Build completed successfully via Cloud Builder!',
                    'outputs': outputs
                }
                if build_id in build_progress and 'github_download_urls' in build_progress[build_id]:
                    final_status['github_download_urls'] = build_progress[build_id]['github_download_urls']

                if keystore_generated and keystore_info:
                    final_status['keystore_generated'] = True
                    final_status['keystore_path'] = keystore_info['path']
                    final_status['keystore_info_path'] = keystore_info.get('info_path')

                if config.get('enable_google_play_publish'):
                    final_status['google_play_published'] = True
                    final_status['play_track'] = config.get('play_track', 'internal')
                if config.get('enable_app_store_publish'):
                    final_status['app_store_published'] = True

                check_build_cancelled(build_id)
                build_progress[build_id] = final_status
                record_completed_build(build_id, config, final_status)
                return
            else:
                raise RuntimeError("Flutter SDK is not installed on this system. Please install Flutter or configure GITHUB_TOKEN in .env for Cloud Builds.")

        check_build_cancelled(build_id)
        set_build_progress(build_id, status='dependencies', progress=22, message='Getting dependencies...')

        # Run flutter pub get
        subprocess.run(['flutter', 'pub', 'get'], cwd=project_dir, check=True, capture_output=True, timeout=180)

        outputs = {}
        platform_count = len(config['platforms'])
        progress_per_platform = 65 / max(platform_count, 1)
        current_progress = 28

        for platform in config['platforms']:
            check_build_cancelled(build_id)
            set_build_progress(
                build_id,
                status='building',
                progress=int(current_progress),
                message=f'Building {get_platform_display_name(platform)}...'
            )

            try:
                output_path = build_platform(project_dir, build_dir, platform, config)
                if output_path:
                    outputs[platform] = output_path
            except Exception as e:
                outputs[platform] = f'Error: {str(e)}'

            current_progress += progress_per_platform

        check_build_cancelled(build_id)
        # Prepare final status
        final_status = {
            'status': 'completed',
            'progress': 100,
            'message': 'Build completed!',
            'outputs': outputs
        }

        # Add keystore info if we generated one
        if keystore_generated and keystore_info:
            final_status['keystore_generated'] = True
            final_status['keystore_path'] = keystore_info['path']
            final_status['keystore_info_path'] = keystore_info.get('info_path')

        if config.get('enable_google_play_publish'):
            final_status['google_play_published'] = True
            final_status['play_track'] = config.get('play_track', 'internal')
        if config.get('enable_app_store_publish'):
            final_status['app_store_published'] = True

        build_progress[build_id] = final_status
        record_completed_build(build_id, config, final_status)
        # ✅ Webhook on success
        webhook_url = config.get('webhook_url')
        payload = {
            "build_id": build_id,
            "status": final_status.get('status'),
            "platforms": config.get('platforms'),
            "outputs": final_status.get('outputs')
        }

        threading.Thread(
            target=send_webhook_notification,
            args=(webhook_url, payload),
            daemon=True
        ).start()

    except BuildCancelledException:
        logger.info(f"Build {build_id} was cancelled by user.")
        if build_id in build_progress:
            build_progress[build_id].update({
                'status': 'cancelled',
                'progress': 0,
                'message': 'Build cancelled by user.'
            })
        if session.get('active_build_id') == build_id:
            session.pop('active_build_id', None)

    except Exception as e:
        if is_build_cancelled(build_id):
            logger.info(f"Build {build_id} was cancelled by user (caught {e}).")
            if build_id in build_progress:
                build_progress[build_id].update({
                    'status': 'cancelled',
                    'progress': 0,
                    'message': 'Build cancelled by user.'
                })
            if session.get('active_build_id') == build_id:
                session.pop('active_build_id', None)
        else:
            error_status = {
                'status': 'error',
                'progress': 0,
                'message': f'Build failed: {str(e)}'
            }
            build_progress[build_id].update(error_status)

        # ✅ Webhook on failure
        webhook_url = config.get('webhook_url')
        payload = {
            "build_id": build_id,
            "status": "error",
            "error": str(e),
            "platforms": config.get('platforms')
        }

        threading.Thread(
            target=send_webhook_notification,
            args=(webhook_url, payload),
            daemon=True
        ).start()


def get_platform_display_name(platform):
    """Get display name for platform"""
    names = {
        'android': 'Android APK',
        'android_aab': 'Android AAB',
        'ios': 'iOS',
        'macos': 'macOS',
        'windows': 'Windows',
        'linux': 'Linux'
    }
    return names.get(platform, platform)

def update_android_config(project_dir, config):
    """Update Android configuration"""
    build_gradle_path = os.path.join(project_dir, 'android', 'app', 'build.gradle.kts')
    if os.path.exists(build_gradle_path):
        with open(build_gradle_path, 'r') as f:
            content = f.read()

        # Replace placeholders
        content = content.replace('{{APP_PACKAGE_NAME}}', config['package_name'])
        content = content.replace('{{APP_VERSION}}', config['app_version'])
        content = content.replace('{{APP_BUILD_NUMBER}}', str(config['build_number']))

        # Handle keystore configuration
        keystore_path = config.get('keystore_path', '')
        keystore_password = config.get('keystore_password', '')
        key_alias = config.get('key_alias', '')
        key_password = config.get('key_password', '')

        if keystore_path and os.path.exists(keystore_path):
            content = content.replace('{{KEYSTORE_PATH}}', keystore_path)
            content = content.replace('{{KEYSTORE_PASSWORD}}', keystore_password)
            content = content.replace('{{KEY_ALIAS}}', key_alias)
            content = content.replace('{{KEY_PASSWORD}}', key_password)
        else:
            # Remove signing config for release and use debug signing
            content = re.sub(
                r'signingConfigs\s*\{[^}]*create\("release"\)[^}]*\}[^}]*\}',
                '',
                content,
                flags=re.DOTALL
            )
            content = re.sub(
                r'signingConfig\s*=\s*signingConfigs\.getByName\("release"\)',
                'signingConfig = signingConfigs.getByName("debug")',
                content
            )

        # Also handle old-style replacements for backwards compatibility
        content = re.sub(
            r'namespace\s*=\s*"[^"]*"',
            f'namespace = "{config["package_name"]}"',
            content
        )
        content = re.sub(
            r'applicationId\s*=\s*"[^"]*"',
            f'applicationId = "{config["package_name"]}"',
            content
        )

        with open(build_gradle_path, 'w') as f:
            f.write(content)

    # Update AndroidManifest.xml label
    manifest_path = os.path.join(project_dir, 'android', 'app', 'src', 'main', 'AndroidManifest.xml')
    if os.path.exists(manifest_path):
        with open(manifest_path, 'r') as f:
            content = f.read()

        content = content.replace('{{APP_NAME}}', config['app_name'])
        content = re.sub(
            r'android:label="[^"]*"',
            f'android:label="{config["app_name"]}"',
            content
        )

        if not config.get('enable_camera', True):
            content = re.sub(r'\s*<uses-permission android:name="android\.permission\.CAMERA"\s*/>', '', content)
            content = re.sub(r'\s*<uses-feature android:name="android\.hardware\.camera[^"]*"\s*android:required="false"\s*/>', '', content)
        if not config.get('enable_microphone', True):
            content = re.sub(r'\s*<uses-permission android:name="android\.permission\.RECORD_AUDIO"\s*/>', '', content)
            content = re.sub(r'\s*<uses-permission android:name="android\.permission\.MODIFY_AUDIO_SETTINGS"\s*/>', '', content)
            content = re.sub(r'\s*<uses-feature android:name="android\.hardware\.microphone"\s*android:required="false"\s*/>', '', content)
        if not config.get('enable_biometric_auth', config.get('enable_biometrics', False)):
            content = re.sub(r'\s*<uses-permission android:name="android\.permission\.USE_BIOMETRIC"\s*/>', '', content)
            content = re.sub(r'\s*<uses-permission android:name="android\.permission\.USE_FINGERPRINT"\s*/>', '', content)

        with open(manifest_path, 'w') as f:
            f.write(content)

def update_ios_config(project_dir, config):
    """Update iOS configuration"""
    info_plist_path = os.path.join(project_dir, 'ios', 'Runner', 'Info.plist')
    if os.path.exists(info_plist_path):
        with open(info_plist_path, 'r') as f:
            content = f.read()

        content = content.replace('{{APP_NAME}}', config['app_name'])

        # Update bundle display name
        content = re.sub(
            r'(<key>CFBundleDisplayName</key>\s*<string>)[^<]*(</string>)',
            f'\\g<1>{config["app_name"]}\\g<2>',
            content
        )
        content = re.sub(
            r'(<key>CFBundleName</key>\s*<string>)[^<]*(</string>)',
            f'\\g<1>{config["app_name"]}\\g<2>',
            content
        )

        if not config.get('enable_camera', True):
            content = re.sub(r'\s*<key>NSCameraUsageDescription</key>\s*<string>[^<]*</string>', '', content)
        if not config.get('enable_microphone', True):
            content = re.sub(r'\s*<key>NSMicrophoneUsageDescription</key>\s*<string>[^<]*</string>', '', content)
        if not config.get('enable_biometric_auth', config.get('enable_biometrics', False)):
            content = re.sub(r'\s*<key>NSFaceIDUsageDescription</key>\s*<string>[^<]*</string>', '', content)

        with open(info_plist_path, 'w') as f:
            f.write(content)

    # Update project.pbxproj for bundle ID
    pbxproj_path = os.path.join(project_dir, 'ios', 'Runner.xcodeproj', 'project.pbxproj')
    if os.path.exists(pbxproj_path):
        with open(pbxproj_path, 'r') as f:
            content = f.read()

        content = re.sub(
            r'PRODUCT_BUNDLE_IDENTIFIER\s*=\s*[^;]+;',
            f'PRODUCT_BUNDLE_IDENTIFIER = {config["package_name"]};',
            content
        )

        with open(pbxproj_path, 'w') as f:
            f.write(content)

def update_macos_config(project_dir, config):
    """Update macOS configuration"""
    info_plist_path = os.path.join(project_dir, 'macos', 'Runner', 'Info.plist')
    if os.path.exists(info_plist_path):
        with open(info_plist_path, 'r') as f:
            content = f.read()

        content = re.sub(
            r'(<key>CFBundleName</key>\s*<string>)[^<]*(</string>)',
            f'\\g<1>{config["app_name"]}\\g<2>',
            content
        )

        with open(info_plist_path, 'w') as f:
            f.write(content)

def update_windows_config(project_dir, config):
    """Update Windows configuration"""
    cmake_path = os.path.join(project_dir, 'windows', 'CMakeLists.txt')
    if os.path.exists(cmake_path):
        with open(cmake_path, 'r', encoding='utf-8') as f:
            content = f.read()

        safe_bin_name = re.sub(r'[^a-zA-Z0-9_-]', '', config['app_name']) or 'app'
        content = re.sub(
            r'project\([^)]+\)',
            f'project({safe_bin_name} LANGUAGES CXX)',
            content
        )
        content = re.sub(
            r'set\(BINARY_NAME "[^"]*"\)',
            f'set(BINARY_NAME "{safe_bin_name}")',
            content
        )

        with open(cmake_path, 'w', encoding='utf-8') as f:
            f.write(content)

    # Update window title in main.cpp
    main_cpp_path = os.path.join(project_dir, 'windows', 'runner', 'main.cpp')
    if os.path.exists(main_cpp_path):
        try:
            with open(main_cpp_path, 'r', encoding='utf-8') as f:
                cpp_content = f.read()
            app_name_escaped = config['app_name'].replace('\\', '\\\\').replace('"', '\\"')
            cpp_content = re.sub(
                r'window\.Create\(L"[^"]*"',
                f'window.Create(L"{app_name_escaped}"',
                cpp_content
            )
            with open(main_cpp_path, 'w', encoding='utf-8') as f:
                f.write(cpp_content)
        except Exception as e:
            logger.warning(f"Failed to update Windows main.cpp: {e}")

def update_linux_config(project_dir, config):
    """Update Linux configuration"""
    cmake_path = os.path.join(project_dir, 'linux', 'CMakeLists.txt')
    if os.path.exists(cmake_path):
        with open(cmake_path, 'r') as f:
            content = f.read()

        content = re.sub(
            r'set\(BINARY_NAME\s+"[^"]*"\)',
            f'set(BINARY_NAME "{sanitize_package_name(config["app_name"])}")',
            content
        )

        with open(cmake_path, 'w') as f:
            f.write(content)

def build_ios_signed(project_dir, build_dir, config):
    """Build signed iOS app (.ipa) using Apple credentials"""
    output_dir = os.path.join(build_dir, 'outputs')
    os.makedirs(output_dir, exist_ok=True)

    apple_cert_path = config.get('apple_certificate_path')
    apple_cert_password = config.get('apple_certificate_password')
    apple_profile_path = config.get('apple_provisioning_profile_path')

    with SecureAppleSigning(os.path.basename(build_dir)) as signer:
        try:
            # Create temporary keychain and import certificate
            signer.create_temporary_keychain()
            signer.import_certificate(apple_cert_path, apple_cert_password)

            # Install and validate provisioning profile
            profile_info = signer.install_provisioning_profile(apple_profile_path)

            # Get signing identity
            signing_identity = signer.get_signing_identity()

            # Create ExportOptions.plist
            export_options_path = signer.create_export_options_plist(build_dir, config, profile_info)

            # Build the iOS app with Flutter (this creates the xcarchive)
            subprocess.run(
                ['flutter', 'build', 'ios', '--release'],
                cwd=project_dir,
                check=True,
                capture_output=True,
                timeout=600,
                env={**os.environ, 'CODE_SIGN_IDENTITY': signing_identity}
            )

            # Find the .app file
            app_path = os.path.join(project_dir, 'build', 'ios', 'iphoneos', 'Runner.app')

            if not os.path.exists(app_path):
                raise Exception("iOS build failed - .app not found")

            # Create archive directory structure
            archive_dir = os.path.join(build_dir, 'archive')
            archive_path = os.path.join(archive_dir, f'{config["app_name"]}.xcarchive')
            products_dir = os.path.join(archive_path, 'Products', 'Applications')
            os.makedirs(products_dir, exist_ok=True)

            # Copy .app to archive
            shutil.copytree(app_path, os.path.join(products_dir, 'Runner.app'))

            # Create Info.plist for archive
            archive_info = {
                'ApplicationProperties': {
                    'ApplicationPath': 'Products/Applications/Runner.app',
                    'CFBundleIdentifier': config.get('package_name'),
                    'CFBundleShortVersionString': config.get('app_version', '1.0.0'),
                    'CFBundleVersion': str(config.get('build_number', 1)),
                    'SigningIdentity': signing_identity,
                    'Team': config.get('team_id') or profile_info.get('team_id'),
                },
                'ArchiveVersion': 2,
                'CreationDate': __import__('datetime').datetime.now(),
                'Name': config.get('app_name'),
                'SchemeName': 'Runner',
            }

            with open(os.path.join(archive_path, 'Info.plist'), 'wb') as f:
                plistlib.dump(archive_info, f)

            # Export to IPA using xcodebuild
            ipa_export_dir = os.path.join(build_dir, 'ipa_export')
            os.makedirs(ipa_export_dir, exist_ok=True)

            export_result = subprocess.run(
                [
                    'xcodebuild', '-exportArchive',
                    '-archivePath', archive_path,
                    '-exportPath', ipa_export_dir,
                    '-exportOptionsPlist', export_options_path,
                ],
                capture_output=True,
                text=True,
                timeout=300,
                env={**os.environ, 'KEYCHAIN_PATH': signer.keychain_name}
            )

            if export_result.returncode != 0:
                # If xcodebuild fails, fall back to manual IPA creation
                ipa_path = create_ipa_manually(app_path, build_dir, config, signing_identity)
                if ipa_path:
                    output_path = os.path.join(output_dir, f'{config["app_name"]}.ipa')
                    shutil.move(ipa_path, output_path)
                    return output_path
                raise Exception(f"IPA export failed: {export_result.stderr}")

            # Find the exported IPA
            for file in os.listdir(ipa_export_dir):
                if file.endswith('.ipa'):
                    output_path = os.path.join(output_dir, f'{config["app_name"]}.ipa')
                    shutil.move(os.path.join(ipa_export_dir, file), output_path)
                    return output_path

            raise Exception("IPA file not found after export")

        except Exception as e:
            raise Exception(f"iOS signed build failed: {str(e)}")


def build_macos_signed(project_dir, build_dir, config):
    """Build signed macOS app using Apple credentials"""
    output_dir = os.path.join(build_dir, 'outputs')
    os.makedirs(output_dir, exist_ok=True)

    apple_cert_path = config.get('apple_certificate_path')
    apple_cert_password = config.get('apple_certificate_password')
    apple_profile_path = config.get('apple_provisioning_profile_path')

    with SecureAppleSigning(os.path.basename(build_dir)) as signer:
        try:
            # Create temporary keychain and import certificate
            signer.create_temporary_keychain()
            signer.import_certificate(apple_cert_path, apple_cert_password)

            # Install and validate provisioning profile (optional for macOS)
            profile_info = {}
            if apple_profile_path and os.path.exists(apple_profile_path):
                profile_info = signer.install_provisioning_profile(apple_profile_path)

            # Get signing identity
            signing_identity = signer.get_signing_identity()

            # Build the macOS app with Flutter
            build_env = {**os.environ, 'CODE_SIGN_IDENTITY': signing_identity}

            subprocess.run(
                ['flutter', 'build', 'macos', '--release'],
                cwd=project_dir,
                check=True,
                capture_output=True,
                timeout=600,
                env=build_env
            )

            # Find the .app bundle
            app_path = os.path.join(
                project_dir, 'build', 'macos', 'Build', 'Products', 'Release',
                f'{config.get("app_name", "Runner")}.app'
            )

            # Try default name if custom name not found
            if not os.path.exists(app_path):
                app_path = os.path.join(
                    project_dir, 'build', 'macos', 'Build', 'Products', 'Release', 'Runner.app'
                )

            if not os.path.exists(app_path):
                # Find any .app in the release directory
                release_dir = os.path.join(project_dir, 'build', 'macos', 'Build', 'Products', 'Release')
                for item in os.listdir(release_dir):
                    if item.endswith('.app'):
                        app_path = os.path.join(release_dir, item)
                        break

            if not os.path.exists(app_path):
                raise Exception("macOS build failed - .app not found")

            # Sign the app bundle with codesign
            subprocess.run(
                [
                    'codesign', '--force', '--deep', '--sign', signing_identity,
                    '--keychain', signer.keychain_name,
                    '--options', 'runtime',
                    app_path
                ],
                check=True,
                capture_output=True,
                timeout=120
            )

            # Verify the signature
            verify_result = subprocess.run(
                ['codesign', '--verify', '--deep', '--strict', app_path],
                capture_output=True,
                text=True,
                timeout=60
            )

            if verify_result.returncode != 0:
                raise Exception(f"Code signature verification failed: {verify_result.stderr}")

            # Create DMG or ZIP
            output_path = os.path.join(output_dir, f'{config["app_name"]}_macos_signed.zip')
            shutil.make_archive(
                output_path.replace('.zip', ''),
                'zip',
                os.path.dirname(app_path),
                os.path.basename(app_path)
            )

            return output_path

        except Exception as e:
            raise Exception(f"macOS signed build failed: {str(e)}")


def create_ipa_manually(app_path, build_dir, config, signing_identity):
    """Create IPA file manually when xcodebuild export fails"""
    try:
        ipa_dir = os.path.join(build_dir, 'ipa_manual')
        payload_dir = os.path.join(ipa_dir, 'Payload')
        os.makedirs(payload_dir, exist_ok=True)

        # Copy .app to Payload directory
        app_dest = os.path.join(payload_dir, os.path.basename(app_path))
        shutil.copytree(app_path, app_dest)

        # Create IPA (zip with .ipa extension)
        ipa_path = os.path.join(ipa_dir, f'{config["app_name"]}.ipa')

        # Use zip command for proper IPA structure
        subprocess.run(
            ['zip', '-r', '-q', ipa_path, 'Payload'],
            cwd=ipa_dir,
            check=True,
            capture_output=True,
            timeout=120
        )

        return ipa_path
    except Exception:
        return None


def build_platform(project_dir, build_dir, platform, config):
    """Build for a specific platform - always uses release mode"""
    output_dir = os.path.join(build_dir, 'outputs')
    os.makedirs(output_dir, exist_ok=True)

    if platform == 'android':
        subprocess.run(
            ['flutter', 'build', 'apk', '--release'],
            cwd=project_dir,
            check=True,
            capture_output=True,
            timeout=600
        )
        apk_path = os.path.join(project_dir, 'build', 'app', 'outputs', 'flutter-apk', 'app-release.apk')
        if os.path.exists(apk_path):
            output_path = os.path.join(output_dir, f'{config["app_name"]}.apk')
            shutil.copy(apk_path, output_path)
            return output_path

    elif platform == 'android_aab':
        subprocess.run(
            ['flutter', 'build', 'appbundle', '--release'],
            cwd=project_dir,
            check=True,
            capture_output=True,
            timeout=600
        )
        aab_path = os.path.join(project_dir, 'build', 'app', 'outputs', 'bundle', 'release', 'app-release.aab')
        if os.path.exists(aab_path):
            output_path = os.path.join(output_dir, f'{config["app_name"]}.aab')
            shutil.copy(aab_path, output_path)
            return output_path

    elif platform == 'ios':
        # Check if Apple signing credentials are provided
        apple_cert_path = config.get('apple_certificate_path')
        apple_cert_password = config.get('apple_certificate_password')
        apple_profile_path = config.get('apple_provisioning_profile_path')

        if apple_cert_path and apple_cert_password and apple_profile_path and is_macos():
            # Build with code signing
            return build_ios_signed(project_dir, build_dir, config)
        else:
            # Build without code signing (for development/testing)
            subprocess.run(
                ['flutter', 'build', 'ios', '--release', '--no-codesign'],
                cwd=project_dir,
                check=True,
                capture_output=True,
                timeout=600
            )
            # Create xcarchive for unsigned build
            app_path = os.path.join(project_dir, 'build', 'ios', 'iphoneos', 'Runner.app')
            if os.path.exists(app_path):
                output_path = os.path.join(output_dir, f'{config["app_name"]}_ios_unsigned.zip')
                shutil.make_archive(output_path.replace('.zip', ''), 'zip', os.path.dirname(app_path), 'Runner.app')
                return output_path
            return None

    elif platform == 'web':
        subprocess.run(
            ['flutter', 'build', 'web', '--release'],
            cwd=project_dir,
            check=True,
            capture_output=True,
            timeout=300
        )
        web_dir = os.path.join(project_dir, 'build', 'web')
        if os.path.exists(web_dir):
            output_path = os.path.join(output_dir, f'{config["app_name"]}_web.zip')
            shutil.make_archive(output_path.replace('.zip', ''), 'zip', web_dir)
            return output_path

    elif platform == 'macos':
        # Check if Apple signing credentials are provided
        apple_cert_path = config.get('apple_certificate_path')
        apple_cert_password = config.get('apple_certificate_password')

        if apple_cert_path and apple_cert_password and is_macos():
            # Build with code signing
            return build_macos_signed(project_dir, build_dir, config)
        else:
            # Build without code signing
            subprocess.run(
                ['flutter', 'build', 'macos', '--release'],
                cwd=project_dir,
                check=True,
                capture_output=True,
                timeout=600
            )
            app_path = os.path.join(project_dir, 'build', 'macos', 'Build', 'Products', 'Release')
            if os.path.exists(app_path):
                output_path = os.path.join(output_dir, f'{config["app_name"]}_macos.zip')
                shutil.make_archive(output_path.replace('.zip', ''), 'zip', app_path)
                return output_path

    elif platform == 'windows':
        subprocess.run(
            ['flutter', 'build', 'windows', '--release'],
            cwd=project_dir,
            check=True,
            capture_output=True,
            timeout=600
        )
        exe_dir = os.path.join(project_dir, 'build', 'windows', 'x64', 'runner', 'Release')
        if os.path.exists(exe_dir):
            output_path = os.path.join(output_dir, f'{config["app_name"]}_windows.zip')
            shutil.make_archive(output_path.replace('.zip', ''), 'zip', exe_dir)
            return output_path

    elif platform == 'linux':
        subprocess.run(
            ['flutter', 'build', 'linux', '--release'],
            cwd=project_dir,
            check=True,
            capture_output=True,
            timeout=600
        )
        linux_dir = os.path.join(project_dir, 'build', 'linux', 'x64', 'release', 'bundle')
        if os.path.exists(linux_dir):
            output_path = os.path.join(output_dir, f'{config["app_name"]}_linux.zip')
            shutil.make_archive(output_path.replace('.zip', ''), 'zip', linux_dir)
            return output_path

    return None

# ==================== AUTH API ROUTES ====================

@app.route('/api/auth/signup', methods=['POST'])
def api_signup():
    """Real built-in user registration with SQLite"""
    try:
        data = request.json or {}
        name = data.get('name', '').strip()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not name or not email or not password:
            return jsonify({'success': False, 'error': 'Name, email, and password are required.'}), 400

        if len(password) < 6:
            return jsonify({'success': False, 'error': 'Password must be at least 6 characters.'}), 400

        if not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            return jsonify({'success': False, 'error': 'Please enter a valid email address.'}), 400

        conn = get_db_connection()
        existing = conn.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone()
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': 'An account with this email already exists. Please sign in.'}), 409

        user_id = str(uuid.uuid4())
        password_hash = generate_password_hash(password)
        created_at = datetime.utcnow().isoformat()

        conn.execute(
            'INSERT INTO users (id, name, email, password_hash, created_at) VALUES (?, ?, ?, ?, ?)',
            (user_id, name, email, password_hash, created_at)
        )
        conn.commit()
        conn.close()

        session.permanent = True
        session['user_id'] = user_id
        session['user_name'] = name
        session['user_email'] = email

        return jsonify({
            'success': True,
            'message': 'Account created successfully!',
            'user': {'id': user_id, 'uid': user_id, 'name': name, 'email': email},
            'redirect': '/dashboard'
        })
    except Exception as e:
        logger.exception("Error during signup")
        return jsonify({'success': False, 'error': f'Signup failed: {str(e)}'}), 500


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """Real built-in user sign-in with SQLite"""
    try:
        data = request.json or {}
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')

        if not email or not password:
            return jsonify({'success': False, 'error': 'Email and password are required.'}), 400

        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        conn.close()

        if not user or not check_password_hash(user['password_hash'], password):
            return jsonify({'success': False, 'error': 'Invalid email or password.'}), 401

        session.permanent = True
        session['user_id'] = user['id']
        session['user_name'] = user['name']
        session['user_email'] = user['email']
        user_picture = user['picture'] if 'picture' in user.keys() and user['picture'] else ''
        session['user_picture'] = user_picture

        return jsonify({
            'success': True,
            'message': 'Signed in successfully!',
            'user': {'id': user['id'], 'uid': user['id'], 'name': user['name'], 'email': user['email'], 'picture': user_picture},
            'redirect': '/dashboard'
        })
    except Exception as e:
        logger.exception("Error during login")
        return jsonify({'success': False, 'error': f'Login failed: {str(e)}'}), 500


@app.route('/api/auth/logout', methods=['POST', 'GET'])
def api_logout():
    """Sign out user and clear session"""
    session.clear()
    if request.method == 'GET':
        return redirect(url_for('index'))
    return jsonify({'success': True, 'redirect': '/'})


@app.route('/api/auth/me', methods=['GET'])
def api_me():
    """Get current authenticated user info with fresh database state"""
    if 'user_id' in session:
        uid = session['user_id']
        name = session.get('user_name', 'User')
        email = session.get('user_email', '')
        picture = session.get('user_picture', '')

        # Fetch latest from Firestore or SQLite if available
        if db:
            try:
                udoc = db.collection('users').document(uid).get()
                if udoc.exists:
                    udata = udoc.to_dict() or {}
                    name = udata.get('name') or name
                    email = udata.get('email') or email
                    picture = udata.get('picture') or picture
                    session['user_name'] = name
                    session['user_email'] = email
                    session['user_picture'] = picture
            except Exception as e:
                logger.debug(f"Firestore user fetch: {e}")
        else:
            try:
                conn = get_db_connection()
                urow = conn.execute('SELECT * FROM users WHERE id = ?', (uid,)).fetchone()
                conn.close()
                if urow:
                    name = urow['name'] or name
                    email = urow['email'] or email
                    if 'picture' in urow.keys() and urow['picture']:
                        picture = urow['picture']
                    session['user_name'] = name
                    session['user_email'] = email
                    session['user_picture'] = picture
            except Exception as e:
                logger.debug(f"SQLite user fetch: {e}")

        return jsonify({
            'authenticated': True,
            'user': {
                'id': uid,
                'uid': uid,
                'name': name,
                'email': email,
                'picture': picture
            }
        })
    return jsonify({'authenticated': False, 'user': None})


@app.route('/api/auth/firebase-session', methods=['POST'])
def api_firebase_session():
    """Verify Firebase ID token, sync user to Firestore & SQLite, and establish Flask session"""
    try:
        data = request.json or {}
        id_token = data.get('idToken')
        if not id_token:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer '):
                id_token = auth_header.split('Bearer ')[1].strip()

        if not id_token:
            return jsonify({'success': False, 'error': 'Firebase ID token is required.'}), 400

        if not firebase_initialized:
            return jsonify({
                'success': False,
                'error': 'Firebase backend is not initialized. Please configure serviceAccount.json or environment credentials.'
            }), 503

        try:
            decoded_token = firebase_auth.verify_id_token(id_token)
        except Exception as e:
            logger.warning("Failed to verify Firebase ID token: %s", e)
            return jsonify({'success': False, 'error': f'Invalid or expired Firebase token: {str(e)}'}), 401

        uid = decoded_token.get('uid')
        email = decoded_token.get('email', '').strip().lower()
        name = decoded_token.get('name') or (email.split('@')[0] if email else 'User')
        picture = decoded_token.get('picture', '')

        # 1. Upsert user in Firestore if active
        if db:
            try:
                user_ref = db.collection('users').document(uid)
                user_ref.set({
                    'uid': uid,
                    'name': name,
                    'email': email,
                    'picture': picture,
                    'lastLogin': firestore.SERVER_TIMESTAMP,
                    'updatedAt': firestore.SERVER_TIMESTAMP
                }, merge=True)
            except Exception as fe:
                logger.warning("Could not sync user to Firestore: %s", fe)

        # 2. Upsert user in SQLite for local data continuity
        try:
            conn = get_db_connection()
            existing = conn.execute('SELECT id, picture FROM users WHERE id = ? OR email = ?', (uid, email)).fetchone()
            now = datetime.utcnow().isoformat()
            if existing:
                conn.execute(
                    'UPDATE users SET name = ?, email = ?, picture = COALESCE(NULLIF(?, ""), picture) WHERE id = ?',
                    (name, email, picture, existing['id'])
                )
            else:
                conn.execute(
                    'INSERT INTO users (id, name, email, password_hash, created_at, picture) VALUES (?, ?, ?, ?, ?, ?)',
                    (uid, name, email, 'FIREBASE_AUTH', now, picture)
                )
            conn.commit()
            conn.close()
        except Exception as se:
            logger.warning("Could not sync user to SQLite: %s", se)

        # 3. Establish Flask session
        session.permanent = True
        session['user_id'] = uid
        session['user_name'] = name
        session['user_email'] = email
        session['user_picture'] = picture
        session['auth_provider'] = 'firebase'

        return jsonify({
            'success': True,
            'message': 'Firebase session established!',
            'user': {
                'id': uid,
                'uid': uid,
                'name': name,
                'email': email,
                'picture': picture
            },
            'redirect': '/dashboard'
        })
    except Exception as e:
        logger.exception("Error during Firebase session creation")
        return jsonify({'success': False, 'error': f'Failed to create session: {str(e)}'}), 500


# ==================== USER PROFILE & ACCOUNT MANAGEMENT ====================

@app.route('/api/user/profile', methods=['PUT'])
@firebase_auth_required
def api_update_user_profile():
    """Update current user's profile information (name, picture)"""
    try:
        user_id = request.user['uid']
        data = request.json or {}
        name = data.get('name', '').strip()
        picture = data.get('picture', '').strip()

        if not name and not picture:
            return jsonify({'success': False, 'error': 'No profile data provided to update.'}), 400

        # Update Firestore
        if db:
            try:
                update_fields = {'updatedAt': firestore.SERVER_TIMESTAMP}
                if name:
                    update_fields['name'] = name
                if picture:
                    update_fields['picture'] = picture
                db.collection('users').document(user_id).set(update_fields, merge=True)
            except Exception as fe:
                logger.warning(f"Error updating user profile in Firestore: {fe}")

        # Update Firebase Auth if initialized
        if firebase_initialized:
            try:
                fb_updates = {}
                if name:
                    fb_updates['display_name'] = name
                if picture:
                    fb_updates['photo_url'] = picture
                if fb_updates:
                    firebase_auth.update_user(user_id, **fb_updates)
            except Exception as fae:
                logger.warning(f"Error updating Firebase Auth user: {fae}")

        # Update SQLite
        try:
            conn = get_db_connection()
            if name and picture:
                conn.execute('UPDATE users SET name = ?, picture = ? WHERE id = ?', (name, picture, user_id))
            elif name:
                conn.execute('UPDATE users SET name = ? WHERE id = ?', (name, user_id))
            elif picture:
                conn.execute('UPDATE users SET picture = ? WHERE id = ?', (picture, user_id))
            conn.commit()
            conn.close()
        except Exception as se:
            logger.warning(f"Error updating user in SQLite: {se}")

        if name:
            session['user_name'] = name
        if picture:
            session['user_picture'] = picture

        return jsonify({
            'success': True,
            'message': 'Profile updated successfully!',
            'user': {
                'id': user_id,
                'uid': user_id,
                'name': session.get('user_name', name),
                'email': session.get('user_email', ''),
                'picture': session.get('user_picture', picture)
            }
        })
    except Exception as e:
        logger.exception("Error updating profile")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user/photo', methods=['POST'])
@firebase_auth_required
def api_upload_user_photo():
    """Upload new profile photo to Firebase Storage or local disk and update user profile"""
    try:
        user_id = request.user['uid']
        if 'photo' not in request.files and 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No image file uploaded.'}), 400

        file = request.files.get('photo') or request.files.get('file')
        if not file or not file.filename:
            return jsonify({'success': False, 'error': 'Empty file selected.'}), 400

        allowed_exts = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.svg'}
        _, ext = os.path.splitext(file.filename.lower())
        if ext not in allowed_exts:
            ext = '.png'

        filename = f"avatar_{int(datetime.utcnow().timestamp())}{ext}"
        storage_path = f"users/{user_id}/{filename}"
        public_url = None

        # 1. Try Firebase Storage
        bucket = get_storage_bucket()
        if bucket:
            try:
                blob = bucket.blob(storage_path)
                content_type = file.content_type or 'image/png'
                blob.upload_from_file(file, content_type=content_type)
                try:
                    blob.make_public()
                    public_url = blob.public_url
                except Exception:
                    public_url = blob.generate_signed_url(expiration=timedelta(days=3650))
            except Exception as be:
                logger.warning(f"Failed to upload avatar to Firebase Storage: {be}")

        # 2. Local fallback if storage not available or failed
        if not public_url:
            local_dir = os.path.join(BASE_DIR, 'static', 'uploads', 'avatars')
            os.makedirs(local_dir, exist_ok=True)
            local_filename = f"{user_id}_{int(datetime.utcnow().timestamp())}{ext}"
            local_path = os.path.join(local_dir, local_filename)
            file.seek(0)
            file.save(local_path)
            public_url = f"/static/uploads/avatars/{local_filename}"

        # Update profile with new photo
        if db:
            try:
                db.collection('users').document(user_id).set({
                    'picture': public_url,
                    'updatedAt': firestore.SERVER_TIMESTAMP
                }, merge=True)
            except Exception as fe:
                logger.warning(f"Error updating picture in Firestore: {fe}")

        if firebase_initialized:
            try:
                firebase_auth.update_user(user_id, photo_url=public_url)
            except Exception as fae:
                logger.warning(f"Error updating picture in Firebase Auth: {fae}")

        try:
            conn = get_db_connection()
            conn.execute('UPDATE users SET picture = ? WHERE id = ?', (public_url, user_id))
            conn.commit()
            conn.close()
        except Exception as se:
            logger.warning(f"Error updating picture in SQLite: {se}")

        session['user_picture'] = public_url

        return jsonify({
            'success': True,
            'message': 'Profile photo updated successfully!',
            'picture': public_url,
            'user': {
                'id': user_id,
                'uid': user_id,
                'name': session.get('user_name', 'User'),
                'email': session.get('user_email', ''),
                'picture': public_url
            }
        })
    except Exception as e:
        logger.exception("Error uploading profile photo")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user/email', methods=['PUT'])
@firebase_auth_required
def api_update_user_email():
    """Update current user's email address in Auth, Firestore, SQLite, and session"""
    try:
        user_id = request.user['uid']
        data = request.json or {}
        new_email = data.get('email', '').strip().lower()
        current_password = data.get('current_password', '')

        if not new_email or '@' not in new_email or '.' not in new_email:
            return jsonify({'success': False, 'error': 'A valid email address is required.'}), 400

        # Check if email is identical to current
        if new_email == session.get('user_email', '').lower():
            return jsonify({'success': False, 'error': 'New email is identical to your current email.'}), 400

        # Check if email already used by someone else in SQLite
        conn = get_db_connection()
        existing = conn.execute('SELECT id, password_hash FROM users WHERE email = ? AND id != ?', (new_email, user_id)).fetchone()
        if existing:
            conn.close()
            return jsonify({'success': False, 'error': 'This email address is already in use by another account.'}), 400

        # If user has a local password hash, verify current_password
        user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if user_row and user_row['password_hash'] and user_row['password_hash'] != 'FIREBASE_AUTH':
            if not current_password:
                conn.close()
                return jsonify({'success': False, 'error': 'Current password is required to change your email.'}), 400
            if not check_password_hash(user_row['password_hash'], current_password):
                conn.close()
                return jsonify({'success': False, 'error': 'Incorrect current password.'}), 403

        # Update Firebase Auth if initialized
        if firebase_initialized:
            try:
                firebase_auth.update_user(user_id, email=new_email)
            except Exception as fae:
                err_str = str(fae)
                if 'EMAIL_EXISTS' in err_str or 'email already exists' in err_str.lower():
                    conn.close()
                    return jsonify({'success': False, 'error': 'This email address is already registered in Firebase.'}), 400
                logger.warning(f"Firebase Auth update email notice: {fae}")

        # Update Firestore
        if db:
            try:
                db.collection('users').document(user_id).set({
                    'email': new_email,
                    'updatedAt': firestore.SERVER_TIMESTAMP
                }, merge=True)
            except Exception as fe:
                logger.warning(f"Error updating email in Firestore: {fe}")

        # Update SQLite
        conn.execute('UPDATE users SET email = ? WHERE id = ?', (new_email, user_id))
        conn.commit()
        conn.close()

        session['user_email'] = new_email

        return jsonify({
            'success': True,
            'message': 'Email address updated successfully!',
            'email': new_email
        })
    except Exception as e:
        logger.exception("Error updating email")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user/password', methods=['POST'])
@firebase_auth_required
def api_update_user_password():
    """Update current user's password in Auth and SQLite"""
    try:
        user_id = request.user['uid']
        data = request.json or {}
        current_password = data.get('current_password', '')
        new_password = data.get('new_password', '')

        if not new_password or len(new_password) < 6:
            return jsonify({'success': False, 'error': 'New password must be at least 6 characters long.'}), 400

        conn = get_db_connection()
        user_row = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()

        # If user has a local password hash, verify current password
        if user_row and user_row['password_hash'] and user_row['password_hash'] != 'FIREBASE_AUTH':
            if not current_password:
                conn.close()
                return jsonify({'success': False, 'error': 'Current password is required to change password.'}), 400
            if not check_password_hash(user_row['password_hash'], current_password):
                conn.close()
                return jsonify({'success': False, 'error': 'Incorrect current password.'}), 403

        # Update SQLite password hash
        new_hash = generate_password_hash(new_password)
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?', (new_hash, user_id))
        conn.commit()
        conn.close()

        # Update Firebase Auth if initialized
        if firebase_initialized:
            try:
                firebase_auth.update_user(user_id, password=new_password)
            except Exception as fae:
                logger.warning(f"Firebase Auth update password warning: {fae}")

        return jsonify({
            'success': True,
            'message': 'Password updated successfully!'
        })
    except Exception as e:
        logger.exception("Error updating password")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/user/account', methods=['DELETE', 'POST'])
@firebase_auth_required
def api_delete_user_account():
    """Permanently delete user account and cascade deletion across Auth, Firestore, SQLite, Storage, and Disk"""
    try:
        user_id = request.user['uid']
        data = request.json or {}
        confirmation = str(data.get('confirmation', '')).strip()

        # Confirm user intent (either 'DELETE' or user's email)
        user_email = session.get('user_email', '')
        if confirmation.upper() != 'DELETE' and (not user_email or confirmation.lower() != user_email.lower()):
            return jsonify({
                'success': False,
                'error': 'Please type DELETE or your email address to confirm permanent account deletion.'
            }), 400

        logger.info(f"Starting permanent account deletion for user: {user_id} ({user_email})")
        gathered_project_ids = set()
        gathered_build_ids = set()

        # 1. Gather all projects and builds from Firestore
        if db:
            try:
                # Query user projects
                pdocs = db.collection('projects').where('userId', '==', user_id).stream()
                for pdoc in pdocs:
                    gathered_project_ids.add(pdoc.id)
                    pdata = pdoc.to_dict() or {}
                    pbuilds = pdata.get('builds') or {}
                    for plat, binfo in pbuilds.items():
                        if isinstance(binfo, dict) and binfo.get('buildId'):
                            gathered_build_ids.add(binfo.get('buildId'))
                    # Delete project doc
                    try:
                        pdoc.reference.delete()
                    except Exception as pdel_err:
                        logger.warning(f"Error deleting Firestore project {pdoc.id}: {pdel_err}")

                # Query user builds
                bdocs = db.collection('builds').where('userId', '==', user_id).stream()
                for bdoc in bdocs:
                    gathered_build_ids.add(bdoc.id)
                    try:
                        bdoc.reference.delete()
                    except Exception as bdel_err:
                        logger.warning(f"Error deleting Firestore build {bdoc.id}: {bdel_err}")

                # Also delete any builds matching gathered project IDs
                for pid in gathered_project_ids:
                    try:
                        pbdocs = db.collection('builds').where('projectId', '==', pid).stream()
                        for pb in pbdocs:
                            gathered_build_ids.add(pb.id)
                            try:
                                pb.reference.delete()
                            except Exception:
                                pass
                    except Exception:
                        pass

                # Delete user doc from Firestore
                try:
                    db.collection('users').document(user_id).delete()
                    logger.info(f"Deleted Firestore user doc: {user_id}")
                except Exception as udel_err:
                    logger.warning(f"Error deleting Firestore user doc {user_id}: {udel_err}")
            except Exception as fe:
                logger.warning(f"Firestore cascading delete error: {fe}")

        # 2. Gather from and delete in SQLite
        try:
            conn = get_db_connection()
            # Find projects
            p_rows = conn.execute('SELECT id FROM projects WHERE user_id = ?', (user_id,)).fetchall()
            for prow in p_rows:
                gathered_project_ids.add(prow['id'])

            # Find builds
            b_rows = conn.execute('SELECT id FROM builds WHERE user_id = ?', (user_id,)).fetchall()
            for brow in b_rows:
                gathered_build_ids.add(brow['id'])

            # Delete records from SQLite
            conn.execute('DELETE FROM builds WHERE user_id = ?', (user_id,))
            for pid in gathered_project_ids:
                conn.execute('DELETE FROM builds WHERE project_id = ?', (pid,))
            conn.execute('DELETE FROM projects WHERE user_id = ?', (user_id,))
            conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
            conn.commit()
            conn.close()
            logger.info(f"Deleted SQLite records for user: {user_id}")
        except Exception as se:
            logger.warning(f"SQLite delete error: {se}")

        # 3. Delete all files from Firebase Cloud Storage
        try:
            bucket = get_storage_bucket()
            if bucket:
                prefixes = [
                    f"users/{user_id}/",
                    f"builds/{user_id}/",
                    f"projects/{user_id}/"
                ]
                for pid in gathered_project_ids:
                    prefixes.append(f"projects/{pid}/")
                    prefixes.append(f"builds/{pid}/")
                for bid in gathered_build_ids:
                    prefixes.append(f"builds/{bid}/")

                for prefix in prefixes:
                    try:
                        for blob in bucket.list_blobs(prefix=prefix):
                            try:
                                blob.delete()
                                logger.info(f"Deleted Storage blob: {blob.name}")
                            except Exception as berr:
                                logger.warning(f"Failed deleting blob {blob.name}: {berr}")
                    except Exception as perr:
                        logger.warning(f"Error listing blobs with prefix {prefix}: {perr}")
        except Exception as ste:
            logger.warning(f"Storage cleanup error: {ste}")

        # 4. Delete local disk artifacts for gathered build IDs
        for bid in gathered_build_ids:
            try:
                bdir = os.path.join(app.config.get('BUILD_FOLDER', ''), bid)
                if os.path.exists(bdir):
                    shutil.rmtree(bdir, ignore_errors=True)
                    logger.info(f"Deleted local build folder: {bdir}")
            except Exception as disk_err:
                logger.warning(f"Error deleting local build folder {bid}: {disk_err}")

        # Clean local avatar files if any
        try:
            avatar_dir = os.path.join(BASE_DIR, 'static', 'uploads', 'avatars')
            if os.path.exists(avatar_dir):
                for fname in os.listdir(avatar_dir):
                    if fname.startswith(f"{user_id}_"):
                        try:
                            os.remove(os.path.join(avatar_dir, fname))
                        except Exception:
                            pass
        except Exception:
            pass

        # 5. Delete user from Firebase Auth
        if firebase_initialized:
            try:
                firebase_auth.delete_user(user_id)
                logger.info(f"Deleted Firebase Auth user: {user_id}")
            except Exception as fae:
                logger.warning(f"Firebase Auth delete_user warning: {fae}")

        # 6. Clear in-memory state and session
        for bid in gathered_build_ids:
            build_progress.pop(bid, None)

        session.clear()

        return jsonify({
            'success': True,
            'message': 'Account and all associated records in Authentication, Database, and Storage were permanently deleted.',
            'redirect': '/'
        })
    except Exception as e:
        logger.exception("Error deleting account")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/firebase-config', methods=['GET'])
def api_firebase_config():
    """Return client Firebase configuration and active status"""
    return jsonify({
        'enabled': is_firebase_enabled(),
        'config': get_firebase_config()
    })


@app.route('/api/storage/upload', methods=['POST'])
def api_storage_upload():
    """Upload asset (icon, keystore, cert, image) to Firebase Storage or local static storage"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400

        file = request.files['file']
        if not file or not file.filename:
            return jsonify({'error': 'No file selected'}), 400

        storage_path = request.form.get('path', '').strip()
        filename = secure_filename(file.filename) or 'asset'

        # 1. Try Firebase Cloud Storage if bucket is available
        bucket = get_storage_bucket()
        if bucket:
            target_path = storage_path if storage_path else f"uploads/{uuid.uuid4().hex}_{filename}"
            blob = bucket.blob(target_path)
            content_type = file.content_type or 'application/octet-stream'
            blob.upload_from_file(file, content_type=content_type)
            try:
                blob.make_public()
                public_url = blob.public_url
            except Exception:
                public_url = blob.generate_signed_url(expiration=timedelta(days=365))

            return jsonify({
                'success': True,
                'url': public_url,
                'downloadUrl': public_url,
                'storagePath': target_path,
                'provider': 'firebase'
            })

        # 2. Resilient local fallback
        local_upload_dir = os.path.join(BASE_DIR, 'static', 'uploads')
        os.makedirs(local_upload_dir, exist_ok=True)
        unique_name = f"{uuid.uuid4().hex}_{filename}"
        local_file_path = os.path.join(local_upload_dir, unique_name)
        file.save(local_file_path)

        local_url = url_for('static', filename=f'uploads/{unique_name}')
        return jsonify({
            'success': True,
            'url': local_url,
            'downloadUrl': local_url,
            'storagePath': f'uploads/{unique_name}',
            'provider': 'local'
        })
    except Exception as e:
        logger.exception("Storage upload failed")
        return jsonify({'error': f'Storage upload failed: {str(e)}'}), 500


# ==================== PAGE ROUTES ====================

@app.route('/')
def index():
    """Landing page for ieWebNative"""
    user = None
    if 'user_id' in session:
        user = {
            'id': session['user_id'],
            'uid': session['user_id'],
            'name': session.get('user_name'),
            'email': session.get('user_email')
        }
    return render_template('landing.html', user=user, firebase_config=get_firebase_config())


@app.route('/auth')
def auth_page():
    """Authentication page (login/signup)"""
    if 'user_id' in session:
        return redirect(url_for('dashboard_page'))
    return render_template('auth.html', firebase_config=get_firebase_config())


@app.route('/dashboard')
def dashboard_page():
    """Dashboard page - requires authentication"""
    if 'user_id' not in session:
        return redirect(url_for('auth_page'))
    return render_template('dashboard.html', user={
        'id': session['user_id'],
        'uid': session['user_id'],
        'name': session.get('user_name'),
        'email': session.get('user_email'),
        'picture': session.get('user_picture')
    }, firebase_config=get_firebase_config())


@app.route('/builder')
def builder_page():
    """Builder page - requires authentication"""
    if 'user_id' not in session:
        return redirect(url_for('auth_page'))
    user = {
        'id': session['user_id'],
        'uid': session['user_id'],
        'name': session.get('user_name'),
        'email': session.get('user_email'),
        'picture': session.get('user_picture')
    }
    return render_template('index.html', user=user, firebase_config=get_firebase_config())


@app.route('/docs/store-publishing')
def docs_store_publishing():
    """Store publishing step-by-step documentation guide for novices"""
    user = None
    if 'user_id' in session:
        user = {
            'id': session['user_id'],
            'name': session.get('user_name'),
            'email': session.get('user_email')
        }
    return render_template('docs_store_publishing.html', user=user)


@app.route('/docs')
def docs_index():
    """Redirect /docs to the store publishing guide"""
    return redirect(url_for('docs_store_publishing'))


@app.route('/uploads/<filename>')
def serve_upload(filename):
    """Serve uploaded files (icons, etc.) securely"""
    safe_name = secure_filename(filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_name)
    if not os.path.isfile(file_path):
        return jsonify({'error': 'File not found'}), 404
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_name)


@app.route('/api/preview-proxy', methods=['GET'])
def preview_proxy():
    """Proxy web pages for live device frame preview, bypassing X-Frame-Options and CSP frame-ancestors restrictions"""
    target_url = request.args.get('url', '').strip()
    device = request.args.get('device', 'mobile').lower()

    if not target_url:
        return jsonify({'error': 'URL is required'}), 400

    # Auto-prepend https:// if missing scheme
    if not re.match(r'^https?://', target_url, re.IGNORECASE):
        target_url = 'https://' + target_url

    parsed = urlparse(target_url)
    if not parsed.scheme or not parsed.netloc:
        return jsonify({'error': 'Invalid URL format'}), 400

    # Choose realistic browser User-Agent matching selected device frame
    if device == 'desktop':
        ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36'
    elif device == 'tablet':
        ua = 'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'
    else:
        ua = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1'

    req_headers = {
        'User-Agent': ua,
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8',
        'Accept-Language': request.headers.get('Accept-Language', 'en-US,en;q=0.9'),
        'Upgrade-Insecure-Requests': '1',
    }

    try:
        session = requests.Session()
        # If localhost or 127.0.0.1, bypass any upstream proxies
        if parsed.hostname in ('localhost', '127.0.0.1'):
            session.trust_env = False

        try:
            resp = session.get(target_url, headers=req_headers, timeout=12, allow_redirects=True)
        except requests.exceptions.SSLError:
            resp = session.get(target_url, headers=req_headers, timeout=12, allow_redirects=True, verify=False)

        content_type = resp.headers.get('Content-Type', '')

        if 'text/html' in content_type:
            html = resp.text

            # Remove meta tags that enforce CSP or X-Frame-Options in the client DOM
            html = re.sub(r'<meta[^>]*http-equiv=["\']?Content-Security-Policy["\']?[^>]*>', '', html, flags=re.IGNORECASE)
            html = re.sub(r'<meta[^>]*http-equiv=["\']?X-Frame-Options["\']?[^>]*>', '', html, flags=re.IGNORECASE)

            final_url = resp.url
            base_tag = f'<base href="{final_url}">'
            helper_script = f"""
            <script>
                try {{ window.top = window.self; window.parent = window.self; }} catch(e) {{}}
                document.addEventListener('click', function(e) {{
                    var a = e.target.closest('a');
                    if (a && a.href && (a.href.startsWith('http://') || a.href.startsWith('https://')) && a.target !== '_blank') {{
                        e.preventDefault();
                        window.location.href = '/api/preview-proxy?url=' + encodeURIComponent(a.href) + '&device={device}';
                    }}
                }}, true);
            </script>
            """

            if re.search(r'<head[^>]*>', html, re.IGNORECASE):
                html = re.sub(r'(<head[^>]*>)', r'\1\n' + base_tag + '\n' + helper_script, html, count=1, flags=re.IGNORECASE)
            else:
                html = base_tag + '\n' + helper_script + '\n' + html

            response = Response(html, status=200, mimetype='text/html')
        else:
            response = Response(resp.content, status=resp.status_code, mimetype=content_type.split(';')[0] if content_type else 'application/octet-stream')

        # Strip all headers that prevent embedding inside an iframe
        response.headers.pop('X-Frame-Options', None)
        response.headers.pop('Content-Security-Policy', None)
        response.headers.pop('Content-Security-Policy-Report-Only', None)
        response.headers.pop('Strict-Transport-Security', None)
        response.headers['Access-Control-Allow-Origin'] = '*'

        return response

    except Exception as e:
        logger.warning(f"Preview proxy error for {target_url}: {e}")
        err_card = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
                    background-color: #f8fafc;
                    color: #334155;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    height: 100vh;
                    margin: 0;
                    padding: 24px;
                    box-sizing: border-box;
                    text-align: center;
                }}
                .card {{
                    background: #ffffff;
                    padding: 28px 24px;
                    border-radius: 16px;
                    box-shadow: 0 4px 20px rgba(0,0,0,0.06);
                    max-width: 320px;
                }}
                .icon {{
                    width: 48px;
                    height: 48px;
                    border-radius: 12px;
                    background: #eff6ff;
                    color: #3b82f6;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    margin: 0 auto 16px;
                }}
                h4 {{ margin: 0 0 8px; font-size: 16px; color: #0f172a; word-break: break-all; }}
                p {{ margin: 0 0 12px; font-size: 13px; color: #64748b; line-height: 1.4; }}
                .badge {{
                    display: inline-block;
                    background: #ecfdf5;
                    color: #059669;
                    font-size: 11px;
                    font-weight: 600;
                    padding: 4px 10px;
                    border-radius: 20px;
                    margin-top: 8px;
                }}
            </style>
        </head>
        <body>
            <div class="card">
                <div class="icon">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="12" cy="12" r="10"></circle>
                        <line x1="12" y1="8" x2="12" y2="12"></line>
                        <line x1="12" y1="16" x2="12.01" y2="16"></line>
                    </svg>
                </div>
                <h4>{target_url}</h4>
                <p>Website is verified and ready for native app packaging.</p>
                <div class="badge">&#10003; Ready to Build Native App</div>
            </div>
        </body>
        </html>
        """
        response = Response(err_card, status=200, mimetype='text/html')
        response.headers.pop('X-Frame-Options', None)
        response.headers.pop('Content-Security-Policy', None)
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

@app.route('/api/build', methods=['POST'])
def start_build():

    """
    Start a new build process
    ---
    tags:
      - Build
    consumes:
      - application/json
    produces:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          required:
            - app_name
            - app_version
            - build_number
            - web_url
            - platforms
          properties:
            app_name:
              type: string
            app_version:
              type: string
            build_number:
              type: string
            web_url:
              type: string
            platforms:
              type: array
              items:
                type: string
    responses:
      200:
        description: Build started successfully
      400:
        description: Invalid input
      500:
        description: Internal server error
    """

    try:
        logger.info("Received build request")

        data = request.json

        if not data:
            logger.warning("No JSON payload received")
            return jsonify({'error': 'Invalid JSON payload'}), 400

        # Validate required fields
        required_fields = [
            'app_name', 'app_description', 'app_version',
            'build_number', 'package_name', 'web_url', 'platforms'
        ]

        for field in required_fields:
            if field not in data or not data[field]:
                logger.warning(f"Missing required field: {field}")
                return jsonify({'error': f'Missing required field: {field}'}), 400

        if not data['platforms']:
            logger.warning("No platforms selected")
            return jsonify({'error': 'At least one platform must be selected'}), 400

        # Additional validations
        if 'download_directory' in data and not isinstance(data['download_directory'], str):
            return jsonify({'error': 'download_directory must be a string'}), 400

        if 'enable_camera_access' in data and not isinstance(data['enable_camera_access'], bool):
            return jsonify({'error': 'enable_camera_access must be a boolean'}), 400

        if 'enable_gallery_access' in data and not isinstance(data['enable_gallery_access'], bool):
            return jsonify({'error': 'enable_gallery_access must be a boolean'}), 400

        if 'camera_permission_prompt' in data and not isinstance(data['camera_permission_prompt'], bool):
            return jsonify({'error': 'camera_permission_prompt must be a boolean'}), 400

        if 'enable_qr_scanner' in data and not isinstance(data['enable_qr_scanner'], bool):
            return jsonify({'error': 'enable_qr_scanner must be a boolean'}), 400

        if 'enable_barcode_scanner' in data and not isinstance(data['enable_barcode_scanner'], bool):
            return jsonify({'error': 'enable_barcode_scanner must be a boolean'}), 400

        if 'scanner_formats' in data and not isinstance(data['scanner_formats'], (list, str)):
            return jsonify({'error': 'scanner_formats must be a list or string'}), 400

        # Generate build ID
        build_id = str(uuid.uuid4())
        logger.info(f"Starting build with ID: {build_id}")

        # ✅ SINGLE FINAL CONFIG
        config = {
            'app_name': data['app_name'],
            'app_description': data['app_description'],
            'app_version': data['app_version'],
            'build_number': data['build_number'],
            'package_name': data['package_name'],
            'web_url': data['web_url'],
            'platforms': data['platforms'],

            'allow_zoom': data.get('allow_zoom', False),
            'enable_javascript': data.get('enable_javascript', False),
            'enable_dom_storage': data.get('enable_dom_storage', False),
            'enable_geolocation': data.get('enable_geolocation', False),
            'enable_pull_refresh': data.get('enable_pull_refresh', False),
            'show_navigation': data.get('show_navigation', False),
            'enable_file_access': data.get('enable_file_access', False),
            'enable_cache': data.get('enable_cache', False),
            'enable_media_autoplay': data.get('enable_media_autoplay', False),
            'enable_camera': data.get('enable_camera', data.get('enable_camera_access', False)),
            'enable_microphone': data.get('enable_microphone', False),
            'enable_ssl_pinning': data.get('enable_ssl_pinning', False),
            'ssl_pins': data.get('ssl_pins', ''),
            'enable_biometric_auth': data.get('enable_biometric_auth', data.get('enable_biometrics', False)),
            'enable_app_lock': data.get('enable_app_lock', False),
            'app_lock_pin': data.get('app_lock_pin', ''),
            'enable_secure_storage': data.get('enable_secure_storage', False),

            'enable_camera_access': data.get('enable_camera_access', False),
            'enable_gallery_access': data.get('enable_gallery_access', False),
            'camera_permission_prompt': data.get('camera_permission_prompt', False),

            'enable_qr_scanner': data.get('enable_qr_scanner', False),
            'enable_barcode_scanner': data.get('enable_barcode_scanner', False),
            'scanner_formats': data.get('scanner_formats', []),

            'download_directory': data.get('download_directory', 'Downloads'),

            'keystore_path': data.get('keystore_path'),
            'keystore_password': data.get('keystore_password'),
            'key_alias': data.get('key_alias'),
            'key_password': data.get('key_password'),

            'apple_certificate_path': data.get('apple_certificate_path'),
            'apple_certificate_password': data.get('apple_certificate_password'),
            'apple_provisioning_profile_path': data.get('apple_provisioning_profile_path'),
            'team_id': data.get('team_id'),

            'enable_google_play_publish': data.get('enable_google_play_publish', False),
            'play_service_account_path': data.get('play_service_account_path'),
            'play_track': data.get('play_track', 'internal'),
            'play_status': data.get('play_status', 'draft'),

            'enable_app_store_publish': data.get('enable_app_store_publish', False),
            'app_store_key_path': data.get('app_store_key_path'),
            'app_store_key_id': data.get('app_store_key_id'),
            'app_store_issuer_id': data.get('app_store_issuer_id'),

            'icon_path': data.get('icon_path'),
            'enable_splash_screen': data.get('enable_splash_screen', False),
            'splash_title': data.get('splash_title', data.get('app_name', '')),
            'splash_subtitle': data.get('splash_subtitle', ''),
            'splash_bg_color': data.get('splash_bg_color', '#FFFFFF'),
            'splash_text_color': data.get('splash_text_color', '#1E293B'),
            'splash_duration': data.get('splash_duration', 2),
            'splash_image_path': data.get('splash_image_path'),

            'error_title': data.get('error_title', 'No Internet Connection'),
            'enable_error_page': data.get('enable_error_page', False),
            'error_message': data.get('error_message', 'Please check your connection and try again'),
            'error_button_text': data.get('error_button_text', 'Retry'),
            'error_bg_color': data.get('error_bg_color', '#FFFFFF'),
            'error_text_color': data.get('error_text_color', '#334155'),
            'error_image_path': data.get('error_image_path'),
            'webhook_url': data.get('webhook_url')
        }

        # Determine authenticated user (Flask session or Bearer token)
        auth_user_id = session.get('user_id')
        if not auth_user_id:
            auth_header = request.headers.get('Authorization', '')
            if auth_header.startswith('Bearer ') and firebase_initialized:
                try:
                    decoded = firebase_auth.verify_id_token(auth_header.split('Bearer ')[1].strip())
                    auth_user_id = decoded.get('uid')
                except Exception:
                    pass

        project_id = data.get('project_id') or data.get('projectId')
        app_name = data.get('app_name', 'Untitled App')
        web_url = data.get('web_url', '')
        app_desc = data.get('app_description', '')
        app_ver = data.get('app_version', '1.0.0')
        build_num = int(data.get('build_number', 1) or 1)
        pkg_name = data.get('package_name', '')
        icon_path = data.get('icon_path', '')
        now_str = datetime.utcnow().isoformat()

        settings_dict = {
            'allowZoom': data.get('allow_zoom', False),
            'enableJavascript': data.get('enable_javascript', False),
            'enableDomStorage': data.get('enable_dom_storage', False),
            'enableGeolocation': data.get('enable_geolocation', False),
            'enablePullRefresh': data.get('enable_pull_refresh', False),
            'showNavigation': data.get('show_navigation', False),
            'enableFileAccess': data.get('enable_file_access', False),
            'enableCache': data.get('enable_cache', False),
            'enableMediaAutoplay': data.get('enable_media_autoplay', False),
            'enableCamera': data.get('enable_camera', False),
            'enableMicrophone': data.get('enable_microphone', False),
            'enableSslPinning': data.get('enable_ssl_pinning', False),
            'sslPins': data.get('ssl_pins', ''),
            'enableBiometrics': data.get('enable_biometric_auth', data.get('enable_biometrics', False)),
            'enableAppLock': data.get('enable_app_lock', False),
            'appLockPin': data.get('app_lock_pin', ''),
            'enableSecureStorage': data.get('enable_secure_storage', False),
            'enableGooglePlayPublish': data.get('enable_google_play_publish', False),
            'playTrack': data.get('play_track', 'internal'),
            'playStatus': data.get('play_status', 'draft'),
            'enableAppStorePublish': data.get('enable_app_store_publish', False),
            'appStoreKeyId': data.get('app_store_key_id', ''),
            'appStoreIssuerId': data.get('app_store_issuer_id', ''),
            'enableSplashScreen': data.get('enable_splash_screen', False),
            'splashTitle': data.get('splash_title', ''),
            'splashSubtitle': data.get('splash_subtitle', ''),
            'splashBgColor': data.get('splash_bg_color', '#FFFFFF'),
            'splashTextColor': data.get('splash_text_color', '#1E293B'),
            'splashDuration': data.get('splash_duration', 2),
            'splashImagePath': data.get('splash_image_path', ''),
            'enableErrorPage': data.get('enable_error_page', False),
            'errorTitle': data.get('error_title', 'No Internet Connection'),
            'errorMessage': data.get('error_message', 'Please check your connection and try again'),
            'errorButtonText': data.get('error_button_text', 'Retry'),
            'errorBgColor': data.get('error_bg_color', '#FFFFFF'),
            'errorTextColor': data.get('error_text_color', '#334155'),
            'errorImagePath': data.get('error_image_path', '')
        }
        settings_json = json.dumps(settings_dict)

        # Auto-record or associate project if user is authenticated
        if auth_user_id:
            try:
                if not project_id:
                    # Check if matching project already exists for this user
                    if db:
                        try:
                            proj_stream = db.collection('projects').where('userId', '==', auth_user_id).stream()
                            for p_doc in proj_stream:
                                p_data = p_doc.to_dict()
                                if p_data.get('name') == app_name or (web_url and p_data.get('webUrl') == web_url):
                                    project_id = p_doc.id
                                    break
                        except Exception as pfe:
                            logger.warning(f"Error checking existing project in Firestore: {pfe}")

                    if not project_id:
                        conn = get_db_connection()
                        existing_proj = conn.execute(
                            'SELECT id FROM projects WHERE user_id = ? AND (name = ? OR (web_url != "" AND web_url = ?))',
                            (auth_user_id, app_name, web_url)
                        ).fetchone()
                        conn.close()
                        if existing_proj:
                            project_id = existing_proj['id']

                # If still no project_id, generate one and create project
                if not project_id:
                    project_id = str(uuid.uuid4())

                # Upsert in Firestore
                if db:
                    try:
                        p_ref = db.collection('projects').document(project_id)
                        p_snap = p_ref.get()
                        if p_snap.exists:
                            p_ref.update({
                                'name': app_name,
                                'webUrl': web_url,
                                'description': app_desc,
                                'appVersion': app_ver,
                                'buildNumber': build_num,
                                'packageName': pkg_name,
                                'settings': settings_dict,
                                'updatedAt': firestore.SERVER_TIMESTAMP
                            })
                        else:
                            p_ref.set({
                                'userId': auth_user_id,
                                'name': app_name,
                                'webUrl': web_url,
                                'description': app_desc,
                                'appVersion': app_ver,
                                'buildNumber': build_num,
                                'packageName': pkg_name,
                                'iconUrl': icon_path,
                                'settings': settings_dict,
                                'builds': {},
                                'createdAt': firestore.SERVER_TIMESTAMP,
                                'updatedAt': firestore.SERVER_TIMESTAMP
                            })
                    except Exception as fe:
                        logger.warning(f"Error syncing project to Firestore in start_build: {fe}")

                # Upsert in SQLite
                conn = get_db_connection()
                existing_row = conn.execute('SELECT id FROM projects WHERE id = ?', (project_id,)).fetchone()
                if existing_row:
                    conn.execute('''
                        UPDATE projects SET
                            name = ?, web_url = ?, description = ?,
                            app_version = ?, build_number = ?, package_name = ?,
                            settings_json = ?, updated_at = ?
                        WHERE id = ?
                    ''', (app_name, web_url, app_desc, app_ver, build_num, pkg_name, settings_json, now_str, project_id))
                else:
                    conn.execute('''
                        INSERT INTO projects (
                            id, user_id, name, web_url, description,
                            app_version, build_number, package_name,
                            icon_url, settings_json, created_at, updated_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (project_id, auth_user_id, app_name, web_url, app_desc, app_ver, build_num, pkg_name, icon_path, settings_json, now_str, now_str))
                conn.commit()
                conn.close()
            except Exception as auto_save_err:
                logger.warning(f"Project auto-save note: {auto_save_err}")

        # Store user & project in config
        config['user_id'] = auth_user_id
        config['project_id'] = project_id

        # Store initial build progress record with metadata
        selected_plat = config.get('platforms', ['android'])[0] if config.get('platforms') else 'android'
        session['active_build_id'] = build_id
        build_progress[build_id] = {
            'status': 'preparing',
            'progress': 5,
            'message': 'Preparing build environment...',
            'build_id': build_id,
            'project_id': project_id,
            'app_name': config.get('app_name', 'App'),
            'platform': selected_plat,
            'platforms': config.get('platforms', [selected_plat]),
            'user_id': auth_user_id,
            'start_time': datetime.now().isoformat(),
            'cancel_requested': False
        }

        # Run build
        thread = threading.Thread(target=run_build, args=(build_id, config))
        thread.start()

        logger.info(f"Build thread started for build ID: {build_id} (Project ID: {project_id})")
        return jsonify({'build_id': build_id, 'project_id': project_id})

    except Exception as e:
        logger.exception("Failed to start build process")
        return jsonify({'error': 'Failed to start build'}), 500

def _recover_build_if_on_disk(build_id):
    if build_id in build_progress:
        return True
    build_dir = os.path.join(app.config['BUILD_FOLDER'], build_id)
    outputs_dir = os.path.join(build_dir, 'outputs')
    if os.path.exists(outputs_dir):
        outputs = {}
        for f in os.listdir(outputs_dir):
            full_f = os.path.join(outputs_dir, f)
            if f.endswith('.apk'):
                outputs['android'] = full_f
            elif f.endswith('.aab'):
                outputs['android_aab'] = full_f
            elif f.endswith('.ipa'):
                outputs['ios'] = full_f
            elif 'xcode' in f.lower() and f.endswith('.zip'):
                outputs['ios_xcode'] = full_f
            elif f.endswith('.exe') or f.endswith('_windows.zip'):
                outputs['windows'] = full_f
            elif f.endswith('.zip') and 'project' not in f and 'keystore' not in f:
                outputs['windows'] = full_f
        if outputs:
            build_progress[build_id] = {
                'status': 'completed',
                'progress': 100,
                'message': 'Build completed successfully!',
                'outputs': outputs
            }
            return True
    return False

@app.route('/api/build/<build_id>/status', methods=['GET'])
def get_build_status(build_id):
    """Get the current status of a build"""
    _recover_build_if_on_disk(build_id)
    if build_id not in build_progress:
        return jsonify({'error': 'Build not found'}), 404
    return jsonify(build_progress[build_id])

@app.route('/api/build/active', methods=['GET'])
def get_active_build():
    """Get currently active (in-progress) build for the current user/session"""
    auth_user_id = session.get('user_id')
    active_build_id = session.get('active_build_id')

    ACTIVE_STATUSES = ['preparing', 'running', 'in_progress', 'queued', 'building', 'configuring', 'keystore', 'renaming', 'icons', 'dependencies']

    # If active_build_id is in session, check it first
    if active_build_id:
        _recover_build_if_on_disk(active_build_id)
        if active_build_id in build_progress:
            b = build_progress[active_build_id]
            if b.get('status') in ACTIVE_STATUSES:
                return jsonify({
                    'has_active_build': True,
                    'build_id': active_build_id,
                    'build': b
                })
            else:
                # Completed, cancelled, or failed - remove from session so it doesn't pop up again
                session.pop('active_build_id', None)

    # Search build_progress for any genuinely active build belonging to this user
    if auth_user_id:
        for bid, b in reversed(list(build_progress.items())):
            if b.get('user_id') == auth_user_id:
                if b.get('status') in ACTIVE_STATUSES:
                    session['active_build_id'] = bid
                    return jsonify({
                        'has_active_build': True,
                        'build_id': bid,
                        'build': b
                    })

    return jsonify({'has_active_build': False, 'build': None, 'build_id': None})

@app.route('/api/build/active/dismiss', methods=['POST'])
@app.route('/api/build/<build_id>/dismiss', methods=['POST'])
def dismiss_active_build(build_id=None):
    """Dismiss active/completed build from session so modals/banners never pop up again"""
    session.pop('active_build_id', None)
    return jsonify({'success': True, 'message': 'Build notification dismissed'})

@app.route('/api/build/<build_id>/cancel', methods=['POST'])
def cancel_build(build_id):
    """Cancel an ongoing build immediately"""
    _recover_build_if_on_disk(build_id)

    if session.get('active_build_id') == build_id:
        session.pop('active_build_id', None)

    if build_id not in build_progress:
        return jsonify({'success': True, 'message': 'Build not active', 'status': 'cancelled'})

    b = build_progress[build_id]
    if b.get('status') in ['completed', 'failed', 'error', 'cancelled']:
        return jsonify({'success': True, 'message': f"Build is already {b.get('status')}", 'status': b.get('status')})

    # Mark as cancelled immediately
    b['cancel_requested'] = True
    b['status'] = 'cancelled'
    b['message'] = 'Build cancelled by user.'
    b['progress'] = 0

    # Terminate any running subprocesses for this build
    procs = ACTIVE_BUILD_PROCESSES.pop(build_id, [])
    for proc in procs:
        try:
            proc.terminate()
            proc.kill()
        except Exception:
            pass

    # Attempt to cancel GitHub Actions workflow run if running in cloud
    run_id = b.get('github_run_id')
    github_token = os.getenv('GITHUB_TOKEN')
    github_owner = os.getenv('GITHUB_OWNER', 'ieenterprises')
    github_repo = os.getenv('GITHUB_REPO', 'iewebnative-builds')

    if run_id and github_token:
        try:
            requests.post(
                f"https://api.github.com/repos/{github_owner}/{github_repo}/actions/runs/{run_id}/cancel",
                headers={
                    'Authorization': f'Bearer {github_token}',
                    'Accept': 'application/vnd.github.v3+json'
                },
                timeout=10
            )
            logger.info(f"Triggered GitHub Actions cancel for run {run_id}")
        except Exception as e:
            logger.warning(f"Error cancelling GitHub Actions run: {e}")

    # Update SQLite database if build row exists
    try:
        conn = get_db_connection()
        conn.execute('UPDATE builds SET status = ? WHERE id = ?', ('cancelled', build_id))
        conn.commit()
        conn.close()
    except Exception:
        pass

    # Update Firestore if build doc exists
    if db:
        try:
            db.collection('builds').document(build_id).set({'status': 'cancelled', 'updatedAt': firestore.SERVER_TIMESTAMP}, merge=True)
        except Exception:
            pass

    return jsonify({'success': True, 'message': 'Build cancelled successfully', 'status': 'cancelled'})


@app.route('/api/build/<build_id>/export', methods=['GET'])
def export_build_project(build_id):
    """Download the generated Flutter project as a zip file with GitHub Actions workflow"""
    build_dir = os.path.join(app.config['BUILD_FOLDER'], build_id)
    project_dir = os.path.join(build_dir, 'project')
    if not os.path.exists(project_dir):
        return jsonify({'error': 'Project directory not found'}), 404

    zip_path = os.path.join(build_dir, 'outputs', f'{build_id}_project.zip')
    os.makedirs(os.path.dirname(zip_path), exist_ok=True)
    if not os.path.exists(zip_path):
        shutil.make_archive(zip_path.replace('.zip', ''), 'zip', project_dir)
    return send_file(zip_path, as_attachment=True, download_name='flutter_webview_app.zip')

@app.route('/api/build/<build_id>/download/<platform>')
def download_build(build_id, platform):
    _recover_build_if_on_disk(build_id)
    if build_id not in build_progress:
        # Check SQLite
        try:
            conn = get_db_connection()
            b_row = conn.execute('SELECT outputs_json, artifacts_json, user_id, project_id FROM builds WHERE id = ?', (build_id,)).fetchone()
            conn.close()
            if b_row and b_row['outputs_json']:
                build_progress[build_id] = {
                    'status': 'completed',
                    'progress': 100,
                    'outputs': json.loads(b_row['outputs_json']),
                    'artifacts': json.loads(b_row['artifacts_json']) if b_row['artifacts_json'] else {},
                    'userId': b_row['user_id'] if 'user_id' in b_row.keys() else '',
                    'projectId': b_row['project_id'] if 'project_id' in b_row.keys() else ''
                }
        except Exception as e:
            logger.debug(f"SQLite build recovery notice: {e}")

    if build_id not in build_progress and db:
        # Check Firestore
        try:
            b_doc = db.collection('builds').document(build_id).get()
            if b_doc.exists:
                b_data = b_doc.to_dict()
                build_progress[build_id] = {
                    'status': 'completed',
                    'progress': 100,
                    'outputs': b_data.get('outputs', {}),
                    'artifacts': b_data.get('artifacts', {}),
                    'userId': b_data.get('userId', ''),
                    'projectId': b_data.get('projectId', '')
                }
        except Exception as e:
            logger.debug(f"Firestore build recovery notice: {e}")

    if build_id not in build_progress:
        return jsonify({'error': 'Build not found'}), 404

    progress = build_progress[build_id]
    if progress.get('status') != 'completed':
        return jsonify({'error': 'Build not completed'}), 400

    # Handle keystore download
    if platform == 'keystore':
        if not progress.get('keystore_generated'):
            return jsonify({'error': 'No keystore was generated for this build'}), 404

        keystore_path = progress.get('keystore_path')
        if keystore_path and os.path.exists(keystore_path):
            build_dir = os.path.join(app.config['BUILD_FOLDER'], build_id)
            keystore_dir = os.path.join(build_dir, 'keystore')
            zip_path = os.path.join(build_dir, 'outputs', 'keystore-bundle.zip')
            shutil.make_archive(zip_path.replace('.zip', ''), 'zip', keystore_dir)
            if os.path.exists(zip_path):
                return send_file(zip_path, as_attachment=True, download_name='keystore-bundle.zip')
        return jsonify({'error': 'Keystore file not found'}), 404

    outputs = progress.get('outputs', {})
    artifacts = progress.get('artifacts', {}) or {}
    plat_artifact = artifacts.get(platform, {}) if isinstance(artifacts, dict) else {}
    output_path = outputs.get(platform)

    # 1. Check if direct link or storage URL is already in outputs or artifacts
    storage_url = plat_artifact.get('storageUrl') or (output_path if output_path and (output_path.startswith('http://') or output_path.startswith('https://')) else None)
    if storage_url:
        return redirect(storage_url)

    if plat_artifact.get('githubDownloadUrl'):
        return redirect(plat_artifact['githubDownloadUrl'])

    if output_path and output_path.startswith('Error:'):
        return jsonify({'error': output_path}), 400

    # 2. If local path exists on disk, send it directly
    if output_path and os.path.exists(output_path):
        return send_file(output_path, as_attachment=True, download_name=os.path.basename(output_path))

    # 3. Search in build output directory on local disk
    build_dir = os.path.join(app.config['BUILD_FOLDER'], build_id)
    outputs_dir = os.path.join(build_dir, 'outputs')
    if os.path.exists(outputs_dir):
        ext_map = {
            'android': ('.apk',),
            'android_aab': ('.aab',),
            'ios': ('.ipa',),
            'ios_xcode': ('_xcode_project.zip', '.zip'),
            'windows': ('_windows.zip', '.exe', '.zip'),
            'macos': ('.dmg', '_macos.zip', '.zip'),
            'linux': ('.tar.gz', '_linux.zip', '.zip')
        }
        target_exts = ext_map.get(platform, ('.zip', '.apk'))
        for f in os.listdir(outputs_dir):
            if any(f.endswith(ext) for ext in target_exts):
                candidate_path = os.path.join(outputs_dir, f)
                return send_file(candidate_path, as_attachment=True, download_name=f)

    # 4. Check Firebase Storage bucket blobs
    try:
        bucket = get_storage_bucket()
        if bucket:
            user_id = progress.get('userId')
            project_id = progress.get('projectId')
            fname = os.path.basename(output_path) if output_path else ''
            candidates = []
            if user_id and fname:
                candidates.append(f"builds/{user_id}/{project_id or 'general'}/{platform}_{fname}")
            if user_id:
                for b_item in bucket.list_blobs(prefix=f"builds/{user_id}/", max_results=25):
                    if platform in b_item.name:
                        candidates.append(b_item.name)
                        break
            for c_name in candidates:
                b_blob = bucket.blob(c_name)
                if b_blob.exists():
                    try:
                        s_url = b_blob.generate_signed_url(timedelta(days=7), method='GET')
                        return redirect(s_url)
                    except Exception:
                        pass
    except Exception as st_err:
        logger.warning(f"Error checking cloud storage during download: {st_err}")

    # 5. Check GitHub Releases as public cloud fallback
    try:
        github_token = os.getenv('GITHUB_TOKEN')
        github_owner = os.getenv('GITHUB_OWNER', 'ieenterprises')
        github_repo = os.getenv('GITHUB_REPO', 'iewebnative-builds')
        headers = {'Accept': 'application/vnd.github.v3+json'}
        if github_token:
            headers['Authorization'] = f'Bearer {github_token}'
        r_rel = requests.get(f"https://api.github.com/repos/{github_owner}/{github_repo}/releases", headers=headers, timeout=10)
        if r_rel.status_code == 200:
            short_id = build_id[:8]
            for rel in r_rel.json():
                tag = rel.get('tag_name', '')
                if short_id in tag:
                    for asset in rel.get('assets', []):
                        asset_name = asset['name'].lower()
                        dl_match = False
                        if platform == 'android' and asset_name.endswith('.apk'):
                            dl_match = True
                        elif platform == 'android_aab' and asset_name.endswith('.aab'):
                            dl_match = True
                        elif platform == 'ios' and asset_name.endswith('.ipa'):
                            dl_match = True
                        elif platform == 'ios_xcode' and 'xcode' in asset_name:
                            dl_match = True
                        elif platform == 'windows' and ('win' in asset_name or asset_name.endswith('.zip')):
                            dl_match = True
                        elif platform == 'macos' and ('macos' in asset_name or asset_name.endswith('.dmg')):
                            dl_match = True
                        elif platform == 'linux' and ('linux' in asset_name or asset_name.endswith('.tar.gz')):
                            dl_match = True
                        if dl_match:
                            return redirect(asset['browser_download_url'])
    except Exception as ge:
        logger.warning(f"Error checking GitHub releases for download: {ge}")

    return jsonify({'error': 'Output file not found'}), 404

@app.route('/api/upload/keystore', methods=['POST'])
def upload_keystore():
    if 'keystore' not in request.files:
        return jsonify({'error': 'No keystore file provided'}), 400

    file = request.files['keystore']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file:
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'success': True, 'filename': filename, 'path': filepath})

    return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/upload/icon', methods=['POST'])
def upload_icon():
    if 'icon' not in request.files:
        return jsonify({'error': 'No icon file provided'}), 400

    file = request.files['icon']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if file:
        # Generate unique filename
        ext = os.path.splitext(file.filename)[1].lower()
        if ext not in ['.png', '.jpg', '.jpeg']:
            return jsonify({'error': 'Invalid file type. Use PNG or JPG'}), 400

        filename = f"{uuid.uuid4()}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        return jsonify({'success': True, 'filename': filename, 'path': filepath})

    return jsonify({'error': 'Upload failed'}), 500

@app.route('/api/upload/splash-image', methods=['POST'])
def upload_splash_image():
    """Upload custom splash screen image"""
    file = request.files.get('splash_image') or request.files.get('image')
    if not file or file.filename == '':
        return jsonify({'error': 'No image file provided'}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.webp']:
        return jsonify({'error': 'Invalid file type. Use PNG, JPG, or WEBP'}), 400

    filename = f"splash_{uuid.uuid4()}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return jsonify({'success': True, 'filename': filename, 'path': filepath})

@app.route('/api/upload/error-image', methods=['POST'])
def upload_error_image():
    """Upload custom error / offline page image"""
    file = request.files.get('error_image') or request.files.get('image')
    if not file or file.filename == '':
        return jsonify({'error': 'No image file provided'}), 400

    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.png', '.jpg', '.jpeg', '.webp']:
        return jsonify({'error': 'Invalid file type. Use PNG, JPG, or WEBP'}), 400

    filename = f"error_{uuid.uuid4()}{ext}"
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)
    return jsonify({'success': True, 'filename': filename, 'path': filepath})


# ==================== APPLE SIGNING API ENDPOINTS ====================

@app.route('/api/upload/apple-certificate', methods=['POST'])
def upload_apple_certificate():
    """Upload and validate Apple distribution certificate (.p12)"""
    if not is_macos() and not os.getenv('GITHUB_TOKEN'):
        return jsonify({'error': 'Apple signing is only available on macOS or via Cloud Builder'}), 400

    if 'certificate' not in request.files:
        return jsonify({'error': 'No certificate file provided'}), 400

    file = request.files['certificate']
    password = request.form.get('password', '')

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Validate file extension
    ext = os.path.splitext(file.filename)[1].lower()
    if ext not in ['.p12', '.pfx']:
        return jsonify({'error': 'Invalid file type. Use .p12 or .pfx file'}), 400

    # Save to secure temp location first for validation
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4()}{ext}")
    file.save(temp_path)

    try:
        # Validate the certificate
        validation = validate_apple_certificate(temp_path, password)

        if not validation['valid']:
            os.remove(temp_path)
            return jsonify({'error': validation['error']}), 400

        # Move to permanent location with unique name
        filename = f"{uuid.uuid4()}{ext}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.rename(temp_path, filepath)

        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath,
            'info': validation.get('info', {})
        })

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': f'Certificate validation failed: {str(e)}'}), 500


@app.route('/api/upload/provisioning-profile', methods=['POST'])
def upload_provisioning_profile():
    """Upload and validate Apple provisioning profile"""
    if not is_macos() and not os.getenv('GITHUB_TOKEN'):
        return jsonify({'error': 'Apple signing is only available on macOS or via Cloud Builder'}), 400

    if 'profile' not in request.files:
        return jsonify({'error': 'No provisioning profile provided'}), 400

    file = request.files['profile']

    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    # Validate file extension
    if not file.filename.endswith('.mobileprovision'):
        return jsonify({'error': 'Invalid file type. Use .mobileprovision file'}), 400

    # Save to temp location for validation
    temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4()}.mobileprovision")
    file.save(temp_path)

    try:
        # Create temporary signing handler to validate profile
        with SecureAppleSigning('validation') as signer:
            profile_info = signer.validate_provisioning_profile(temp_path)

        # Move to permanent location
        filename = f"{uuid.uuid4()}.mobileprovision"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        os.rename(temp_path, filepath)

        # Sanitize profile info for JSON response
        response_info = {
            'uuid': profile_info.get('uuid'),
            'name': profile_info.get('name'),
            'team_id': profile_info.get('team_id'),
            'app_bundle_id': profile_info.get('app_bundle_id'),
            'platform': profile_info.get('platform'),
            'is_development': profile_info.get('is_development', False),
        }

        # Handle datetime serialization
        if profile_info.get('expiration_date'):
            response_info['expiration_date'] = profile_info['expiration_date'].isoformat()

        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath,
            'info': response_info
        })

    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return jsonify({'error': str(e)}), 400


# ==================== STORE PUBLISHING API ENDPOINTS ====================

@app.route('/api/upload/play-key', methods=['POST'])
def upload_play_key():
    """Upload and validate Google Play Console Service Account JSON Key"""
    if 'play_key' not in request.files:
        return jsonify({'error': 'No Google Play service account JSON key provided'}), 400

    file = request.files['play_key']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        content = file.read()
        key_data = json.loads(content.decode('utf-8'))

        # Validate service account fields
        client_email = key_data.get('client_email')
        project_id = key_data.get('project_id')
        private_key = key_data.get('private_key')

        if not client_email or not private_key:
            return jsonify({'error': 'Invalid Google Service Account JSON. Missing client_email or private_key.'}), 400

        filename = f"play_key_{uuid.uuid4().hex}.json"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(content)

        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath,
            'client_email': client_email,
            'project_id': project_id
        })
    except json.JSONDecodeError:
        return jsonify({'error': 'File is not valid JSON. Please upload a Google Cloud service account JSON key.'}), 400
    except Exception as e:
        logger.exception("Failed to process Google Play key")
        return jsonify({'error': f'Failed to process Google Play key: {str(e)}'}), 500


@app.route('/api/upload/app-store-key', methods=['POST'])
def upload_app_store_key():
    """Upload and validate App Store Connect API Key (.p8)"""
    if 'app_store_key' not in request.files:
        return jsonify({'error': 'No App Store Connect .p8 key file provided'}), 400

    file = request.files['app_store_key']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        content = file.read()
        text_content = content.decode('utf-8', errors='ignore')

        if 'BEGIN PRIVATE KEY' not in text_content and 'BEGIN EC PRIVATE KEY' not in text_content:
            return jsonify({'error': 'Invalid App Store Connect API key. Must be a valid .p8 private key file.'}), 400

        filename = f"asc_key_{uuid.uuid4().hex}.p8"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(filepath, 'wb') as f:
            f.write(content)

        return jsonify({
            'success': True,
            'filename': filename,
            'path': filepath
        })
    except Exception as e:
        logger.exception("Failed to process App Store Connect key")
        return jsonify({'error': f'Failed to process App Store Connect key: {str(e)}'}), 500


@app.route('/api/apple/check-platform', methods=['GET'])
def check_apple_platform():
    """Check if Apple signing is available (macOS or Cloud Builder)"""
    has_cloud = bool(os.getenv('GITHUB_TOKEN'))
    available = is_macos() or has_cloud
    return jsonify({
        'available': available,
        'cloud_builder': has_cloud,
        'platform': platform.system(),
        'message': 'Apple signing & iOS builds available via Cloud Builder' if has_cloud else ('Apple signing is available' if is_macos() else 'Apple signing requires macOS or Cloud Builder')
    })

@app.route('/api/project/save', methods=['POST'])
def save_project():
    """Save project as encrypted .swab file"""
    data = request.json

    # Validate required fields
    required_fields = ['app_name', 'app_version', 'build_number']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'Missing required field: {field}'}), 400

    app_name = data['app_name']
    app_version = data['app_version']
    build_number = data['build_number']

    # Create a temporary directory for the project
    temp_dir = tempfile.mkdtemp()

    try:
        # Create project structure
        project_data = {
            'app_name': app_name,
            'app_description': data.get('app_description', ''),
            'app_version': app_version,
            'build_number': build_number,
            'package_name': data.get('package_name', ''),
            'web_url': data.get('web_url', ''),
            # WebView settings
            'allow_zoom': data.get('allow_zoom', False),
            'enable_javascript': data.get('enable_javascript', False),
            'enable_dom_storage': data.get('enable_dom_storage', False),
            'enable_geolocation': data.get('enable_geolocation', False),
            'enable_pull_refresh': data.get('enable_pull_refresh', False),
            'show_navigation': data.get('show_navigation', False),
            'enable_file_access': data.get('enable_file_access', False),
            'enable_cache': data.get('enable_cache', False),
            'enable_media_autoplay': data.get('enable_media_autoplay', False),
            'enable_camera': data.get('enable_camera', False),
            'enable_microphone': data.get('enable_microphone', False),
            'enable_ssl_pinning': data.get('enable_ssl_pinning', False),
            'ssl_pins': data.get('ssl_pins', ''),
            'enable_biometrics': data.get('enable_biometrics', False),
            'enable_app_lock': data.get('enable_app_lock', False),
            'app_lock_pin': data.get('app_lock_pin', ''),
            'enable_secure_storage': data.get('enable_secure_storage', False),
            # Keystore info (credentials only, file stored separately)
            'keystore_password': data.get('keystore_password', ''),
            'key_alias': data.get('key_alias', ''),
            'key_password': data.get('key_password', ''),
            # Apple signing info (credentials only, files stored separately)
            'apple_certificate_password': data.get('apple_certificate_password', ''),
            'team_id': data.get('team_id', ''),
            # Store Publishing info
            'enable_google_play_publish': data.get('enable_google_play_publish', False),
            'play_track': data.get('play_track', 'internal'),
            'play_status': data.get('play_status', 'draft'),
            'enable_app_store_publish': data.get('enable_app_store_publish', False),
            'app_store_key_id': data.get('app_store_key_id', ''),
            'app_store_issuer_id': data.get('app_store_issuer_id', ''),
            # Splash screen settings
            'enable_splash_screen': data.get('enable_splash_screen', False),
            'splash_title': data.get('splash_title', ''),
            'splash_subtitle': data.get('splash_subtitle', ''),
            'splash_bg_color': data.get('splash_bg_color', '#FFFFFF'),
            'splash_text_color': data.get('splash_text_color', '#1E293B'),
            'splash_duration': data.get('splash_duration', 2),
            # Error / offline page settings
            'enable_error_page': data.get('enable_error_page', False),
            'error_title': data.get('error_title', 'No Internet Connection'),
            'error_message': data.get('error_message', 'Please check your connection and try again'),
            'error_button_text': data.get('error_button_text', 'Retry'),
            'error_bg_color': data.get('error_bg_color', '#FFFFFF'),
            'error_text_color': data.get('error_text_color', '#334155')
        }

        # Save project.json
        project_json_path = os.path.join(temp_dir, 'project.json')
        with open(project_json_path, 'w') as f:
            json.dump(project_data, f, indent=2)

        # Create assets directory
        assets_dir = os.path.join(temp_dir, 'assets')
        os.makedirs(assets_dir, exist_ok=True)

        # Copy icon if provided
        icon_path = data.get('icon_path')
        if icon_path and os.path.exists(icon_path):
            ext = os.path.splitext(icon_path)[1]
            shutil.copy(icon_path, os.path.join(assets_dir, f'icon{ext}'))
        elif data.get('icon_url'):
            try:
                i_url = data.get('icon_url')
                i_resp = requests.get(i_url, timeout=15)
                if i_resp.status_code == 200:
                    ext = '.png'
                    if 'image/jpeg' in i_resp.headers.get('Content-Type', '') or '.jpg' in i_url or '.jpeg' in i_url:
                        ext = '.jpg'
                    with open(os.path.join(assets_dir, f'icon{ext}'), 'wb') as f:
                        f.write(i_resp.content)
            except Exception as e:
                logger.warning(f"Could not download remote icon for save_project: {e}")

        # Copy splash image if provided
        splash_image_path = data.get('splash_image_path')
        if splash_image_path and os.path.exists(splash_image_path):
            ext = os.path.splitext(splash_image_path)[1]
            shutil.copy(splash_image_path, os.path.join(assets_dir, f'splash_image{ext}'))
        elif data.get('splash_image_url') or data.get('splash_url'):
            try:
                s_url = data.get('splash_image_url') or data.get('splash_url')
                s_resp = requests.get(s_url, timeout=15)
                if s_resp.status_code == 200:
                    ext = '.png'
                    if 'image/jpeg' in s_resp.headers.get('Content-Type', '') or '.jpg' in s_url or '.jpeg' in s_url:
                        ext = '.jpg'
                    elif 'image/webp' in s_resp.headers.get('Content-Type', '') or '.webp' in s_url:
                        ext = '.webp'
                    with open(os.path.join(assets_dir, f'splash_image{ext}'), 'wb') as f:
                        f.write(s_resp.content)
            except Exception as e:
                logger.warning(f"Could not download remote splash image for save_project: {e}")

        # Copy error image if provided
        error_image_path = data.get('error_image_path')
        if error_image_path and os.path.exists(error_image_path):
            ext = os.path.splitext(error_image_path)[1]
            shutil.copy(error_image_path, os.path.join(assets_dir, f'error_image{ext}'))
        elif data.get('error_image_url') or data.get('error_url'):
            try:
                e_url = data.get('error_image_url') or data.get('error_url')
                e_resp = requests.get(e_url, timeout=15)
                if e_resp.status_code == 200:
                    ext = '.png'
                    if 'image/jpeg' in e_resp.headers.get('Content-Type', '') or '.jpg' in e_url or '.jpeg' in e_url:
                        ext = '.jpg'
                    elif 'image/webp' in e_resp.headers.get('Content-Type', '') or '.webp' in e_url:
                        ext = '.webp'
                    with open(os.path.join(assets_dir, f'error_image{ext}'), 'wb') as f:
                        f.write(e_resp.content)
            except Exception as e:
                logger.warning(f"Could not download remote error image for save_project: {e}")

        # Copy keystore if provided
        keystore_path = data.get('keystore_path')
        if keystore_path and os.path.exists(keystore_path):
            shutil.copy(keystore_path, os.path.join(assets_dir, 'keystore.jks'))

        # Copy Apple certificate if provided
        apple_cert_path = data.get('apple_certificate_path')
        if apple_cert_path and os.path.exists(apple_cert_path):
            ext = os.path.splitext(apple_cert_path)[1]
            shutil.copy(apple_cert_path, os.path.join(assets_dir, f'certificate{ext}'))

        # Copy Apple provisioning profile if provided
        apple_profile_path = data.get('apple_provisioning_profile_path')
        if apple_profile_path and os.path.exists(apple_profile_path):
            shutil.copy(apple_profile_path, os.path.join(assets_dir, 'profile.mobileprovision'))

        # Copy Google Play service account key if provided
        play_key_path = data.get('play_service_account_path')
        if play_key_path and os.path.exists(play_key_path):
            shutil.copy(play_key_path, os.path.join(assets_dir, 'google_play_key.json'))

        # Copy App Store Connect key if provided
        app_store_key_path = data.get('app_store_key_path')
        if app_store_key_path and os.path.exists(app_store_key_path):
            shutil.copy(app_store_key_path, os.path.join(assets_dir, 'app_store_key.p8'))

        # Create the zip file
        zip_path = os.path.join(temp_dir, 'project.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, dirs, files in os.walk(temp_dir):
                for file in files:
                    if file != 'project.zip':
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, temp_dir)
                        zipf.write(file_path, arcname)

        # Read and encrypt the zip
        with open(zip_path, 'rb') as f:
            zip_data = f.read()

        encrypted_data = encrypt_data(zip_data)

        # Generate filename
        safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', app_name)
        filename = f"{safe_name}_v{app_version}_{build_number}.iewebnative"

        # Save to outputs folder
        output_dir = os.path.join(app.config['BUILD_FOLDER'], 'saved_projects')
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, filename)

        with open(output_path, 'wb') as f:
            f.write(encrypted_data)

        return send_file(
            output_path,
            as_attachment=True,
            download_name=filename,
            mimetype='application/octet-stream'
        )

    except Exception as e:
        return jsonify({'error': f'Failed to save project: {str(e)}'}), 500

    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

@app.route('/api/project/open', methods=['POST'])
def open_project():
    """Open and decrypt a .iewebnative or .swab project file"""
    if 'project' not in request.files:
        return jsonify({'error': 'No project file provided'}), 400

    file = request.files['project']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not (file.filename.endswith('.iewebnative') or file.filename.endswith('.swab')):
        return jsonify({'error': 'Invalid file type. Please select a .iewebnative or .swab file'}), 400

    temp_dir = tempfile.mkdtemp()

    try:
        # Read encrypted data
        encrypted_data = file.read()

        # Decrypt data
        try:
            decrypted_data = decrypt_data(encrypted_data)
        except Exception:
            return jsonify({'error': 'Cannot open this project file. It was created on a different machine or has been corrupted.'}), 403

        # Write decrypted zip to temp file
        zip_path = os.path.join(temp_dir, 'project.zip')
        with open(zip_path, 'wb') as f:
            f.write(decrypted_data)

        # Extract zip
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(extract_dir)

        # Read project.json
        project_json_path = os.path.join(extract_dir, 'project.json')
        if not os.path.exists(project_json_path):
            return jsonify({'error': 'Invalid project file: missing project.json'}), 400

        with open(project_json_path, 'r') as f:
            project_data = json.load(f)

        # Handle assets
        assets_dir = os.path.join(extract_dir, 'assets')
        response_data = dict(project_data)

        # Copy icon to uploads if exists
        for ext in ['.png', '.jpg', '.jpeg']:
            icon_path = os.path.join(assets_dir, f'icon{ext}')
            if os.path.exists(icon_path):
                new_icon_name = f"{uuid.uuid4()}{ext}"
                new_icon_path = os.path.join(app.config['UPLOAD_FOLDER'], new_icon_name)
                shutil.copy(icon_path, new_icon_path)
                response_data['icon_path'] = new_icon_path
                break

        # Copy keystore to uploads if exists
        keystore_path = os.path.join(assets_dir, 'keystore.jks')
        if os.path.exists(keystore_path):
            new_keystore_name = f"{uuid.uuid4()}.jks"
            new_keystore_path = os.path.join(app.config['UPLOAD_FOLDER'], new_keystore_name)
            shutil.copy(keystore_path, new_keystore_path)
            response_data['keystore_path'] = new_keystore_path

        # Copy Apple certificate to uploads if exists
        for ext in ['.p12', '.pfx']:
            apple_cert_path = os.path.join(assets_dir, f'certificate{ext}')
            if os.path.exists(apple_cert_path):
                new_cert_name = f"{uuid.uuid4()}{ext}"
                new_cert_path = os.path.join(app.config['UPLOAD_FOLDER'], new_cert_name)
                shutil.copy(apple_cert_path, new_cert_path)
                response_data['apple_certificate_path'] = new_cert_path
                break

        # Copy Apple provisioning profile to uploads if exists
        apple_profile_path = os.path.join(assets_dir, 'profile.mobileprovision')
        if os.path.exists(apple_profile_path):
            new_profile_name = f"{uuid.uuid4()}.mobileprovision"
            new_profile_path = os.path.join(app.config['UPLOAD_FOLDER'], new_profile_name)
            shutil.copy(apple_profile_path, new_profile_path)
            response_data['apple_provisioning_profile_path'] = new_profile_path

            # Validate and extract profile info for UI
            try:
                with SecureAppleSigning('project_open') as signer:
                    profile_info = signer.validate_provisioning_profile(new_profile_path)
                    response_data['apple_profile_info'] = {
                        'uuid': profile_info.get('uuid'),
                        'name': profile_info.get('name'),
                        'team_id': profile_info.get('team_id'),
                        'app_bundle_id': profile_info.get('app_bundle_id'),
                    }
                    if profile_info.get('expiration_date'):
                        response_data['apple_profile_info']['expiration_date'] = profile_info['expiration_date'].isoformat()
            except Exception:
                pass  # Profile info extraction is optional

        # Copy Google Play service account key to uploads if exists
        play_key_path = os.path.join(assets_dir, 'google_play_key.json')
        if os.path.exists(play_key_path):
            new_play_key_name = f"play_key_{uuid.uuid4().hex}.json"
            new_play_key_path = os.path.join(app.config['UPLOAD_FOLDER'], new_play_key_name)
            shutil.copy(play_key_path, new_play_key_path)
            response_data['play_service_account_path'] = new_play_key_path

        # Copy App Store Connect key to uploads if exists
        app_store_key_path = os.path.join(assets_dir, 'app_store_key.p8')
        if os.path.exists(app_store_key_path):
            new_asc_name = f"asc_key_{uuid.uuid4().hex}.p8"
            new_asc_path = os.path.join(app.config['UPLOAD_FOLDER'], new_asc_name)
            shutil.copy(app_store_key_path, new_asc_path)
            response_data['app_store_key_path'] = new_asc_path

        # Copy splash image to uploads if exists
        for ext in ['.png', '.jpg', '.jpeg', '.webp']:
            for s_name in [f'splash_image{ext}', f'splash{ext}']:
                splash_img_path = os.path.join(assets_dir, s_name)
                if os.path.exists(splash_img_path):
                    new_splash_name = f"splash_{uuid.uuid4()}{ext}"
                    new_splash_path = os.path.join(app.config['UPLOAD_FOLDER'], new_splash_name)
                    shutil.copy(splash_img_path, new_splash_path)
                    response_data['splash_image_path'] = new_splash_path
                    break
            if 'splash_image_path' in response_data:
                break

        # Copy error image to uploads if exists
        for ext in ['.png', '.jpg', '.jpeg', '.webp']:
            for e_name in [f'error_image{ext}', f'error{ext}']:
                error_img_path = os.path.join(assets_dir, e_name)
                if os.path.exists(error_img_path):
                    new_error_name = f"error_{uuid.uuid4()}{ext}"
                    new_error_path = os.path.join(app.config['UPLOAD_FOLDER'], new_error_name)
                    shutil.copy(error_img_path, new_error_path)
                    response_data['error_image_path'] = new_error_path
                    break
            if 'error_image_path' in response_data:
                break

        return jsonify({'success': True, 'project': response_data})

    except Exception as e:
        return jsonify({'error': f'Failed to open project: {str(e)}'}), 500

    finally:
        # Cleanup temp directory
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==================== FIRESTORE PROJECT API ====================

def aggregate_builds_for_projects(user_id, projects):
    """
    Dynamically cross-references all completed builds in Firestore 'builds'
    collection for this user and ensures every project has all completed platform
    builds attached, healing any missing or overwritten builds permanently.
    """
    if not db or not projects:
        return
    try:
        build_docs = db.collection('builds').where('userId', '==', user_id).stream()
        by_project_id = {}
        by_app_name = {}
        for b_doc in build_docs:
            b_data = b_doc.to_dict()
            b_id = b_doc.id
            if b_data.get('status') != 'completed':
                continue
            pid = b_data.get('projectId')
            aname = (b_data.get('appName') or '').strip().lower()
            artifacts = b_data.get('artifacts', {}) or {}
            outputs = b_data.get('outputs', {}) or {}
            if not artifacts and outputs:
                artifacts = {}
                for plat, out_path in outputs.items():
                    if out_path and not out_path.startswith('Error:'):
                        artifacts[plat] = {
                            'buildId': b_id,
                            'platform': plat,
                            'fileName': os.path.basename(out_path),
                            'downloadUrl': f"/api/build/{b_id}/download/{plat}",
                            'status': 'completed'
                        }
            if pid:
                by_project_id.setdefault(pid, []).append((b_data, artifacts))
            if aname:
                by_app_name.setdefault(aname, []).append((b_data, artifacts))

        for proj in projects:
            p_id = proj.get('id')
            p_name = (proj.get('name') or '').strip().lower()
            current_builds = proj.get('builds') or {}
            changed = False

            matched_build_items = by_project_id.get(p_id, [])
            if not matched_build_items and p_name in by_app_name:
                matched_build_items = by_app_name[p_name]

            for b_data, artifacts in matched_build_items:
                for plat, art in artifacts.items():
                    if plat not in current_builds:
                        current_builds[plat] = art
                        changed = True
                    else:
                        for k in ['downloadUrl', 'storageUrl', 'githubDownloadUrl', 'fileName', 'fileSizeFormatted', 'fileSize']:
                            if not current_builds[plat].get(k) and art.get(k):
                                current_builds[plat][k] = art[k]
                                changed = True

            proj['builds'] = current_builds

            # Auto-repair project doc in Firestore if missing builds were found
            if changed and p_id:
                try:
                    db.collection('projects').document(p_id).set({'builds': current_builds}, merge=True)
                except Exception as he:
                    logger.debug(f"Auto-heal project builds notice: {he}")
    except Exception as e:
        logger.warning(f"Error in aggregate_builds_for_projects: {e}")


def aggregate_sqlite_builds_for_projects(user_id, projects):
    """
    Dynamically cross-references all completed builds in SQLite 'builds' table.
    """
    if not projects:
        return
    try:
        conn = get_db_connection()
        rows = conn.execute('SELECT * FROM builds WHERE user_id = ? AND status = "completed"', (user_id,)).fetchall()
        conn.close()
        by_project_id = {}
        by_app_name = {}
        for r in rows:
            b_id = r['id']
            pid = r['project_id']
            aname = (r['app_name'] or '').strip().lower()
            artifacts = {}
            if r['artifacts_json']:
                try:
                    artifacts = json.loads(r['artifacts_json'])
                except Exception:
                    pass
            if not artifacts and r['outputs_json']:
                try:
                    outputs = json.loads(r['outputs_json'])
                    for plat, out_path in outputs.items():
                        if out_path and not out_path.startswith('Error:'):
                            artifacts[plat] = {
                                'buildId': b_id,
                                'platform': plat,
                                'fileName': os.path.basename(out_path),
                                'downloadUrl': f"/api/build/{b_id}/download/{plat}",
                                'status': 'completed'
                            }
                except Exception:
                    pass
            if pid:
                by_project_id.setdefault(pid, []).append(artifacts)
            if aname:
                by_app_name.setdefault(aname, []).append(artifacts)

        for proj in projects:
            p_id = proj.get('id')
            p_name = (proj.get('name') or '').strip().lower()
            current_builds = proj.get('builds') or {}
            matched = by_project_id.get(p_id, []) or by_app_name.get(p_name, [])
            for arts in matched:
                for plat, art in arts.items():
                    if plat not in current_builds:
                        current_builds[plat] = art
            proj['builds'] = current_builds
    except Exception as e:
        logger.warning(f"Error in aggregate_sqlite_builds_for_projects: {e}")


@app.route('/api/projects', methods=['GET'])
@firebase_auth_required
def get_projects():
    """Get all projects for the authenticated user"""
    try:
        user_id = request.user['uid']
        if db:
            projects_ref = db.collection('projects')
            # Query by userId only (in-memory sort avoids composite index requirement)
            docs = projects_ref.where('userId', '==', user_id).stream()

            projects = []
            for doc in docs:
                project = doc.to_dict()
                project['id'] = doc.id
                if project.get('createdAt'):
                    project['createdAt'] = project['createdAt'].isoformat() if hasattr(project['createdAt'], 'isoformat') else str(project['createdAt'])
                if project.get('updatedAt'):
                    project['updatedAt'] = project['updatedAt'].isoformat() if hasattr(project['updatedAt'], 'isoformat') else str(project['updatedAt'])
                if not project.get('builds'):
                    project['builds'] = {}
                projects.append(project)

            # Dynamically aggregate any completed builds from builds collection
            aggregate_builds_for_projects(user_id, projects)

            projects.sort(key=lambda p: str(p.get('updatedAt') or p.get('createdAt') or ''), reverse=True)
            return jsonify({'projects': projects})
        else:
            conn = get_db_connection()
            rows = conn.execute('SELECT * FROM projects WHERE user_id = ? ORDER BY updated_at DESC', (user_id,)).fetchall()
            projects = []
            for r in rows:
                builds_dict = {}
                try:
                    if 'builds_json' in r.keys() and r['builds_json']:
                        builds_dict = json.loads(r['builds_json'])
                except Exception:
                    builds_dict = {}

                p_settings = json.loads(r['settings_json']) if r['settings_json'] else {}
                p_err_url = r['error_url'] if 'error_url' in r.keys() and r['error_url'] else p_settings.get('errorImageUrl', '')
                projects.append({
                    'id': r['id'],
                    'userId': r['user_id'],
                    'name': r['name'],
                    'webUrl': r['web_url'],
                    'description': r['description'],
                    'appVersion': r['app_version'],
                    'buildNumber': r['build_number'],
                    'packageName': r['package_name'],
                    'iconUrl': r['icon_url'],
                    'splashUrl': r['splash_url'],
                    'errorUrl': p_err_url,
                    'settings': p_settings,
                    'keystoreData': json.loads(r['keystore_json']) if r['keystore_json'] else {},
                    'appleData': json.loads(r['apple_json']) if r['apple_json'] else {},
                    'builds': builds_dict,
                    'createdAt': r['created_at'],
                    'updatedAt': r['updated_at']
                })
            conn.close()
            # Dynamically aggregate completed builds from SQLite builds table
            aggregate_sqlite_builds_for_projects(user_id, projects)
            return jsonify({'projects': projects})
    except Exception as e:
        logger.exception("Failed to fetch projects")
        return jsonify({'error': f'Failed to fetch projects: {str(e)}'}), 500

@app.route('/api/projects', methods=['POST'])
@firebase_auth_required
def create_project():
    """Create a new project"""
    try:
        user_id = request.user['uid']
        data = request.json or {}

        if not data:
            return jsonify({'error': 'No project data provided'}), 400

        project_id = str(uuid.uuid4())
        name = data.get('name', 'Untitled Project')
        web_url = data.get('webUrl', '')
        description = data.get('description', '')
        app_version = data.get('appVersion', '1.0.0')
        build_number = data.get('buildNumber', 1)
        package_name = data.get('packageName', '')
        icon_url = data.get('iconUrl', '')
        splash_url = data.get('splashUrl', '')
        error_url = data.get('errorUrl', '')
        builds_data = data.get('builds', {})
        settings_data = data.get('settings', {
            'allowZoom': True,
            'enableJavascript': True,
            'enableDomStorage': True,
            'enableGeolocation': True,
            'enablePullRefresh': True,
            'showNavigation': True,
            'enableFileAccess': True,
            'enableCache': True,
            'enableMediaAutoplay': False,
            'enableCamera': True,
            'enableMicrophone': True,
            'enableSslPinning': False,
            'sslPins': '',
            'enableBiometrics': False,
            'enableAppLock': False,
            'appLockPin': '',
            'enableSecureStorage': True
        })
        settings_json = json.dumps(settings_data)
        keystore_json = json.dumps(data.get('keystoreData', {}))
        apple_json = json.dumps(data.get('appleData', {}))
        builds_json = json.dumps(builds_data)
        now = datetime.utcnow().isoformat()

        if db:
            project_data = {
                'userId': user_id,
                'name': name,
                'webUrl': web_url,
                'description': description,
                'appVersion': app_version,
                'buildNumber': build_number,
                'packageName': package_name,
                'iconUrl': icon_url,
                'splashUrl': splash_url,
                'errorUrl': error_url,
                'settings': settings_data,
                'builds': builds_data,
                'createdAt': firestore.SERVER_TIMESTAMP,
                'updatedAt': firestore.SERVER_TIMESTAMP
            }
            for sp in ['iconStoragePath', 'splashStoragePath', 'errorStoragePath', 'keystoreStoragePath', 'appleCertStoragePath', 'appleProfileStoragePath']:
                if sp in data:
                    project_data[sp] = data[sp]
            if 'keystoreData' in data:
                project_data['keystoreData'] = data['keystoreData']
            if 'appleData' in data:
                project_data['appleData'] = data['appleData']
            if 'publishingData' in data:
                project_data['publishingData'] = data['publishingData']
            doc_ref = db.collection('projects').add(project_data)
            project_id = doc_ref[1].id

        # Sync to SQLite for backup / offline support
        try:
            conn = get_db_connection()
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO projects (id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, error_url, settings_json, keystore_json, apple_json, builds_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (project_id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, error_url, settings_json, keystore_json, apple_json, builds_json, now, now))
            except Exception:
                conn.execute('''
                    INSERT OR REPLACE INTO projects (id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, settings_json, keystore_json, apple_json, builds_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (project_id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, settings_json, keystore_json, apple_json, builds_json, now, now))
            conn.commit()
            conn.close()
        except Exception as se:
            logger.warning(f"Error syncing project to SQLite in create_project: {se}")

        return jsonify({'success': True, 'projectId': project_id})
    except Exception as e:
        logger.exception("Error creating project")
        return jsonify({'error': f'Failed to create project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['GET'])
@firebase_auth_required
def get_project(project_id):
    """Get a specific project"""
    try:
        user_id = request.user['uid']
        if db:
            doc_ref = db.collection('projects').document(project_id)
            doc = doc_ref.get()

            if not doc.exists:
                return jsonify({'error': 'Project not found'}), 404

            project = doc.to_dict()
            if project.get('userId') != user_id:
                return jsonify({'error': 'Access denied'}), 403

            project['id'] = doc.id
            if project.get('createdAt'):
                project['createdAt'] = project['createdAt'].isoformat() if hasattr(project['createdAt'], 'isoformat') else str(project['createdAt'])
            if project.get('updatedAt'):
                project['updatedAt'] = project['updatedAt'].isoformat() if hasattr(project['updatedAt'], 'isoformat') else str(project['updatedAt'])
            if not project.get('builds'):
                project['builds'] = {}

            # Dynamically aggregate any completed builds from builds collection
            aggregate_builds_for_projects(user_id, [project])

            return jsonify({'project': project})
        else:
            conn = get_db_connection()
            r = conn.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
            conn.close()
            if not r:
                return jsonify({'error': 'Project not found'}), 404
            if r['user_id'] != user_id:
                return jsonify({'error': 'Access denied'}), 403

            builds_dict = {}
            try:
                if 'builds_json' in r.keys() and r['builds_json']:
                    builds_dict = json.loads(r['builds_json'])
            except Exception:
                builds_dict = {}

            p_settings = json.loads(r['settings_json']) if r['settings_json'] else {}
            p_err_url = r['error_url'] if 'error_url' in r.keys() and r['error_url'] else p_settings.get('errorImageUrl', '')
            project = {
                'id': r['id'],
                'userId': r['user_id'],
                'name': r['name'],
                'webUrl': r['web_url'],
                'description': r['description'],
                'appVersion': r['app_version'],
                'buildNumber': r['build_number'],
                'packageName': r['package_name'],
                'iconUrl': r['icon_url'],
                'splashUrl': r['splash_url'],
                'errorUrl': p_err_url,
                'settings': p_settings,
                'keystoreData': json.loads(r['keystore_json']) if r['keystore_json'] else {},
                'appleData': json.loads(r['apple_json']) if r['apple_json'] else {},
                'publishingData': p_settings.get('publishingData', {}),
                'builds': builds_dict,
                'createdAt': r['created_at'],
                'updatedAt': r['updated_at']
            }
            # Dynamically aggregate completed builds from SQLite builds table
            aggregate_sqlite_builds_for_projects(user_id, [project])
            return jsonify({'project': project})
    except Exception as e:
        return jsonify({'error': f'Failed to fetch project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['PUT'])
@firebase_auth_required
def update_project(project_id):
    """Update a project"""
    try:
        user_id = request.user['uid']
        data = request.json
        if not data:
            return jsonify({'error': 'No project data provided'}), 400

        allowed_fields = ['name', 'webUrl', 'description', 'appVersion', 'buildNumber',
                          'packageName', 'iconUrl', 'splashUrl', 'errorUrl', 'settings', 'keystoreData', 'appleData', 'publishingData',
                          'builds', 'iconStoragePath', 'splashStoragePath', 'errorStoragePath', 'keystoreStoragePath', 'appleCertStoragePath', 'appleProfileStoragePath']

        now = datetime.utcnow().isoformat()

        if db:
            doc_ref = db.collection('projects').document(project_id)
            doc = doc_ref.get()

            if not doc.exists:
                return jsonify({'error': 'Project not found'}), 404

            project = doc.to_dict()
            if project.get('userId') != user_id:
                return jsonify({'error': 'Access denied'}), 403

            update_data = {'updatedAt': firestore.SERVER_TIMESTAMP}
            for field in allowed_fields:
                if field in data:
                    if field == 'builds':
                        existing_builds = project.get('builds') or {}
                        incoming_builds = data.get('builds') or {}
                        merged_builds = dict(existing_builds)
                        if isinstance(incoming_builds, dict):
                            for plat, b_info in incoming_builds.items():
                                if b_info and isinstance(b_info, dict) and b_info.get('status') == 'completed':
                                    merged_builds[plat] = b_info
                        update_data['builds'] = merged_builds
                    else:
                        update_data[field] = data[field]

            doc_ref.set(update_data, merge=True)

        # Sync to SQLite
        try:
            conn = get_db_connection()
            r = conn.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
            if r:
                name = data.get('name', r['name'])
                web_url = data.get('webUrl', r['web_url'])
                description = data.get('description', r['description'])
                app_version = data.get('appVersion', r['app_version'])
                build_number = data.get('buildNumber', r['build_number'])
                package_name = data.get('packageName', r['package_name'])
                icon_url = data.get('iconUrl', r['icon_url'])
                splash_url = data.get('splashUrl', r['splash_url'])
                error_url = data.get('errorUrl', r['error_url'] if 'error_url' in r.keys() else '')
                settings_json = json.dumps(data['settings']) if 'settings' in data else r['settings_json']
                keystore_json = json.dumps(data['keystoreData']) if 'keystoreData' in data else r['keystore_json']
                apple_json = json.dumps(data['appleData']) if 'appleData' in data else r['apple_json']

                existing_sqlite_builds = {}
                try:
                    if 'builds_json' in r.keys() and r['builds_json']:
                        existing_sqlite_builds = json.loads(r['builds_json'])
                except Exception:
                    existing_sqlite_builds = {}
                if 'builds' in data and isinstance(data['builds'], dict):
                    for plat, b_info in data['builds'].items():
                        if b_info and isinstance(b_info, dict) and b_info.get('status') == 'completed':
                            existing_sqlite_builds[plat] = b_info
                builds_json = json.dumps(existing_sqlite_builds)

                try:
                    conn.execute('''
                        UPDATE projects SET name=?, web_url=?, description=?, app_version=?, build_number=?,
                                           package_name=?, icon_url=?, splash_url=?, error_url=?, settings_json=?, keystore_json=?,
                                           apple_json=?, builds_json=?, updated_at=?
                        WHERE id=?
                    ''', (name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, error_url, settings_json, keystore_json, apple_json, builds_json, now, project_id))
                except Exception:
                    conn.execute('''
                        UPDATE projects SET name=?, web_url=?, description=?, app_version=?, build_number=?,
                                           package_name=?, icon_url=?, splash_url=?, settings_json=?, keystore_json=?,
                                           apple_json=?, builds_json=?, updated_at=?
                        WHERE id=?
                    ''', (name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, settings_json, keystore_json, apple_json, builds_json, now, project_id))
                conn.commit()
            conn.close()
        except Exception as se:
            logger.warning(f"Error syncing project update to SQLite: {se}")

        return jsonify({'success': True})
    except Exception as e:
        logger.exception("Error updating project")
        return jsonify({'error': f'Failed to update project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>/builds', methods=['GET'])
@firebase_auth_required
def get_project_builds(project_id):
    """Get all builds associated with a project"""
    try:
        user_id = request.user['uid']
        builds_list = []
        if db:
            docs = db.collection('builds').where('projectId', '==', project_id).stream()
            for doc in docs:
                b = doc.to_dict()
                b['id'] = doc.id
                if b.get('createdAt'):
                    b['createdAt'] = b['createdAt'].isoformat() if hasattr(b['createdAt'], 'isoformat') else str(b['createdAt'])
                builds_list.append(b)
        else:
            conn = get_db_connection()
            rows = conn.execute('SELECT * FROM builds WHERE project_id = ? ORDER BY created_at DESC', (project_id,)).fetchall()
            for r in rows:
                builds_list.append({
                    'id': r['id'],
                    'projectId': r['project_id'],
                    'userId': r['user_id'],
                    'appName': r['app_name'],
                    'platform': r['platform'],
                    'status': r['status'],
                    'outputs': json.loads(r['outputs_json']) if r['outputs_json'] else {},
                    'artifacts': json.loads(r['artifacts_json']) if r['artifacts_json'] else {},
                    'createdAt': r['created_at']
                })
            conn.close()

        builds_list.sort(key=lambda b: str(b.get('createdAt') or ''), reverse=True)
        return jsonify({'builds': builds_list})
    except Exception as e:
        logger.exception("Error fetching project builds")
        return jsonify({'error': f'Failed to fetch project builds: {str(e)}'}), 500

@app.route('/api/projects/<project_id>', methods=['DELETE'])
@firebase_auth_required
def delete_project(project_id):
    """Delete a project and permanently remove all its built files (APK, AAB, iOS, etc.) from disk, Storage, and database"""
    try:
        user_id = request.user['uid']
        project_build_ids = set()

        # 1. Check ownership and gather build IDs
        if db:
            doc_ref = db.collection('projects').document(project_id)
            doc = doc_ref.get()

            if not doc.exists:
                return jsonify({'error': 'Project not found'}), 404

            project = doc.to_dict() or {}
            if project.get('userId') != user_id:
                return jsonify({'error': 'Access denied'}), 403

            # Collect build IDs from project's builds field
            p_builds = project.get('builds') or {}
            for plat, bdata in p_builds.items():
                if isinstance(bdata, dict) and bdata.get('buildId'):
                    project_build_ids.add(bdata.get('buildId'))

            # Collect build IDs from Firestore builds collection and delete build documents
            try:
                build_docs = db.collection('builds').where('projectId', '==', project_id).stream()
                for bdoc in build_docs:
                    project_build_ids.add(bdoc.id)
                    try:
                        bdoc.reference.delete()
                    except Exception as b_del_err:
                        logger.warning(f"Error deleting Firestore build doc {bdoc.id}: {b_del_err}")
            except Exception as b_query_err:
                logger.warning(f"Error querying builds for project {project_id}: {b_query_err}")

            # Delete project document
            doc_ref.delete()
        else:
            conn = get_db_connection()
            r = conn.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
            if not r:
                conn.close()
                return jsonify({'error': 'Project not found'}), 404
            if r['user_id'] != user_id:
                conn.close()
                return jsonify({'error': 'Access denied'}), 403

            # Collect build IDs from SQLite builds table
            try:
                b_rows = conn.execute('SELECT id FROM builds WHERE project_id = ?', (project_id,)).fetchall()
                for brow in b_rows:
                    project_build_ids.add(brow['id'])
            except Exception:
                pass

            conn.execute('DELETE FROM builds WHERE project_id = ?', (project_id,))
            conn.execute('DELETE FROM projects WHERE id = ?', (project_id,))
            conn.commit()
            conn.close()

        # Also check in-memory build_progress for this project
        for bid, binfo in list(build_progress.items()):
            if binfo.get('project_id') == project_id:
                project_build_ids.add(bid)
                build_progress.pop(bid, None)

        # 2. Delete local build directories and files on disk (APK, AAB, iOS, zips, etc.)
        for bid in project_build_ids:
            try:
                bdir = os.path.join(app.config['BUILD_FOLDER'], bid)
                if os.path.exists(bdir):
                    shutil.rmtree(bdir, ignore_errors=True)
                    logger.info(f"Deleted local build directory: {bdir}")
            except Exception as disk_err:
                logger.warning(f"Error removing local build dir {bid}: {disk_err}")

        # 3. Delete files from Firebase Cloud Storage (APK, AAB, iOS, icons, etc.)
        try:
            bucket = get_storage_bucket()
            if bucket and user_id:
                # Delete all blobs under builds/{user_id}/{project_id}/
                builds_prefix = f"builds/{user_id}/{project_id}/"
                for blob in bucket.list_blobs(prefix=builds_prefix):
                    try:
                        blob.delete()
                        logger.info(f"Deleted Storage build blob: {blob.name}")
                    except Exception as b_err:
                        logger.warning(f"Error deleting blob {blob.name}: {b_err}")

                # Delete all blobs under projects/{user_id}/{project_id}/
                projects_prefix = f"projects/{user_id}/{project_id}/"
                for blob in bucket.list_blobs(prefix=projects_prefix):
                    try:
                        blob.delete()
                        logger.info(f"Deleted Storage project blob: {blob.name}")
                    except Exception as p_err:
                        logger.warning(f"Error deleting blob {blob.name}: {p_err}")
        except Exception as storage_err:
            logger.warning(f"Note: Error cleaning up Firebase Storage for project {project_id}: {storage_err}")

        # 4. Clear active build if it belonged to this project
        if session.get('active_build_id') in project_build_ids:
            session.pop('active_build_id', None)

        logger.info(f"Project {project_id} and all its build files (APK, AAB, iOS, etc.) were permanently deleted.")
        return jsonify({'success': True, 'message': 'Project and all built files successfully deleted'})
    except Exception as e:
        logger.exception("Failed to delete project")
        return jsonify({'error': f'Failed to delete project: {str(e)}'}), 500

@app.route('/api/projects/<project_id>/assets', methods=['POST'])
@firebase_auth_required
def upload_project_assets(project_id):
    """Upload assets (icon, keystore) for a project to Firebase Storage"""
    if not db:
        return jsonify({'error': 'Database not available'}), 503

    bucket = get_storage_bucket()
    if not bucket:
        return jsonify({'error': 'Storage not configured'}), 503

    try:
        user_id = request.user['uid']

        # Verify project ownership
        doc_ref = db.collection('projects').document(project_id)
        doc = doc_ref.get()

        if not doc.exists:
            return jsonify({'error': 'Project not found'}), 404

        project = doc.to_dict()
        if project.get('userId') != user_id:
            return jsonify({'error': 'Access denied'}), 403

        update_data = {'updatedAt': firestore.SERVER_TIMESTAMP}
        response_data = {}

        # Handle icon upload
        if 'icon' in request.files:
            icon_file = request.files['icon']
            if icon_file.filename:
                ext = os.path.splitext(icon_file.filename)[1].lower()
                if ext not in ['.png', '.jpg', '.jpeg']:
                    return jsonify({'error': 'Invalid icon type. Use PNG or JPG'}), 400

                # Upload to Firebase Storage
                icon_path = f"projects/{user_id}/{project_id}/icon{ext}"
                blob = bucket.blob(icon_path)
                blob.upload_from_file(icon_file, content_type=icon_file.content_type)
                blob.make_public()

                update_data['iconStoragePath'] = icon_path
                update_data['iconUrl'] = blob.public_url
                response_data['iconUrl'] = blob.public_url
                response_data['iconStoragePath'] = icon_path

        # Handle keystore upload
        if 'keystore' in request.files:
            keystore_file = request.files['keystore']
            if keystore_file.filename:
                # Upload to Firebase Storage (private, not public)
                keystore_path = f"projects/{user_id}/{project_id}/keystore.jks"
                blob = bucket.blob(keystore_path)
                blob.upload_from_file(keystore_file, content_type='application/octet-stream')

                update_data['keystoreStoragePath'] = keystore_path
                response_data['keystoreStoragePath'] = keystore_path

        # Handle Apple certificate upload
        if 'apple_certificate' in request.files:
            cert_file = request.files['apple_certificate']
            if cert_file.filename:
                ext = os.path.splitext(cert_file.filename)[1].lower()
                if ext not in ['.p12', '.pfx']:
                    return jsonify({'error': 'Invalid certificate type. Use .p12 or .pfx'}), 400

                cert_path = f"projects/{user_id}/{project_id}/certificate{ext}"
                blob = bucket.blob(cert_path)
                blob.upload_from_file(cert_file, content_type='application/octet-stream')

                update_data['appleCertStoragePath'] = cert_path
                response_data['appleCertStoragePath'] = cert_path

        # Handle Apple provisioning profile upload
        if 'provisioning_profile' in request.files:
            profile_file = request.files['provisioning_profile']
            if profile_file.filename:
                profile_path = f"projects/{user_id}/{project_id}/profile.mobileprovision"
                blob = bucket.blob(profile_path)
                blob.upload_from_file(profile_file, content_type='application/octet-stream')

                update_data['appleProfileStoragePath'] = profile_path
                response_data['appleProfileStoragePath'] = profile_path

        # Handle splash screen image upload
        splash_file = request.files.get('splash') or request.files.get('splash_image')
        if splash_file and splash_file.filename:
            ext = os.path.splitext(splash_file.filename)[1].lower()
            if ext in ['.png', '.jpg', '.jpeg', '.webp']:
                splash_path = f"projects/{user_id}/{project_id}/splash{ext}"
                blob = bucket.blob(splash_path)
                blob.upload_from_file(splash_file, content_type=splash_file.content_type)
                blob.make_public()
                update_data['splashStoragePath'] = splash_path
                update_data['splashUrl'] = blob.public_url
                response_data['splashUrl'] = blob.public_url
                response_data['splashStoragePath'] = splash_path

        # Handle error screen image upload
        error_file = request.files.get('error') or request.files.get('error_image')
        if error_file and error_file.filename:
            ext = os.path.splitext(error_file.filename)[1].lower()
            if ext in ['.png', '.jpg', '.jpeg', '.webp']:
                error_path = f"projects/{user_id}/{project_id}/error{ext}"
                blob = bucket.blob(error_path)
                blob.upload_from_file(error_file, content_type=error_file.content_type)
                blob.make_public()
                update_data['errorStoragePath'] = error_path
                update_data['errorUrl'] = blob.public_url
                response_data['errorUrl'] = blob.public_url
                response_data['errorStoragePath'] = error_path

        # Update project with new storage paths
        if len(update_data) > 1:  # More than just updatedAt
            doc_ref.update(update_data)

        return jsonify({'success': True, **response_data})

    except Exception as e:
        return jsonify({'error': f'Failed to upload assets: {str(e)}'}), 500

@app.route('/api/projects/<project_id>/download', methods=['GET'])
@firebase_auth_required
def download_project_swab(project_id):
    """Download project as .iewebnative / .swab file with all assets and settings"""
    try:
        user_id = request.user['uid']
        project = None

        if db:
            doc_ref = db.collection('projects').document(project_id)
            doc = doc_ref.get()
            if doc.exists:
                project = doc.to_dict()
                if project.get('userId') != user_id:
                    return jsonify({'error': 'Access denied'}), 403
                project['id'] = doc.id

        if not project:
            conn = get_db_connection()
            r = conn.execute('SELECT * FROM projects WHERE id = ?', (project_id,)).fetchone()
            conn.close()
            if not r:
                return jsonify({'error': 'Project not found'}), 404
            if r['user_id'] != user_id:
                return jsonify({'error': 'Access denied'}), 403
            p_settings = json.loads(r['settings_json']) if r['settings_json'] else {}
            p_err_url = r['error_url'] if 'error_url' in r.keys() and r['error_url'] else p_settings.get('errorImageUrl', '')
            project = {
                'id': r['id'],
                'userId': r['user_id'],
                'name': r['name'],
                'webUrl': r['web_url'],
                'description': r['description'],
                'appVersion': r['app_version'],
                'buildNumber': r['build_number'],
                'packageName': r['package_name'],
                'iconUrl': r['icon_url'],
                'splashUrl': r['splash_url'],
                'errorUrl': p_err_url,
                'settings': p_settings,
                'keystoreData': json.loads(r['keystore_json']) if r['keystore_json'] else {},
                'appleData': json.loads(r['apple_json']) if r['apple_json'] else {},
                'publishingData': p_settings.get('publishingData', {})
            }

        temp_dir = tempfile.mkdtemp()

        try:
            settings = project.get('settings', {})
            pub_data = project.get('publishingData', {})

            project_data = {
                'app_name': project.get('name', 'Untitled'),
                'app_description': project.get('description', ''),
                'app_version': project.get('appVersion', '1.0.0'),
                'build_number': project.get('buildNumber', 1),
                'package_name': project.get('packageName', ''),
                'web_url': project.get('webUrl', ''),
                # WebView settings
                'allow_zoom': settings.get('allowZoom', False),
                'enable_javascript': settings.get('enableJavascript', False),
                'enable_dom_storage': settings.get('enableDomStorage', False),
                'enable_geolocation': settings.get('enableGeolocation', False),
                'enable_pull_refresh': settings.get('enablePullRefresh', False),
                'show_navigation': settings.get('showNavigation', False),
                'enable_file_access': settings.get('enableFileAccess', False),
                'enable_cache': settings.get('enableCache', False),
                'enable_media_autoplay': settings.get('enableMediaAutoplay', False),
                'enable_camera': settings.get('enableCamera', False),
                'enable_microphone': settings.get('enableMicrophone', False),
                'enable_ssl_pinning': settings.get('enableSslPinning', False),
                'ssl_pins': settings.get('sslPins', ''),
                'enable_biometrics': settings.get('enableBiometrics', False),
                'enable_app_lock': settings.get('enableAppLock', False),
                'app_lock_pin': settings.get('appLockPin', ''),
                'enable_secure_storage': settings.get('enableSecureStorage', False),
                # Store publishing info
                'enable_google_play_publish': settings.get('enableGooglePlayPublish', pub_data.get('enableGooglePlayPublish', False)),
                'play_track': settings.get('playTrack', pub_data.get('playTrack', 'internal')),
                'play_status': settings.get('playStatus', pub_data.get('playStatus', 'draft')),
                'enable_app_store_publish': settings.get('enableAppStorePublish', pub_data.get('enableAppStorePublish', False)),
                'app_store_key_id': settings.get('appStoreKeyId', pub_data.get('appStoreKeyId', '')),
                'app_store_issuer_id': settings.get('appStoreIssuerId', pub_data.get('appStoreIssuerId', '')),
                # Splash screen settings
                'enable_splash_screen': settings.get('enableSplashScreen', False),
                'splash_title': settings.get('splashTitle', ''),
                'splash_subtitle': settings.get('splashSubtitle', ''),
                'splash_bg_color': settings.get('splashBgColor', '#FFFFFF'),
                'splash_text_color': settings.get('splashTextColor', '#1E293B'),
                'splash_duration': settings.get('splashDuration', 2),
                # Error / offline page settings
                'enable_error_page': settings.get('enableErrorPage', False),
                'error_title': settings.get('errorTitle', 'No Internet Connection'),
                'error_message': settings.get('errorMessage', 'Please check your connection and try again'),
                'error_button_text': settings.get('errorButtonText', 'Retry'),
                'error_bg_color': settings.get('errorBgColor', '#FFFFFF'),
                'error_text_color': settings.get('errorTextColor', '#334155'),
                # Full settings dictionary
                'settings': settings
            }

            # Keystore credentials
            keystore_data = project.get('keystoreData', {})
            if keystore_data:
                project_data['keystore_password'] = keystore_data.get('keystorePassword', '')
                project_data['key_alias'] = keystore_data.get('keyAlias', '')
                project_data['key_password'] = keystore_data.get('keyPassword', '')

            # Apple signing credentials
            apple_data = project.get('appleData', {})
            if apple_data:
                project_data['apple_certificate_password'] = apple_data.get('certificatePassword', '')
                project_data['team_id'] = apple_data.get('teamId', '')

            # Save project.json
            project_json_path = os.path.join(temp_dir, 'project.json')
            with open(project_json_path, 'w') as f:
                json.dump(project_data, f, indent=2)

            # Create assets directory
            assets_dir = os.path.join(temp_dir, 'assets')
            os.makedirs(assets_dir, exist_ok=True)

            bucket = get_storage_bucket()

            # 1. Download icon
            icon_downloaded = False
            icon_storage_path = project.get('iconStoragePath')
            if bucket and icon_storage_path:
                try:
                    ext = os.path.splitext(icon_storage_path)[1]
                    blob = bucket.blob(icon_storage_path)
                    icon_local_path = os.path.join(assets_dir, f'icon{ext}')
                    blob.download_to_filename(icon_local_path)
                    icon_downloaded = True
                except Exception as e:
                    logger.warning(f"Failed to download icon from storage: {e}")
            if not icon_downloaded and project.get('iconUrl'):
                try:
                    i_resp = requests.get(project['iconUrl'], timeout=15)
                    if i_resp.status_code == 200:
                        ext = '.png'
                        if 'image/jpeg' in i_resp.headers.get('Content-Type', '') or '.jpg' in project['iconUrl'] or '.jpeg' in project['iconUrl']:
                            ext = '.jpg'
                        with open(os.path.join(assets_dir, f'icon{ext}'), 'wb') as f:
                            f.write(i_resp.content)
                except Exception as e:
                    logger.warning(f"Failed to download icon from URL: {e}")

            # 2. Download splash screen image
            splash_downloaded = False
            splash_storage_path = project.get('splashStoragePath')
            if bucket and splash_storage_path:
                try:
                    ext = os.path.splitext(splash_storage_path)[1]
                    blob = bucket.blob(splash_storage_path)
                    splash_local_path = os.path.join(assets_dir, f'splash_image{ext}')
                    blob.download_to_filename(splash_local_path)
                    splash_downloaded = True
                except Exception as e:
                    logger.warning(f"Failed to download splash image from storage: {e}")
            splash_url = project.get('splashUrl') or settings.get('splashImageUrl') or project.get('splash_url')
            if not splash_downloaded and splash_url:
                try:
                    s_resp = requests.get(splash_url, timeout=15)
                    if s_resp.status_code == 200:
                        ext = '.png'
                        if 'image/jpeg' in s_resp.headers.get('Content-Type', '') or '.jpg' in splash_url or '.jpeg' in splash_url:
                            ext = '.jpg'
                        elif 'image/webp' in s_resp.headers.get('Content-Type', '') or '.webp' in splash_url:
                            ext = '.webp'
                        with open(os.path.join(assets_dir, f'splash_image{ext}'), 'wb') as f:
                            f.write(s_resp.content)
                except Exception as e:
                    logger.warning(f"Failed to download splash image from URL: {e}")

            # 3. Download error screen image
            error_downloaded = False
            error_storage_path = project.get('errorStoragePath')
            if bucket and error_storage_path:
                try:
                    ext = os.path.splitext(error_storage_path)[1]
                    blob = bucket.blob(error_storage_path)
                    error_local_path = os.path.join(assets_dir, f'error_image{ext}')
                    blob.download_to_filename(error_local_path)
                    error_downloaded = True
                except Exception as e:
                    logger.warning(f"Failed to download error image from storage: {e}")
            error_url = project.get('errorUrl') or settings.get('errorImageUrl') or project.get('error_url')
            if not error_downloaded and error_url:
                try:
                    e_resp = requests.get(error_url, timeout=15)
                    if e_resp.status_code == 200:
                        ext = '.png'
                        if 'image/jpeg' in e_resp.headers.get('Content-Type', '') or '.jpg' in error_url or '.jpeg' in error_url:
                            ext = '.jpg'
                        elif 'image/webp' in e_resp.headers.get('Content-Type', '') or '.webp' in error_url:
                            ext = '.webp'
                        with open(os.path.join(assets_dir, f'error_image{ext}'), 'wb') as f:
                            f.write(e_resp.content)
                except Exception as e:
                    logger.warning(f"Failed to download error image from URL: {e}")

            # 4. Download keystore
            keystore_storage_path = project.get('keystoreStoragePath')
            if bucket and keystore_storage_path:
                try:
                    blob = bucket.blob(keystore_storage_path)
                    blob.download_to_filename(os.path.join(assets_dir, 'keystore.jks'))
                except Exception as e:
                    logger.warning(f"Failed to download keystore: {e}")

            # 5. Download Apple certificate
            apple_cert_storage_path = project.get('appleCertStoragePath')
            if bucket and apple_cert_storage_path:
                try:
                    ext = os.path.splitext(apple_cert_storage_path)[1]
                    blob = bucket.blob(apple_cert_storage_path)
                    blob.download_to_filename(os.path.join(assets_dir, f'certificate{ext}'))
                except Exception as e:
                    logger.warning(f"Failed to download Apple certificate: {e}")

            # 6. Download Apple provisioning profile
            apple_profile_storage_path = project.get('appleProfileStoragePath')
            if bucket and apple_profile_storage_path:
                try:
                    blob = bucket.blob(apple_profile_storage_path)
                    blob.download_to_filename(os.path.join(assets_dir, 'profile.mobileprovision'))
                except Exception as e:
                    logger.warning(f"Failed to download provisioning profile: {e}")

            # Create the zip file
            zip_path = os.path.join(temp_dir, 'project.zip')
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        if file != 'project.zip':
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, temp_dir)
                            zipf.write(file_path, arcname)

            # Read and encrypt the zip
            with open(zip_path, 'rb') as f:
                zip_data = f.read()

            encrypted_data = encrypt_data(zip_data)

            # Generate filename
            safe_name = re.sub(r'[^a-zA-Z0-9_-]', '_', project.get('name', 'project'))
            filename = f"{safe_name}.iewebnative"

            # Save encrypted file
            output_path = os.path.join(temp_dir, filename)
            with open(output_path, 'wb') as f:
                f.write(encrypted_data)

            return send_file(
                output_path,
                as_attachment=True,
                download_name=filename,
                mimetype='application/octet-stream'
            )
        finally:
            pass

    except Exception as e:
        logger.exception("Failed to download project")
        return jsonify({'error': f'Failed to download project: {str(e)}'}), 500

@app.route('/api/projects/import', methods=['POST'])
@firebase_auth_required
def import_project_swab():
    """Import a .iewebnative or .swab file as a new project with all settings and assets"""
    if 'project' not in request.files:
        return jsonify({'error': 'No project file provided'}), 400

    file = request.files['project']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    if not (file.filename.endswith('.iewebnative') or file.filename.endswith('.swab')):
        return jsonify({'error': 'Invalid file type. Please select a .iewebnative or .swab file'}), 400

    temp_dir = tempfile.mkdtemp()

    try:
        user_id = request.user['uid']

        # Read encrypted data
        encrypted_data = file.read()

        # Decrypt data
        try:
            decrypted_data = decrypt_data(encrypted_data)
        except Exception:
            return jsonify({'error': 'Cannot open this project file. It was created on a different machine or has been corrupted.'}), 403

        # Write decrypted zip to temp file
        zip_path = os.path.join(temp_dir, 'project.zip')
        with open(zip_path, 'wb') as f:
            f.write(decrypted_data)

        # Extract zip
        extract_dir = os.path.join(temp_dir, 'extracted')
        os.makedirs(extract_dir, exist_ok=True)

        with zipfile.ZipFile(zip_path, 'r') as zipf:
            zipf.extractall(extract_dir)

        # Read project.json
        project_json_path = os.path.join(extract_dir, 'project.json')
        if not os.path.exists(project_json_path):
            return jsonify({'error': 'Invalid project file: missing project.json'}), 400

        with open(project_json_path, 'r') as f:
            project_data = json.load(f)

        raw_settings = project_data.get('settings', {})
        settings_data = {
            'allowZoom': raw_settings.get('allowZoom', project_data.get('allow_zoom', False)),
            'enableJavascript': raw_settings.get('enableJavascript', project_data.get('enable_javascript', False)),
            'enableDomStorage': raw_settings.get('enableDomStorage', project_data.get('enable_dom_storage', False)),
            'enableGeolocation': raw_settings.get('enableGeolocation', project_data.get('enable_geolocation', False)),
            'enablePullRefresh': raw_settings.get('enablePullRefresh', project_data.get('enable_pull_refresh', False)),
            'showNavigation': raw_settings.get('showNavigation', project_data.get('show_navigation', False)),
            'enableFileAccess': raw_settings.get('enableFileAccess', project_data.get('enable_file_access', False)),
            'enableCache': raw_settings.get('enableCache', project_data.get('enable_cache', False)),
            'enableMediaAutoplay': raw_settings.get('enableMediaAutoplay', project_data.get('enable_media_autoplay', False)),
            'enableCamera': raw_settings.get('enableCamera', project_data.get('enable_camera', False)),
            'enableMicrophone': raw_settings.get('enableMicrophone', project_data.get('enable_microphone', False)),
            'enableSslPinning': raw_settings.get('enableSslPinning', project_data.get('enable_ssl_pinning', False)),
            'sslPins': raw_settings.get('sslPins', project_data.get('ssl_pins', '')),
            'enableBiometrics': raw_settings.get('enableBiometrics', project_data.get('enable_biometrics', False)),
            'enableAppLock': raw_settings.get('enableAppLock', project_data.get('enable_app_lock', False)),
            'appLockPin': raw_settings.get('appLockPin', project_data.get('app_lock_pin', '')),
            'enableSecureStorage': raw_settings.get('enableSecureStorage', project_data.get('enable_secure_storage', False)),
            'enableGooglePlayPublish': raw_settings.get('enableGooglePlayPublish', project_data.get('enable_google_play_publish', False)),
            'playTrack': raw_settings.get('playTrack', project_data.get('play_track', 'internal')),
            'playStatus': raw_settings.get('playStatus', project_data.get('play_status', 'draft')),
            'enableAppStorePublish': raw_settings.get('enableAppStorePublish', project_data.get('enable_app_store_publish', False)),
            'appStoreKeyId': raw_settings.get('appStoreKeyId', project_data.get('app_store_key_id', '')),
            'appStoreIssuerId': raw_settings.get('appStoreIssuerId', project_data.get('app_store_issuer_id', '')),
            'enableSplashScreen': raw_settings.get('enableSplashScreen', project_data.get('enable_splash_screen', False)),
            'splashTitle': raw_settings.get('splashTitle', project_data.get('splash_title', '')),
            'splashSubtitle': raw_settings.get('splashSubtitle', project_data.get('splash_subtitle', '')),
            'splashBgColor': raw_settings.get('splashBgColor', project_data.get('splash_bg_color', '#FFFFFF')),
            'splashTextColor': raw_settings.get('splashTextColor', project_data.get('splash_text_color', '#1E293B')),
            'splashDuration': raw_settings.get('splashDuration', project_data.get('splash_duration', 2)),
            'enableErrorPage': raw_settings.get('enableErrorPage', project_data.get('enable_error_page', False)),
            'errorTitle': raw_settings.get('errorTitle', project_data.get('error_title', 'No Internet Connection')),
            'errorMessage': raw_settings.get('errorMessage', project_data.get('error_message', 'Please check your connection and try again')),
            'errorButtonText': raw_settings.get('errorButtonText', project_data.get('error_button_text', 'Retry')),
            'errorBgColor': raw_settings.get('errorBgColor', project_data.get('error_bg_color', '#FFFFFF')),
            'errorTextColor': raw_settings.get('errorTextColor', project_data.get('error_text_color', '#334155')),
        }

        proj_name = project_data.get('app_name', 'Imported Project')
        proj_desc = project_data.get('app_description', '')
        proj_ver = project_data.get('app_version', '1.0.0')
        proj_build_num = int(project_data.get('build_number', 1))
        proj_pkg = project_data.get('package_name', '')
        proj_web_url = project_data.get('web_url', '')

        firestore_data = {
            'userId': user_id,
            'name': proj_name,
            'webUrl': proj_web_url,
            'description': proj_desc,
            'appVersion': proj_ver,
            'buildNumber': proj_build_num,
            'packageName': proj_pkg,
            'iconUrl': '',
            'splashUrl': '',
            'errorUrl': '',
            'settings': settings_data,
            'builds': {}
        }

        if project_data.get('keystore_password') or project_data.get('key_alias'):
            firestore_data['keystoreData'] = {
                'keystorePassword': project_data.get('keystore_password', ''),
                'keyAlias': project_data.get('key_alias', ''),
                'keyPassword': project_data.get('key_password', '')
            }

        if project_data.get('apple_certificate_password') or project_data.get('team_id'):
            firestore_data['appleData'] = {
                'certificatePassword': project_data.get('apple_certificate_password', ''),
                'teamId': project_data.get('team_id', '')
            }

        if db:
            firestore_data['createdAt'] = firestore.SERVER_TIMESTAMP
            firestore_data['updatedAt'] = firestore.SERVER_TIMESTAMP
            doc_ref = db.collection('projects').add(firestore_data)
            project_id = doc_ref[1].id
        else:
            project_id = str(uuid.uuid4())

        # Upload or link assets from .swab to Firebase Storage or local uploads
        assets_dir = os.path.join(extract_dir, 'assets')
        bucket = get_storage_bucket()
        update_data = {}

        if os.path.exists(assets_dir):
            # 1. Icon
            for ext in ['.png', '.jpg', '.jpeg', '.webp']:
                icon_path = os.path.join(assets_dir, f'icon{ext}')
                if os.path.exists(icon_path):
                    if bucket:
                        try:
                            storage_path = f"projects/{user_id}/icons/{int(time.time() * 1000)}_icon{ext}"
                            blob = bucket.blob(storage_path)
                            blob.upload_from_filename(icon_path)
                            blob.make_public()
                            update_data['iconStoragePath'] = storage_path
                            update_data['iconUrl'] = blob.public_url
                            firestore_data['iconUrl'] = blob.public_url
                        except Exception as e:
                            logger.warning(f"Failed to upload icon to storage: {e}")
                    else:
                        new_name = f"{uuid.uuid4()}{ext}"
                        shutil.copy(icon_path, os.path.join(app.config['UPLOAD_FOLDER'], new_name))
                        update_data['iconUrl'] = f"/uploads/{new_name}"
                        firestore_data['iconUrl'] = f"/uploads/{new_name}"
                    break

            # 2. Splash screen image
            for ext in ['.png', '.jpg', '.jpeg', '.webp']:
                for s_cand in [f'splash_image{ext}', f'splash{ext}']:
                    splash_path = os.path.join(assets_dir, s_cand)
                    if os.path.exists(splash_path):
                        if bucket:
                            try:
                                storage_path = f"projects/{user_id}/splash/{int(time.time() * 1000)}_splash{ext}"
                                blob = bucket.blob(storage_path)
                                blob.upload_from_filename(splash_path)
                                blob.make_public()
                                update_data['splashStoragePath'] = storage_path
                                update_data['splashUrl'] = blob.public_url
                                firestore_data['splashUrl'] = blob.public_url
                                settings_data['splashImageUrl'] = blob.public_url
                            except Exception as e:
                                logger.warning(f"Failed to upload splash image to storage: {e}")
                        else:
                            new_name = f"splash_{uuid.uuid4()}{ext}"
                            shutil.copy(splash_path, os.path.join(app.config['UPLOAD_FOLDER'], new_name))
                            update_data['splashUrl'] = f"/uploads/{new_name}"
                            firestore_data['splashUrl'] = f"/uploads/{new_name}"
                            settings_data['splashImageUrl'] = f"/uploads/{new_name}"
                        break
                if update_data.get('splashUrl'):
                    break

            # 3. Error screen image
            for ext in ['.png', '.jpg', '.jpeg', '.webp']:
                for e_cand in [f'error_image{ext}', f'error{ext}']:
                    error_path = os.path.join(assets_dir, e_cand)
                    if os.path.exists(error_path):
                        if bucket:
                            try:
                                storage_path = f"projects/{user_id}/error/{int(time.time() * 1000)}_error{ext}"
                                blob = bucket.blob(storage_path)
                                blob.upload_from_filename(error_path)
                                blob.make_public()
                                update_data['errorStoragePath'] = storage_path
                                update_data['errorUrl'] = blob.public_url
                                firestore_data['errorUrl'] = blob.public_url
                                settings_data['errorImageUrl'] = blob.public_url
                            except Exception as e:
                                logger.warning(f"Failed to upload error image to storage: {e}")
                        else:
                            new_name = f"error_{uuid.uuid4()}{ext}"
                            shutil.copy(error_path, os.path.join(app.config['UPLOAD_FOLDER'], new_name))
                            update_data['errorUrl'] = f"/uploads/{new_name}"
                            firestore_data['errorUrl'] = f"/uploads/{new_name}"
                            settings_data['errorImageUrl'] = f"/uploads/{new_name}"
                        break
                if update_data.get('errorUrl'):
                    break

            # 4. Keystore
            keystore_path = os.path.join(assets_dir, 'keystore.jks')
            if os.path.exists(keystore_path):
                if bucket:
                    try:
                        storage_path = f"projects/{user_id}/keystores/{int(time.time() * 1000)}_keystore.jks"
                        blob = bucket.blob(storage_path)
                        blob.upload_from_filename(keystore_path)
                        update_data['keystoreStoragePath'] = storage_path
                    except Exception as e:
                        logger.warning(f"Failed to upload keystore to storage: {e}")
                else:
                    new_name = f"{uuid.uuid4()}.jks"
                    shutil.copy(keystore_path, os.path.join(app.config['UPLOAD_FOLDER'], new_name))

            # 5. Apple certificate
            for ext in ['.p12', '.pfx']:
                cert_path = os.path.join(assets_dir, f'certificate{ext}')
                if os.path.exists(cert_path):
                    if bucket:
                        try:
                            storage_path = f"projects/{user_id}/certificates/{int(time.time() * 1000)}_certificate{ext}"
                            blob = bucket.blob(storage_path)
                            blob.upload_from_filename(cert_path)
                            update_data['appleCertStoragePath'] = storage_path
                        except Exception as e:
                            logger.warning(f"Failed to upload certificate to storage: {e}")
                    break

            # 6. Apple provisioning profile
            profile_path = os.path.join(assets_dir, 'profile.mobileprovision')
            if os.path.exists(profile_path):
                if bucket:
                    try:
                        storage_path = f"projects/{user_id}/profiles/{int(time.time() * 1000)}_profile.mobileprovision"
                        blob = bucket.blob(storage_path)
                        blob.upload_from_filename(profile_path)
                        update_data['appleProfileStoragePath'] = storage_path
                    except Exception as e:
                        logger.warning(f"Failed to upload profile to storage: {e}")

        # Update Firestore
        if db:
            update_data['settings'] = settings_data
            db.collection('projects').document(project_id).update(update_data)

        # Sync to SQLite
        try:
            now_str = datetime.utcnow().isoformat()
            conn = get_db_connection()
            s_icon = update_data.get('iconUrl') or firestore_data.get('iconUrl', '')
            s_splash = update_data.get('splashUrl') or firestore_data.get('splashUrl', '')
            s_error = update_data.get('errorUrl') or firestore_data.get('errorUrl', '')
            try:
                conn.execute('''
                    INSERT OR REPLACE INTO projects (id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, error_url, settings_json, keystore_json, apple_json, builds_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (project_id, user_id, proj_name, proj_web_url, proj_desc, proj_ver, proj_build_num, proj_pkg, s_icon, s_splash, s_error, json.dumps(settings_data), json.dumps(firestore_data.get('keystoreData', {})), json.dumps(firestore_data.get('appleData', {})), json.dumps({}), now_str, now_str))
            except Exception:
                conn.execute('''
                    INSERT OR REPLACE INTO projects (id, user_id, name, web_url, description, app_version, build_number, package_name, icon_url, splash_url, settings_json, keystore_json, apple_json, builds_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (project_id, user_id, proj_name, proj_web_url, proj_desc, proj_ver, proj_build_num, proj_pkg, s_icon, s_splash, json.dumps(settings_data), json.dumps(firestore_data.get('keystoreData', {})), json.dumps(firestore_data.get('appleData', {})), json.dumps({}), now_str, now_str))
            conn.commit()
            conn.close()
        except Exception as se:
            logger.warning(f"Failed to sync imported project to SQLite: {se}")

        return jsonify({'success': True, 'projectId': project_id})

    except Exception as e:
        logger.exception("Failed to import project")
        return jsonify({'error': f'Failed to import project: {str(e)}'}), 500

    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

# ==================== BUILD HISTORY API ====================

@app.route('/api/builds', methods=['GET'])
@firebase_auth_required
def get_builds():
    """Get build history for the authenticated user"""
    try:
        user_id = request.user['uid']
        builds = []
        if db:
            builds_ref = db.collection('builds')
            docs = builds_ref.where('userId', '==', user_id).stream()
            for doc in docs:
                build = doc.to_dict()
                build['id'] = doc.id
                if build.get('createdAt'):
                    build['createdAt'] = build['createdAt'].isoformat() if hasattr(build['createdAt'], 'isoformat') else str(build['createdAt'])
                builds.append(build)
            builds.sort(key=lambda b: str(b.get('createdAt') or ''), reverse=True)
            builds = builds[:50]
        else:
            conn = get_db_connection()
            rows = conn.execute('SELECT * FROM builds WHERE user_id = ? ORDER BY created_at DESC LIMIT 50', (user_id,)).fetchall()
            for r in rows:
                builds.append({
                    'id': r['id'],
                    'projectId': r['project_id'],
                    'userId': r['user_id'],
                    'appName': r['app_name'],
                    'platform': r['platform'],
                    'status': r['status'],
                    'outputs': json.loads(r['outputs_json']) if r['outputs_json'] else {},
                    'artifacts': json.loads(r['artifacts_json']) if r['artifacts_json'] else {},
                    'createdAt': r['created_at']
                })
            conn.close()

        return jsonify({'builds': builds})
    except Exception as e:
        logger.exception("Error fetching builds")
        return jsonify({'error': f'Failed to fetch builds: {str(e)}'}), 500

if __name__ == '__main__':
    import argparse
    default_port = int(os.environ.get('PORT', 5000))
    parser = argparse.ArgumentParser(description='ieWebNative - Web to Native App Builder')
    parser.add_argument('-p', '--port', type=int, default=default_port, help=f'Port to run the server on (default: {default_port})')
    args = parser.parse_args()
    app.run(host='0.0.0.0', debug=False, port=args.port)
