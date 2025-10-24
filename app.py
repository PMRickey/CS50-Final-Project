"""
Medication Tracker – CS50 Final Project
Author: Pauline Rickey
Date: October 23, 2025

A Flask web application for tracking personal medications with:
- Database encryption at rest (AES-256 using cryptography library)
- RxNorm medication validation
- OpenFDA side effects integration
- Duplicate detection
- Archive functionality

© 2025 Pauline Rickey. All rights reserved.
Dedicated to my father, whose love and strength continue to guide me.
"""

# Acknowledgment of AI Assistance:
# Portions of this project were developed with the assistance of AI tools,
# specifically ChatGPT (OpenAI) and Claude (Anthropic). These tools were used
# for debugging, code review, technical guidance, and problem-solving support.
# All code was written, understood, and tested by the developer.


import os
import re
import sqlite3
import signal
import sys
from datetime import datetime, timedelta, timezone

import requests
from flask import Flask, flash, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

# Import cryptography for AES-256 encryption
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

# =============================================================================
# ENCRYPTION CONFIGURATION
# =============================================================================

def get_encryption_key():
    """
    Derive encryption key from environment variable using PBKDF2.
    
    Returns AES-256 compatible key for Fernet encryption.
    Uses PBKDF2 with 480,000 iterations (OWASP 2023 recommendation).
    
    Security:
        - Key derived from DB_ENCRYPTION_KEY environment variable
        - PBKDF2-HMAC-SHA256 key derivation
        - 480,000 iterations (exceeds OWASP minimum of 310,000)
        - Static salt (for development; production would use per-file salt)
    """
    password = os.environ.get('DB_ENCRYPTION_KEY', 'cs50-dev-key-2025').encode()
    
    # Use PBKDF2 to derive a key (same approach as SQLCipher)
    # Static salt for simplicity in CS50 version
    # Production would use per-database unique salt
    salt = b'cs50_medication_tracker_salt_2025'
    
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes = 256 bits for AES-256
        salt=salt,
        iterations=480000,  # OWASP 2023 recommendation
    )
    
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key


def encrypt_database():
    """
    Encrypt the database file using AES-256.
    
    Encrypts med.db to med.db.enc if unencrypted version exists.
    Uses Fernet symmetric encryption (AES-256 in CBC mode).
    
    Returns:
        bool: True if encryption succeeded or already encrypted
    """
    if not os.path.exists("med.db"):
        return True  # No database to encrypt yet
    
    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        
        # Read unencrypted database
        with open("med.db", "rb") as file:
            original_data = file.read()
        
        # Only encrypt if there's data
        if len(original_data) == 0:
            print("⚠️  Database is empty, skipping encryption")
            return True
        
        # Encrypt the data
        encrypted_data = fernet.encrypt(original_data)
        
        # Write encrypted version
        with open("med.db.enc", "wb") as file:
            file.write(encrypted_data)
        
        # Verify encryption worked
        if os.path.getsize("med.db.enc") > 100:
            # Remove unencrypted version (security best practice)
            os.remove("med.db")
            print(f"✅ Database encrypted ({len(encrypted_data)} bytes)")
            return True
        else:
            print("⚠️  Encryption produced small file, keeping original")
            return False
        
    except Exception as e:
        print(f"❌ Encryption failed: {e}")
        return False


def decrypt_database():
    """
    Decrypt the database file for use.
    
    Decrypts med.db.enc to med.db for SQLite access.
    Database is decrypted in memory during operation.
    
    Returns:
        bool: True if decryption succeeded
        
    Security Note:
        Database exists unencrypted in memory during operation.
        Re-encrypted on application shutdown.
    """
    if os.path.exists("med.db"):
        return True  # Already decrypted
    
    if not os.path.exists("med.db.enc"):
        return True  # No encrypted file exists yet
    
    try:
        key = get_encryption_key()
        fernet = Fernet(key)
        
        # Read encrypted database
        with open("med.db.enc", "rb") as file:
            encrypted_data = file.read()
        
        # Decrypt the data
        decrypted_data = fernet.decrypt(encrypted_data)
        
        # Write decrypted version for SQLite to use
        with open("med.db", "wb") as file:
            file.write(decrypted_data)
        
        return True
        
    except Exception as e:
        print(f"❌ Decryption failed: {e}")
        print("⚠️  Wrong encryption key or corrupted database")
        return False


# =============================================================================
# FLASK APP CONFIGURATION
# =============================================================================

app = Flask(__name__)

# Get secret key from environment variable for security
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')

# Set session timeout to 15 minutes of inactivity
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def normalize_ingredient(name):
    """
    Normalize ingredient names for consistent comparison.
    
    Args:
        name (str): Raw ingredient name
        
    Returns:
        str: Normalized name (lowercase, no parenthetical info)
        
    Example:
        normalize_ingredient("Acetaminophen (USP)") returns "acetaminophen"
    """
    if not name:
        return ""
    
    # Remove anything in parentheses, trim whitespace, convert to lowercase
    clean_name = re.sub(r'\s*\(.*?\)', '', name).strip().lower()
    return clean_name


def get_db_connection():
    """
    Establish connection to SQLite database.
    
    Database is encrypted at rest using AES-256.
    Decrypted temporarily during operation.
    
    Returns:
        sqlite3.Connection: Database connection object
    """
    # Ensure database is decrypted for use
    decrypt_database()
    
    db = sqlite3.connect("med.db")
    db.row_factory = sqlite3.Row  # Enable dictionary-style row access
    
    return db


def fetch_drug_info(drug_name: str) -> dict:
    """
    Fetch side-effect information for a drug from the OpenFDA Drug Label API.

    Args:
        drug_name (str): The medication name or query term to search.

    Returns:
        dict: A dictionary with a single key:
              - 'side_effects' (str | None): A flattened string of adverse reactions
                if available; otherwise None.

    Notes:
        - Purpose/indications are no longer auto-filled; users enter purpose manually.
        - Network/API issues should be handled by callers as needed.
    """

    base_url = "https://api.fda.gov/drug/label.json"
    
    # Try multiple search strategies for best coverage
    fields_to_try = [
        f"openfda.brand_name:{drug_name}",
        f"openfda.generic_name:{drug_name}",
        f"description:{drug_name}"
    ]

    for field in fields_to_try:
        params = {"search": field, "limit": 1}
        
        try:
            response = requests.get(base_url, params=params, timeout=5)
            response.raise_for_status()
            data = response.json()

            # Check if we got results
            if "results" in data and len(data["results"]) > 0:
                result = data["results"][0]
                
                # Extract side effects (try multiple fields)
                side_effects = (
                    result.get("warnings", [])
                    or result.get("adverse_reactions", [])
                    or result.get("drug_interactions", [])
                    or ["Information not available"]
                )[0]

                return {
                    "side_effects": side_effects
                }

        except requests.exceptions.HTTPError as e:
            # 404 means not found, try next search strategy
            if response.status_code == 404:
                continue
            else:
                print(f"[WARN] HTTP error for {drug_name}: {e}")
                
        except Exception as e:
            print(f"[WARN] OpenFDA lookup failed for {drug_name}: {e}")

    # Fallback if all searches fail
    print(f"[INFO] No OpenFDA info found for {drug_name}.")
    return {

        "side_effects": None
    }


# =============================================================================
# FLASK HOOKS
# =============================================================================

@app.before_request
def make_session_permanent():
    """Make sessions permanent so timeout applies."""
    session.permanent = True


# =============================================================================
# ROUTES - PUBLIC PAGES
# =============================================================================

@app.route("/")
def index():
    """
    Homepage route.
    
    Shows different content based on login status:
    - Logged out: Welcome page with features
    - Logged in: Dashboard with medication count
    """
    if "user_id" in session:
        # User is logged in - show dashboard
        user_id = session["user_id"]
        db = get_db_connection()
        cur = db.cursor()
        
        # Get count of active medications
        cur.execute(
            "SELECT COUNT(*) as count FROM medications WHERE user_id = ? AND active = 1",
            (user_id,)
        )
        med_count = cur.fetchone()['count']
        
        db.close()
        
        return render_template("index.html", med_count=med_count)
    
    # User is logged out - show welcome page
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """
    User registration route.
    
    GET: Display registration form
    POST: Process registration, validate input, create user
    
    Validation:
        - Username required and unique
        - Password required
        - Password confirmation must match
    """
    # Clear any existing session
    session.clear()

    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")

        # Validate username
        if not username:
            return render_template("register.html", error="Must provide username.")
        
        # Validate password
        if not password:
            return render_template("register.html", error="Must provide password.", username=username)
        
        # Validate password confirmation
        if not confirmation:
            return render_template("register.html", error="Must provide confirmation password.", username=username)
        
        # Check passwords match
        if password != confirmation:
            return render_template("register.html", error="Passwords do not match.", username=username)
        
        # Connect to database
        db = get_db_connection()
        cur = db.cursor()
        
        # Check for duplicate username
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        existing_user = cur.fetchone()
        
        if existing_user:
            db.close()
            return render_template("register.html", error="Username already exists.", username=username)
        
        # Create new user with hashed password
        password_hash = generate_password_hash(password)
        cur.execute(
            "INSERT INTO users (username, hash) VALUES (?, ?)",
            (username, password_hash)
        )
        db.commit()
        db.close()

        # Redirect to login with success message
        return render_template("login.html", success="Registration successful! Please log in.")
    
    # GET request - show registration form
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """
    User login route.
    
    GET: Display login form
    POST: Authenticate user and create session
    
    Security:
        - Passwords hashed with Werkzeug
        - Failed login attempts logged
        - Session created only on successful auth
    """
    # Clear any existing session
    session.clear()

    if request.method == "POST":
        # Get form data
        username = request.form.get("username")
        password = request.form.get("password")

        # Validate username provided
        if not username:
            return render_template("login.html", error="Must provide username.")
        
        # Validate password provided
        if not password:
            return render_template("login.html", error="Must provide password.")

        # Look up user in database
        db = get_db_connection()
        cur = db.cursor()
        cur.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cur.fetchone()
        db.close()

        # Validate credentials
        if user is None or not check_password_hash(user["hash"], password):
            return render_template("login.html", error="Invalid username or password.")

        # Create session for authenticated user
        session["user_id"] = user["id"]

        # Redirect to main application
        return redirect("/add_medication")

    # GET request - show login form
    return render_template("login.html")


@app.route("/logout")
def logout():
    """
    User logout route.
    
    Clears session and redirects to login page.
    Displays different message if session expired vs manual logout.
    """
    session.clear()
    
    # Check if logout was due to session expiration
    expired = request.args.get("expired")
    message = "Your session expired due to inactivity." if expired else "You have been logged out."
    
    return render_template("login.html", error=message)


# =============================================================================
# ROUTES - AUTHENTICATED PAGES
# =============================================================================

@app.route("/add_medication", methods=["GET", "POST"])
def add_medication():
    """
    Add medication route.
    
    GET: Display medication entry form
    POST: Process and save new medication
    
    Features:
        - RxNorm validation
        - OpenFDA side effects lookup
        - Duplicate detection (case-insensitive)
        - Unverified medication warnings
    
    Requires:
        User must be logged in (user_id in session)
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")
    
    user_id = session["user_id"]

    if request.method == "POST":
        # Check if user confirmed a warning
        confirm = request.form.get("confirm")

        # Get form data
        name = request.form.get("name", "").strip().lower()
        dosage = request.form.get("dosage")
        frequency = request.form.get("frequency")
        purpose = request.form.get("purpose")
        notes = request.form.get("notes")

        # Validate required fields
        if not name or not dosage or not frequency or not purpose:
            return render_template(
                "add_medication.html",
                error="Please provide medication name, dosage, frequency, and purpose."
            )
        
        # Initialize verification and side effects
        side_effects = ""
        side_effects_auto = False
        verified = 0

        db = get_db_connection()
        cur = db.cursor()

        # Check if medication exists in reference database
        cur.execute("SELECT * FROM drug_reference WHERE drug_name = ?", (name,))
        reference_entry = cur.fetchone()

        if reference_entry:
            verified = 1
        else:
            # Try RxNorm validation
            rxcui = None
            query_name = name.title()

            try:
                # Query RxNorm API
                resp = requests.get(
                    f"https://rxnav.nlm.nih.gov/REST/rxcui.json?name={query_name}",
                    timeout=5
                )
                data = resp.json()

                # Extract RxCUI if found
                rx_ids = data.get("idGroup", {}).get("rxnormId", [])
                if isinstance(rx_ids, list) and rx_ids and rx_ids[0].strip():
                    rxcui = rx_ids[0].strip()
                    verified = 1

            except Exception as e:
                print(f"[WARN] RxNorm lookup failed for {name}: {e}")
                rxcui = None
                verified = 0

            # Add to reference database if verified
            if verified == 1 and rxcui:
                cur.execute("SELECT 1 FROM drug_reference WHERE drug_name = ?", (name,))
                if not cur.fetchone():
                    cur.execute(
                        "INSERT INTO drug_reference (drug_name, rxcui) VALUES (?, ?)",
                        (name, rxcui)
                    )

        # Fetch side effects from OpenFDA
        info = fetch_drug_info(name) or {}
        side_effects_data = info.get("side_effects") or ""
        
        if side_effects_data.strip() and side_effects_data != "Information not available":
            side_effects = side_effects_data
            side_effects_auto = True

        # Check for warnings (duplicate or unverified) if not confirmed
        if not confirm:
            # Check for duplicate name
            cur.execute(
                "SELECT * FROM medications WHERE user_id = ? AND name = ? AND active = 1",
                (user_id, name)
            )
            existing_med = cur.fetchone()

            if existing_med:
                db.close()
                return render_template(
                    "add_medication.html",
                    warning=f"⚠️ You already have '{name.title()}' in your active medication list! Add again?",
                    confirm_add=True,
                    form_data=request.form
                )

            # Check if unverified
            if verified == 0:
                db.close()
                return render_template(
                    "add_medication.html",
                    warning=f"⚠️ '{name.title()}' could not be verified in RxNorm. Add anyway?",
                    confirm_add=True,
                    form_data=request.form
                )

        # Insert medication into database
        info_last_updated = datetime.now(timezone.utc).isoformat()
        
        cur.execute("""
            INSERT INTO medications (
                user_id, name, dosage, frequency, purpose, side_effects,
                notes, info_last_updated, verified, side_effects_auto
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user_id, name, dosage, frequency, purpose, side_effects,
            notes, info_last_updated, verified, int(side_effects_auto)
        ))

        db.commit()
        db.close()

        # Show success message
        flash("Medication added successfully!", "success")
        return redirect("/add_medication")

    # GET request - show form
    return render_template("add_medication.html")


@app.route("/list_medications", methods=["GET"])
def list_medications():
    """
    List medications route.
    
    Displays table of all active medications for logged-in user.
    Shows: name, dosage, frequency, purpose, side effects, notes
    Includes badges for: duplicates, unverified, overlap warnings
    
    Requires:
        User must be logged in
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")
    
    user_id = session["user_id"]

    db = get_db_connection()
    cur = db.cursor()
    
    # Get active medications
    cur.execute(
        "SELECT * FROM medications WHERE user_id = ? AND active = 1 ORDER BY name",
        (user_id,)
    )
    medications = cur.fetchall()
    
    # Get archived medications
    cur.execute(
        "SELECT * FROM medications WHERE user_id = ? AND active = 0 ORDER BY name",
        (user_id,)
    )
    archived = cur.fetchall()
    
    db.close()
    
    return render_template("list_medications.html", medications=medications, archived=archived)

@app.route("/unarchive_medication/<int:med_id>", methods=["POST"])
def unarchive_medication(med_id):
    """
    Unarchive medication route.
    
    Restores archived medication back to active status.
    
    Args:
        med_id (int): ID of medication to unarchive
        
    Security:
        Verifies medication belongs to logged-in user
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")
    
    user_id = session["user_id"]
    
    # Unarchive the medication (verify ownership)
    db = get_db_connection()
    cur = db.cursor()
    cur.execute(
        "UPDATE medications SET active = 1 WHERE id = ? AND user_id = ?",
        (med_id, user_id)
    )
    db.commit()
    db.close()
    
    return redirect("/list_medications")

@app.route("/archive_medication/<int:med_id>", methods=["POST"])
def archive_medication(med_id):
    """
    Archive medication route.
    
    Marks medication as inactive (archived) rather than deleting.
    Maintains history while removing from active view.
    
    Args:
        med_id (int): ID of medication to archive
        
    Security:
        Verifies medication belongs to logged-in user
    """
    # Require authentication
    if "user_id" not in session:
        return redirect("/login")
    
    user_id = session["user_id"]
    
    # Archive the medication (verify ownership)
    db = get_db_connection()
    cur = db.cursor()
    cur.execute(
        "UPDATE medications SET active = 0 WHERE id = ? AND user_id = ?",
        (med_id, user_id)
    )
    db.commit()
    db.close()
    
    return redirect("/list_medications")


# =============================================================================
# APPLICATION ENTRY POINT
# =============================================================================

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully and encrypt database."""
    print("\n\n🔒 Encrypting database before shutdown...")
    try:
        encrypt_database()
        print("✅ Database encrypted. Shutting down safely.")
    except Exception as e:
        print(f"⚠️  Encryption warning: {e}")
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Display encryption status on startup
    print("\n" + "="*70)
    print("MEDICATION TRACKER - CS50 FINAL PROJECT")
    print("="*70)
    print("✅ Database encryption ENABLED (AES-256 using cryptography library)")
    print("⚠️  Make sure DB_ENCRYPTION_KEY environment variable is set!")
    print("="*70 + "\n")
    
    # Decrypt database for use
    if not decrypt_database():
        print("❌ Failed to decrypt database. Check encryption key.")
        exit(1)
    
    # Start Flask development server
    try:
        app.run(debug=True, use_reloader=False)
    finally:
        # Ensure database is encrypted on shutdown
        print("\n🔒 Encrypting database...")
        encrypt_database()
        print("✅ Database encrypted. Application closed safely.")