from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash, after_this_request
from functools import wraps
import os
import time
import sqlite3
import secrets
import hashlib
from supabase import create_client, Client
from Crypto.Cipher import AES

# ====== Temp folder ======
TEMP_DIR = "temp"
os.makedirs(TEMP_DIR, exist_ok=True)

# ====== (Optional) SQLite setup (not used for auth now) ======
DB_PATH = "users.db"
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(
        '''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL
        )'''
    )
    conn.commit()
    conn.close()

init_db()

# ====== Supabase config ======
SUPABASE_URL = "https://qwaqnzwpihbgtrtvquem.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InF3YXFuendwaWhiZ3RydHZxdWVtIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NjQwNzkzNjksImV4cCI6MjA3OTY1NTM2OX0.0w-DP6QKAubWS888dFGnumlNyiL9ZGV6TF1DDiRia3M"
BUCKET_NAME = "secure-files"
FILES_TABLE = "files_info"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

# ====== Flask config ======
app = Flask(__name__)
app.secret_key = "Murtaza_sukhsarwala@200513"  # change for real use

# ====== AES config ======
AES_KEY = b'ThisIsA16ByteKey'  # change for real use

# ====== Helpers: crypto ======
def encrypt_file(file_path, key):
    cipher = AES.new(key, AES.MODE_EAX)
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    enc_path = file_path + ".enc"
    with open(enc_path, 'wb') as f_enc:
        f_enc.write(cipher.nonce)
        f_enc.write(tag)
        f_enc.write(ciphertext)
    return enc_path

def decrypt_file(enc_file_path, key, output_path):
    with open(enc_file_path, 'rb') as f_enc:
        nonce = f_enc.read(16)
        tag = f_enc.read(16)
        ciphertext = f_enc.read()
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    with open(output_path, 'wb') as f:
        f.write(data)

# ====== Helpers: Supabase storage ======
def upload_to_supabase(enc_path, filename):
    with open(enc_path, "rb") as f:
        supabase.storage.from_(BUCKET_NAME).upload(filename, f)

def download_from_supabase(filename, temp_path):
    res = supabase.storage.from_(BUCKET_NAME).download(filename)
    with open(temp_path, "wb") as f:
        f.write(res)

def delete_from_supabase(filename_enc):
    supabase.storage.from_(BUCKET_NAME).remove([filename_enc])

# ====== Helpers: file metadata in Supabase table ======
def save_file_metadata(file_name, owner_id, share_token=None, password_hash=None):
    data = {"file_name": file_name, "owner": owner_id}
    if share_token is not None:
        data["share_token"] = share_token
    if password_hash is not None:
        data["share_password_hash"] = password_hash
    supabase.table(FILES_TABLE).insert(data).execute()

def list_my_files(owner_id):
    response = supabase.table(FILES_TABLE).select("file_name").eq("owner", owner_id).execute()
    data = getattr(response, "data", None)
    if data:
        return [row["file_name"].replace(".enc", "") for row in data]
    return []

def get_file_by_token(token):
    resp = supabase.table(FILES_TABLE).select("file_name, share_password_hash").eq("share_token", token).execute()
    data = getattr(resp, "data", None)
    if not data:
        return None
    return data[0]

def delete_file_metadata(file_name, owner_id):
    supabase.table(FILES_TABLE).delete().eq("file_name", file_name).eq("owner", owner_id).execute()

# ====== Helpers: unique names, tokens, password hash ======
def generate_unique_filename(filename):
    timestamp = int(time.time())
    name, ext = os.path.splitext(filename)
    return f"{name}_{timestamp}{ext}"

def generate_share_token():
    return secrets.token_urlsafe(16)

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# ====== Login protection ======
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# ====== Auth routes ======
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        name = request.form.get('name', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password or not name:
            flash("Please fill all fields.", "danger")
            return render_template('signup.html')

        try:
            res = supabase.auth.sign_up({
                "email": email,
                "password": password
            })
        except Exception:
            flash("Signup failed. Try a different email.", "danger")
            return render_template('signup.html')

        user = getattr(res, "user", None)
        if not user:
            flash("Signup failed. Try a different email.", "danger")
            return render_template('signup.html')

        supabase.table("profiles").insert({
            "id": user.id,
            "full_name": name
        }).execute()

        flash("Account created! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash("Please enter email and password.", "danger")
            return render_template('login.html')

        try:
            res = supabase.auth.sign_in_with_password({
                "email": email,
                "password": password
            })
        except Exception:
            flash("Invalid email or password.", "danger")
            return render_template('login.html')

        session_user = getattr(res, "user", None)
        if not session_user:
            flash("Invalid email or password.", "danger")
            return render_template('login.html')

        prof = supabase.table("profiles").select("full_name").eq("id", session_user.id).execute()
        data = getattr(prof, "data", None)
        full_name = data[0].get("full_name") if data else email

        session['user_id'] = session_user.id
        session['user_email'] = session_user.email
        session['name'] = full_name

        return redirect(url_for('index'))

    return render_template('login.html')

@app.route('/forgot', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            flash("Enter your email.", "danger")
            return render_template('forgot.html')

        try:
            supabase.auth.reset_password_for_email(email)
            flash("If that email exists, a reset link was sent.", "info")
        except Exception:
            flash("Could not send reset email. Try again.", "danger")

        return redirect(url_for('login'))

    return render_template('forgot.html')

from urllib.parse import urlparse, parse_qs

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'GET':
        # Just take whatever access_token comes from Supabase and show the form
        access_token = request.args.get('access_token', '').strip()
        return render_template('reset.html', access_token=access_token)

    # POST: user submitted new password
    password = request.form.get('password', '').strip()
    password_confirm = request.form.get('password_confirm', '').strip()
    access_token = request.form.get('access_token', '').strip()

    if not password or not password_confirm:
        flash("Please fill both password fields.", "danger")
        return render_template('reset.html', access_token=access_token)

    if password != password_confirm:
        flash("Passwords do not match.", "danger")
        return render_template('reset.html', access_token=access_token)

    if not access_token:
        flash("Reset link is invalid or expired. Please request a new one.", "danger")
        return redirect(url_for('forgot_password'))

    try:
        # use the recovery access token to update the password
        supabase.auth.set_session(access_token, None)  # temporary session
        resp = supabase.auth.update_user({"password": password})  # [web:269]
        if getattr(resp, "user", None) is None:
            flash("Could not update password. Request a new reset link.", "danger")
            return render_template('reset.html', access_token=access_token)
    except Exception:
        flash("Error updating password. The link may be expired.", "danger")
        return render_template('reset.html', access_token=access_token)

    flash("Password updated. Please log in with your new password.", "success")
    return redirect(url_for('login'))



    # Temporarily set the session with the access token, then call update_user
    try:
        supabase.auth.set_session(access_token, None)  # refresh_token not needed for one call
        resp = supabase.auth.update_user({"password": password})  # [web:269]
        if getattr(resp, "user", None) is None:
            flash("Could not update password. Try requesting a new reset link.", "danger")
            return render_template('reset.html', access_token=access_token)
    except Exception:
        flash("Error updating password. The link may be expired.", "danger")
        return render_template('reset.html', access_token=access_token)

    flash("Password updated. Please log in with your new password.", "success")
    return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('user_email', None)
    session.pop('name', None)
    return redirect(url_for('login'))

# ====== Main index: only this user's files ======
@app.route('/')
@login_required
def index():
    files = list_my_files(session['user_id'])
    return render_template('index.html', files=files)

# ====== Upload with optional share password + share link ======
@app.route('/upload', methods=['POST'])
@login_required
def upload():
    uploaded_file = request.files['file']
    share_password = request.form.get('share_password', '').strip()
    if uploaded_file.filename != '':
        unique_filename = generate_unique_filename(uploaded_file.filename)
        temp_path = os.path.join(TEMP_DIR, "temp_" + unique_filename)
        uploaded_file.save(temp_path)
        enc_path = encrypt_file(temp_path, AES_KEY)
        storage_name = unique_filename + ".enc"

        upload_to_supabase(enc_path, storage_name)

        token = generate_share_token()
        pwd_hash = hash_password(share_password) if share_password else None
        save_file_metadata(storage_name, session['user_id'], token, pwd_hash)

        os.remove(temp_path)
        os.remove(enc_path)

        session['last_share_link'] = f"{request.host_url}share/{token}"
        flash("File uploaded and share link generated.", "success")
    return redirect(url_for('index'))

# ====== Normal download for logged-in owner ======
@app.route('/download/<filename>')
@login_required
def download(filename):
    enc_file_name = filename + ".enc"
    temp_enc_path = os.path.join(TEMP_DIR, "temp_" + enc_file_name)
    temp_out_path = os.path.join(TEMP_DIR, "temp_" + filename)
    download_from_supabase(enc_file_name, temp_enc_path)
    decrypt_file(temp_enc_path, AES_KEY, temp_out_path)

    @after_this_request
    def cleanup(response):
        try:
            os.remove(temp_enc_path)
            os.remove(temp_out_path)
        except Exception:
            pass
        return response

    return send_file(
        temp_out_path,
        as_attachment=True,
        download_name=filename
    )

# ====== Delete file (owner only) ======
@app.route('/delete/<filename>', methods=['POST'])
@login_required
def delete_file(filename):
    file_name_enc = filename + ".enc"
    delete_from_supabase(file_name_enc)
    delete_file_metadata(file_name_enc, session['user_id'])
    flash("File deleted.", "success")
    return redirect(url_for('index'))

# ====== Shared link download (with optional password) ======
@app.route('/share/<token>', methods=['GET', 'POST'])
def shared_download(token):
    info = get_file_by_token(token)
    if not info:
        return "Invalid or expired link", 404

    file_name_enc = info["file_name"]
    pwd_hash = info.get("share_password_hash")

    if request.method == 'POST':
        entered = request.form.get('password', '')
        if pwd_hash and hash_password(entered) != pwd_hash:
            flash("Wrong password", "danger")
            return render_template('shared_password.html', token=token)
        return _send_shared_file(file_name_enc)

    if pwd_hash:
        return render_template('shared_password.html', token=token)
    return _send_shared_file(file_name_enc)

def _send_shared_file(file_name_enc):
    filename = file_name_enc.replace(".enc", "")
    enc_file_name = file_name_enc
    temp_enc_path = os.path.join(TEMP_DIR, "temp_" + enc_file_name)
    temp_out_path = os.path.join(TEMP_DIR, "temp_" + filename)
    download_from_supabase(enc_file_name, temp_enc_path)
    decrypt_file(temp_enc_path, AES_KEY, temp_out_path)

    @after_this_request
    def cleanup(response):
        try:
            os.remove(temp_enc_path)
            os.remove(temp_out_path)
        except Exception:
            pass
        return response

    return send_file(temp_out_path, as_attachment=True, download_name=filename)

if __name__ == '__main__':
    app.run(debug=True)
