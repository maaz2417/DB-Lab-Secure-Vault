import os
from flask import Flask, render_template, request, redirect, session, url_for, flash, jsonify
from functools import wraps
from db import get_connection
from crypto import hash_master_password, verify_master_password, encrypt_field, decrypt_field

app = Flask(
    __name__, 
    template_folder='frontend/templates', 
    static_folder='frontend/static'
)
app.secret_key = 'securevault-super-secret-key-13579'

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to unlock your vault.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Context processor to inject user preferences globally into all templates
@app.context_processor
def inject_prefs():
    if 'user_id' in session:
        try:
            conn = get_connection()
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM user_preferences WHERE user_id = %s", (session['user_id'],))
            prefs = cur.fetchone()
            cur.close()
            conn.close()
            if prefs:
                return dict(prefs=prefs)
        except Exception as e:
            print(f"Error fetching preferences: {e}")
    # Default fallback preferences
    default_prefs = {
        'auto_logout_minutes': 10,
        'clipboard_clear_seconds': 30,
        'theme': 'dark',
        'default_security_level': 'medium'
    }
    return dict(prefs=default_prefs)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '')
        
        conn = get_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        user = cur.fetchone()
        
        if user and verify_master_password(master_password, user['master_password_hash']):
            # Successful authentication
            session['user_id'] = user['user_id']
            session['username'] = user['username']
            
            # Record audit log
            cur.execute(
                "INSERT INTO audit_log (user_id, action) VALUES (%s, 'LOGIN_SUCCESS')",
                (user['user_id'],)
            )
            conn.commit()
            cur.close()
            conn.close()
            
            flash("Vault successfully unlocked!", "success")
            return redirect(url_for('dashboard'))
        else:
            # Failed authentication
            # Get IP address
            ip_addr = request.remote_addr or '127.0.0.1'
            
            if user:
                # User exists, record failed login attempt
                cur.execute(
                    "INSERT INTO failed_login_attempts (user_id, ip_address) VALUES (%s, %s)",
                    (user['user_id'], ip_addr)
                )
                cur.execute(
                    "INSERT INTO audit_log (user_id, action) VALUES (%s, 'LOGIN_FAILURE')",
                    (user['user_id'],)
                )
            
            conn.commit()
            cur.close()
            conn.close()
            
            flash("Invalid master password or username. Access Denied.", "error")
            return render_template('login.html')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        master_password = request.form.get('master_password', '')
        confirm_password = request.form.get('confirm_password', '')
        
        if master_password != confirm_password:
            flash("Passwords do not match.", "error")
            return render_template('register.html')
            
        if len(master_password) < 6:
            flash("Master password must be at least 6 characters.", "error")
            return render_template('register.html')
            
        conn = get_connection()
        cur = conn.cursor(dictionary=True)
        
        # Check if username exists
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.close()
            conn.close()
            flash("Username already exists.", "error")
            return render_template('register.html')
            
        # Create user
        hashed = hash_master_password(master_password)
        cur.execute(
            "INSERT INTO users (username, master_password_hash) VALUES (%s, %s)",
            (username, hashed)
        )
        new_user_id = cur.lastrowid
        
        # Insert default preferences for new user
        cur.execute(
            "INSERT INTO user_preferences (user_id, auto_logout_minutes, clipboard_clear_seconds, theme, default_security_level) VALUES (%s, 10, 30, 'dark', 'medium')",
            (new_user_id,)
        )
        
        # Record audit log
        cur.execute(
            "INSERT INTO audit_log (user_id, action) VALUES (%s, 'REGISTER_USER')",
            (new_user_id,)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash("Vault account created successfully! You can now log in.", "success")
        return redirect(url_for('login'))
        
    return render_template('register.html')

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    reason = request.args.get('reason')
    user_id = session.get('user_id')
    
    if user_id:
        try:
            conn = get_connection()
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO audit_log (user_id, action) VALUES (%s, 'LOGOUT')",
                (user_id,)
            )
            conn.commit()
            cur.close()
            conn.close()
        except Exception as e:
            print(f"Error logging logout: {e}")
            
    session.clear()
    
    if reason == 'inactivity':
        flash("Logged out automatically due to inactivity.", "warning")
    else:
        flash("Vault locked. Session terminated safely.", "success")
        
    return redirect(url_for('login'))

@app.route('/')
@app.route('/dashboard')
@login_required
def dashboard():
    search_query = request.args.get('search', '').strip()
    selected_type = request.args.get('type_id', '').strip()
    user_id = session['user_id']
    
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    # 1. Fetch categories for filtering
    cur.execute("SELECT * FROM credential_types ORDER BY type_name")
    credential_types = cur.fetchall()
    
    # 2. Fetch vault items
    query = """
        SELECT v.vault_id, v.user_id, v.type_id, v.site_name, v.username, v.encrypted_password, v.notes, 
               ct.type_name, ct.security_level, ct.requires_reauth, ct.clipboard_timeout,
               bc.bank_id, bc.bank_name, bc.account_type, bc.card_last_four
        FROM vault v
        LEFT JOIN credential_types ct ON v.type_id = ct.type_id
        LEFT JOIN bank_credentials bc ON v.vault_id = bc.vault_id
        WHERE v.user_id = %s
    """
    params = [user_id]
    
    if search_query:
        query += " AND (v.site_name LIKE %s OR v.username LIKE %s)"
        params.extend([f"%{search_query}%", f"%{search_query}%"])
        
    if selected_type:
        query += " AND v.type_id = %s"
        params.append(selected_type)
        
    query += " ORDER BY v.site_name"
    
    cur.execute(query, params)
    vault_items = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template(
        'dashboard.html',
        vault_items=vault_items,
        credential_types=credential_types,
        search_query=search_query,
        selected_type=selected_type
    )

@app.route('/vault/add', methods=['GET', 'POST'])
@login_required
def add_vault():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    if request.method == 'POST':
        site_name = request.form.get('site_name', '').strip()
        type_id = request.form.get('type_id')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        
        # Encrypt the password
        encrypted_pwd = encrypt_field(password)
        
        cur.execute(
            "INSERT INTO vault (user_id, type_id, site_name, username, encrypted_password, notes) VALUES (%s, %s, %s, %s, %s, %s)",
            (session['user_id'], type_id, site_name, username, encrypted_pwd, notes)
        )
        vault_id = cur.lastrowid
        
        # If category is Financial (type_id = 4 represents Bank / Credit Card)
        if type_id == '4':
            bank_name = request.form.get('bank_name', '').strip()
            account_type = request.form.get('account_type', 'savings')
            account_number = request.form.get('account_number', '')
            card_last_four = request.form.get('card_last_four', '').strip()
            pin = request.form.get('pin', '')
            
            enc_account = encrypt_field(account_number)
            enc_pin = encrypt_field(pin)
            
            cur.execute(
                "INSERT INTO bank_credentials (vault_id, bank_name, account_number_encrypted, card_last_four, account_type, pin_encrypted) VALUES (%s, %s, %s, %s, %s, %s)",
                (vault_id, bank_name, enc_account, card_last_four if card_last_four else None, account_type, enc_pin if pin else None)
            )
            
        # Log action
        cur.execute(
            "INSERT INTO audit_log (user_id, vault_id, action) VALUES (%s, %s, 'ADD_ENTRY')",
            (session['user_id'], vault_id)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash("New credential successfully secured in your vault!", "success")
        return redirect(url_for('dashboard'))
        
    # GET: Load categories
    cur.execute("SELECT * FROM credential_types ORDER BY type_name")
    credential_types = cur.fetchall()
    cur.close()
    conn.close()
    
    return render_template('vault_entry.html', item=None, credential_types=credential_types)

@app.route('/vault/edit/<int:vault_id>', methods=['GET', 'POST'])
@login_required
def edit_vault(vault_id):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    # Verify ownership
    cur.execute("SELECT * FROM vault WHERE vault_id = %s AND user_id = %s", (vault_id, session['user_id']))
    vault_item = cur.fetchone()
    if not vault_item:
        cur.close()
        conn.close()
        flash("Requested vault entry not found or unauthorized.", "error")
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        site_name = request.form.get('site_name', '').strip()
        type_id = request.form.get('type_id')
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        notes = request.form.get('notes', '').strip()
        
        # Check if password has changed to save into history
        current_enc_pwd = vault_item['encrypted_password']
        # If the user submitted the exact text matching decrypted form, or edited it:
        submitted_decrypted = password
        original_decrypted = decrypt_field(current_enc_pwd)
        
        if submitted_decrypted != original_decrypted:
            # Password changed, archive old one
            cur.execute(
                "INSERT INTO password_history (vault_id, encrypted_password) VALUES (%s, %s)",
                (vault_id, current_enc_pwd)
            )
            # Encrypt new password
            encrypted_pwd = encrypt_field(submitted_decrypted)
        else:
            encrypted_pwd = current_enc_pwd
            
        cur.execute(
            "UPDATE vault SET type_id=%s, site_name=%s, username=%s, encrypted_password=%s, notes=%s WHERE vault_id=%s AND user_id=%s",
            (type_id, site_name, username, encrypted_pwd, notes, vault_id, session['user_id'])
        )
        
        # Update Bank Credentials if Financial type
        if type_id == '4':
            bank_name = request.form.get('bank_name', '').strip()
            account_type = request.form.get('account_type', 'savings')
            account_number = request.form.get('account_number', '')
            card_last_four = request.form.get('card_last_four', '').strip()
            pin = request.form.get('pin', '')
            
            # Check if bank credentials already exist
            cur.execute("SELECT * FROM bank_credentials WHERE vault_id = %s", (vault_id,))
            bank_item = cur.fetchone()
            
            enc_account = encrypt_field(account_number)
            enc_pin = encrypt_field(pin) if pin else None
            
            if bank_item:
                # Update
                cur.execute(
                    "UPDATE bank_credentials SET bank_name=%s, account_number_encrypted=%s, card_last_four=%s, account_type=%s, pin_encrypted=%s WHERE vault_id=%s",
                    (bank_name, enc_account, card_last_four if card_last_four else None, account_type, enc_pin, vault_id)
                )
            else:
                # Insert
                cur.execute(
                    "INSERT INTO bank_credentials (vault_id, bank_name, account_number_encrypted, card_last_four, account_type, pin_encrypted) VALUES (%s, %s, %s, %s, %s, %s)",
                    (vault_id, bank_name, enc_account, card_last_four if card_last_four else None, account_type, enc_pin)
                )
        else:
            # If changed FROM category 4, delete bank details
            cur.execute("DELETE FROM bank_credentials WHERE vault_id = %s", (vault_id,))
            
        # Log action
        cur.execute(
            "INSERT INTO audit_log (user_id, vault_id, action) VALUES (%s, %s, 'EDIT_ENTRY')",
            (session['user_id'], vault_id)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash("Credential entry updated successfully!", "success")
        return redirect(url_for('dashboard'))
        
    # GET: Load item details, history, categories
    cur.execute("""
        SELECT v.*, bc.bank_name, bc.account_number_encrypted, bc.card_last_four, bc.account_type, bc.pin_encrypted
        FROM vault v
        LEFT JOIN bank_credentials bc ON v.vault_id = bc.vault_id
        WHERE v.vault_id = %s
    """, (vault_id,))
    item = cur.fetchone()
    
    # Decrypt main password & bank details for GET form
    decrypted_password = decrypt_field(item['encrypted_password'])
    bank_account = decrypt_field(item.get('account_number_encrypted')) if item.get('account_number_encrypted') else ''
    bank_pin = decrypt_field(item.get('pin_encrypted')) if item.get('pin_encrypted') else ''
    
    cur.execute("SELECT * FROM password_history WHERE vault_id = %s ORDER BY changed_at DESC", (vault_id,))
    history = cur.fetchall()
    
    cur.execute("SELECT * FROM credential_types ORDER BY type_name")
    credential_types = cur.fetchall()
    
    cur.close()
    conn.close()
    
    return render_template(
        'vault_entry.html', 
        item=item, 
        decrypted_password=decrypted_password,
        bank_account=bank_account,
        bank_pin=bank_pin,
        history=history,
        credential_types=credential_types
    )

@app.route('/vault/delete/<int:vault_id>', methods=['POST'])
@login_required
def delete_vault(vault_id):
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    # Verify ownership
    cur.execute("SELECT * FROM vault WHERE vault_id = %s AND user_id = %s", (vault_id, session['user_id']))
    if not cur.fetchone():
        cur.close()
        conn.close()
        flash("Requested vault entry not found or unauthorized.", "error")
        return redirect(url_for('dashboard'))
        
    # Delete / Update dependencies
    cur.execute("UPDATE audit_log SET vault_id = NULL WHERE vault_id = %s", (vault_id,))
    cur.execute("DELETE FROM password_history WHERE vault_id = %s", (vault_id,))
    cur.execute("DELETE FROM bank_credentials WHERE vault_id = %s", (vault_id,))
    cur.execute("DELETE FROM vault WHERE vault_id = %s", (vault_id,))
    
    # Log delete action
    cur.execute(
        "INSERT INTO audit_log (user_id, action) VALUES (%s, 'DELETE_ENTRY')",
        (session['user_id'],)
    )
    
    conn.commit()
    cur.close()
    conn.close()
    
    flash("Credential entry deleted and erased from history.", "success")
    return redirect(url_for('dashboard'))

@app.route('/generator')
@login_required
def generator():
    return render_template('generator.html')

@app.route('/audit-logs')
@login_required
def audit_logs():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT al.action_time, al.action, al.user_id, v.site_name 
        FROM audit_log al 
        LEFT JOIN vault v ON al.vault_id = v.vault_id 
        WHERE al.user_id = %s 
        ORDER BY al.action_time DESC 
        LIMIT 100
    """, (session['user_id'],))
    logs = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('audit_log.html', logs=logs)

@app.route('/failed-logins')
@login_required
def failed_logins():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT attempted_at, ip_address 
        FROM failed_login_attempts 
        WHERE user_id = %s 
        ORDER BY attempted_at DESC 
        LIMIT 100
    """, (session['user_id'],))
    attempts = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('failed_logins.html', attempts=attempts)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    if request.method == 'POST':
        auto_logout_minutes = request.form.get('auto_logout_minutes')
        clipboard_clear_seconds = request.form.get('clipboard_clear_seconds')
        default_security_level = request.form.get('default_security_level')
        theme = request.form.get('theme')
        
        cur.execute("""
            UPDATE user_preferences 
            SET auto_logout_minutes=%s, clipboard_clear_seconds=%s, default_security_level=%s, theme=%s 
            WHERE user_id=%s
        """, (auto_logout_minutes, clipboard_clear_seconds, default_security_level, theme, session['user_id']))
        
        cur.execute(
            "INSERT INTO audit_log (user_id, action) VALUES (%s, 'UPDATE_PREFERENCES')",
            (session['user_id'],)
        )
        
        conn.commit()
        cur.close()
        conn.close()
        
        flash("User settings and security thresholds updated!", "success")
        return redirect(url_for('settings'))
        
    cur.execute("SELECT * FROM user_preferences WHERE user_id = %s", (session['user_id'],))
    prefs = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('settings.html', prefs=prefs)

# ── AJAX DECIPHER ENDPOINTS ──

@app.route('/vault/decrypt', methods=['POST'])
@login_required
def decrypt_vault_pwd():
    data = request.get_json() or {}
    vault_id = data.get('vault_id')
    master_password = data.get('master_password', '')
    
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    # 1. Fetch vault item and ownership
    cur.execute("""
        SELECT v.*, ct.requires_reauth, ct.clipboard_timeout 
        FROM vault v
        LEFT JOIN credential_types ct ON v.type_id = ct.type_id
        WHERE v.vault_id = %s AND v.user_id = %s
    """, (vault_id, session['user_id']))
    item = cur.fetchone()
    
    if not item:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Item not found or unauthorized."})
        
    # 2. Check re-auth if required by security tier
    if item['requires_reauth']:
        cur.execute("SELECT master_password_hash FROM users WHERE user_id = %s", (session['user_id'],))
        user = cur.fetchone()
        
        if not user or not verify_master_password(master_password, user['master_password_hash']):
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Incorrect master password."})
            
    # 3. Decrypt and return
    decrypted_pwd = decrypt_field(item['encrypted_password'])
    
    # Log decryption action
    cur.execute(
        "INSERT INTO audit_log (user_id, vault_id, action) VALUES (%s, %s, 'DECRYPT_PASSWORD')",
        (session['user_id'], vault_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({"success": True, "password": decrypted_pwd})

@app.route('/vault/decrypt-bank', methods=['POST'])
@login_required
def decrypt_bank_details():
    data = request.get_json() or {}
    vault_id = data.get('vault_id')
    master_password = data.get('master_password', '')
    
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    # 1. Fetch bank details & ownership
    cur.execute("""
        SELECT bc.*, v.user_id, ct.requires_reauth
        FROM bank_credentials bc
        JOIN vault v ON bc.vault_id = v.vault_id
        LEFT JOIN credential_types ct ON v.type_id = ct.type_id
        WHERE bc.vault_id = %s AND v.user_id = %s
    """, (vault_id, session['user_id']))
    item = cur.fetchone()
    
    if not item:
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Bank details not found or unauthorized."})
        
    # 2. Check re-auth
    if item['requires_reauth']:
        cur.execute("SELECT master_password_hash FROM users WHERE user_id = %s", (session['user_id'],))
        user = cur.fetchone()
        
        if not user or not verify_master_password(master_password, user['master_password_hash']):
            cur.close()
            conn.close()
            return jsonify({"success": False, "error": "Incorrect master password."})
            
    # 3. Decrypt and return
    account_number = decrypt_field(item['account_number_encrypted'])
    pin = decrypt_field(item['pin_encrypted']) if item['pin_encrypted'] else ''
    
    # Log action
    cur.execute(
        "INSERT INTO audit_log (user_id, vault_id, action) VALUES (%s, %s, 'DECRYPT_BANK')",
        (session['user_id'], vault_id)
    )
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({"success": True, "account_number": account_number, "pin": pin})

@app.route('/vault/decrypt-history', methods=['POST'])
@login_required
def decrypt_history():
    data = request.get_json() or {}
    encrypted_pwd = data.get('encrypted_password', '')
    master_password = data.get('master_password', '')
    
    conn = get_connection()
    cur = conn.cursor(dictionary=True)
    
    cur.execute("SELECT master_password_hash FROM users WHERE user_id = %s", (session['user_id'],))
    user = cur.fetchone()
    
    if not user or not verify_master_password(master_password, user['master_password_hash']):
        cur.close()
        conn.close()
        return jsonify({"success": False, "error": "Incorrect master password."})
        
    decrypted_pwd = decrypt_field(encrypted_pwd)
    
    # Log action
    cur.execute(
        "INSERT INTO audit_log (user_id, action) VALUES (%s, 'DECRYPT_HISTORY')",
        (session['user_id'],)
    )
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({"success": True, "password": decrypted_pwd})

if __name__ == '__main__':
    # Bind to all interfaces to support local network access
    app.run(host='0.0.0.0', port=5000, debug=True)
