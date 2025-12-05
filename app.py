from flask import Flask, request, render_template_string
import time
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_PATH = "security.db"

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>Secure Login</title>
</head>
<body>
    <h1>Secure Login</h1>
    <form method="GET">
        <label>Username:</label><br>
        <input type="text" name="username"><br>
        <label>Password:</label><br>
        <input type="password" name="password"><br>
        <input type="submit" name="Login" value="Login">
    </form>
    <div style="margin-top: 20px; border-top: 1px solid #ccc; padding-top: 10px;">
        <h3>Unlock Panel</h3>
        <form method="GET">
            <input type="hidden" name="unlock_account" value="true">
            <input type="text" name="account_username" placeholder="Username to unlock" style="width: 150px;">
            <input type="submit" value="Unlock Account">
        </form>
        <form method="GET" style="margin-top: 10px;">
            <input type="hidden" name="unlock_ip" value="true">
            <input type="text" name="ip_address" placeholder="IP to unlock" style="width: 150px;">
            <input type="submit" value="Unlock IP">
        </form>
        <form method="GET" style="margin-top: 10px;">
            <input type="hidden" name="show_status" value="true">
            <input type="submit" value="Show Status">
        </form>
    </div>
    {{ message|safe }}
</body>
</html>
'''

def db_query(query, params=(), fetch=False, fetchone=False):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(query, params)
    result = None
    if fetch:
        result = c.fetchall()
    if fetchone:
        result = c.fetchone()
    conn.commit()
    conn.close()
    return result

def init_db():
    db_query("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL
    )""")
    db_query("""
    CREATE TABLE IF NOT EXISTS failed_attempts (
        username TEXT PRIMARY KEY,
        attempts INTEGER
    )""")
    db_query("""
    CREATE TABLE IF NOT EXISTS account_locks (
        username TEXT PRIMARY KEY,
        lock_until REAL
    )""")
    db_query("""
    CREATE TABLE IF NOT EXISTS ip_attempts (
        ip TEXT PRIMARY KEY,
        attempts INTEGER,
        first_attempt REAL
    )""")
    if not db_query("SELECT 1 FROM users WHERE username='admin'", fetchone=True):
        db_query("INSERT INTO users VALUES (?, ?)", ('admin', 'admin@123'))

def get_user_password(username):
    row = db_query("SELECT password FROM users WHERE username=?", (username,), fetchone=True)
    return row[0] if row else None

def get_failed_attempts(username):
    row = db_query("SELECT attempts FROM failed_attempts WHERE username=?", (username,), fetchone=True)
    return row[0] if row else 0

def set_failed_attempts(username, attempts):
    if attempts == 0:
        db_query("DELETE FROM failed_attempts WHERE username=?", (username,))
    else:
        if db_query("SELECT 1 FROM failed_attempts WHERE username=?", (username,), fetchone=True):
            db_query("UPDATE failed_attempts SET attempts=? WHERE username=?", (attempts, username))
        else:
            db_query("INSERT INTO failed_attempts VALUES (?, ?)", (username, attempts))

def get_account_lock(username):
    row = db_query("SELECT lock_until FROM account_locks WHERE username=?", (username,), fetchone=True)
    return row[0] if row else None

def set_account_lock(username, lock_until):
    if lock_until is None:
        db_query("DELETE FROM account_locks WHERE username=?", (username,))
    else:
        if db_query("SELECT 1 FROM account_locks WHERE username=?", (username,), fetchone=True):
            db_query("UPDATE account_locks SET lock_until=? WHERE username=?", (lock_until, username))
        else:
            db_query("INSERT INTO account_locks VALUES (?, ?)", (username, lock_until))

def get_ip_attempts(ip):
    row = db_query("SELECT attempts, first_attempt FROM ip_attempts WHERE ip=?", (ip,), fetchone=True)
    return row if row else (0, time.time())

def set_ip_attempts(ip, attempts, first_attempt=None):
    if attempts == 0:
        db_query("DELETE FROM ip_attempts WHERE ip=?", (ip,))
    else:
        first = first_attempt if first_attempt else time.time()
        if db_query("SELECT 1 FROM ip_attempts WHERE ip=?", (ip,), fetchone=True):
            db_query("UPDATE ip_attempts SET attempts=?, first_attempt=? WHERE ip=?", (attempts, first, ip))
        else:
            db_query("INSERT INTO ip_attempts VALUES (?, ?, ?)", (ip, attempts, first))

def log_event(event_type, username, ip, details=""):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {event_type}: user='{username}' ip={ip} {details}")

def unlock_account(username):
    set_account_lock(username, None)
    set_failed_attempts(username, 0)
    log_event("MANUAL_UNLOCK", username, "SYSTEM", "Account unlocked")
    return True

def unlock_ip(ip_address):
    set_ip_attempts(ip_address, 0)
    log_event("MANUAL_UNLOCK_IP", "SYSTEM", ip_address, "IP unlocked")
    return True

def get_system_status():
    locked_accounts = [r[0] for r in db_query("SELECT username FROM account_locks", fetch=True)]
    active_ips = [r[0] for r in db_query("SELECT ip FROM ip_attempts", fetch=True)]
    failed = {r[0]: r[1] for r in db_query("SELECT username, attempts FROM failed_attempts", fetch=True)}
    return {
        'locked_accounts': locked_accounts,
        'active_ips': active_ips,
        'failed_attempts': failed
    }

def get_client_ip():
    return request.remote_addr

def handle_unlock_account(account_username):
    if unlock_account(account_username):
        return f'<p style="color: green"> Account {account_username} unlocked!</p>'
    return ''

def handle_unlock_ip(ip_address):
    if unlock_ip(ip_address):
        return f'<p style="color: green"> IP {ip_address} unlocked!</p>'
    return ''

def handle_show_status():
    status = get_system_status()
    message = '<div style="background: #f5f5f5; padding: 10px; border-radius: 5px;">'
    message += '<h4>System Status:</h4>'
    message += f'<p><strong>Locked accounts:</strong> {", ".join(status["locked_accounts"]) or "None"}</p>'
    message += f'<p><strong>Active IPs:</strong> {", ".join(status["active_ips"]) or "None"}</p>'
    message += f'<p><strong>Failed attempts:</strong> {status["failed_attempts"]}</p>'
    message += '</div>'
    return message

def check_ip_blocked(client_ip, username, ip_count, first_ip_attempt):
    time_window = 300
    if time.time() - first_ip_attempt < time_window and ip_count >= 5:
        log_event("IP_BLOCKED", username, client_ip, f"attempts={ip_count}")
        return '<pre><br />Login failed: IP address temporarily blocked (too many attempts)</pre>'
    return None

def handle_successful_login(username, client_ip):
    set_failed_attempts(username, 0)
    set_ip_attempts(client_ip, 0)
    log_event("LOGIN_SUCCESS", username, client_ip)
    message = f'<p>Welcome to the password protected area {username}</p>'
    message += '<p>Login successful!</p>'
    return message

def handle_failed_login(username, client_ip, attempts):
    set_failed_attempts(username, attempts)
    if attempts >= 3:
        lock_time = 300 if attempts == 3 else 1800
        set_account_lock(username, time.time() + lock_time)
        log_event("ACCOUNT_BLOCKED", username, client_ip, f"attempts={attempts}, lock_time={lock_time}s")
        return f'<pre><br />Login failed: Incorrect credentials (account locked for {lock_time} seconds)</pre>'
    else:
        remaining_attempts = 3 - attempts
        log_event("LOGIN_FAILED", username, client_ip, f"attempt={attempts}/3")
        return f'<pre><br />Login failed: Incorrect credentials ({remaining_attempts} attempts remaining before lock)</pre>'


@app.route('/auth/')
def login():
    username = request.args.get('username', '').strip()
    password = request.args.get('password', '')
    account_username = request.args.get('account_username', '').strip()
    ip_address = request.args.get('ip_address', '').strip()
    client_ip = get_client_ip()
    message = ""

    if 'unlock_account' in request.args and account_username:
        message = handle_unlock_account(account_username)
        return render_template_string(HTML_TEMPLATE, message=message)

    if 'unlock_ip' in request.args and ip_address:
        message = handle_unlock_ip(ip_address)
        return render_template_string(HTML_TEMPLATE, message=message)

    if 'show_status' in request.args:
        message = handle_show_status()
        return render_template_string(HTML_TEMPLATE, message=message)

    ip_count, first_ip_attempt = get_ip_attempts(client_ip)
    ip_blocked = check_ip_blocked(client_ip, username, ip_count, first_ip_attempt)
    if ip_blocked:
        return render_template_string(HTML_TEMPLATE, message=ip_blocked)


    time.sleep(3)

    if 'Login' in request.args:
        if time.time() - first_ip_attempt > 300:
            set_ip_attempts(client_ip, 1)
            ip_count = 1
        else:
            set_ip_attempts(client_ip, ip_count + 1, first_ip_attempt)
            ip_count += 1


        lock_until = get_account_lock(username)
        if lock_until and time.time() < lock_until:
            remaining = int(lock_until - time.time())
            log_event("LOGIN_FAILED", username, client_ip, f"account_locked({remaining}s)")
            message = f'<pre><br />Login failed: Account temporarily locked ({remaining} seconds remaining)</pre>'
            return render_template_string(HTML_TEMPLATE, message=message)


        set_account_lock(username, None)
        

        stored_pw = get_user_password(username)
        if stored_pw and stored_pw == password:
            message = handle_successful_login(username, client_ip)
        else:
            attempts = get_failed_attempts(username) + 1
            message = handle_failed_login(username, client_ip, attempts)

    return render_template_string(HTML_TEMPLATE, message=message)



if __name__ == '__main__':
    init_db()
    print("http://localhost:5000/auth/")
    print("admin / admin@123")
    app.run(port=5000)
