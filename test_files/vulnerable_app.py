import sqlite3
import os
import hashlib
import pickle
import base64
import subprocess
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect, url_for, session, make_response

app = Flask(__name__)

app.secret_key = "production_secret_key_12345"
DB_NAME = "enterprise.db"
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            ssn TEXT,
            salary INTEGER
        )
    ''')
    
    admin_pass = hashlib.md5("admin123".encode()).hexdigest()
    user_pass = hashlib.md5("guest123".encode()).hexdigest()
    
    try:
        cursor.execute(f"INSERT INTO users (username, password, role, ssn, salary) VALUES ('admin', '{admin_pass}', 'admin', '123-45-6789', 95000)")
        cursor.execute(f"INSERT INTO users (username, password, role, ssn, salary) VALUES ('jdoe', '{user_pass}', 'user', '987-65-4321', 45000)")
        conn.commit()
    except:
        pass
    conn.close()

init_db()

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        hashed_password = hashlib.md5(password.encode()).hexdigest()
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + hashed_password + "'"
        
        try:
            cursor.execute(query)
            user = cursor.fetchone()
            conn.close()
        except Exception as e:
            return f"Database Error: {str(e)}", 500

        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            resp = make_response(redirect(url_for('dashboard')))
            resp.set_cookie('user_role', user['role'])
            return resp
        else:
            error = "Invalid credentials"
            
    return f"""
    <html>
    <head><title>Login</title></head>
    <body>
        <h2>Enterprise Login</h2>
        <p style="color:red">{error if error else ''}</p>
        <form method="POST">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Login">
        </form>
    </body>
    </html>
    """

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    username = session['username']
    
    return f"""
    <html>
    <body>
        <h1>Welcome, {username}</h1>
        <nav>
            <a href="/profile?id={session['user_id']}">My Profile</a> |
            <a href="/search">Search Users</a> |
            <a href="/tools/ping">Network Tools</a> |
            <a href="/admin/logs">System Logs</a> |
            <a href="/import">Import Config</a> |
            <a href="/api/xml">XML Processor</a>
        </nav>
    </body>
    </html>
    """

@app.route('/search')
def search():
    query = request.args.get('q', '')
    results = []
    if query:
        conn = get_db_connection()
        cursor = conn.cursor()
        sql = f"SELECT username FROM users WHERE username LIKE '%{query}%'"
        cursor.execute(sql)
        results = cursor.fetchall()
        conn.close()
    
    result_html = ""
    for r in results:
        result_html += f"<li>{r[0]}</li>"

    return f"""
    <html>
    <body>
        <h2>User Search</h2>
        <form>
            Search: <input type="text" name="q" value="{query}">
            <input type="submit" value="Go">
        </form>
        <p>Results for <b>{query}</b>:</p>
        <ul>{result_html}</ul>
        <a href="/dashboard">Back</a>
    </body>
    </html>
    """

@app.route('/profile')
def profile():
    user_id = request.args.get('id')
    if not user_id:
        return "Missing ID"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT username, role, ssn, salary FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    conn.close()

    if user:
        return f"""
        <h2>User Profile</h2>
        <p>Username: {user['username']}</p>
        <p>Role: {user['role']}</p>
        <p>SSN: {user['ssn']}</p>
        <p>Salary: ${user['salary']}</p>
        """
    return "User not found"

@app.route('/tools/ping', methods=['GET', 'POST'])
def ping_tool():
    output = ""
    if request.method == 'POST':
        target = request.form.get('target')
        cmd = "ping -c 3 " + target
        try:
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            output = output.decode('utf-8')
        except subprocess.CalledProcessError as e:
            output = e.output.decode('utf-8')
    
    return f"""
    <h2>Network Diagnostic Tool</h2>
    <form method="POST">
        Target IP/Host: <input type="text" name="target">
        <input type="submit" value="Ping">
    </form>
    <pre>{output}</pre>
    """

@app.route('/admin/logs')
def view_logs():
    log_file = request.args.get('file')
    if not log_file:
        return "Please specify a file parameter"
    
    try:
        with open(log_file, 'r') as f:
            content = f.read()
        return f"<pre>{content}</pre>"
    except Exception as e:
        return f"Error reading file: {str(e)}"

@app.route('/import', methods=['GET', 'POST'])
def import_config():
    message = ""
    if request.method == 'POST':
        config_data = request.form.get('config')
        try:
            decoded = base64.b64decode(config_data)
            obj = pickle.loads(decoded)
            message = f"Configuration loaded for: {obj}"
        except Exception as e:
            message = "Import failed"

    return f"""
    <h2>Import System Configuration</h2>
    <form method="POST">
        Base64 Config: <textarea name="config"></textarea>
        <input type="submit" value="Upload">
    </form>
    <p>{message}</p>
    """

@app.route('/api/xml', methods=['GET', 'POST'])
def process_xml():
    result = ""
    if request.method == 'POST':
        xml_data = request.data
        try:
            parser = ET.XMLParser()
            tree = ET.fromstring(xml_data, parser=parser)
            if tree.find('content') is not None:
                result = tree.find('content').text
        except Exception as e:
            result = str(e)
            
    return f"""
    <h2>XML API Endpoint</h2>
    <p>Post raw XML data to this endpoint.</p>
    <p>Last processed: {result}</p>
    """

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)