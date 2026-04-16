from flask import Flask, render_template, request, redirect, url_for, session, flash
import sys
import datetime
from datetime import timezone

sys.path.insert(0, '.')

from detector import detect_url, get_model_info, is_url_valid, normalize_url, refresh_whitelist
from database import init_db, save_scan, get_scan_history, get_statistics, verify_admin, search_scans, add_to_whitelist, get_whitelist, remove_from_whitelist

app = Flask(__name__)
app.secret_key = 'phishing_detection_secret_key_2024'

# Session configuration
app.config['SESSION_PERMANENT'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# ==========================================
# NEW SECURITY FEATURE: AUTO LOGOUT LOGIC
# ==========================================
@app.before_request
def protect_admin_session():
    """Auto logout if admin navigates to public pages."""
    # Halaman yang dianggap 'Public'
    public_endpoints = ['home', 'detect', 'about', 'result']
    
    # Jika pengguna sedang login admin TETAPI cuba akses page public
    if request.endpoint in public_endpoints and 'admin_logged_in' in session:
        session.clear() # Padam terus session
        # flash("Admin session closed for security.", "info")

def check_session():
    """Check if session is valid and not expired."""
    if 'admin_logged_in' not in session:
        return False
    
    now = datetime.datetime.now(timezone.utc)
    
    if 'last_activity' not in session:
        session['last_activity'] = now.isoformat()
        return True
    
    try:
        last_activity_raw = session.get('last_activity')
        last_activity = datetime.datetime.fromisoformat(last_activity_raw)
        
        if last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)
            
        elapsed = now - last_activity
        
        if elapsed > app.config['PERMANENT_SESSION_LIFETIME']:
            session.clear()
            return False
            
    except Exception:
        session.clear()
        return False
    
    session['last_activity'] = now.isoformat()
    return True

# Initialize database
init_db()

@app.route("/")
def home():
    return render_template("home.html")

@app.route("/detect", methods=["GET", "POST"])
def detect():
    result = None
    if request.method == "POST":
        url = request.form.get("url", "").strip()
        if url:
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            detection_result = detect_url(url)
            scan_id = save_scan(
                url=detection_result['url'],
                prediction=detection_result['prediction'],
                confidence=detection_result['confidence'],
                risk_level=detection_result['risk_level'],
                rf_prediction=detection_result['rf_prediction'],
                xgb_prediction=detection_result['xgb_prediction'],
                rule_score=detection_result['rule_score']
            )
            result = detection_result
            result['id'] = scan_id
    return render_template("index.html", result=result)

@app.route("/result/<int:scan_id>")
def result(scan_id):
    history = get_scan_history(limit=100)
    scan = next((s for s in history if s[0] == scan_id), None)
    if scan:
        result_data = {'id': scan[0], 'url': scan[1], 'prediction': scan[2], 'confidence': scan[3], 'risk_level': scan[4], 'scan_date': scan[5]}
        return render_template("result.html", result=result_data)
    return redirect(url_for('detect'))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if verify_admin(username, password):
            session.clear() # Clear any old session before new login
            session['admin_logged_in'] = True
            session['username'] = username
            session['last_activity'] = datetime.datetime.now(timezone.utc).isoformat()
            return redirect(url_for('admin'))
        else:
            error = "Invalid username or password"
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for('home'))

@app.route("/admin")
def admin():
    if not check_session():
        flash("⏰ Session expired. Please login again.", "error")
        return redirect(url_for('login'))
    stats = get_statistics()
    recent_scans = get_scan_history(limit=20)
    whitelist = get_whitelist()
    return render_template("admin.html", stats=stats, recent_scans=recent_scans, whitelist=whitelist)

# --- Routes Admin lain kekal sama ---
@app.route("/admin/search", methods=["GET", "POST"])
def admin_search():
    if not check_session(): return redirect(url_for('login'))
    results = []
    query = request.form.get("query", "").strip() if request.method == "POST" else ""
    if query: results = search_scans(query)
    return render_template("admin.html", stats=get_statistics(), recent_scans=get_scan_history(limit=20), search_results=results, search_query=query, whitelist=get_whitelist())

@app.route("/admin/whitelist/add", methods=["POST"])
def admin_whitelist_add():
    if not check_session(): return redirect(url_for('login'))
    url = request.form.get("url", "").strip()
    if url:
        is_valid, msg = is_url_valid(url)
        if is_valid:
            success, err = add_to_whitelist(url, session.get('username', 'admin'))
            if success: 
                flash(f"✅ URL added!", "success")
                refresh_whitelist()
            else: flash(f"❌ {err}", "error")
        else: flash(f"❌ {msg}", "error")
    return redirect(url_for('admin'))

@app.route("/admin/whitelist/remove/<int:whitelist_id>")
def admin_whitelist_remove(whitelist_id):
    if not check_session(): return redirect(url_for('login'))
    remove_from_whitelist(whitelist_id)
    refresh_whitelist()
    flash("✅ Removed from whitelist", "success")
    return redirect(url_for('admin'))

if __name__ == "__main__":
    app.run(debug=True, port=5000)