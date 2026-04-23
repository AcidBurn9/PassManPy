from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from secrets import token_urlsafe
from datetime import timedelta
import PassManLib as passman
import logging
import os


#----------
#   INIT
#----------


# Config
debug = False
localhost = True # True - server hosted only on 127.0.0.1, False - server is publically accessible.
port = 5000
MASTERPASS_RATE_LIMIT = "5 per 5 seconds"
GLOBAL_RATE_LIMIT = "30 per 15 seconds"

# Flask init
app = Flask(__name__)
key = os.environ.get("FLASK_SECRET_KEY") # Make sure to set this ENV variable before running the server.
if not key:
    #key = token_urlsafe(32) # Fallback to random key if ENV variable is not set. NOT RECOMMENDED! WILL CAUSE ISSUES!
    raise RuntimeError("FLASK_SECRET_KEY env variable is not set!")
app.secret_key = key
app.config.update(
    SESSION_TYPE="filesystem", # Crossplatform unlike "redis" which lacks proper Windows support
    SESSION_PERMANENT=True,
    PERMANENT_SESSION_LIFETIME = timedelta(hours=2),
    SESSION_COOKIE_HTTPONLY=True,
    #SESSION_COOKIE_SECURE=True, # TLS is not set up yet.
    SESSION_COOKIE_SAMESITE="Lax",
)
Session(app)
csrf = CSRFProtect(app)


# Rate limiter init
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    storage_uri="memory://",
    strategy="fixed-window"
)


# Logging init
LOG_PATH = "PassManWeb.log"
logging.basicConfig(
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)


#--------------------------
#   HELPERS / DECORATORS
#--------------------------


class Flash_Category:
    SUCCESS = 'flash-success'
    INFO = 'flash-info'
    ERROR = 'flash-error'


# Rate limits
def get_ratelimit_target():
    pid = request.form.get('pid') # Target pid for DELETE / UPDATE operations
    if pid is None and request.is_json:
        pid = request.get_json().get('pid') # Target pid for DECRYPT operation

    if pid:
        try:
            uid = passman.get_password_owner(int(pid))
            if uid:
                return f"target_uid_{uid}"
        except (ValueError, TypeError):
            pass # Failed to identify target uid. Falling back to other means.

    username = request.form.get('username') # Target username for LOGIN operation
    if username:
        return f"target_username_{username}"

    return get_remote_address() # Fallback to IP

class RateLimit():
    GLOBAL_IP = limiter.limit(
        limit_value=GLOBAL_RATE_LIMIT,
        scope='global',
        key_func=get_remote_address
    )
    GLOBAL_IP.shared = True # Why is this not in the constructor, flask-limiter devs?
    
    MASTERPASS_SENDER_IP = limiter.limit(
        limit_value=MASTERPASS_RATE_LIMIT,
        scope='masterpass_sender_ip',
        key_func=get_remote_address,
        exempt_when=lambda: request.method == 'GET'
    )
    MASTERPASS_SENDER_IP.shared = True # Why is this not in the constructor, flask-limiter devs?
    
    MASTERPASS_TARGET_ACCOUNT = limiter.limit(
        limit_value=MASTERPASS_RATE_LIMIT,
        scope='masterpass_target_account',
        key_func=get_ratelimit_target,
        exempt_when=lambda: request.method == 'GET'
    )
    MASTERPASS_TARGET_ACCOUNT.shared = True # Why is this not in the constructor, flask-limiter devs?


# Auth
def login(uid: int, username: str):
    session['uid'] = uid
    session['username'] = username
    return redirect(url_for('dashboard_page'))

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if session.get('uid') is None:
            return redirect(url_for('login_page'))
        return view(*args, **kwargs)
    return wrapped_view


# Handlers
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return {"success": False, "error": "CSRF validation failed"}, 400

@app.errorhandler(429)
def ratelimit_handler(e):
    if request.is_json:
        return {"success": False, "error": "Too many requests."}, 429
    
    flash("Too many requests.", Flash_Category.ERROR)
    
    template_map = {
        'login_page': 'login.html',
        'register_page': 'register.html',
        'dashboard_page': 'dashboard.html'
    }
    
    target_template = template_map.get(request.endpoint, 'login.html')
    
    return render_template(target_template, error="Too many requests."), 429


#-------------
#   ROUTES
#-------------


@app.route('/')
@RateLimit.GLOBAL_IP
def default_route():
    return redirect(url_for('login_page'))


@app.route('/register', methods=['GET', 'POST'])
@RateLimit.GLOBAL_IP
def register_page():
    if session.get('uid'): return redirect(url_for('dashboard_page'))
    username = password1 = password2 = ''
    
    if request.method == 'POST':
        username = request.form['username']
        password1 = request.form['password1']
        password2 = request.form['password2']
        if password1 == password2:
            status = passman.create_user(username, password1)
            match status:
                case passman.Reg_Status.FAIL:
                    flash('Registration failed!', Flash_Category.ERROR)
                case passman.Reg_Status.TAKEN:
                    flash('Username is taken!', Flash_Category.INFO)
                case passman.Reg_Status.SUCCESS:
                    flash('Registration successful!', Flash_Category.SUCCESS)
                    
                    uid = passman.auth_user(username, password1)
                    if uid: return login(uid, username)
                    
                    return redirect(url_for('login_page'))
        else:
            flash("Passwords don't match!", Flash_Category.ERROR)

    return render_template('register.html', username=username, password1=password1, password2=password2)


@app.route('/login', methods=['GET', 'POST'])
@RateLimit.MASTERPASS_TARGET_ACCOUNT
@RateLimit.MASTERPASS_SENDER_IP
@RateLimit.GLOBAL_IP
def login_page():
    if session.get('uid'): return redirect(url_for('dashboard_page'))
    
    username = ""
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        uid = passman.auth_user(username, password)
        if uid is None:
            flash('Authentication failed!', Flash_Category.ERROR)
        else:
            return login(uid, username)
    
    return render_template('login.html', username=username)


@app.route('/logout')
@login_required
@RateLimit.GLOBAL_IP
def logout():
    uid = session.get('uid', '')
    logging.info(f"Successful LOGOUT for uid={uid}")
    session.clear()
    flash('Logged out.', Flash_Category.INFO)
    return redirect(url_for('login_page'))


@app.route('/dashboard', methods=['GET'])
@login_required
@RateLimit.GLOBAL_IP
def dashboard_page():
    search_query = request.args.get('search', '')
    uid = session.get('uid')
    entries = passman.search_passwords(uid, search_query)
    return render_template('dashboard.html', username=session.get('username'), entries=entries, search_query=search_query)


@app.route('/add_password', methods=['POST'])
@login_required
@RateLimit.GLOBAL_IP
def add_password():
    label = request.form.get('label')
    login = request.form.get('login')
    password = request.form.get('password')
    uid = session.get('uid')
    if passman.add_password(uid, label, login, password):
        flash('Password added successfully!', Flash_Category.SUCCESS)
    else:
        flash('Failed to add password!', Flash_Category.ERROR)
    return redirect(request.referrer or url_for('dashboard_page'))


@app.route('/decrypt_password', methods=['POST'])
@RateLimit.MASTERPASS_TARGET_ACCOUNT
@login_required
@RateLimit.MASTERPASS_SENDER_IP
def decrypt_password():
    data = request.get_json()
    pid = data.get('pid')
    masterpass = data.get('masterpass')
    
    if pid is None or masterpass is None or not isinstance(masterpass, str):
        return {"success": False, "error": "Invalid request"}, 400
    
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        return {"success": False, "error": "Non-integer pid"}, 400
    
    uid = session.get('uid')
    ownerid = passman.get_password_owner(pid)
    if uid != ownerid:
        logging.warning(f"Unauthorized DECRYPT attempt from uid={uid} for pid={pid} (owner uid={ownerid})")
        return {"success": False, "error": "Unauthorized access"}, 403
    
    password = passman.decrypt_password(pid, masterpass)
    masterpass = None

    if password is None:
        return {'success': False, "error": "Decryption failed"}, 400

    return {'success': True, 'password': password}


@app.route('/update_password', methods=['POST'])
@RateLimit.MASTERPASS_TARGET_ACCOUNT
@login_required
@RateLimit.MASTERPASS_SENDER_IP
def update_password():
    pid = request.form.get('pid')
    
    if not pid:
        flash('Invalid request', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        flash('Invalid request', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    uid = session.get('uid')
    ownerid = passman.get_password_owner(pid)
    if uid != ownerid:
        logging.warning(f"Unauthorized UPDATE attempt from uid={uid} for pid={pid} (owner uid={ownerid})")
        flash('Failed to update the password!', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    new_password = request.form.get('new_password')
    
    if not new_password:
        flash('Please enter a new password to update.', Flash_Category.INFO)
    else:
        masterpass = request.form.get('masterpass')
        success = passman.update_password(pid, masterpass, new_password)
        masterpass = None
        if success:
            flash('Password updated successfully!', Flash_Category.SUCCESS)
        else:
            flash('Failed to update the password!', Flash_Category.ERROR)
    
    return redirect(request.referrer or url_for('dashboard_page'))


@app.route('/delete_password', methods=['POST'])
@RateLimit.MASTERPASS_TARGET_ACCOUNT
@login_required
@RateLimit.MASTERPASS_SENDER_IP
def delete_password():
    pid = request.form.get('pid')
    
    if not pid:
        flash('Invalid request', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    try:
        pid = int(pid)
    except (ValueError, TypeError):
        flash('Invalid request', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    uid = session.get('uid')
    ownerid = passman.get_password_owner(pid)
    if uid != ownerid:
        logging.warning(f"Unauthorized DELETE attempt from uid={uid} for pid={pid} (owner uid={ownerid})")
        flash('Failed to delete the password!', Flash_Category.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))
    
    masterpass = request.form.get('masterpass')
    success = passman.delete_password(pid, masterpass)
    masterpass = None
    
    if success:
        flash('Password deleted successfully!', Flash_Category.SUCCESS)
    else:
        flash('Failed to delete the password!', Flash_Category.ERROR)
    
    return redirect(request.referrer or url_for('dashboard_page'))


#----------
#   MAIN
#----------


def main():
    logging.info("========== Starting PassManWeb ==========")
    
    if localhost:
        app.run(debug=debug)
    else:
        app.run(host="0.0.0.0", port=port, debug=debug)

if __name__ == "__main__":
    main()
