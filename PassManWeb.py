from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
from flask_wtf.csrf import CSRFProtect, CSRFError
from secrets import token_urlsafe
from datetime import timedelta
import PassManLib as passman
import logging
import os

debug = False
localhost = True
port = 5000
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

LOG_PATH = "PassManWeb.log"
logging.basicConfig(
    filename=LOG_PATH,
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO
)

class Flash_Category:
    SUCCESS = 'flash-success'
    INFO = 'flash-info'
    ERROR = 'flash-error'
    
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


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return {"success": False, "error": "CSRF validation failed"}, 400


@app.route('/')
def default_route():
    return redirect(url_for('login_page'))


@app.route('/login', methods=['GET', 'POST'])
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
def logout():
    uid = session.get('uid', '')
    logging.info(f"Successful LOGOUT for uid={uid}")
    session.clear()
    flash('Logged out.', Flash_Category.INFO)
    return redirect(url_for('login_page'))


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard_page():
    if request.method == 'POST':
        command = request.form.get('command')
        pid = request.form.get('pid')
        masterpass = request.form.get('masterpass')
        
        if not pid:
            flash('Invalid request', Flash_Category.ERROR)
            return redirect(url_for('dashboard_page'))
        
        try:
            pid = int(pid)
        except ValueError:
            flash('Invalid request', Flash_Category.ERROR)
            return redirect(url_for('dashboard_page'))
        
        match command:
            case 'update_password':
                new_password = request.form.get('new_password')
                if not new_password:
                    flash('Please enter a new password to update.', Flash_Category.INFO)
                else:
                    success = passman.update_password(pid, masterpass, new_password)
                    if success:
                        flash('Password updated successfully!', Flash_Category.SUCCESS)
                    else:
                        flash('Could not update the password!', Flash_Category.ERROR)
            case 'delete_password':
                success = passman.delete_password(pid, masterpass)
                if success:
                    flash('Password deleted successfully!', Flash_Category.SUCCESS)
                else:
                    flash('Failed to delete the password!', Flash_Category.ERROR)
            case _:
                flash('Invalid command!', Flash_Category.ERROR)
        return redirect(url_for('dashboard_page'))
    
    search_query = request.args.get('search', '')
    uid = session.get('uid')
    entries = passman.search_passwords(uid, search_query)
    return render_template('dashboard.html', username=session.get('username'), entries=entries, search_query=search_query)


@app.route('/add_password', methods=['GET', 'POST'])
@login_required
def add_password_page():
    if request.method == 'POST':
        label = request.form.get('label')
        login = request.form.get('login')
        password = request.form.get('password')
        uid = session.get('uid')

        if passman.add_password(uid, label, login, password):
            flash('Password added successfully!', Flash_Category.SUCCESS)
        else:
            flash('Failed to add password!', Flash_Category.ERROR)
    return redirect(url_for('dashboard_page'))


@app.route('/decrypt_password', methods=['POST'])
@login_required
def decrypt_password():
    data = request.get_json()
    pid = data.get('pid')
    masterpass = data.get('masterpass')
    
    if pid is None or masterpass is None:
        return {"success": False, "error": "Invalid request"}, 400
    
    try:
        pid = int(pid)
    except ValueError:
        return {"success": False, "error": "Non-integer pid"}, 400
    
    password = passman.decrypt_password(pid, masterpass)

    if password is None:
        return {'success': False, "error": "Decryption failed"}, 400

    return {'success': True, 'password': password}


@app.route('/register', methods=['GET', 'POST'])
def registration_menu_page():
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


def main():
    logging.info("========== Starting PassManWeb ==========")
    
    if localhost:
        app.run(debug=debug)
    else:
        app.run(host="0.0.0.0", port=port, debug=debug)

if __name__ == "__main__":
    main()
