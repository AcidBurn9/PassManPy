from pathlib import Path
from functools import wraps
from typing import ClassVar
from dataclasses import dataclass
from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_session import Session
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect, CSRFError
from secrets import token_urlsafe
from datetime import timedelta
from PassManLib import PassMan, RegStatus
import configparser
import argparse
import logging
import os


class FlashCategory:
    SUCCESS = 'flash-success'
    INFO = 'flash-info'
    ERROR = 'flash-error'


def _get_ratelimit_target() -> str:
    uid = session.get('uid') # Target uid for logged in operations
    if uid:
        return f"uid_{uid}"
    username = request.form.get('username') # Target username for LOGIN operation
    if username:
        return f"username_{username}"
    return get_remote_address() # Fallback to IP

class RateLimit():
    MASTERPASS_RATE_LIMIT = "5 per 5 seconds"
    GLOBAL_RATE_LIMIT = "30 per 15 seconds"
    REGISTER_RATE_LIMIT = "1 per 10 seconds"
    
    limiter = Limiter(
        key_func=get_remote_address,
        storage_uri="memory://",
        strategy="fixed-window"
    )
    
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
        key_func=_get_ratelimit_target,
        exempt_when=lambda: request.method == 'GET'
    )
    MASTERPASS_TARGET_ACCOUNT.shared = True # Why is this not in the constructor, flask-limiter devs?
    
    REGISTER_POST_IP = limiter.limit(
        limit_value=REGISTER_RATE_LIMIT,
        key_func=get_remote_address,
        exempt_when=lambda: request.method == 'GET'
    )


# Auth
def set_session(uid: int, username: str):
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


def create_app(db_path: str = None) -> Flask:
    app = Flask(__name__)
    
    ENV_VAR = "FLASK_SECRET_KEY"
    key = os.environ.get(ENV_VAR) # Make sure to set this ENV variable before running the server.
    if not key:
        #key = token_urlsafe(32) # Fallback to random key if ENV variable is not set. NOT RECOMMENDED! WILL CAUSE ISSUES!
        raise RuntimeError(f"""
            
            {ENV_VAR} environment variable is not set!
            
            Make sure to generate a secure key (f.e. `python` -> `import secrets` -> `secrets.token_urlsafe(32)`)
            and store it in the {ENV_VAR} environment variable.
        """)
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
    CSRFProtect(app)
    RateLimit.limiter.init_app(app)
    
    passman = PassMan(db_path) if db_path else PassMan()
    passman.init_db()
    
    
    # Handlers
    
    
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return {"success": False, "error": "CSRF validation failed"}, 400

    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.is_json:
            return {"success": False, "error": "Too many requests."}, 429

        flash("Too many requests.", FlashCategory.ERROR)

        template_map = {
            'login_page': 'login.html',
            'register_page': 'register.html',
            'dashboard_page': 'dashboard.html'
        }

        target_template = template_map.get(request.endpoint, 'login.html')

        return render_template(target_template, error="Too many requests."), 429


    # Routes
    
    
    @app.route('/')
    @RateLimit.GLOBAL_IP
    def default_route():
        return redirect(url_for('login_page'))


    @app.route('/register', methods=['GET', 'POST'])
    @RateLimit.GLOBAL_IP
    @RateLimit.REGISTER_POST_IP
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
                    case RegStatus.FAIL:
                        flash('Registration failed!', FlashCategory.ERROR)
                    case RegStatus.TAKEN:
                        flash('Username is taken!', FlashCategory.INFO)
                    case RegStatus.SUCCESS:
                        flash('Registration successful!', FlashCategory.SUCCESS)

                        uid = passman.auth_user(username, password1)
                        if uid: return set_session(uid, username)

                        return redirect(url_for('login_page'))
            else:
                flash("Passwords don't match!", FlashCategory.ERROR)

        return render_template('register.html', username=username, password1=password1, password2=password2)


    @app.route('/login', methods=['GET', 'POST'])
    @RateLimit.GLOBAL_IP
    @RateLimit.MASTERPASS_SENDER_IP
    @RateLimit.MASTERPASS_TARGET_ACCOUNT
    def login_page():
        if session.get('uid'): return redirect(url_for('dashboard_page'))

        username = ""

        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            uid = passman.auth_user(username, password)
            if uid is None:
                flash('Authentication failed!', FlashCategory.ERROR)
            else:
                return set_session(uid, username)

        return render_template('login.html', username=username)


    @app.route('/logout')
    @RateLimit.GLOBAL_IP
    @login_required
    def logout():
        uid = session.get('uid', '')
        logging.info(f"Successful LOGOUT for uid={uid}")
        session.clear()
        flash('Logged out.', FlashCategory.INFO)
        return redirect(url_for('login_page'))


    @app.route('/dashboard', methods=['GET'])
    @RateLimit.GLOBAL_IP
    @login_required
    def dashboard_page():
        search_query = request.args.get('search', '')
        uid = session.get('uid')
        entries = passman.search_passwords(uid, search_query)
        return render_template('dashboard.html', username=session.get('username'), entries=entries, search_query=search_query)


    @app.route('/add_password', methods=['POST'])
    @RateLimit.GLOBAL_IP
    @login_required
    def add_password():
        label = request.form.get('label')
        login = request.form.get('login')
        password = request.form.get('password')
        uid = session.get('uid')
        if passman.add_password(uid, label, login, password):
            flash('Password added successfully!', FlashCategory.SUCCESS)
        else:
            flash('Failed to add password!', FlashCategory.ERROR)
        return redirect(request.referrer or url_for('dashboard_page'))


    @app.route('/decrypt_password', methods=['POST'])
    @RateLimit.MASTERPASS_SENDER_IP
    @login_required
    @RateLimit.MASTERPASS_TARGET_ACCOUNT
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
    @RateLimit.MASTERPASS_SENDER_IP
    @login_required
    @RateLimit.MASTERPASS_TARGET_ACCOUNT
    def update_password():
        pid = request.form.get('pid')

        if not pid:
            flash('Invalid request', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        try:
            pid = int(pid)
        except (ValueError, TypeError):
            flash('Invalid request', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        uid = session.get('uid')
        ownerid = passman.get_password_owner(pid)
        if uid != ownerid:
            logging.warning(f"Unauthorized UPDATE attempt from uid={uid} for pid={pid} (owner uid={ownerid})")
            flash('Failed to update the password!', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        new_password = request.form.get('new_password')

        if not new_password:
            flash('Please enter a new password to update.', FlashCategory.INFO)
        else:
            masterpass = request.form.get('masterpass')
            success = passman.update_password(pid, masterpass, new_password)
            masterpass = None
            if success:
                flash('Password updated successfully!', FlashCategory.SUCCESS)
            else:
                flash('Failed to update the password!', FlashCategory.ERROR)

        return redirect(request.referrer or url_for('dashboard_page'))


    @app.route('/delete_password', methods=['POST'])
    @RateLimit.MASTERPASS_SENDER_IP
    @login_required
    @RateLimit.MASTERPASS_TARGET_ACCOUNT
    def delete_password():
        pid = request.form.get('pid')

        if not pid:
            flash('Invalid request', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        try:
            pid = int(pid)
        except (ValueError, TypeError):
            flash('Invalid request', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        uid = session.get('uid')
        ownerid = passman.get_password_owner(pid)
        if uid != ownerid:
            logging.warning(f"Unauthorized DELETE attempt from uid={uid} for pid={pid} (owner uid={ownerid})")
            flash('Failed to delete the password!', FlashCategory.ERROR)
            return redirect(request.referrer or url_for('dashboard_page'))

        masterpass = request.form.get('masterpass')
        success = passman.delete_password(pid, masterpass)
        masterpass = None

        if success:
            flash('Password deleted successfully!', FlashCategory.SUCCESS)
        else:
            flash('Failed to delete the password!', FlashCategory.ERROR)

        return redirect(request.referrer or url_for('dashboard_page'))
    
    
    return app


@dataclass
class Config:
    DEFAULT_CONFIG_PATH: ClassVar[str] = "settings.cfg"
    DEFAULT_DEBUG: ClassVar[bool] = False
    DEFAULT_LOCALHOST: ClassVar[bool] = True
    DEFAULT_PORT: ClassVar[int] = 5000
    DEFAULT_DB_PATH: ClassVar[str] = "vault.db"
    DEFAULT_LOG_PATH: ClassVar[str] = "PassManWeb.log"

    debug: bool = DEFAULT_DEBUG
    localhost: bool = DEFAULT_LOCALHOST
    port: int = DEFAULT_PORT
    db_path: str = DEFAULT_DB_PATH
    log_path: str = DEFAULT_LOG_PATH
    
    @staticmethod
    def _create_default(path: str):
        cfg = configparser.ConfigParser()
        
        cfg["server"]   = {
            "debug": Config.DEFAULT_DEBUG,
            "localhost": Config.DEFAULT_LOCALHOST,
            "port": Config.DEFAULT_PORT
        }
        cfg["database"] = {"path": Config.DEFAULT_DB_PATH}
        cfg["logging"]  = {"path": Config.DEFAULT_LOG_PATH}
        
        with open(path, "w") as f:
            cfg.write(f)

    @staticmethod
    def parse_file(path: str) -> "Config":
        if not Path(path).exists():
            Config._create_default(path)
            return Config()
        
        cfg = configparser.ConfigParser()
        cfg.read(path)
        return Config(
            debug = cfg.getboolean("server", "debug", fallback=Config.DEFAULT_DEBUG),
            localhost = cfg.getboolean("server", "localhost", fallback=Config.DEFAULT_LOCALHOST),
            port = cfg.getint("server", "port", fallback=Config.DEFAULT_PORT),
            db_path = cfg.get("database", "path", fallback=Config.DEFAULT_DB_PATH),
            log_path = cfg.get("logging", "path", fallback=Config.DEFAULT_LOG_PATH)
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default=Config.DEFAULT_CONFIG_PATH, help = f"Path to the configuration file (Default: {Config.DEFAULT_CONFIG_PATH})")
    parser.add_argument("--debug", default=None, action="store_true", help = f"Runs Flask in debug mode")
    parser.add_argument("--localhost", default=None, action="store_true", help = f"Server will only be visible on localhost")
    parser.add_argument("--port", default=None, type=int, help = f"Port for Flask to listen on (Default: {Config.DEFAULT_PORT})")
    parser.add_argument("--db", default=None, help = f"Path to the vault database file (Default: {Config.DEFAULT_DB_PATH})")
    parser.add_argument("--log", default=None, help = f"Destination path for logs (Default: {Config.DEFAULT_LOG_PATH})")
    
    args = parser.parse_args()
    config = Config.parse_file(args.config)
    
    # Passed arguments take precedence over the configuration file
    if args.debug is not None: config.debug = args.debug
    if args.localhost is not None: config.localhost = args.localhost
    if args.port is not None: config.port = args.port
    if args.db is not None: config.db_path = args.db
    if args.log is not None: config.log_path = args.log
    
    logging.basicConfig(
        filename=config.log_path,
        filemode="a",
        format="%(asctime)s [%(levelname)s] %(message)s",
        level=logging.INFO
    )
    logging.info("========== Starting PassManWeb ==========")
    
    app = create_app(config.db_path)
    host = "127.0.0.1" if config.localhost else "0.0.0.0"
    
    app.run(host=host, port=config.port, debug=config.debug)

if __name__ == "__main__":
    main()
