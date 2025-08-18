
# Import your Flask app and give it an alias
import os
import random
import string
import re
import uuid
import secrets
import time
import hashlib
import logging
import requests
from io import BytesIO
from urllib.parse import urlparse
from functools import wraps
from datetime import timedelta, date, timezone, datetime
from datetime import datetime, UTC
from flask import (
    Flask,
    request,
    render_template,
    redirect,
    url_for,
    flash,
    session,
    jsonify,
    send_from_directory,
    abort,
    g,
    current_app,
    json,
)
from flask_bcrypt import Bcrypt
from flask_mail import Mail, Message
from flask_login import (
    LoginManager,
    UserMixin,
    login_user,
    logout_user,
    current_user,
    login_required,
)
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.utils import secure_filename
from werkzeug.security import check_password_hash, generate_password_hash
from PIL import Image
from flask_apscheduler import APScheduler
from dotenv import load_dotenv
from firebase_functions import https_fn
import firebase_admin
from firebase_admin import credentials, storage,  firestore, auth, exceptions, initialize_app
from firebase_admin.exceptions import FirebaseError
from google.cloud.firestore_v1.base_query import FieldFilter, BaseCompositeFilter
from google.cloud.firestore_v1 import Increment
import boto3
from botocore.exceptions import ClientError

from authlib.integrations.flask_client import OAuth

from firebase_functions import https_fn
from google.cloud import firestore
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from botocore.exceptions import ClientError
import boto3
import re

from google.cloud import firestore as gcp_firestore
from google.oauth2 import service_account
from firebase_admin import credentials, firestore as admin_firestore, initialize_app
import tempfile


 

# --------------------
# Firebase Initialization
# --------------------

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'Jamiecoo15012004')

bcrypt = Bcrypt(app)
mail = Mail(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'warning'
oauth = OAuth(app)

try:
    raw_json = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if not raw_json:
        raise ValueError("FIREBASE_CREDENTIALS_JSON environment variable not set.")

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as temp:
        temp.write(raw_json)
        temp.flush()
        temp_path = temp.name

    cred = credentials.Certificate(temp_path)
    initialize_app(cred, {'storageBucket': 'schomart-7a743.appspot.com'})
    admin_db = admin_firestore.client()
    
    # Initialize Cloud Storage
    cloud_storage = storage.bucket()

except Exception as e:
    logging.error(f"Failed to initialize Firebase: {e}")
    raise RuntimeError("Firebase initialization failed. Check your credentials and environment setup.")
finally:
    if 'temp_path' in locals() and os.path.exists(temp_path):
        os.remove(temp_path)

logger = logging.getLogger(__name__)

# Note: Local file storage configurations are now obsolete, but kept for context.
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'mp3', 'wav', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

# --------------------
# Firebase Authentication and Firestore API Endpoints
# --------------------

@app.route('/api/signup', methods=['POST'])
def api_signup():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    username = data.get('username')

    if not email or not password or not username:
        return jsonify({'error': 'Missing email, password, or username'}), 400

    try:
        # Create user in Firebase Auth
        user = auth.create_user(email=email, password=password)
        
        # Save additional user data to Firestore
        user_ref = admin_db.collection('users').document(user.uid)
        user_ref.set({
            'username': username,
            'email': email,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        
        # This is where we would send a verification email, but the frontend SDK handles it.
        # For a backend-only approach, we would use auth.generate_email_verification_link()
        
        return jsonify({
            'message': 'User created successfully.',
            'uid': user.uid
        }), 201

    except auth.EmailAlreadyExistsError:
        return jsonify({'error': 'Email already in use.'}), 409
    except Exception as e:
        logger.error(f"Signup error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to create user.'}), 500


@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    id_token = data.get('idToken')

    if not id_token:
        return jsonify({'error': 'Missing ID token'}), 400

    try:
        # Verify the ID token sent from the frontend
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        user_doc = admin_db.collection('users').document(uid).get()
        
        if not user_doc.exists:
            # This is an edge case, but good to handle
            return jsonify({'error': 'User data not found in Firestore'}), 404

        return jsonify({
            'message': 'Login successful',
            'uid': uid,
            'username': user_doc.get('username')
        }), 200

    except Exception as e:
        logger.error(f"Login error: {e}", exc_info=True)
        return jsonify({'error': 'Invalid ID token'}), 401


@app.route('/api/update-password', methods=['POST'])
def api_update_password():
    data = request.get_json()
    id_token = data.get('idToken')
    new_password = data.get('newPassword')

    if not id_token or not new_password:
        return jsonify({'error': 'Missing ID token or new password'}), 400
    
    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        
        auth.update_user(uid, password=new_password)
        
        return jsonify({'message': 'Password updated successfully'}), 200
        
    except auth.AuthError as e:
        logger.error(f"Password update error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to update password'}), 400
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


@app.route('/api/update-email', methods=['POST'])
def api_update_email():
    data = request.get_json()
    id_token = data.get('idToken')
    new_email = data.get('newEmail')

    if not id_token or not new_email:
        return jsonify({'error': 'Missing ID token or new email'}), 400

    try:
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        
        auth.update_user(uid, email=new_email)

        # Update Firestore as well for data consistency
        user_ref = admin_db.collection('users').document(uid)
        user_ref.update({'email': new_email})
        
        # Note: The email verification link is usually sent by the frontend SDK
        # after a successful update, or you can send it from here as well.
        # auth.generate_email_verification_link()

        return jsonify({'message': 'Email updated successfully'}), 200

    except auth.EmailAlreadyExistsError:
        return jsonify({'error': 'This email is already in use by another account'}), 409
    except auth.AuthError as e:
        logger.error(f"Email update error: {e}", exc_info=True)
        return jsonify({'error': 'Failed to update email'}), 400
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=True)
        return jsonify({'error': 'Internal server error'}), 500


# --------------------
# Cloud Storage File Upload API Endpoint
# --------------------

@app.route('/api/upload-file', methods=['POST'])
def api_upload_file():
    # Example to get ID token from headers (best practice)
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({'error': 'Unauthorized'}), 401
    
    id_token = auth_header.split('Bearer ')[1]
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
    
    file = request.files['file']
    file_type = request.form.get('file_type', 'media') # Default to media
    
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_file(file.filename):
        try:
            decoded_token = auth.verify_id_token(id_token)
            uid = decoded_token['uid']
            original_filename = secure_filename(file.filename)
            file_extension = os.path.splitext(original_filename)[1]
            unique_filename = f"{uid}/{file_type}/{uuid.uuid4().hex}{file_extension}"
            
            # Create a blob and upload the file
            blob = cloud_storage.blob(unique_filename)
            blob.upload_from_file(file, content_type=file.content_type)
            
            # Make the file publicly accessible
            blob.make_public()
            public_url = blob.public_url

            return jsonify({
                'message': 'File uploaded successfully',
                'file_url': public_url
            }), 201

        except Exception as e:
            logger.error(f"File upload error: {e}", exc_info=True)
            return jsonify({'error': 'Failed to upload file'}), 500
    
    return jsonify({'error': 'Invalid file type'}), 400








# Assuming 'admin_db' and 'app' are already initialized.
# from your_firebase_setup import admin_db, app
# from flask_login import LoginManager

# --- Helper Functions ---

def get_client_ip():
    """Attempts to get the client's IP address, handling proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr

def get_device_fingerprint_hash(device_data_json):
    """
    Generates a consistent SHA256 hash from collected device data (JSON string).
    """
    if not device_data_json:
        return None
    try:
        device_data_dict = json.loads(device_data_json)
        canonical_json = json.dumps(device_data_dict, sort_keys=True)
        return hashlib.sha256(canonical_json.encode('utf-8')).hexdigest()
    except json.JSONDecodeError:
        logging.error(f"Invalid device fingerprint data JSON: {device_data_json}")
        return None

def record_behavioral_log(user_id, action, additional_info=None):
    """
    Records behavioral data to Firestore.
    """
    device_hash = request.form.get('device_fingerprint_hash', 'unknown')
    log_entry = {
        "timestamp": datetime.now(timezone.utc),
        "user_id": user_id,
        "action": action,
        "ip_address": getattr(g, 'client_ip', 'unknown'),
        "device_hash": device_hash,
        "additional_info": additional_info
    }
    logging.info(f"BEHAVIORAL_LOG: {json.dumps(log_entry, default=str)}")
    
    try:
        admin_db.collection('behavioral_logs').add(log_entry)
    except Exception as e:
        logging.error(f"Error saving behavioral log to Firestore: {e}")

def is_suspicious_behavior(user_id, ip_address, device_hash):
    """
    Analyzes behavioral data from Firestore for suspicious activity.
    """
    logging.info(f"Performing behavioral analysis for user {user_id} from IP {ip_address} with device {device_hash}")
    
    try:
        # Rule 1: Too many failed login attempts from this IP recently
        time_limit = datetime.now(timezone.utc) - timedelta(minutes=10)
        failed_attempts_query = admin_db.collection('behavioral_logs').where(
            'ip_address', '==', ip_address
        ).where(
            'action', '==', 'login_failed'
        ).where(
            'timestamp', '>', time_limit
        ).stream()
        
        failed_attempts_count = len(list(failed_attempts_query))
        if failed_attempts_count > 5:
            logging.warning(f"Suspicious behavior: IP {ip_address} has {failed_attempts_count} recent failed login attempts.")
            return True
        
        # Rule 2: Multiple registrations from the same IP very recently
        time_limit = datetime.now(timezone.utc) - timedelta(hours=1)
        recent_registrations_query = admin_db.collection('behavioral_logs').where(
            'ip_address', '==', ip_address
        ).where(
            'action', '==', 'registration_success'
        ).where(
            'timestamp', '>', time_limit
        ).stream()
        
        recent_registrations_count = len(list(recent_registrations_query))
        if recent_registrations_count > 2:
            logging.warning(f"Suspicious behavior: IP {ip_address} has {recent_registrations_count} recent registrations.")
            return True
            
    except Exception as e:
        logging.error(f"Error during behavioral analysis: {e}")
    return False

# --- Before Request: Set IP Address for all requests ---

@app.before_request
def before_request_func():
    g.client_ip = get_client_ip()

# --- Security Headers ---

@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

# --- User Class and Flask-Login Integration ---

class User(UserMixin):
    """
    User data model and Flask-Login integration.
    This class now handles both data representation and Flask-Login methods.
    """
    def __init__(self, **kwargs):
        self.id = str(kwargs.get('id'))
        self.username = kwargs.get('username', '')
        self.email = kwargs.get('email', '')
        self.profile_picture = kwargs.get('profile_picture')
        self.cover_photo = kwargs.get('cover_photo')
        self.location = kwargs.get('location', '')
        self.referral_code = kwargs.get('referral_code', '')
        self.first_name = kwargs.get('first_name', '')
        self.last_name = kwargs.get('last_name', '')
        self.birthday = kwargs.get('birthday')
        self.sex = kwargs.get('sex', '')
        self.created_at = kwargs.get('created_at')
        self.last_active = kwargs.get('last_active')
        self.referral_count = kwargs.get('referral_count', 0)
        self.is_verified = bool(kwargs.get('is_verified', False))
        self.is_admin = bool(kwargs.get('is_admin', False))
        self.is_referral_verified = bool(kwargs.get('is_referral_verified', False))
        self.last_referral_verification_at = kwargs.get('last_referral_verification_at')
        self.businessname = kwargs.get('businessname', '')
        self.phone_number = kwargs.get('phone_number', '')
        self.verified_phone = bool(kwargs.get('verified_phone', False))
        self.last_email_otp_sent_at = kwargs.get('last_email_otp_sent_at')
        self.email_code_expiry = kwargs.get('email_code_expiry')
        self.token_created_at = kwargs.get('token_created_at')
        self.is_online = bool(kwargs.get('is_online', False))
        self.last_online = kwargs.get('last_online')
        self.social_links = kwargs.get('social_links') if isinstance(kwargs.get('social_links'), dict) else {}
        self.working_days = kwargs.get('working_days') if isinstance(kwargs.get('working_days'), list) else []
        self.working_times = kwargs.get('working_times') if isinstance(kwargs.get('working_times'), dict) else {}
        self.delivery_methods = kwargs.get('delivery_methods') if isinstance(kwargs.get('delivery_methods'), list) else []

        # Format timestamps and dates
        for key in [
            'created_at', 'last_active', 'last_referral_verification_at',
            'last_email_otp_sent_at', 'email_code_expiry', 'token_created_at', 'last_online'
        ]:
            value = getattr(self, key)
            if isinstance(value, datetime):
                setattr(self, key, value.replace(tzinfo=None).strftime('%Y-%m-%d %H:%M:%S'))
        
        if isinstance(self.birthday, datetime):
            self.birthday = self.birthday.replace(tzinfo=None).strftime('%Y-%m-%d')
        
        # Image URLs (assuming helper functions exist)
        try:
            # Placeholder for image URL retrieval
            self.profile_picture_url = f"/static/images/{self.profile_picture}"
        except Exception:
            self.profile_picture_url = "/static/default_avatar.png"

        try:
            # Placeholder for image URL retrieval
            self.cover_photo_url = f"/static/images/{self.cover_photo}"
        except Exception:
            self.cover_photo_url = "/static/default_cover.png"

    def get_id(self):
        """Required by Flask-Login to get the user's ID."""
        return self.id

    @staticmethod
    def get(user_id):
        """
        Retrieves a user document from Firestore and returns a User object.
        """
        if not user_id:
            return None
        try:
            user_ref = admin_db.collection('users').document(str(user_id))
            user_doc = user_ref.get()
            if user_doc.exists:
                user_data = user_doc.to_dict()
                user_data['id'] = user_doc.id
                return User(**user_data)
            return None
        except Exception as e:
            current_app.logger.error(f"Error fetching user by ID {user_id}: {e}", exc_info=True)
            return None

    @staticmethod
    def update_online_status(user_id, status):
        """
        Updates the user's online status in Firestore.
        """
        try:
            user_ref = admin_db.collection('users').document(str(user_id))
            user_ref.update({
                'is_online': status,
                'last_online': firestore.SERVER_TIMESTAMP
            })
            current_app.logger.info(f"User {user_id} online status set to {status}")
        except Exception as e:
            current_app.logger.error(f"Error updating online status for user {user_id}: {e}", exc_info=True)

# --- Flask-Login User Loader ---

@login_manager.user_loader
def load_user(user_id):
    """
    Loads a user from the database based on their user ID.
    This function is required by Flask-Login.
    """
    logging.info(f"Attempting to load user with ID: {user_id}")
    return User.get(user_id)







#--- Referral Code Generator ---
def generate_referral_code(length=8):
    """Generates a random alphanumeric referral code."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))





@app.route('/signup')
def signup():
    return render_template('signup.html')

@app.route('/login')
def login():
    return render_template('login.html')









        







@app.route('/logout')
@login_required
def logout():
    """
    Logs the user out.
    """
    # Set the user's online status to False upon logout
    User.update_online_status(current_user.id, False)

    logout_user()
    flash("You have been logged out.", "success")
    return redirect(url_for('home')) 
# --- Application Context Processor for Templates ---
@app.context_processor
def inject_user_into_templates():
    # This makes 'g.user' available as 'current_user' in all templates
    return {'current_user': g.user}

@app.before_request
def load_logged_in_user():
    user_id = session.get('user_id')
    g.user = None # Initialize g.user to None for every request

    if user_id is not None:
        g.user = User.get(user_id)
    g.client_ip = request.remote_addr






# --- Helper Functions for URLs (Ensure they construct paths correctly) ---
def get_profile_picture_url(profile_picture_filename_str):
    if profile_picture_filename_str:
        # Assumes profile_picture_filename_str is ONLY the filename (e.g., 'abc.jpg')
        return url_for('static', filename=f'uploads/profile_pictures/{profile_picture_filename_str}')
    else:
        return url_for('static', filename='images/default_profile.png')

def get_cover_photo_url(cover_photo_filename_str):
    if cover_photo_filename_str:
        # Assumes cover_photo_filename_str is ONLY the filename
        return url_for('static', filename=f'uploads/cover_photos/{cover_photo_filename_str}')
    return url_for('static', filename='images/no-photo-selected.png')




@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    # POST request to update the profile
    if request.method == 'POST':
        try:
            # Get data from the form
            first_name = request.form.get('first_name')
            last_name = request.form.get('last_name')
            email = request.form.get('email')
            location = request.form.get('location')
            birthday_str = request.form.get('birthday')
            birthday = datetime.strptime(birthday_str, '%Y-%m-%d').date() if birthday_str else None
            sex = request.form.get('sex')
            
            # Use g.user.id, which should be a string (the Firestore document ID)
            user_id_str = g.user.id 

            # Validate email format
            if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
                flash("Invalid email format.", "error")
                return redirect(url_for('profile'))

            # Check for existing email in Firestore, excluding the current user's document
            users_ref = db.collection('users')
            query = users_ref.where('email', '==', email).stream()
            
            email_exists = False
            for doc in query:
                if doc.id != user_id_str:
                    email_exists = True
                    break
            
            if email_exists:
                flash("Email already registered by another user.", "error")
                return redirect(url_for('profile'))

            # Prepare the data for the Firestore update
            update_data = {
                'first_name': first_name,
                'last_name': last_name,
                'email': email,
                'location': location,
                'birthday': birthday,
                'sex': sex,
                'updated_at': firestore.SERVER_TIMESTAMP
            }

            # Update the user's document in Firestore
            user_ref = db.collection('users').document(user_id_str)
            user_ref.update(update_data)
            
            flash("Profile updated successfully.", "success")
            record_behavioral_log(user_id_str, 'profile_update', {'ip': g.client_ip if 'client_ip' in g else 'N/A'})
            return redirect(url_for('profile'))

        except Exception as e:
            current_app.logger.error(f"Error in profile POST route for user {g.user.id}: {e}", exc_info=True)
            flash("An error occurred updating your profile. Please try again.", "danger")
            return redirect(url_for('home'))

    # GET request to display the profile
    else: 
        try:
            # g.user is loaded by the @login_required decorator
            if not g.user:
                flash("User profile not found.", "danger")
                return redirect(url_for('home'))

            # Construct the referral link
            referral_link = url_for('signup', ref=g.user.referral_code, _external=True)

            full_location = g.user.location if hasattr(g.user, 'location') and g.user.location else "Not set"

            return render_template('profile.html', user=g.user, referral_link=referral_link, full_location=full_location)

        except Exception as e:
            current_app.logger.error(f"Error in profile GET route for user {g.user.id}: {e}", exc_info=True)
            flash("An error occurred loading your profile. Please try again.", "danger")
            return redirect(url_for('home'))




@app.route("/profile/personal", methods=["GET", "POST"])
@login_required
def personal_details():
    user_id = g.user.id # Assuming 'g.user' object has an 'id' attribute from Flask-Login or similar

    # Get a reference to the user's Firestore document
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    # If the user document doesn't exist, handle it gracefully
    if not user_doc.exists:
        flash("User data not found in Firestore. Please create a profile.", "danger")
        return redirect(url_for('profile'))

    user_data = user_doc.to_dict()

    # Populate a user object for the template, making sure all fields exist
    # This is similar to your original code, but uses Firestore's native data.
    # Firestore stores lists and dictionaries directly, so no need for json.loads
    user = type('UserObject', (object,), user_data)
    user.profile_picture = user_data.get('profile_picture', None)
    user.cover_photo = user_data.get('cover_photo', None)
    user.state = user_data.get('state', '')
    user.location = user_data.get('location', '')
    user.sublocation = user_data.get('sublocation', '')
    user.working_days = user_data.get('working_days', [])
    user.working_times = user_data.get('working_times', {})
    user.delivery_methods = user_data.get('delivery_methods', [])
    user.social_links = user_data.get('social_links', {})

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        businessname = request.form.get("businessname", "").strip()
        birthday = request.form.get("birthday")
        sex = request.form.get("sex", "").strip()

        # --- Handle Location Inputs as Strings ---
        # No more integer IDs. We will store the user's text input directly.
        state_input = request.form.get("state_input", "").strip()
        location_input = request.form.get("location_input", "").strip()
        sublocation_input = request.form.get("sublocation_input", "").strip()

        # Basic validation for mandatory fields (expand as needed)
        errors = []
        if not state_input:
            errors.append("State is required.")
        if not location_input:
            errors.append("Location (University) is required.")

        # --- Handle Working Days & Hours ---
        selected_days = request.form.getlist('working_days')
        working_times_data = {}
        all_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

        for day in all_days:
            if day in selected_days:
                open_time = request.form.get(f"{day}_open")
                close_time = request.form.get(f"{day}_close")
                if open_time and close_time:
                    working_times_data[day] = {'open': open_time, 'close': close_time}
                else:
                    flash(f"Please provide both open and close times for {day}.", "warning")
                    working_times_data[day] = {'open': None, 'close': None}
            else:
                working_times_data[day] = {'open': None, 'close': None}

        # --- Handle Delivery Methods ---
        delivery_methods_list = request.form.getlist('delivery_methods')

        # --- Handle Social Links ---
        social_links_dict = {
            "website": request.form.get("social_links[website]", "").strip(),
            "instagram": request.form.get("social_links[instagram]", "").strip(),
            "facebook": request.form.get("social_links[facebook]", "").strip(),
            "linkedin": request.form.get("social_links[linkedin]", "").strip(),
            "twitter": request.form.get("social_links[twitter]", "").strip(),
        }
        # Filter out empty social links
        social_links_dict = {k: v for k, v in social_links_dict.items() if v}

        # --- Handle File Uploads (placeholder for Firebase Storage) ---
        # In a real app, this would use a Firebase Storage library.
        # This function is a placeholder and should be implemented with proper storage logic.
        def save_uploaded_file_to_storage(file, folder, user_id):
            # Placeholder logic: return a dummy path.
            if file and file.filename:
                filename = f"{user_id}_{file.filename}"
                # In a real app, upload 'file' to Firebase Storage at f"{folder}/{filename}"
                # and get the download URL. For this example, we'll use a mock URL.
                print(f"Uploading file '{filename}' to Firebase Storage in folder '{folder}'.")
                return f"https://firebase-storage.com/{folder}/{filename}"
            return None

        # Initialize paths with current user's DB values
        profile_path_to_store = user.profile_picture
        cover_path_to_store = user.cover_photo

        profile_picture_file = request.files.get("profile_picture")
        if profile_picture_file and profile_picture_file.filename:
            new_profile_path = save_uploaded_file_to_storage(profile_picture_file, 'profile', user_id)
            if new_profile_path:
                profile_path_to_store = new_profile_path
            else:
                flash("Failed to upload profile picture.", "danger")

        cover_photo_file = request.files.get("cover_photo")
        if cover_photo_file and cover_photo_file.filename:
            new_cover_path = save_uploaded_file_to_storage(cover_photo_file, 'cover', user_id)
            if new_cover_path:
                cover_path_to_store = new_cover_path
            else:
                flash("Failed to upload cover photo.", "danger")

        # Handle validation errors
        if errors:
            for error in errors:
                flash(error, "danger")
            # Re-render the form with existing data
            # Use the data that was just posted to preserve user input
            user.state = state_input
            user.location = location_input
            user.sublocation = sublocation_input
            user.working_days = selected_days
            user.working_times = working_times_data
            user.delivery_methods = delivery_methods_list
            user.social_links = social_links_dict
            user.profile_picture = profile_path_to_store
            user.cover_photo = cover_path_to_store
            return render_template("personal_details.html", user=user)

        try:
            # Create a dictionary of the data to update
            update_data = {
                "first_name": first_name,
                "last_name": last_name,
                "businessname": businessname,
                "state": state_input,
                "location": location_input,
                "sublocation": sublocation_input,
                "birthday": birthday,
                "sex": sex,
                "social_links": social_links_dict,
                "working_days": selected_days,
                "working_times": working_times_data,
                "delivery_methods": delivery_methods_list,
                "profile_picture": profile_path_to_store,
                "cover_photo": cover_path_to_store,
            }

            # Update the user's document in Firestore
            user_ref.update(update_data)

            flash("Your personal details have been updated successfully!", "success")
            return redirect(url_for('profile'))

        except Exception as e:
            current_app.logger.error(f"Error updating personal details for user {user_id}: {e}", exc_info=True)
            flash(f"An error occurred while saving your details: {e}", "danger")
            return render_template("personal_details.html", user=user)

    else: # GET request
        # The user object is already loaded from Firestore at the start of the function.
        # Generate the URLs for display using the paths from Firestore
        # The URL generation functions should handle the mock URLs from the file upload placeholder
        def get_profile_picture_url(path):
            return path if path else "https://placehold.co/150x150/E5E7EB/4B5563?text=Profile"

        def get_cover_photo_url(path):
            return path if path else "https://placehold.co/1000x300/E5E7EB/4B5563?text=Cover+Photo"

        user.profile_picture_url = get_profile_picture_url(user.profile_picture)
        user.cover_photo_url = get_cover_photo_url(user.cover_photo)

        return render_template("personal_details.html", user=user)



@app.route('/profile/<username>')
def profile_by_username(username):
    try:
        # Query the 'users' collection where the 'username' field matches the provided username.
        # This is the Firestore equivalent of your MySQL prepared statement.
        # It's an API call, not a string-based query, so it's not vulnerable to injection.
        users_ref = db.collection('users').where('username', '==', username)
        users_stream = users_ref.stream()
        
        user_data = None
        for doc in users_stream:
            user_data = doc.to_dict()
            user_data['id'] = doc.id # Add the document ID to the data
            break # We expect only one user with a unique username

    except Exception as e:
        current_app.logger.error(f"Error fetching user by username {username}: {e}", exc_info=True)
        flash("An error occurred while fetching user profile.", "danger")
        return redirect(url_for('home'))

    if user_data:
        user = User(**user_data)
        user.profile_picture_url = get_profile_picture_url(getattr(user, 'profile_picture', None))
        user.cover_photo_url = get_cover_photo_url(getattr(user, 'cover_photo', None))

        referral_link = url_for('signup', ref=getattr(user, 'referral_code', ''), _external=True)

        return render_template('profile.html', user=user, referral_link=referral_link)
    else:
        flash("User not found.", "danger")
        return redirect(url_for('home'))

# This route gets and views a user's profile picture by their user ID.
@app.route('/view/profile-picture/<int:user_id>')
def view_profile_picture(user_id):
    try:
        # Fetch the document directly using its ID. We assume the 'user_id' is the document ID.
        user_ref = db.collection('users').document(str(user_id))
        user_doc = user_ref.get()
        user_data = user_doc.to_dict() if user_doc.exists else None

    except Exception as e:
        current_app.logger.error(f"Error fetching profile picture for user {user_id}: {e}", exc_info=True)
        flash("An error occurred while fetching the profile picture.", "danger")
        return redirect(url_for('profile'))

    profile_pic_filename = user_data.get('profile_picture') if user_data else None
    image_url = get_profile_picture_url(profile_pic_filename)

    if profile_pic_filename:
        return render_template('view_image.html', image_url=image_url, title='Profile Picture', user_id=user_id)
    else:
        flash("User or profile picture not found.", "danger")
        return redirect(url_for('profile'))

# This route gets and views a user's cover photo by their user ID.
@app.route('/view/cover-photo/<int:user_id>')
def view_cover_photo(user_id):
    try:
        # Fetch the document directly using its ID.
        user_ref = db.collection('users').document(str(user_id))
        user_doc = user_ref.get()
        user_data = user_doc.to_dict() if user_doc.exists else None
        
    except Exception as e:
        current_app.logger.error(f"Error fetching cover photo for user {user_id}: {e}", exc_info=True)
        flash("An error occurred while fetching the cover photo.", "danger")
        return redirect(url_for('profile'))

    cover_photo_filename = user_data.get('cover_photo') if user_data else None
    image_url = get_cover_photo_url(cover_photo_filename)

    if cover_photo_filename:
        return render_template('view_image.html', image_url=image_url, title='Cover Photo', user_id=user_id)
    else:
        flash("User or cover photo not found.", "danger")
        return redirect(url_for('profile'))

# This route fetches a complete user profile, including associated data.
@app.route('/user/<int:user_id>/view')
def view_user_profile(user_id):
    try:
        user_doc_ref = db.collection('users').document(str(user_id))
        user_doc = user_doc_ref.get()
        if not user_doc.exists:
            flash("User not found.", "danger")
            return redirect(url_for('home'))

        user_data = user_doc.to_dict()
        user = User(**user_data)
        user.id = user_doc.id # Add the document ID for use in the template
        
        # Firestore automatically handles datetime objects, so the parsing is no longer needed.
        # Firestore stores timestamps, which can be converted to datetime objects.
        # Example: user.created_at = user_data.get('created_at').to_pydatetime() if user_data.get('created_at') else None

        # Fetch adverts for the user
        adverts_ref = db.collection('adverts').where('user_id', '==', str(user_id)).where('status', '==', 'published').stream()
        user_adverts = [advert.to_dict() for advert in adverts_ref]

        # Fetch Followers and Following Counts (less efficient than a denormalized counter)
        # For better performance, you should maintain these counts in the user document itself.
        followers_ref = db.collection('follows').where('followed_id', '==', str(user_id))
        followers_count = len(list(followers_ref.stream()))

        following_ref = db.collection('follows').where('follower_id', '==', str(user_id))
        following_count = len(list(following_ref.stream()))

        # Get posts count (assuming 'posts' is a separate collection)
        posts_ref = db.collection('posts').where('user_id', '==', str(user_id))
        posts_count = len(list(posts_ref.stream()))

        # Calculate average rating (also less efficient, consider denormalization)
        ratings_ref = db.collection('ratings').where('rated_user_id', '==', str(user_id))
        all_ratings = [rating.to_dict().get('rating', 0) for rating in ratings_ref.stream()]
        average_rating = round(sum(all_ratings) / len(all_ratings), 1) if all_ratings else 'N/A'

    except Exception as e:
        current_app.logger.error(f"Error fetching user profile data or adverts for user {user_id}: {e}", exc_info=True)
        user_adverts = []
        followers_count = 0
        following_count = 0
        posts_count = 0
        average_rating = 'N/A'
    
    user.adverts = user_adverts
    user.followers_count = followers_count
    user.following_count = following_count
    user.posts_count = posts_count
    user.average_rating = average_rating
    user.profile_picture_url = get_profile_picture_url(getattr(user, 'profile_picture', None))
    user.cover_photo_url = get_cover_photo_url(getattr(user, 'cover_photo', None))

    is_owner = False
    is_following_user = False
    current_user_id = None
    if 'user_id' in session:
        current_user_id = session['user_id']
        if str(current_user_id) == str(user_id):
            is_owner = True
        else:
            # Check if current_user is following this profile user
            follow_check_ref = db.collection('follows').where('follower_id', '==', str(current_user_id)).where('followed_id', '==', str(user_id)).limit(1)
            is_following_user = len(list(follow_check_ref.stream())) > 0

    return render_template('view_profile.html', 
                           profile_user=user, 
                           is_owner=is_owner,
                           is_following_user=is_following_user,
                           current_user_id=current_user_id)



def get_unread_notifications_count(user_id):
    """
    Counts the number of unread notifications for a given user in Firestore.
    
    This function queries the 'notifications' collection, filtering for documents
    where 'user_id' matches and 'is_read' is False. It then counts the number
    of documents in the resulting stream.
    
    For a very large number of notifications, a denormalized counter in the
    'users' document would be a more scalable approach to avoid reading all
    notification documents just to get a count.
    """
    try:
        # Create a query to find unread notifications for the user.
        # Firestore's query syntax is naturally protected from injection.
        # We use a filter instead of a raw SQL string.
        unread_notifications_query = db.collection('notifications').where(
            filter=FieldFilter('user_id', '==', str(user_id))
        ).where(
            filter=FieldFilter('is_read', '==', False)
        )
        
        # We stream the documents and count them.
        notifications_stream = unread_notifications_query.stream()
        
        # Count the documents in the generator. This is an efficient way to count
        # if the number of documents is not extremely large.
        count = sum(1 for _ in notifications_stream)
        
        return count
    except Exception as e:
        current_app.logger.error(f"Error getting unread notification count for user {user_id}: {e}", exc_info=True)
        return 0  # Default to 0 on any error


def get_advert_info(advert_id: int) -> dict:
    """
    Fetches basic advert information (like title) from the 'adverts' collection.
    
    This function assumes the 'advert_id' from your original MySQL table
    is used as the document ID in Firestore.
    """
    try:
        # Get the document reference for the specific advert_id.
        advert_ref = db.collection('adverts').document(str(advert_id))
        
        # Fetch the document.
        advert_doc = advert_ref.get()
        
        # If the document exists, return a dictionary of its data.
        if advert_doc.exists:
            # We explicitly add the ID to the dictionary for consistency.
            data = advert_doc.to_dict()
            data['id'] = advert_doc.id
            return data
        else:
            return {}  # Return an empty dictionary if the advert is not found
            
    except Exception as e:
        # The 'logger' in your original code is likely 'current_app.logger' in a Flask context
        current_app.logger.error(f"Error retrieving advert info for {advert_id}: {e}", exc_info=True)
        return {}


def sanitize_input(text):
    """
    Sanitizes text to prevent XSS (Cross-Site Scripting).
    
    This function is not database-specific. It's a general security measure
    that you should use before rendering any user-provided data on a web page.
    It remains unchanged as it's a good practice.
    """
    if text is None:
        return ""
    return text.replace('<', '&lt;').replace('>', '&gt;')




# In-memory maps for Socket.IO, these do not need to be in the database
user_sid_map = {}  # Map user_id to list of SIDs (for multiple tabs/devices)
chat_room_map = {}  # Map room_id to set of user_ids in that room (for read receipts)


def get_or_create_chat_thread(advert_id, user1_id, user2_id):
    """
    Helper function to find an existing chat thread or create a new one.
    This avoids code duplication in the routes.
    """
    try:
        # Query for an existing chat thread
        chat_query = (
            db.collection("chats")
            .where(filter=FieldFilter("advert_id", "==", str(advert_id)))
            .where(filter=FieldFilter("user1_id", "==", str(user1_id)))
            .where(filter=FieldFilter("user2_id", "==", str(user2_id)))
            .limit(1)
        )
        chat_docs = chat_query.stream()
        chat_thread = next(chat_docs, None)

        if chat_thread:
            # If the chat thread exists, return its ID and document object
            return chat_thread.id, chat_thread.to_dict()
        else:
            # If not, create a new one with initial data
            new_chat_ref = db.collection("chats").add(
                {
                    "advert_id": str(advert_id),
                    "user1_id": str(user1_id),
                    "user2_id": str(user2_id),
                    "last_message_content": None,
                    "last_message_timestamp": None,
                    "user1_unread_count": 0,
                    "user2_unread_count": 0,
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "updated_at": firestore.SERVER_TIMESTAMP,
                }
            )
            current_app.logger.info(
                f"Created new chat thread with ID: {new_chat_ref[1].id}"
            )
            # Fetch the newly created document to return its data
            new_chat_doc = new_chat_ref[1].get()
            return new_chat_doc.id, new_chat_doc.to_dict()

    except Exception as e:
        current_app.logger.error(
            f"Error finding/creating chat thread for advert {advert_id}: {e}",
            exc_info=True,
        )
        return None, None


def fetch_chat_sidebar_data(user_id):
    """
    Helper function to fetch all chat threads for the sidebar.
    This replaces the complex JOIN query with multiple Firestore queries.
    """
    chat_users = []
    
    # Get all chats where the current user is either user1 or user2
    chats_query1 = db.collection('chats').where(filter=FieldFilter('user1_id', '==', str(user_id)))
    chats_query2 = db.collection('chats').where(filter=FieldFilter('user2_id', '==', str(user_id)))
    
    # We combine the results in memory.
    chats_stream = list(chats_query1.stream()) + list(chats_query2.stream())

    # Sort the chats by last_message_timestamp in descending order
    chats_stream.sort(key=lambda x: x.to_dict().get('last_message_timestamp', firestore.SERVER_TIMESTAMP), reverse=True)
    
    # Batch fetching related data to minimize reads
    partner_ids = {
        (
            chat.to_dict()["user2_id"]
            if chat.to_dict()["user1_id"] == str(user_id)
            else chat.to_dict()["user1_id"]
        )
        for chat in chats_stream
    }
    advert_ids = {chat.to_dict()["advert_id"] for chat in chats_stream}

    # Fetch all partner user and advert documents in a single batch
    partner_docs = db.collection("users").where(filter=FieldFilter(firestore.FieldPath.document_id(), 'in', list(partner_ids))).stream()
    advert_docs = db.collection("adverts").where(filter=FieldFilter(firestore.FieldPath.document_id(), 'in', list(advert_ids))).stream()

    partner_cache = {doc.id: doc.to_dict() for doc in partner_docs}
    advert_cache = {doc.id: doc.to_dict() for doc in advert_docs}

    for chat_data in chats_stream:
        chat_dict = chat_data.to_dict()
        chat_id = chat_data.id
        
        # Determine the partner user and advert for the current chat
        partner_id = (
            chat_dict["user2_id"]
            if chat_dict["user1_id"] == str(user_id)
            else chat_dict["user1_id"]
        )
        advert_id = chat_dict["advert_id"]

        partner_user_data = partner_cache.get(partner_id)
        advert_data = advert_cache.get(advert_id)
        
        if not partner_user_data or not advert_data:
            # Skip chats with missing data
            continue

        unread_count = (
            chat_dict["user1_unread_count"]
            if chat_dict["user1_id"] == str(user_id)
            else chat_dict["user2_unread_count"]
        )
        last_message_timestamp = chat_dict.get("last_message_timestamp")
        
        chat_users.append(
            {
                "chat_id": chat_id,
                "id": partner_id,
                "username": partner_user_data.get("username"),
                "profile_picture_url": get_profile_picture_url(
                    partner_user_data.get("profile_picture")
                ),
                "last_message": chat_dict.get("last_message_content"),
                "last_message_time": last_message_timestamp.strftime("%H:%M")
                if last_message_timestamp
                else "",
                "unread": unread_count,
                "advert_id": advert_id,
                "advert_title": advert_data.get("title"),
            }
        )

    return chat_users


@app.route("/messages")
def messages():
    user_id = g.user.id
    chat_users_data = fetch_chat_sidebar_data(user_id)
    
    # The logic below for redirecting to the first chat is preserved
    if chat_users_data and request.args.get('redirect_to_first_chat', 'true').lower() == 'true':
        first_chat = chat_users_data[0]
        return redirect(url_for('message', receiver_id=first_chat['id'], advert_id=first_chat['advert_id']))

    # The original route had two identical queries. This refactors it.
    return render_template(
        "messages.html", chat_users=chat_users_data, recipient=None, messages=[], advert_id=None
    )


@app.route("/message/<string:receiver_id>/<string:advert_id>", methods=["GET"])
def message(receiver_id, advert_id):
    user_id = g.user.id
    advert_doc = db.collection("adverts").document(advert_id).get()

    if not advert_doc.exists:
        flash("Advert not found.", "error")
        return redirect(url_for("messages"))

    advert_owner_id = advert_doc.to_dict().get("user_id")

    # The logic for validating chat participants is preserved
    if (
        (user_id == advert_owner_id and receiver_id != advert_owner_id)
        or (receiver_id == advert_owner_id and user_id != advert_owner_id)
    ):
        user1_id = min(str(user_id), str(receiver_id))
        user2_id = max(str(user_id), str(receiver_id))
    else:
        flash("Invalid chat participants for this advert.", "error")
        return redirect(url_for("messages"))

    # Use the helper function to find or create the chat thread
    chat_id, chat_data = get_or_create_chat_thread(advert_id, user1_id, user2_id)
    if not chat_id:
        flash("Could not establish chat. Please try again.", "error")
        return redirect(url_for("messages"))

    # Update unread count to 0 for the current user
    try:
        if user_id == user1_id:
            db.collection("chats").document(chat_id).update({"user1_unread_count": 0})
        else:
            db.collection("chats").document(chat_id).update({"user2_unread_count": 0})
    except Exception as e:
        current_app.logger.error(f"Error updating unread count: {e}", exc_info=True)

    # Fetch all messages for the chat thread from the subcollection
    messages_query = (
        db.collection("chats")
        .document(chat_id)
        .collection("messages")
        .order_by("timestamp", direction=firestore.Query.ASCENDING)
    )
    messages_stream = messages_query.stream()
    
    processed_messages = []
    user_info_cache = {str(user_id): g.user}

    for msg in messages_stream:
        msg_dict = msg.to_dict()
        sender_id = msg_dict.get("sender_id")
        
        # Cache sender user info to avoid repeated database reads
        if sender_id not in user_info_cache:
            sender_doc = db.collection("users").document(sender_id).get()
            if sender_doc.exists:
                user_info_cache[sender_id] = sender_doc.to_dict()
            else:
                current_app.logger.warning(
                    f"Sender user ID {sender_id} not found for message."
                )
                user_info_cache[sender_id] = {"username": "Unknown", "profile_picture": None}
        
        sender_info = user_info_cache.get(sender_id)
        
        processed_messages.append(
            {
                "sender_id": sender_id,
                "content": msg_dict.get("content"),
                "file_path": msg_dict.get("file_path"),
                "attached_advert_details": msg_dict.get("attached_advert_details"),
                "timestamp": msg_dict.get("timestamp").strftime("%H:%M") if msg_dict.get("timestamp") else '',
                "sender_username": sender_info.get("username"),
                "sender_profile_picture_url": get_profile_picture_url(
                    sender_info.get("profile_picture")
                ),
            }
        )
    
    # Fetch recipient information
    recipient_doc = db.collection("users").document(receiver_id).get()
    recipient = recipient_doc.to_dict() if recipient_doc.exists else None
    if recipient:
        recipient['profile_picture_url'] = get_profile_picture_url(recipient.get('profile_picture'))
    
    advert_details = advert_doc.to_dict()
    if advert_details:
        advert_details['main_image_url'] = url_for('static', filename=f'uploads/adverts/{advert_details["main_image"]}') if advert_details.get('main_image') else url_for('static', filename='images/default_advert_image.png')

    chat_users_for_sidebar = fetch_chat_sidebar_data(user_id)

    return render_template(
        "messages.html",
        recipient=recipient,
        advert_id=advert_id,
        messages=processed_messages,
        chat_users=chat_users_for_sidebar,
        advert_details=advert_details,
    )


@app.route("/message_seller/<string:seller_id>/<string:advert_id>")
def message_seller(seller_id, advert_id):
    if g.user.id == seller_id:
        flash("You cannot message yourself.", "warning")
        return redirect(url_for("home"))
    
    # Check if the advert exists in Firestore
    advert_ref = db.collection('adverts').document(advert_id)
    if not advert_ref.get().exists:
        flash('The advert you are trying to message about does not exist.', 'error')
        return redirect(url_for('home'))

    return redirect(url_for("message", receiver_id=seller_id, advert_id=advert_id))


# --- Socket.IO Event Handlers ---
@socketio.on('join_room')
def handle_join_room(data):
    current_user_obj = get_current_user()
    if not request.sid or not current_user_obj:
        current_app.logger.warning("Unauthenticated user or missing session ID tried to join room.")
        return

    receiver_id = data.get('receiver_id')
    advert_id = data.get('advert_id')
    
    if not receiver_id or not advert_id:
        current_app.logger.warning("Missing receiver_id or advert_id for join_room.")
        return

    advert_doc = db.collection('adverts').document(advert_id).get()
    if not advert_doc.exists:
        current_app.logger.warning(f"Advert {advert_id} not found for room join by user {current_user_obj.id}.")
        return

    advert_owner_id = advert_doc.to_dict().get("user_id")

    if (
        (str(current_user_obj.id) == advert_owner_id and str(receiver_id) != advert_owner_id) or
        (str(receiver_id) == advert_owner_id and str(current_user_obj.id) != advert_owner_id)
    ):
        user1_id = min(str(current_user_obj.id), str(receiver_id))
        user2_id = max(str(current_user_obj.id), str(receiver_id))
    else:
        current_app.logger.warning(f"Invalid participants for chat room: current_user={current_user_obj.id}, receiver={receiver_id}, advert_owner={advert_owner_id}")
        return

    room = f"chat_{user1_id}_{user2_id}_{advert_id}"
    join_room(room)
    current_app.logger.info(f"User {current_user_obj.username} (ID: {current_user_obj.id}) joined room: {room} with SID {request.sid}")
    
    # ... (in-memory map logic remains the same)
    if current_user_obj.id not in user_sid_map:
        user_sid_map[current_user_obj.id] = []
    if request.sid not in user_sid_map[current_user_obj.id]:
        user_sid_map[current_user_obj.id].append(request.sid)
    
    if room not in chat_room_map:
        chat_room_map[room] = set()
    chat_room_map[room].add(current_user_obj.id)

    # --- Firestore Logic for Read Receipts ---
    other_user_id = user1_id if str(current_user_obj.id) == user2_id else user2_id
    if other_user_id in chat_room_map[room]:
        try:
            # Find the chat thread document
            chat_id, chat_data = get_or_create_chat_thread(advert_id, user1_id, user2_id)
            if not chat_id: return

            # Get the path to the messages subcollection
            messages_ref = db.collection("chats").document(chat_id).collection("messages")

            # Update all unread messages from the other user to 'read'
            unread_messages_query = messages_ref.where(
                filter=FieldFilter("sender_id", "==", other_user_id)
            ).where(
                filter=FieldFilter("status", "in", ["sent", "delivered"])
            )

            # Use a batch write to perform multiple updates atomically
            batch = db.batch()
            for doc in unread_messages_query.stream():
                batch.update(doc.reference, {"status": "read"})
            batch.commit()

            # Reset the unread count in the chat document to 0
            if str(current_user_obj.id) == user1_id:
                db.collection("chats").document(chat_id).update({"user1_unread_count": 0})
            else:
                db.collection("chats").document(chat_id).update({"user2_unread_count": 0})
            
            # Emit the read event to the other user's active clients
            if other_user_id in user_sid_map:
                for sid in user_sid_map[other_user_id]:
                    emit('message_read', {'chat_id': chat_id, 'reader_id': str(current_user_obj.id)}, room=sid)

        except Exception as e:
            current_app.logger.error(f"Error marking messages as read on join_room: {e}", exc_info=True)


@socketio.on('send_message')
def handle_send_message(data):
    current_user_obj = get_current_user()
    if not current_user_obj:
        current_app.logger.warning("Unauthenticated user tried to send message.")
        return

    receiver_id = data.get('receiver_id')
    advert_id = data.get('advert_id')
    message_content = sanitize_input(data.get('message', ''))
    file_path = data.get('file_path')
    attached_advert = data.get('advert_details')

    if not message_content and not file_path and not attached_advert:
        current_app.logger.info("Empty message, no file, and no attached advert received, not saving.")
        return

    advert_doc = db.collection('adverts').document(advert_id).get()
    if not advert_doc.exists:
        current_app.logger.warning(f"Advert {advert_id} not found for message sending by user {current_user_obj.id}.")
        return

    user1_id = min(str(current_user_obj.id), str(receiver_id))
    user2_id = max(str(current_user_obj.id), str(receiver_id))
    
    # Use the helper function to find or create the chat thread
    chat_id, chat_data = get_or_create_chat_thread(advert_id, user1_id, user2_id)
    if not chat_id: return

    # Firestore logic for saving the message
    try:
        # Get a reference to the messages subcollection
        messages_ref = db.collection('chats').document(chat_id).collection('messages')
        
        # Add the new message document to the subcollection
        new_message_ref = messages_ref.add(
            {
                "sender_id": str(current_user_obj.id),
                "content": message_content,
                "file_path": file_path,
                "attached_advert_details": attached_advert,
                "timestamp": firestore.SERVER_TIMESTAMP,
                "status": "sent",
            }
        )

        display_content = message_content if message_content else os.path.basename(file_path) if file_path else "[Advert Inquiry]"
        
        # Update the parent chat document with last message and increment unread count
        chat_ref = db.collection('chats').document(chat_id)
        update_data = {
            "last_message_content": display_content,
            "last_message_timestamp": firestore.SERVER_TIMESTAMP,
            "updated_at": firestore.SERVER_TIMESTAMP,
        }
        
        # Firestore's Increment field value is used for atomic updates
        if str(current_user_obj.id) == user1_id:
            update_data["user2_unread_count"] = Increment(1)
        else:
            update_data["user1_unread_count"] = Increment(1)
            
        chat_ref.update(update_data)

    except Exception as e:
        current_app.logger.error(f"Error saving message to DB: {e}", exc_info=True)
        return

    # Prepare message data for WebSocket emission
    message_data = {
        'id': new_message_ref[1].id, # The new message ID from Firestore
        'sender_id': str(current_user_obj.id),
        'content': message_content,
        'file_path': file_path,
        'timestamp': datetime.now().strftime('%H:%M'),
        'status': 'sent',
        'sender_username': current_user_obj.username,
        'sender_profile_picture_url': get_profile_picture_url(current_user_obj.profile_picture),
        'advert_details': attached_advert,
        'chat_id': chat_id
    }
    
    # Emit messages and notifications
    room = f"chat_{user1_id}_{user2_id}_{advert_id}"
    emit('receive_message', message_data, room=room, include_self=False)
    emit('message_sent', message_data, room=request.sid)

    # ... (sidebar update logic remains the same)
    emit('update_sidebar_unread', {'chat_id': chat_id, 'participant_id': str(current_user_obj.id), 'unread_delta': 0}, room=request.sid)

    other_user_id = user1_id if str(current_user_obj.id) == user2_id else user2_id
    if other_user_id in user_sid_map:
        for sid in user_sid_map[other_user_id]:
            emit('update_sidebar_unread', {'chat_id': chat_id, 'participant_id': other_user_id, 'unread_delta': 1}, room=sid)

    if room not in chat_room_map or other_user_id not in chat_room_map[room]:
        sender_username = current_user_obj.username
        advert_title_for_notification = ""
        advert_info = get_advert_info(advert_id)
        if advert_info:
            advert_title_for_notification = f" about '{advert_info.get('title', 'an advert')}'"
        
        notification_message = f"{sender_username} sent you a new message{advert_title_for_notification}."
        create_notification(other_user_id, 'new_message', notification_message, related_id=str(current_user_obj.id))
        current_app.logger.info(f"Notification created for user {other_user_id} about new message from {sender_username}.")


@socketio.on('message_received_ack')
def handle_message_received_ack(data):
    message_id = data.get('message_id')
    chat_id = data.get('chat_id')
    sender_id = data.get('sender_id')
    
    if not message_id or not chat_id:
        current_app.logger.warning("Missing message_id or chat_id for message_received_ack.")
        return

    # Firestore logic for updating message status
    try:
        # Get a reference to the specific message document in its subcollection
        message_ref = db.collection("chats").document(chat_id).collection("messages").document(message_id)

        # Use an atomic update to change the status
        message_ref.update({"status": "delivered"})
        current_app.logger.info(f"Message {message_id} status updated to 'delivered'.")

        # Notify the original sender that their message has been delivered
        if sender_id in user_sid_map:
            for sid in user_sid_map[sender_id]:
                emit('message_status_update', {'message_id': message_id, 'status': 'delivered'}, room=sid)

    except Exception as e:
        current_app.logger.error(f"Error updating message status to 'delivered' for ID {message_id}: {e}", exc_info=True)


# --- Helper functions that remain unchanged ---
@app.route('/upload_message_file', methods=['POST'])
def upload_message_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    new_filename = save_uploaded_file(file, 'media', g.user.id)

    if new_filename:
        file_url = url_for('static', filename=f'media/{new_filename}')
        return jsonify({'filepath': file_url}), 200
    else:
        return jsonify({'error': 'File upload failed or invalid file type.'}), 500






            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
@app.route('/seller_profile/<seller_id>')
def seller_profile_view(seller_id):
    current_user_id = session.get('user_id')
    
    # If the current user is the seller, redirect them to their full profile
    if current_user_id == seller_id:
        # Note: You need to have a 'profile' route defined for this to work
        return redirect(url_for('profile'))

    seller_info = None
    seller_adverts = []
    is_following = False

    try:
        # Fetch public seller information from the 'users' collection
        # Firestore uses document references for single items.
        seller_doc_ref = db.collection('users').document(seller_id)
        seller_doc = seller_doc_ref.get()

        if not seller_doc.exists:
            flash("Seller profile not found.", "error")
            return redirect(url_for('home'))
        
        seller_info = seller_doc.to_dict()

        # Construct full URLs for profile and cover pictures.
        # This assumes your file paths are relative to a 'static' folder.
        seller_info['profile_picture_url'] = url_for('static', filename=f'uploads/profile_pictures/{seller_info.get("profile_picture", "default_profile.png")}')
        seller_info['cover_photo_url'] = url_for('static', filename=f'uploads/cover_photos/{seller_info.get("cover_photo")}') if seller_info.get('cover_photo') else None

        # Convert Firestore Timestamps to a formatted string for display
        if seller_info.get('created_at') and isinstance(seller_info['created_at'], firestore.Timestamp):
            seller_info['created_at'] = seller_info['created_at'].strftime('%Y-%m-%d %H:%M')

        # Get seller's average rating and review count from the 'reviews' collection
        # Firestore doesn't have a built-in AVG or COUNT. We must query and calculate.
        reviews_ref = db.collection('reviews').where('reviewee_id', '==', seller_id)
        reviews = reviews_ref.stream()
        
        total_rating = 0
        review_count = 0
        for review in reviews:
            total_rating += review.to_dict().get('rating', 0)
            review_count += 1
        
        seller_info['rating'] = total_rating / review_count if review_count > 0 else 0.0
        seller_info['review_count'] = review_count

        # Check if the logged-in user is following this seller
        if current_user_id: # Only check if a user is logged in
            followers_query = db.collection('followers').where('follower_id', '==', current_user_id).where('followed_id', '==', seller_id).limit(1)
            is_following = len(list(followers_query.stream())) > 0

        # Fetch only published/active adverts for this seller
        # Firestore requires an index for this type of query.
        # Create a composite index on 'user_id', 'status', and 'expires_at'
        adverts_ref = db.collection('adverts').where('user_id', '==', seller_id).where('status', '==', 'published').where('expires_at', '>', firestore.SERVER_TIMESTAMP).order_by('created_at', direction=firestore.Query.DESCENDING)
        
        seller_adverts = []
        for advert_doc in adverts_ref.stream():
            advert = advert_doc.to_dict()
            advert['id'] = advert_doc.id # Add the document ID
            if advert.get('main_image'):
                advert['main_image_url'] = url_for('static', filename=f'uploads/{advert["main_image"]}')
            else:
                advert['main_image_url'] = url_for('static', filename='default_advert_image.png')
            
            # Convert Firestore Timestamps for display
            if advert.get('created_at') and isinstance(advert['created_at'], firestore.Timestamp):
                advert['created_at'] = advert['created_at'].strftime('%Y-%m-%d %H:%M')
            if advert.get('expires_at') and isinstance(advert['expires_at'], firestore.Timestamp):
                advert['expires_at'] = advert['expires_at'].strftime('%Y-%m-%d %H:%M')
            
            seller_adverts.append(advert)

        return render_template('seller_profile_view.html',
                               seller=seller_info,
                               adverts=seller_adverts,
                               is_following=is_following,
                               current_user_id=current_user_id)
    except Exception as e:
        logger.error(f"Unexpected error in seller_profile_view for user {seller_id}: {e}", exc_info=True)
        flash("An unexpected error occurred while loading the seller's profile. Please try again later.", "error")
        return redirect(url_for('home'))
    # The 'finally' block with cur.close() is not needed with Firestore client.


# --- Helper Functions to fetch data from DB ---

def get_all_locations():
    # Firestore doesn't have a DISTINCT query. We'll get all adverts and create a unique set.
    adverts_ref = db.collection('adverts')
    locations = set()
    for doc in adverts_ref.stream():
        location = doc.to_dict().get('location')
        if location:
            locations.add(location)
    return sorted(list(locations))

def get_all_categories_with_subcategories():
    categories_ref = db.collection('categories').order_by('name')
    categories_data = []

    for cat_doc in categories_ref.stream():
        category_id = cat_doc.id
        category_name = cat_doc.to_dict().get('name')
        
        # Now get subcategories for this category
        subcategories_ref = db.collection('subcategories').where('category_id', '==', category_id).order_by('name')
        subcategories_list = [sub_doc.to_dict().get('name') for sub_doc in subcategories_ref.stream()]
        
        categories_data.append({
            'id': category_id,
            'name': category_name,
            'subcategories': subcategories_list
        })
    return categories_data

def get_subcategories_for_category(category_name):
    # First, find the category document ID
    category_query = db.collection('categories').where('name', '==', category_name).limit(1)
    category_docs = list(category_query.stream())
    
    if not category_docs:
        return []

    category_id = category_docs[0].id
    
    # Then, get the subcategories using the ID
    subcategories_ref = db.collection('subcategories').where('category_id', '==', category_id).order_by('name')
    subcategories_list = [sub_doc.to_dict().get('name') for sub_doc in subcategories_ref.stream()]
    
    return subcategories_list







# --- Home Route - Rewritten for Firestore ---
@app.route('/')
def home():
    try:
        # --- Fetching Static Data: Locations and Categories ---
        # The equivalent of `SELECT name FROM location ORDER BY name ASC`
        locations_ref = admin_db.collection('locations').order_by('name').stream()
        locations = [{'name': doc.to_dict()['name']} for doc in locations_ref]

        # The equivalent of `get_all_categories_with_subcategories`
        categories_ref = admin_db.collection('categories').stream()
        categories_data = [doc.to_dict() for doc in categories_ref]

        # --- Adverts Logic ---
        user_id = session.get('user_id')
        view_following_priority = False
        followed_user_ids = []

        if user_id:
            user_settings = get_user_info(user_id)
            if user_settings and user_settings.get('view_following_users_advert_first'):
                view_following_priority = True
                followed_user_ids = get_followers_of_user(user_id)

        # Firestore does not support complex ORDER BY clauses like the SQL `CASE` statement.
        # Instead, we will fetch all published adverts and then sort them in Python.
        
        # Define the visibility order for sorting
        visibility_order = {
            'Ultimate': 1,
            'Premium': 2,
            'Top': 3,
            'High': 4,
            'Standard': 5
        }

        # Query for all published and non-expired adverts
        adverts_ref = admin_db.collection('adverts').where('status', '==', 'published').stream()
        all_published_adverts = []
        now = datetime.now(timezone.utc)

        # Get all published adverts and their associated user data
        for advert_doc in adverts_ref:
            advert_data = advert_doc.to_dict()
            expires_at = advert_data.get('expires_at')
            if expires_at and expires_at.replace(tzinfo=timezone.utc) > now:
                advert_data['id'] = advert_doc.id # Add document ID
                
                # Fetch user data for each advert to get username and role
                poster_user_ref = admin_db.collection('users').document(advert_data['user_id'])
                poster_user_doc = poster_user_ref.get()
                if poster_user_doc.exists:
                    poster_user_data = poster_user_doc.to_dict()
                    advert_data['poster_username'] = poster_user_data.get('username')
                    advert_data['poster_role'] = poster_user_data.get('role')
                else:
                    advert_data['poster_username'] = 'Unknown'
                    advert_data['poster_role'] = 'standard'
                
                all_published_adverts.append(advert_data)

        # --- Featured by Admin Ads ---
        # Filter the fetched data in Python, since we can't do complex `WHERE` clauses in Firestore
        admin_ads_for_display = [
            ad for ad in all_published_adverts if ad.get('featured') or ad.get('poster_role') == 'admin'
        ]

        # Sort the admin ads in Python
        def sort_ads_by_visibility_and_date(ad):
            visibility_rank = visibility_order.get(ad.get('visibility_level', 'Standard'), 99)
            created_at_dt = ad.get('created_at', datetime.min)
            return (visibility_rank, -created_at_dt.timestamp())
        
        admin_ads_for_display.sort(key=sort_ads_by_visibility_and_date)
        
        # --- Trending Adverts ---
        # Sort the main advert list based on the user's preference
        def sort_trending_ads(ad):
            # 1. Prioritize adverts from followed users
            is_followed = 0 if view_following_priority and ad.get('user_id') in followed_user_ids else 1
            # 2. Prioritize by visibility level
            visibility_rank = visibility_order.get(ad.get('visibility_level', 'Standard'), 99)
            # 3. Prioritize by most recent creation date
            created_at_ts = ad.get('created_at', datetime.min).timestamp()
            return (is_followed, visibility_rank, -created_at_ts)

        adverts = sorted(all_published_adverts, key=sort_trending_ads)
        # Limit to the top 20 after sorting
        adverts = adverts[:20]

        return render_template('home.html',
                               locations=locations,
                               categories=categories_data,
                               admin_ads=admin_ads_for_display,
                               adverts=adverts)

    except Exception as e:
        # In a real app, use a proper logger
        print(f"Error fetching homepage data: {e}")
        flash("There was an error loading the adverts. Please try again later.", "danger")
        return render_template('home.html', admin_ads=[], adverts=[], locations=[], categories=[])




# Firestore collections. Ad-hoc creation is not needed, Firestore creates them on first write.
# This serves as a reference for our data model.
USERS_COLLECTION = 'users'
ADVERTS_COLLECTION = 'adverts'
STATES_COLLECTION = 'states'
LOCATIONS_COLLECTION = 'locations'
SUBLOCATIONS_COLLECTION = 'sublocations'
CATEGORIES_COLLECTION = 'categories'

# ====================================================================
# Helper Functions to interact with Firestore
# These replace the direct SQL queries from your original code.
# ====================================================================

def get_all_states():
    """Fetches all states from the 'states' collection."""
    states_ref = db.collection(STATES_COLLECTION)
    docs = states_ref.stream()
    return [{'id': doc.id, 'name': doc.to_dict().get('name', '')} for doc in docs]

def get_all_categories_with_subcategories():
    """Fetches all categories and their subcategories."""
    categories_ref = db.collection(CATEGORIES_COLLECTION)
    docs = categories_ref.stream()
    return [doc.to_dict() for doc in docs]

def get_subcategories_for_category(category_name):
    """Fetches subcategories for a given category name."""
    if not category_name:
        return []
    
    category_ref = db.collection(CATEGORIES_COLLECTION).document(category_name)
    doc = category_ref.get()
    if doc.exists:
        return doc.to_dict().get('subcategories', [])
    return []

def get_state_info(state_id):
    """Fetches state information by ID."""
    if not state_id:
        return None
    state_ref = db.collection(STATES_COLLECTION).document(str(state_id))
    doc = state_ref.get()
    return doc.to_dict() if doc.exists else None

def get_location_info(location_id):
    """Fetches location information by ID."""
    if not location_id:
        return None
    location_ref = db.collection(LOCATIONS_COLLECTION).document(str(location_id))
    doc = location_ref.get()
    return doc.to_dict() if doc.exists else None

def get_sub_location_info(sublocation_id):
    """Fetches sub-location information by ID."""
    if not sublocation_id:
        return None
    sublocation_ref = db.collection(SUBLOCATIONS_COLLECTION).document(str(sublocation_id))
    doc = sublocation_ref.get()
    return doc.to_dict() if doc.exists else None

def get_user_info(user_id):
    """Fetches user information by ID."""
    if not user_id:
        return None
    user_ref = db.collection(USERS_COLLECTION).document(str(user_id))
    doc = user_ref.get()
    return doc.to_dict() if doc.exists else None
    
def get_followers_of_user(user_id):
    """Fetches the user IDs that the given user is following."""
    # This assumes a 'followers' subcollection or similar structure.
    # We will simulate this for now, but a proper implementation would query a 'followings' collection.
    # For this example, we'll return a hardcoded list.
    # In a real app, you would query a 'following' collection for documents where the 'follower_id' is the current user's ID.
    return []

# ====================================================================
# API Endpoints for dynamic dropdowns (replaces your old API routes)
# ====================================================================

@app.route('/api/locations_by_state/<state_id>')
def api_locations_by_state(state_id):
    """API endpoint to get locations for a specific state."""
    locations_ref = db.collection(LOCATIONS_COLLECTION).where('state_id', '==', str(state_id))
    docs = locations_ref.stream()
    locations = [{'id': doc.id, 'name': doc.to_dict().get('name', '')} for doc in docs]
    return jsonify(locations)

@app.route('/api/sublocations/<location_id>')
def api_sublocations_by_location(location_id):
    """API endpoint to get sublocations for a specific location."""
    sublocations_ref = db.collection(SUBLOCATIONS_COLLECTION).where('location_id', '==', str(location_id))
    docs = sublocations_ref.stream()
    sublocations = [{'id': doc.id, 'name': doc.to_dict().get('name', '')} for doc in docs]
    return jsonify(sublocations)

# ====================================================================
# Main Search Route (Completely rewritten for Firestore)
# ====================================================================

@app.route('/search')
def search():
    adverts = []
    all_states_data = get_all_states()
    all_categories_data = get_all_categories_with_subcategories()
    
    # Get search parameters from the request
    search_query = request.args.get('search_query', '').strip().lower()
    selected_state_id = request.args.get('state_id', '')
    selected_location_id = request.args.get('location_id', '')
    selected_sublocation_id = request.args.get('sublocation_id', '')
    category = request.args.get('category', '').strip()
    sub_category = request.args.get('sub_category', '').strip()
    price_min_str = request.args.get('price_min', '').strip()
    price_max_str = request.args.get('price_max', '').strip()
    condition = request.args.get('condition', '').strip()
    negotiation = request.args.get('negotiation', '').strip()

    # Get names for display from IDs
    selected_state_name = get_state_info(selected_state_id)['name'] if selected_state_id and get_state_info(selected_state_id) else ''
    selected_location_name = get_location_info(selected_location_id)['name'] if selected_location_id and get_location_info(selected_location_id) else ''
    selected_sublocation_name = get_sub_location_info(selected_sublocation_id)['name'] if selected_sublocation_id and get_sub_location_info(selected_sublocation_id) else ''

    # Get subcategories for the selected category for the dropdown
    selected_category_subcategories = get_subcategories_for_category(category)

    # Build the Firestore query
    adverts_query = db.collection(ADVERTS_COLLECTION).where('status', '==', 'published')
    
    # Firestore does not support 'expires_at > NOW()' directly. You must use a a specific
    # timestamp field and check against the current time. We'll use a `valid_until` field
    # and assume it's a datetime object.
    now = datetime.datetime.now()
    adverts_query = adverts_query.where('valid_until', '>', now)

    # Add filters for equality
    if selected_state_id:
        adverts_query = adverts_query.where('state_id', '==', selected_state_id)
    if selected_location_id:
        adverts_query = adverts_query.where('location_id', '==', selected_location_id)
    if selected_sublocation_id:
        adverts_query = adverts_query.where('sublocation_id', '==', selected_sublocation_id)
    if category:
        adverts_query = adverts_query.where('category', '==', category)
    if sub_category:
        adverts_query = adverts_query.where('sub_category', '==', sub_category)
    if condition:
        adverts_query = adverts_query.where('condition', '==', condition)
    if negotiation:
        is_negotiable = negotiation == 'yes'
        adverts_query = adverts_query.where('negotiable', '==', is_negotiable)

    # Firestore queries are simple. We can't do complex `AND` or `OR` queries with multiple `in` clauses
    # or `>` on different fields. We must fetch and filter in-memory for some cases.
    
    # Price filtering
    price_min = None
    price_max = None
    if price_min_str:
        try:
            price_min = float(price_min_str)
            adverts_query = adverts_query.where('price', '>=', price_min)
        except ValueError:
            flash("Invalid minimum price entered. Please enter a number.", "warning")
    if price_max_str:
        try:
            price_max = float(price_max_str)
            adverts_query = adverts_query.where('price', '<=', price_max)
        except ValueError:
            flash("Invalid maximum price entered. Please enter a number.", "warning")

    # Fetch initial results from Firestore
    try:
        adverts_stream = adverts_query.stream()
        fetched_adverts = []
        for doc in adverts_stream:
            advert_data = doc.to_dict()
            advert_data['id'] = doc.id # Add document ID
            fetched_adverts.append(advert_data)
        
        adverts = fetched_adverts
        
        # Now, filter and sort the data in Python
        # Text search for 'title' and 'description' (in-memory filtering)
        if search_query:
            adverts = [
                a for a in adverts if 
                search_query in a.get('title', '').lower() or 
                search_query in a.get('description', '').lower()
            ]

        # Get user info for all fetched adverts in one batch to reduce queries
        user_ids = {a.get('user_id') for a in adverts if a.get('user_id')}
        users_info = {}
        if user_ids:
            # Firestore allows `in` queries for up to 10 user IDs
            # If there are more, you'll need to batch the queries
            for user_id_chunk in [list(user_ids)[i:i + 10] for i in range(0, len(user_ids), 10)]:
                users_info_ref = db.collection(USERS_COLLECTION).where(firestore.FieldPath.document_id(), 'in', user_id_chunk)
                users_docs = users_info_ref.stream()
                for user_doc in users_docs:
                    users_info[user_doc.id] = user_doc.to_dict()

        for advert in adverts:
            user_data = users_info.get(advert.get('user_id', ''))
            if user_data:
                advert['poster_username'] = user_data.get('username', 'N/A')
                advert['is_verified'] = user_data.get('is_verified', False)
                # You might need to add logic for following users here if needed
            else:
                advert['poster_username'] = 'N/A'
                advert['is_verified'] = False

        # Apply custom sorting logic in Python
        visibility_order = {
            'Ultimate': 1, 'Premium': 2, 'Top': 3, 'High': 4, 'Standard': 5
        }
        
        # This sorts by multiple criteria in Python, which is not possible in a single Firestore query
        adverts.sort(key=lambda a: (
            # 1. Verified users first
            not a.get('is_verified', False), 
            # 2. Title match priority
            0 if search_query and a.get('title', '').lower() == search_query.lower() else
            1 if search_query and a.get('title', '').lower().startswith(search_query.lower()) else
            2 if search_query and search_query.lower() in a.get('title', '').lower() else
            3,
            # 3. Visibility level
            visibility_order.get(a.get('visibility_level', 'Standard'), 99),
            # 4. Created_at (descending)
            a.get('created_at', datetime.datetime.min),
        ), reverse=False)
        # Note: You need to store 'created_at' as a Firestore Timestamp or a datetime object.

    except Exception as e:
        flash(f"An unexpected error occurred during your search: {e}", "danger")
        adverts = []
        
    return render_template('search.html',
                            search_query=search_query,
                            adverts=adverts,
                            states=all_states_data,
                            selected_state_id=selected_state_id,
                            selected_state_name=selected_state_name,
                            selected_location_id=selected_location_id,
                            selected_location_name=selected_location_name,
                            selected_sublocation_id=selected_sublocation_id,
                            selected_sublocation_name=selected_sublocation_name,
                            categories=all_categories_data,
                            selected_category=category,
                            selected_sub_category=sub_category,
                            selected_price_min=price_min_str,
                            selected_price_max=price_max_str,
                            selected_condition=condition,
                            selected_negotiation=negotiation,
                            selected_category_subcategories=selected_category_subcategories)

        
        
        
    
@app.route('/get_subcategories/<category_name>')
def get_subcategories_api(category_name):
    # This endpoint is for AJAX requests to dynamically load subcategories
    subcategories = get_subcategories_for_category(category_name)
    return jsonify(subcategories)
      

# Settings page
@app.route('/settings')
def settings():
    return render_template('settings.html')



   
    
    


    
@app.route('/disable-chats')
def disable_chats():
    return render_template('disable_chats.html')

@app.route('/disable-feedback')
def disable_feedback():
    return render_template('disable_feedback.html')



# FAQ page
@app.route('/faq')
def faq():
    # Implement FAQ
     return render_template('faq.html')

# Support page
@app.route('/support')
def support():
    # Implement support
     return render_template('support.html')


    



@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    user_id = session['user_id']
    
    # Reference the user's document in the 'users' collection
    user_ref = db.collection('users').document(user_id)
    
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        # Get the user document data
        user_doc = user_ref.get()
        
        # Check if the document exists and has a password field
        if not user_doc.exists or 'password' not in user_doc.to_dict():
            flash('User document not found or password not set.', 'error')
        else:
            user_data = user_doc.to_dict()
            stored_password_hash = user_data.get('password')
            
            # Use bcrypt.check_password_hash to securely verify the current password
            if not check_password_hash(stored_password_hash, current_password):
                flash('Current password is incorrect.', 'error')
            elif new_password != confirm_password:
                flash('New passwords do not match.', 'error')
            elif len(new_password) < 6:
                flash('New password must be at least 6 characters.', 'error')
            else:
                # Hash the new password before storing it
                hashed_pw = generate_password_hash(new_password).decode('utf-8')
                
                # Update the password field in the user's document
                user_ref.update({'password': hashed_pw})
                
                flash('Password changed successfully!', 'success')
                return redirect(url_for('profile'))

    return render_template('change_password.html')


# Replace the existing `delete_account` function with this one.
@app.route('/delete-account', methods=['GET', 'POST'])
@login_required
def delete_account():
    user_id = session['user_id']
    
    if request.method == 'POST':
        try:
            # Delete the user's document from the 'users' collection
            db.collection('users').document(user_id).delete()
            
            # Clear the Flask session and log the user out
            session.clear()
            flash("Your account has been deleted.", "success")
            return redirect(url_for('index'))
            
        except Exception as e:
            flash(f"An error occurred while deleting the account: {e}", "error")
            
    return render_template('delete_account.html')


# Replace the existing `update_location` function with this one.
@app.route('/update-location', methods=['GET', 'POST'])
@login_required
def update_location():
    user_id = session['user_id']
    
    if request.method == 'POST':
        new_location = request.form['location']
        
        # Update the 'location' field in the user's document
        user_ref = db.collection('users').document(user_id)
        user_ref.update({'location': new_location})
        
        flash("Location updated.", "success")
        return redirect(url_for('profile'))
        
    return render_template('update_location.html')









# Example function to get existing settings (replace with your data retrieval logic)
def get_user_settings():
    # Fetch user settings from database
    # Example return:
    return {
        'email_notifications': True,
        'hot_deals': True,
        'ad_info': False,
        'premium_packages': True,
        'subscriptions': True,
        'messages': False,
        'feedback': True,
        'sms_info': False,
        'web_notification': True,
        'new_followers': True,
        'subscription_plan': False,
        'school_update': True
    }

# Example function to save settings (replace with your data save logic)
def save_user_settings(settings):
    # Save settings to database
    pass



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# --- Helper Functions for Firestore ---

def get_username(user_id):
    """Fetches a username given a user ID from Firestore."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    if user_doc.exists:
        return user_doc.to_dict().get('username', 'Unknown User')
    return 'Unknown User'

def create_notification(user_id, notification_type, notification_message, **kwargs):
    """Creates a new notification document for a user."""
    notification_data = {
        'type': notification_type,
        'message': notification_message,
        'timestamp': firestore.SERVER_TIMESTAMP,
        'is_read': False,
        'related_data': kwargs
    }
    # Add a new notification document to the user's subcollection
    db.collection('users').document(user_id).collection('notifications').add(notification_data)

# --- Updated Routes with Firestore ---

@app.route('/notification-settings', methods=['GET', 'POST'])
@login_required
def manage_notifications():
    user_id = session['user_id']
    settings_ref = db.collection('users').document(user_id).collection('settings').document('notifications')
    
    if request.method == 'POST':
        notification_settings = {
            'email_notifications': bool(request.form.get('email_notifications')),
            'hot_deals': bool(request.form.get('hot_deals')),
            'ad_info': bool(request.form.get('ad_info')),
            'premium_packages': bool(request.form.get('premium_packages')),
            'subscriptions': bool(request.form.get('subscriptions')),
            'messages': bool(request.form.get('messages')),
            'feedback': bool(request.form.get('feedback')),
            'sms_info': bool(request.form.get('sms_info')),
            'web_notification': bool(request.form.get('web_notification')),
        }
        
        # Use set with merge=True to update or create the document
        settings_ref.set(notification_settings, merge=True)
        flash('Notification preferences updated!', 'success')
        return redirect(url_for('manage_notifications'))
        
    # GET request: Fetch existing settings
    settings_doc = settings_ref.get()
    settings = settings_doc.to_dict() if settings_doc.exists else {}
    return render_template('notifications.html', settings=settings)

@app.route('/mark_all_read', methods=['POST'])
@login_required
def mark_all_read():
    user_id = session['user_id']
    notifications_ref = db.collection('users').document(user_id).collection('notifications')
    
    try:
        # Get all unread notifications for the user
        unread_notifications = notifications_ref.where('is_read', '==', False).stream()
        
        batch = db.batch()
        for doc in unread_notifications:
            batch.update(doc.reference, {'is_read': True})
        
        batch.commit()
        flash('All notifications marked as read.', 'success')
    except Exception as e:
        flash(f'Error marking notifications as read: {str(e)}', 'danger')
        
    return redirect(url_for('manage_notifications'))

@app.route('/clear_notifications', methods=['POST'])
@login_required
def clear_notifications():
    user_id = session['user_id']
    notifications_ref = db.collection('users').document(user_id).collection('notifications')
    
    try:
        # Get all notifications for the user
        all_notifications = notifications_ref.stream()
        
        batch = db.batch()
        for doc in all_notifications:
            batch.delete(doc.reference)
        
        batch.commit()
        flash('All notifications cleared.', 'success')
    except Exception as e:
        flash(f'Error clearing notifications: {str(e)}', 'danger')
        
    return redirect(url_for('manage_notifications'))

@app.route('/follow/<string:user_id>', methods=['POST'])
@login_required
def follow_user(user_id):
    current_user_id = session['user_id']
    if current_user_id == user_id:
        flash("You cannot follow yourself.", "warning")
        return redirect(request.referrer)

    # A document in the `followers` collection represents a single follower relationship.
    # The document ID is a composite of the follower and followed user IDs.
    follow_ref = db.collection('followers').document(f'{current_user_id}_{user_id}')
    
    try:
        if not follow_ref.get().exists:
            follow_ref.set({
                'follower_id': current_user_id,
                'followed_id': user_id,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            
            # --- NOTIFICATION TRIGGER: New Follower ---
            followed_username = get_username(user_id)
            follower_username = get_username(current_user_id)
            create_notification(
                user_id=user_id,
                notification_type='new_follower',
                notification_message=f"{follower_username} is now following you!",
                follower_id=current_user_id
            )
            flash("You are now following this user.", "success")
        else:
            flash("You are already following this user.", "info")
    except Exception as e:
        flash(f"Error following user: {e}", "danger")
    
    return redirect(request.referrer)

@app.route('/unfollow/<string:user_id>', methods=['POST'])
@login_required
def unfollow_user(user_id):
    current_user_id = session['user_id']
    if current_user_id == user_id:
        flash("You cannot unfollow yourself.", "warning")
        return redirect(request.referrer)
    
    follow_ref = db.collection('followers').document(f'{current_user_id}_{user_id}')
    
    try:
        if follow_ref.get().exists:
            follow_ref.delete()
            flash("You have unfollowed this user.", "success")
        else:
            flash("You were not following this user.", "info")
    except Exception as e:
        flash(f"Error unfollowing user: {e}", "danger")
        
    return redirect(request.referrer)


# --- API Routes for following/followers list ---

@app.route('/api/followers', methods=['GET'])
@login_required
def get_followers_api():
    current_user_id = session['user_id']
    followers_ref = db.collection('followers').where('followed_id', '==', current_user_id)
    
    followers_list = []
    
    # Get all follower_ids and then fetch their user details
    follower_ids = [doc.to_dict()['follower_id'] for doc in followers_ref.stream()]
    if follower_ids:
        # Batch get user documents
        users_ref = db.collection('users')
        user_docs = [users_ref.document(uid).get() for uid in follower_ids]
        
        for doc in user_docs:
            if doc.exists:
                user_data = doc.to_dict()
                followers_list.append({
                    'id': doc.id,
                    'username': user_data.get('username', 'Unknown User'),
                    'profile_picture': user_data.get('profile_picture', ''),
                    'is_followed_by_current_user': True # Since these are followers, current user is following them back if they exist.
                })
    
    return jsonify({'followers': followers_list})

@app.route('/api/following', methods=['GET'])
@login_required
def get_following():
    user_id = session['user_id']
    following_ref = db.collection('followers').where('follower_id', '==', user_id)
    
    following_list = []
    followed_ids = [doc.to_dict()['followed_id'] for doc in following_ref.stream()]
    if followed_ids:
        users_ref = db.collection('users')
        user_docs = [users_ref.document(uid).get() for uid in followed_ids]
        
        for doc in user_docs:
            if doc.exists:
                user_data = doc.to_dict()
                following_list.append({
                    'id': doc.id,
                    'username': user_data.get('username', 'Unknown User'),
                    'profile_picture': user_data.get('profile_picture', ''),
                    'is_followed_by_current_user': True
                })

    return jsonify({'following': following_list})

@app.route('/toggle_follow/<string:target_user_id>', methods=['POST'])
@login_required
def toggle_follow(target_user_id):
    current_user_id = session['user_id']
    if current_user_id == target_user_id:
        return jsonify({'success': False, 'message': 'Cannot follow or unfollow yourself'}), 400

    follow_ref = db.collection('followers').document(f'{current_user_id}_{target_user_id}')
    action = request.args.get('action')

    try:
        follow_doc = follow_ref.get()
        if action == 'follow':
            if follow_doc.exists:
                return jsonify({'success': False, 'message': 'Already following'}), 409
            
            follow_ref.set({
                'follower_id': current_user_id,
                'followed_id': target_user_id,
                'timestamp': firestore.SERVER_TIMESTAMP
            })
            
            follower_username = get_username(current_user_id)
            create_notification(
                user_id=target_user_id,
                notification_type='new_follower',
                notification_message=f"{follower_username} is now following you!",
                follower_id=current_user_id
            )
            return jsonify({'success': True, 'is_following': True, 'message': 'Successfully followed user.'})

        elif action == 'unfollow':
            if not follow_doc.exists:
                return jsonify({'success': False, 'message': 'Not currently following this user.'}), 404
            
            follow_ref.delete()
            return jsonify({'success': True, 'is_following': False, 'message': 'Successfully unfollowed user.'})
        
        else:
            return jsonify({'success': False, 'message': 'Invalid action specified'}), 400

    except Exception as e:
        print(f"Error in toggle_follow: {e}")
        return jsonify({'success': False, 'message': f'An unexpected error occurred: {e}'}), 500

@app.route('/search-users', methods=['GET'])
def search_users():
    query = request.args.get('query', '').strip()
    if not query:
        return jsonify({'users': []})

    # Firestore can't do a full LIKE query. This performs a search for usernames that *start with* the query.
    users_ref = db.collection('users').where('username', '>=', query).where('username', '<', query + '\uf8ff')
    
    users = []
    
    try:
        # Check if the user is logged in to determine follow status
        current_user_id = session.get('user_id')
        followed_ids = set()
        if current_user_id:
            following_refs = db.collection('followers').where('follower_id', '==', current_user_id).stream()
            followed_ids = {doc.to_dict()['followed_id'] for doc in following_refs}
            
        for doc in users_ref.stream():
            user_data = doc.to_dict()
            if doc.id == current_user_id:
                continue # Don't show the current user in search results
            
            users.append({
                'id': doc.id,
                'username': user_data.get('username', ''),
                'profile_picture': user_data.get('profile_picture', ''),
                'is_followed': doc.id in followed_ids
            })
        
        return jsonify({'users': users})
    except Exception as e:
        print(f"Error in search-users: {e}")
        return jsonify({'users': []})

        
        
        
        
        
        
        
        

        
        
        
@app.route('/leaderboard')
def leaderboard():
    """
    Fetches user data from Firestore to display a leaderboard.
    """
    user_id = session.get('user_id')
    leaderboard_users = []
    referral_link = "#"
    followed_ids = set()

    try:
        # 1. Fetch leaderboard data from Firestore
        # The .order_by() method replaces the SQL 'ORDER BY referral_count DESC' clause.
        users_ref = db.collection('users').order_by('referral_count', direction=firestore.Query.DESCENDING).stream()
        for doc in users_ref:
            user_data = doc.to_dict()
            leaderboard_users.append({
                'id': doc.id,
                'username': user_data.get('username', 'N/A'),
                'profile_picture': user_data.get('profile_picture', get_profile_picture_url(doc.id)),
                'referral_count': user_data.get('referral_count', 0)
            })

        if user_id:
            # 2. Fetch the current user's referral code and generate the link
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists:
                referral_code = user_doc.to_dict().get('referral_code')
                if referral_code:
                    referral_link = f"http://127.0.0.1:5000/signup?ref={referral_code}"

            # 3. Fetch the list of user IDs the current user is following
            # We assume a 'followers' collection where each document stores who is following whom.
            followers_ref = db.collection('followers').where(filter=FieldFilter('follower_id', '==', user_id)).stream()
            followed_ids = {doc.to_dict().get('followed_id') for doc in followers_ref if doc.to_dict().get('followed_id')}

    except Exception as e:
        logger.error(f"Error fetching leaderboard data from Firestore: {e}", exc_info=True)
        flash('An error occurred while fetching the leaderboard.', 'error')

    # Pass the data to the template
    return render_template('leaderboard.html', leaderboard=leaderboard_users, referral_link=referral_link, followed_ids=followed_ids)











def fetch_posts_for_display(page_category, search_query=None):
    """
    Fetches posts for a specific category from Firestore.
    Note: Firestore does not support full-text search like SQL's LIKE.
    This implementation performs a basic prefix search. For full-text search,
    a dedicated service like Algolia or Elasticsearch would be recommended.
    """
    print(f"[DEBUG] Fetching posts for: {page_category}")
    posts_ref = db.collection('posts').where('display_on', 'array_contains', page_category).order_by('post_date', direction=firestore.Query.DESCENDING)
    
    posts = []
    
    # In-memory filtering for search since Firestore doesn't support 'OR' queries on different fields.
    if search_query:
        search_query_lower = search_query.lower()
        for doc in posts_ref.stream():
            post_data = doc.to_dict()
            if search_query_lower in post_data.get('title', '').lower() or search_query_lower in post_data.get('content', '').lower():
                posts.append(post_data)
    else:
        for doc in posts_ref.stream():
            posts.append(doc.to_dict())
            
    print(f"[DEBUG] Found {len(posts)} posts")
    return posts

def get_user_data(user_id):
    """Fetches user data from the 'users' collection."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()
    return user_doc.to_dict() if user_doc.exists else None

def get_all_categories():
    """Fetches all categories from the 'categories' collection."""
    categories_ref = db.collection('categories').order_by('name')
    categories = [doc.to_dict() for doc in categories_ref.stream()]
    return categories

def get_subcategories_by_category_id(category_id):
    """Fetches subcategories for a given category ID."""
    if not category_id:
        return []
    
    subcategories_ref = db.collection('subcategories').where('category_id', '==', category_id).order_by('name')
    subcategories = [doc.to_dict() for doc in subcategories_ref.stream()]
    return subcategories

def generate_otp():
    """Generates a 6-digit OTP."""
    return f"{random.randint(100000, 999999)}"

# --- Routes ---

@app.route('/change-phone', methods=['GET', 'POST'])
@login_required
def change_phone():
    user_id = session['user_id']
    user_ref = db.collection('users').document(user_id)
    
    if request.method == 'POST':
        new_phone_number_digits = request.form.get('new_phone_number')
        
        # --- Server-Side Validation ---
        if not new_phone_number_digits:
            flash("Phone number cannot be empty.", "error")
            return redirect(url_for('change_phone'))
        
        if not re.fullmatch(r'\d{10}', new_phone_number_digits):
            flash("Phone number must be exactly 10 digits and contain only numbers.", "error")
            return redirect(url_for('change_phone'))
            
        if not re.match(r'^[789]', new_phone_number_digits):
            flash("Phone number must start with 7, 8, or 9.", "error")
            return redirect(url_for('change_phone'))
            
        # If all validations pass, proceed to save the phone number
        try:
            phone_to_save = '+234' + new_phone_number_digits
            
            # Update user's phone number in the database
            user_ref.update({'phone_number': phone_to_save})
            
            # Here you would typically trigger the OTP sending process
            # ... (e.g., call an external SMS service)
            
            flash("Your phone number has been successfully updated!", "success")
            return redirect(url_for('profile'))
            
        except Exception as e:
            flash(f"An error occurred while updating your phone number: {str(e)}", "error")
            return redirect(url_for('change_phone'))
    else:
        # GET request: show current phone number details
        user_doc = user_ref.get()
        user = user_doc.to_dict() if user_doc.exists else {}
        
        # Pass the 'user' object to the template.
        return render_template('change_phone_number.html', user=user)


@app.route('/change-email', methods=['GET', 'POST'])
@login_required
def change_email():
    user_id = session.get('user_id')
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()

    if request.method == 'POST':
        new_email = request.form.get('email').strip()

        if not new_email:
            flash("Email cannot be empty.", "danger")
            return redirect(url_for('change_email'))

        if not re.match(r"[^@]+@[^@]+\.[^@]+", new_email):
            flash("Please enter a valid email address.", "error")
            return redirect(url_for('change_email'))

        # Check if email already exists for another user in Firestore
        users_with_email = db.collection('users').where('email', '==', new_email).limit(1).get()
        if users_with_email:
            existing_user_doc = users_with_email[0]
            if existing_user_doc.id != user_id:
                flash("This email address is already registered to another account.", "error")
                return redirect(url_for('change_email'))

        # Check last OTP sent time to enforce cooldown (e.g., 2 min)
        last_sent_at = user_data.get('last_email_otp_sent_at')
        now = datetime.now(UTC)
        if last_sent_at and (now - last_sent_at.replace(tzinfo=None)) < timedelta(minutes=2):
            flash("Please wait at least 2 minutes before requesting a new OTP.", "warning")
            return redirect(url_for('change_email'))

        # Generate OTP and expiry
        otp = generate_otp()
        expiry_time = now + timedelta(minutes=10)

        try:
            # Update user with new email, OTP, expiry, and last sent time
            # Note: We don't set 'is_verified' to False here as this only changes the pending email.
            # The 'is_verified' field is only updated after successful verification.
            user_ref.update({
                'new_email': new_email,  # Store the new email separately
                'email_verification_code': otp,
                'email_code_expiry': expiry_time,
                'last_email_otp_sent_at': now
            })

            if send_email_otp(new_email, otp):
                flash("Verification code sent to your email. Please check your inbox.", "info")
                return redirect(url_for('verify_email'))
            else:
                flash("Failed to send email verification code. Please try again.", "danger")
                return redirect(url_for('change_email'))
        except Exception as e:
            flash(f"An unexpected error occurred: {str(e)}", "error")
            return redirect(url_for('change_email'))
    else:
        # GET: load current email info
        return render_template('change_email.html', user=user_data)


@app.route('/verify-email', methods=['GET', 'POST'])
@login_required
def verify_email():
    user_id = session.get('user_id')
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()

    # Check if a verification process is pending
    if not user_data.get('email_verification_code'):
        flash('No active verification process found. Please request a new OTP.', 'warning')
        return redirect(url_for('change_email'))

    if request.method == 'POST':
        otp_input = request.form.get('otp').strip()
        now = datetime.now(UTC)

        # Check expiry
        expiry = user_data.get('email_code_expiry')
        if not expiry or now > expiry.replace(tzinfo=None):
            flash('OTP has expired. Please request a new code.', 'danger')
            # Clear expired OTP fields from DB
            user_ref.update({
                'email_verification_code': firestore.DELETE_FIELD,
                'email_code_expiry': firestore.DELETE_FIELD,
                'last_email_otp_sent_at': firestore.DELETE_FIELD
            })
            return redirect(url_for('change_email'))

        # Verify OTP
        if otp_input == user_data['email_verification_code']:
            try:
                # Atomically update the primary email and verification status, and clear OTP fields.
                user_ref.update({
                    'email': user_data['new_email'],  # Update the primary email
                    'is_verified': True,
                    'new_email': firestore.DELETE_FIELD,
                    'email_verification_code': firestore.DELETE_FIELD,
                    'email_code_expiry': firestore.DELETE_FIELD,
                    'last_email_otp_sent_at': firestore.DELETE_FIELD
                })
                flash('Email verified successfully!', 'success')
                return redirect(url_for('profile'))
            except Exception as e:
                flash(f"An unexpected error occurred during verification: {str(e)}", "error")
                return redirect(url_for('change_email'))
        else:
            flash('Incorrect OTP. Please try again.', 'danger')
            return redirect(url_for('verify_email'))
    else:
        # For GET request, check if an OTP is pending
        if not user_data.get('email_verification_code'):
            flash("No active email verification pending. Please request a new OTP.", "info")
            return redirect(url_for('change_email'))
        
        return render_template('verify_email.html', user=user_data)


@app.route('/resend-email-otp', methods=['POST'])
@login_required
def resend_email_otp():
    user_id = session.get('user_id')
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        flash("User not found.", "error")
        return redirect(url_for('login'))

    user_data = user_doc.to_dict()

    if not user_data.get('new_email'):
        flash('No email found to resend OTP. Please set your email first.', 'warning')
        return redirect(url_for('change_email'))

    now = datetime.now(UTC)
    last_sent = user_data.get('last_email_otp_sent_at')

    if last_sent and (now - last_sent.replace(tzinfo=None)) < timedelta(minutes=2):
        flash('Please wait at least 2 minutes before requesting a new OTP.', 'warning')
        return redirect(url_for('verify_email'))

    # Generate and send new OTP
    otp = generate_otp()
    expiry_time = now + timedelta(minutes=10)

    try:
        user_ref.update({
            'email_verification_code': otp,
            'email_code_expiry': expiry_time,
            'last_email_otp_sent_at': now
        })

        if send_email_otp(user_data['new_email'], otp):
            flash('Verification code resent to your email.', 'success')
        else:
            flash('Failed to resend email verification code. Please try again.', 'danger')
    except Exception as e:
        flash(f"An unexpected error occurred: {str(e)}", "error")
    
    return redirect(url_for('verify_email'))



# --- Configuration for Bank Transfers ---
BANK_ACCOUNT_DETAILS = {
    "account_name": "AGWU JAMES NWOKE.",
    "account_number": "2266701415",
    "bank_name": "ZENITH BANK PLC",
    "currency": "NGN"
}

# --- Helper Functions (Firestore) ---

def get_plan_details(plan_id):
    """
    Fetches a single plan's details from the 'plans' Firestore collection by ID.
    Returns None if the plan is not found.
    """
    try:
        plan_ref = db.collection('plans').document(plan_id)
        plan_doc = plan_ref.get()
        if plan_doc.exists:
            return plan_doc.to_dict()
        else:
            return None
    except exceptions.NotFound:
        # This is handled by plan_doc.exists, but good to have for robustness
        logger.error(f"Firestore plan document not found for plan_id {plan_id}.")
        return None
    except Exception as e:
        logger.error(f"Firestore error fetching plan details for plan_id {plan_id}: {e}")
        return None


def get_all_plans_from_db():
    """Fetches all available subscription plans from the 'plans' collection."""
    try:
        plans_ref = db.collection('plans').order_by('amount', direction=firestore.Query.ASCENDING)
        plans = [doc.to_dict() for doc in plans_ref.stream()]
        return plans
    except Exception as e:
        logger.error(f"Firestore error fetching all plans: {e}")
        return []

def generate_unique_reference():
    """Generates a unique payment reference number."""
    return f"REF-{uuid.uuid4().hex[:10].upper()}-{int(time.time())}"


def update_subscription_status(payment_reference, new_status, transaction_amount=None, transaction_currency=None):
    """
    Updates the status of a subscription in the 'subscriptions' collection.
    It first finds the subscription document by the unique payment reference.
    """
    try:
        # Find the subscription document by payment_reference
        subscriptions_ref = db.collection('subscriptions')
        query = subscriptions_ref.where('payment_reference', '==', payment_reference).limit(1)
        docs = query.get()

        if not docs:
            logger.warning(f"Subscription with reference {payment_reference} not found.")
            return False

        subscription_doc = docs[0]
        subscription_data = subscription_doc.to_dict()

        if new_status == 'active':
            if subscription_data.get('status') == 'active':
                logger.info(f"Subscription with reference {payment_reference} is already active. No update needed.")
                return True
            if subscription_data.get('status') == 'failed':
                logger.warning(f"Subscription with reference {payment_reference} is in 'failed' status. Cannot activate directly.")
                return False

            plan_id = subscription_data.get('plan_id')
            plan_details = get_plan_details(plan_id)

            if plan_details:
                duration_days = plan_details['duration_days']
                expiry_date = datetime.now() + timedelta(days=duration_days)

                # Update the subscription document with the new status and expiry date
                subscription_doc.reference.update({
                    'status': new_status,
                    'expiry_date': expiry_date,
                    'transaction_amount': transaction_amount,
                    'transaction_currency': transaction_currency,
                    'updated_at': firestore.SERVER_TIMESTAMP # Use server timestamp for consistency
                })
            else:
                logger.error(f"Plan details not found for plan_id {plan_id} linked to subscription reference {payment_reference} during activation.")
                return False
        else: # For 'pending' or 'failed' statuses
            subscription_doc.reference.update({
                'status': new_status,
                'transaction_amount': transaction_amount,
                'transaction_currency': transaction_currency,
                'updated_at': firestore.SERVER_TIMESTAMP
            })

        logger.info(f"Subscription with reference {payment_reference} successfully updated to status: {new_status}.")
        return True
    except Exception as e:
        logger.error(f"Firestore error updating subscription status for reference {payment_reference}: {e}")
        return False


# --- Routes ---

@app.route('/bank_transfer_instructions')
def bank_transfer_instructions_page():
    # Data is still retrieved from the session, so this route needs minimal changes
    account_details = session.pop('bank_account_details', None)
    amount = session.pop('bank_transfer_amount', None)
    plan_name = session.pop('bank_transfer_plan_name', None)
    payment_reference = session.pop('payment_reference', None)

    if not all([account_details, amount, plan_name, payment_reference]):
        flash("No bank transfer instructions found. Please try subscribing again.", 'error')
        return redirect(url_for('subscribe'))

    try:
        # Cast amount to float to ensure it's a number
        amount = float(amount)
    except (ValueError, TypeError):
        flash("Invalid amount detected. Please try subscribing again.", 'error')
        logger.error(f"Failed to convert amount '{amount}' to float for bank transfer instructions.")
        return redirect(url_for('subscribe'))

    return render_template('bank_transfer_instructions.html',
                           account_details=account_details,
                           amount=amount,
                           plan_name=plan_name,
                           payment_reference=payment_reference)



def create_notification(user_id, notification_type, message, related_id=None):
    """
    Creates a new notification document in the 'notifications' collection.
    This function should be implemented in your application.
    """
    try:
        notification_data = {
            'user_id': user_id,
            'type': notification_type,
            'message': message,
            'related_id': related_id,
            'created_at': firestore.SERVER_TIMESTAMP,
            'read': False
        }
        db.collection('notifications').add(notification_data)
        return True
    except Exception as e:
        logging.error(f"Failed to create notification for user {user_id}: {e}")
        return False

# --- Refactored Routes (Firestore) ---

@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login first.', 'error')
        return redirect(url_for('login'))

    user_info = get_user_info(user_id)
    if not user_info:
        flash('User information not found. Please try logging in again.', 'error')
        return redirect(url_for('login'))

    all_plans = get_all_plans_from_db()
    if not all_plans:
        flash('No subscription plans available at this time. Please try again later.', 'error')
        return redirect(url_for('profile'))

    if request.method == 'POST':
        selected_plan_id_str = request.form.get('plan')
        payment_method_selected = request.form.get('payment_method')

        if not selected_plan_id_str:
            flash('Please select a subscription plan.', 'error')
            return render_template('subscribe.html', user_email=user_info['email'], plans=all_plans)

        selected_plan = next((p for p in all_plans if p['id'] == selected_plan_id_str), None)

        if not selected_plan:
            flash('Selected plan details could not be found. Please try again.', 'error')
            return render_template('subscribe.html', user_email=user_info['email'], plans=all_plans)

        plan_name = selected_plan['name']
        plan_amount = selected_plan['amount']
        plan_duration_days = selected_plan['duration_days']

        # Handle Free Promo Plan
        if plan_name == 'Free Promo Plan':
            try:
                # Firestore query to check if the user has an active Free Promo Plan
                query_ref = db.collection('subscriptions').where('user_id', '==', user_id).where('plan_name', '==', 'Free Promo Plan').where('status', '==', 'active').limit(1)
                docs = query_ref.get()
                free_promo_used = len(docs) > 0
            except Exception as e:
                logging.error(f"Firestore error checking free promo usage for user {user_id}: {e}")
                flash('An internal error occurred. Please try again.', 'error')
                return redirect(url_for('subscribe'))
            
            if free_promo_used:
                flash('You have already used your Free Promo Plan.', 'error')
                return redirect(url_for('subscribe'))
            else:
                expiry_date = date.today() + timedelta(days=plan_duration_days)
                try:
                    subscription_data = {
                        'user_id': user_id,
                        'plan_id': selected_plan.get('id'), # Assuming the plan ID is a string in Firestore
                        'plan_name': plan_name,
                        'status': 'active',
                        'start_date': datetime.now(),
                        'expiry_date': expiry_date,
                        'payment_reference': 'FREE_PROMO_ACTIVATED',
                        'transaction_amount': 0.00,
                        'transaction_currency': 'N/A'
                    }
                    db.collection('subscriptions').add(subscription_data)
                    flash(f'Successfully subscribed to {plan_name}!', 'success')
                    return redirect(url_for('profile'))
                except Exception as e:
                    logging.error(f"Firestore error activating free promo plan for user {user_id}: {e}")
                    flash('An error occurred while activating your free plan. Please try again.', 'error')
                    return redirect(url_for('subscribe'))
        
        # Handle Bank Transfer Payment
        if payment_method_selected == 'bank':
            payment_reference = generate_unique_reference()
            expiry_date = date.today() + timedelta(days=plan_duration_days)

            try:
                subscription_data = {
                    'user_id': user_id,
                    'plan_id': selected_plan.get('id'),
                    'plan_name': plan_name,
                    'status': 'pending',
                    'start_date': datetime.now(),
                    'expiry_date': expiry_date,
                    'payment_reference': payment_reference,
                    'transaction_amount': plan_amount,
                    'transaction_currency': BANK_ACCOUNT_DETAILS['currency']
                }
                db.collection('subscriptions').add(subscription_data)
                
                session['bank_transfer_amount'] = float(plan_amount)
                session['bank_account_details'] = BANK_ACCOUNT_DETAILS
                session['bank_transfer_plan_name'] = plan_name
                session['payment_reference'] = payment_reference

                return redirect(url_for('bank_transfer_instructions_page'))
            except Exception as e:
                logging.error(f"Error saving pending bank transfer subscription for user {user_id}: {e}")
                flash('An error occurred while preparing your bank transfer subscription. Please try again.', 'error')
                return redirect(url_for('subscribe'))
        else:
            flash('Invalid payment method selected. Please choose Bank Transfer.', 'error')
            return render_template('subscribe.html', user_email=user_info['email'], plans=all_plans)

    else:
        # GET request
        return render_template('subscribe.html', user_email=user_info['email'], plans=all_plans)


@app.route('/confirm_bank_transfer', methods=['GET', 'POST'])
def confirm_bank_transfer():
    # --- Role-based Access Control ---
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to access this page.', 'warning')
        return redirect(url_for('login'))

    user_info = get_user_info(user_id)
    if not user_info or user_info.get('role') != 'admin':
        flash('Access Denied: You do not have administrative privileges to view this page.', 'error')
        return redirect(url_for('home'))

    # --- End Role-based Access Control ---

    if request.method == 'POST':
        payment_reference = request.form.get('payment_reference')
        action = request.form.get('action')

        if not payment_reference:
            flash('Payment reference is required.', 'error')
            return redirect(url_for('confirm_bank_transfer'))

        try:
            subscriptions_ref = db.collection('subscriptions')
            query = subscriptions_ref.where('payment_reference', '==', payment_reference).limit(1)
            docs = query.get()

            if not docs:
                flash(f'No subscription found for reference: {payment_reference}. Please check the reference.', 'error')
                return redirect(url_for('confirm_bank_transfer'))

            subscription = docs[0].to_dict()
            current_status = subscription.get('status')
            transaction_amount = subscription.get('transaction_amount')
            transaction_currency = subscription.get('transaction_currency')
            subscriber_user_id = subscription.get('user_id')
            plan_name = subscription.get('plan_name')

            if action == 'confirm':
                if current_status == 'active':
                    flash(f'Subscription with reference {payment_reference} is already active. No action needed.', 'info')
                elif current_status == 'failed':
                    flash(f'Subscription with reference {payment_reference} was previously marked as failed. Please consider creating a new subscription if payment is received now.', 'warning')
                elif current_status == 'pending':
                    if update_subscription_status(payment_reference, 'active', transaction_amount, transaction_currency):
                        flash(f'Subscription {payment_reference} successfully confirmed and activated!', 'success')
                        notification_message = f"Your payment for '{plan_name}' subscription has been confirmed and your subscription is now active!"
                        create_notification(subscriber_user_id, 'subscription_activated', notification_message, related_id=docs[0].id)
                        logging.info(f"Notification sent to user {subscriber_user_id} for activated subscription {docs[0].id}.")
                    else:
                        flash(f'Failed to activate subscription {payment_reference}. An internal error occurred. Check server logs.', 'error')
                else:
                    flash(f'Subscription {payment_reference} is in an unexpected status ({current_status}). Cannot activate.', 'error')

            elif action == 'fail':
                if current_status == 'failed':
                    flash(f'Subscription with reference {payment_reference} is already marked as failed. No action needed.', 'info')
                elif current_status == 'active':
                    flash(f'Subscription with reference {payment_reference} is currently active. Cannot mark as failed. Manual deactivation required if necessary.', 'warning')
                else:
                    if update_subscription_status(payment_reference, 'failed', transaction_amount, transaction_currency):
                        flash(f'Subscription {payment_reference} successfully marked as failed.', 'info')
                    else:
                        flash(f'Failed to mark subscription {payment_reference} as failed. An internal error occurred. Check server logs.', 'error')
            else:
                flash('Invalid action requested.', 'error')

            return redirect(url_for('confirm_bank_transfer'))
        except Exception as e:
            logging.error(f"Error during bank transfer confirmation/failure for reference {payment_reference}: {e}", exc_info=True)
            flash('An unexpected error occurred. Please try again.', 'error')
            return redirect(url_for('confirm_bank_transfer'))

    # GET request: Display the confirmation form
    return render_template('confirm_bank_transfer.html')

# --- Webhook Handler (Refactored for Firestore) ---
@app.route('/webhook/bank_transfer_confirmation', methods=['POST'])
def bank_transfer_webhook():
    data = request.json
    if not data:
        logging.error("Bank transfer webhook received with no data.")
        return '', 400

    payment_reference = data.get('reference')
    transfer_amount = data.get('amount')
    transfer_currency = data.get('currency', BANK_ACCOUNT_DETAILS['currency'])
    transfer_status = data.get('status')

    logging.info(f"Received bank transfer webhook: {data}")

    if not all([payment_reference, transfer_amount, transfer_status]):
        logging.warning(f"Bank transfer webhook missing essential data. Payload: {data}")
        return '', 400

    if transfer_status == 'completed':
        try:
            subscriptions_ref = db.collection('subscriptions')
            query = subscriptions_ref.where('payment_reference', '==', payment_reference).limit(1)
            docs = query.get()

            if not docs:
                logging.warning(f"No subscription found for bank transfer webhook reference: {payment_reference}.")
                return '', 404

            sub_info = docs[0].to_dict()

            if sub_info['status'] == 'active':
                logging.info(f"Subscription for reference {payment_reference} is already active, webhook ignored.")
                return '', 200

            expected_amount = float(sub_info['transaction_amount'])
            received_amount = float(transfer_amount)

            if received_amount >= expected_amount:
                if update_subscription_status(payment_reference, 'active', transfer_amount, transfer_currency):
                    logging.info(f"Bank transfer for reference {payment_reference} successfully confirmed and subscription activated.")
                    return '', 200
                else:
                    logging.error(f"Failed to activate subscription via webhook for reference {payment_reference}. Check update_subscription_status logs.")
                    return '', 500
            else:
                logging.warning(f"Bank transfer amount mismatch for reference {payment_reference}. Expected at least {expected_amount}, received {received_amount}.")
                if update_subscription_status(payment_reference, 'failed', transfer_amount, transfer_currency):
                    logging.info(f"Bank transfer for reference {payment_reference} marked failed due to amount mismatch.")
                    return '', 200
                else:
                    logging.error(f"Failed to mark subscription as failed due to amount mismatch for reference {payment_reference}.")
                    return '', 500
        except Exception as e:
            logging.exception(f"Error processing bank transfer webhook for reference {payment_reference}: {e}")
            return '', 500

    elif transfer_status == 'failed':
        if update_subscription_status(payment_reference, 'failed', transfer_amount, transfer_currency):
            logging.info(f"Bank transfer for reference {payment_reference} marked as failed.")
            return '', 200
        else:
            logging.error(f"Failed to mark subscription as failed via webhook for reference {payment_reference}.")
            return '', 500
    else:
        logging.info(f"Bank transfer webhook with unhandled status: {transfer_status} for reference {payment_reference}.")
        return '', 200     
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            



def get_followers_of_user(user_id):
    """
    Retrieves the user IDs of all users who are following the given user
    using Firestore. Assumes a 'followers' collection where each document
    has 'follower_id' and 'followed_id' fields.
    """
    followers_ids = []
    try:
        # Query Firestore for all documents where 'followed_id' matches the user_id
        followers_ref = db.collection('followers').where('followed_id', '==', user_id).stream()
        for doc in followers_ref:
            followers_ids.append(doc.to_dict()['follower_id'])
    except Exception as e:
        logging.error(f"Firestore error getting followers for user {user_id}: {e}", exc_info=True)
    return followers_ids

def is_admin():
    """
    Checks if the currently logged-in user is an admin.
    Assumes a 'users' collection with user_id as the document ID and a 'role' field.
    """
    user_id = session.get('user_id')
    if not user_id:
        return False
    try:
        user_doc = db.collection('users').document(user_id).get()
        # Check if the document exists and the 'role' field is 'admin'
        return user_doc.exists and user_doc.to_dict().get('role') == 'admin'
    except Exception as e:
        logging.error(f"Firestore error checking admin status for user {user_id}: {e}", exc_info=True)
        return False
        
def admin_required(f):
    """
    A decorator to protect routes, ensuring only logged-in admin users can access them.
    Assumes a Flask `login_required` decorator is also in use.
    """
    @wraps(f)
    # The original code had @login_required, which should be placed here
    # @login_required 
    def wrap(*args, **kwargs):
        user_id = session.get('user_id')
        if not user_id:
            flash('Please log in to view this page.', 'warning')
            return redirect(url_for('login'))
        
        try:
            user_doc = db.collection('users').document(user_id).get()
            if user_doc.exists and user_doc.to_dict().get('role') == 'admin':
                return f(*args, **kwargs)
            else:
                flash('Access denied: You do not have administrator privileges.', 'error')
                return redirect(url_for('home'))
        except Exception as e:
            logging.error(f"Firestore error checking admin privileges: {e}", exc_info=True)
            flash('An unexpected error occurred during authorization.', 'error')
            return redirect(url_for('home'))
            
    return wrap

def get_user_info(user_id):
    """Fetches a user's information from Firestore, including username and role."""
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict()
        return None
    except Exception as e:
        logging.error(f"Firestore error getting user info for {user_id}: {e}", exc_info=True)
        return None

def get_all_categories():
    """Fetches all main categories from Firestore."""
    categories = []
    try:
        categories_ref = db.collection('categories').order_by('name').stream()
        categories = [{'id': doc.id, **doc.to_dict()} for doc in categories_ref]
        return categories
    except Exception as e:
        logging.error(f"Firestore error fetching categories: {e}", exc_info=True)
        return []

def get_subcategories_by_category_id(category_id):
    """Fetches subcategories for a given category ID from Firestore."""
    subcategories = []
    try:
        subcategories_ref = db.collection('subcategories').where('category_id', '==', category_id).order_by('name').stream()
        subcategories = [{'id': doc.id, **doc.to_dict()} for doc in subcategories_ref]
        return subcategories
    except Exception as e:
        logging.error(f"Firestore error fetching subcategories for category_id {category_id}: {e}", exc_info=True)
        return []

def get_plan_details(plan_id):
    """Fetches a single plan's details from Firestore by ID."""
    try:
        plan_doc = db.collection('plans').document(plan_id).get()
        if plan_doc.exists:
            return {'id': plan_doc.id, **plan_doc.to_dict()}
        return None
    except Exception as e:
        logging.error(f"Firestore error fetching plan details for plan_id {plan_id}: {e}", exc_info=True)
        return None

def get_all_plans_from_db():
    """Fetches all available subscription plans from Firestore."""
    plans = []
    try:
        plans_ref = db.collection('plans').order_by('amount').stream()
        plans = [{'id': doc.id, **doc.to_dict()} for doc in plans_ref]
        return plans
    except Exception as e:
        logging.error(f"Firestore error fetching all plans: {e}", exc_info=True)
        return []

def generate_unique_reference():
    """Generates a unique payment reference number."""
    return f"REF-{uuid.uuid4().hex[:10].upper()}-{int(time.time())}"

def update_subscription_status(payment_reference, new_status, transaction_amount=None, transaction_currency=None):
    """Updates the status of a subscription in Firestore."""
    try:
        # Find the subscription document by payment reference
        subscriptions_ref = db.collection('subscriptions')
        query = subscriptions_ref.where('payment_reference', '==', payment_reference).limit(1)
        docs = query.get()

        if not docs:
            logging.warning(f"Subscription with reference {payment_reference} not found for update attempt.")
            return False

        doc_ref = docs[0].reference
        sub_info = docs[0].to_dict()

        if sub_info.get('status') == 'active' and new_status == 'active':
            logging.info(f"Subscription with reference {payment_reference} is already active. No update needed.")
            return True

        update_data = {
            'status': new_status,
            'transaction_amount': transaction_amount,
            'transaction_currency': transaction_currency
        }

        if new_status == 'active':
            plan_id = sub_info.get('plan_id')
            plan_details = get_plan_details(plan_id)
            if plan_details:
                duration_days = plan_details.get('duration_days', 0)
                expiry_date = datetime.now() + timedelta(days=duration_days)
                update_data['expiry_date'] = expiry_date
                
                doc_ref.update(update_data)
                
                # Also update user's subscription_status in users collection
                user_doc_ref = db.collection('users').document(sub_info.get('user_id'))
                user_doc_ref.update({'subscription_status': plan_details.get('name')})
                
            else:
                logging.error(f"Plan details not found for plan_id {plan_id} during activation.")
                return False
        else: # For 'pending' or 'failed' statuses
            doc_ref.update(update_data)

        logging.info(f"Subscription with reference {payment_reference} successfully updated to status: {new_status}.")
        return True
    except Exception as e:
        logging.error(f"Firestore error updating subscription status for reference {payment_reference}: {e}", exc_info=True)
        return False
        
def get_active_subscription(user_id):
    """
    Fetches the user's *most recent active* subscription along with its plan details.
    """
    try:
        # Build the Firestore query
        query = db.collection('subscriptions').where('user_id', '==', user_id).where('status', '==', 'active').order_by('expiry_date', direction=firestore.Query.DESCENDING).limit(1)
        
        # Stream the query results
        docs = query.stream()
        
        # Get the single document (if it exists)
        sub_doc = next(docs, None)
        
        if sub_doc:
            sub_data = sub_doc.to_dict()
            plan_id = sub_data.get('plan_id')
            plan_details = get_plan_details(plan_id) # Reuse the existing helper function
            
            if plan_details:
                # Combine subscription data with plan details
                combined_data = {
                    'subscription_id': sub_doc.id,
                    'start_date': sub_data.get('start_date'),
                    'expiry_date': sub_data.get('expiry_date'),
                    'status': sub_data.get('status'),
                    'plan_name': plan_details.get('name'),
                    'max_adverts': plan_details.get('max_adverts'),
                    'advert_duration_days': plan_details.get('advert_duration_days'),
                    'visibility_level': plan_details.get('visibility_level')
                }
                return combined_data
        
        return None
    except Exception as e:
        logging.error(f"Firestore error fetching active subscription for user {user_id}: {e}", exc_info=True)
        return None

# --- Refactored Routes (Firestore) ---

@app.route('/admin/adverts_review')
@admin_required # Use the refactored decorator
def admin_adverts_review():
    # Decorator now handles the user authentication and admin check
    adverts_for_review = []
    try:
        # Fetch adverts with status 'pending_review' or 'rejected'
        adverts_ref = db.collection('adverts').where('status', 'in', ['pending_review', 'rejected']).order_by('created_at').stream()
        
        for doc in adverts_ref:
            advert_data = doc.to_dict()
            advert_data['id'] = doc.id
            
            # Fetch related user, category, and subcategory data
            user_id = advert_data.get('user_id')
            category_id = advert_data.get('category_id')
            subcategory_id = advert_data.get('subcategory_id')

            user_doc = db.collection('users').document(user_id).get()
            category_doc = db.collection('categories').document(category_id).get() if category_id else None
            subcategory_doc = db.collection('subcategories').document(subcategory_id).get() if subcategory_id else None

            advert_data['seller_username'] = user_doc.to_dict().get('username') if user_doc.exists else 'Unknown'
            advert_data['seller_email'] = user_doc.to_dict().get('email') if user_doc.exists else 'Unknown'
            advert_data['seller_phone'] = user_doc.to_dict().get('phone') if user_doc.exists else 'Unknown'
            advert_data['category_name'] = category_doc.to_dict().get('name') if category_doc and category_doc.exists else 'N/A'
            advert_data['subcategory_name'] = subcategory_doc.to_dict().get('name') if subcategory_doc and subcategory_doc.exists else 'N/A'
            
            adverts_for_review.append(advert_data)
            
        return render_template('admin/adverts_review.html', adverts=adverts_for_review, is_admin_user=True)
    except Exception as e:
        flash(f'An error occurred while loading adverts for review: {str(e)}', 'error')
        logging.error(f"Firestore error loading admin adverts review page: {e}", exc_info=True)
        return redirect(url_for('home'))

@app.route('/adverts/repost/<string:advert_id>', methods=['GET'])
def repost_advert(advert_id):
    """
    Redirects to the create advert page, optionally pre-filling with old advert data.
    Note: advert_id is now treated as a string to match Firestore document IDs.
    """
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to repost adverts.', 'error')
        return redirect(url_for('login'))

    try:
        advert_doc = db.collection('adverts').document(advert_id).get()
        advert = advert_doc.to_dict() if advert_doc.exists else None

        if not advert or advert.get('user_id') != user_id:
            flash('Advert not found or you do not have permission to repost it.', 'error')
            return redirect(url_for('list_adverts'))
        
        # ... logic for pre-filling the form with advert data ...
        # e.g., session['repost_advert_data'] = advert
        # return redirect(url_for('create_advert_page'))
    except Exception as e:
        logging.error(f"Firestore error fetching advert for repost: {e}", exc_info=True)
        flash('An error occurred while fetching advert details.', 'error')
        return redirect(url_for('list_adverts'))

def get_user_adverts_count(user_id):
    """
    Fetches the number of currently 'published' adverts for a given user from Firestore.
    """
    try:
        # Query Firestore for all documents where user_id and status match.
        adverts_ref = db.collection('adverts').where('user_id', '==', user_id).where('status', '==', 'published').stream()
        
        # Count the documents returned by the stream.
        count = sum(1 for _ in adverts_ref)
        
        logging.info(f"Successfully fetched user published adverts count for user {user_id}: {count}")
        return count
    except Exception as e:
        logging.error(f"Firestore error fetching user published adverts count for user {user_id}: {e}", exc_info=True)
        return 0

def create_advert_db(user_id, subscription_id, category_id, subcategory_id, title, description,
                     price, negotiable, condition, location_string, main_image, additional_images_string, video,
                     advert_duration_days, plan_name, visibility_level,
                     state_id, university_id, sub_location_id):
    """Creates a new advert document in Firestore."""
    try:
        expires_at = datetime.now() + timedelta(days=advert_duration_days)
        
        new_advert_data = {
            'user_id': user_id,
            'subscription_id': subscription_id,
            'category_id': category_id,
            'subcategory_id': subcategory_id,
            'title': title,
            'description': description,
            'price': price,
            'negotiable': negotiable,
            'condition': condition,
            'location': location_string,
            'main_image': main_image,
            'additional_images': additional_images_string, # In a real app, this might be a list
            'video': video,
            'status': 'pending_review',
            'created_at': datetime.now(),
            'expires_at': expires_at,
            'published_at': datetime.now(), # Or None, if it's pending review
            'subscription_plan_name': plan_name,
            'visibility_level': visibility_level,
            'featured': 0, # Assuming a numeric value
            'is_admin_featured': 0, # Assuming a numeric value
            'state_id': state_id,
            'location_id': university_id, # location_id maps to university_id
            'sublocation_id': sub_location_id,
        }
        
        # Add a new document to the 'adverts' collection
        doc_ref = db.collection('adverts').add(new_advert_data)
        return doc_ref[1].id # doc_ref is a tuple (WriteResult, DocumentReference)
    except Exception as e:
        logging.error(f"Firestore error creating advert: {e}", exc_info=True)
        return None

def get_advert_details(advert_id, user_id=None):
    """
    Fetches an advert's details from Firestore by ID.
    If user_id is provided, it verifies ownership.
    """
    logging.info(f"Getting advert details for advert_id: {advert_id}, user_id: {user_id}")
    try:
        advert_doc = db.collection('adverts').document(advert_id).get()
        
        if advert_doc.exists:
            advert_data = advert_doc.to_dict()
            advert_data['id'] = advert_doc.id # Add the document ID to the dictionary
            
            # If a user_id is provided, check for ownership
            if user_id and advert_data.get('user_id') != user_id:
                return None
                
            return advert_data
            
        return None
    except Exception as e:
        logging.error(f"Firestore error fetching advert details for {advert_id}: {e}", exc_info=True)
        return None

# The render_sell_template function is a wrapper and does not require changes itself,
# but it relies on the refactored helper functions to work correctly.

def update_advert_db(advert_id, user_id, title, description, image_url, status):
    """
    Updates an existing advert document in Firestore.
    """
    try:
        # Check if the advert exists and belongs to the user
        advert_doc_ref = db.collection('adverts').document(advert_id)
        advert_doc = advert_doc_ref.get()
        
        if not advert_doc.exists or advert_doc.to_dict().get('user_id') != user_id:
            logging.warning(f"Attempted to update advert {advert_id} by unauthorized user {user_id}.")
            return False
        
        update_data = {
            'title': title,
            'description': description,
            'main_image': image_url,
            'status': status
        }
        
        advert_doc_ref.update(update_data)
        
        logging.info(f"Advert ID: {advert_id} updated by user {user_id}.")
        return True
    except Exception as e:
        logging.error(f"Firestore error updating advert {advert_id} for user {user_id}: {e}", exc_info=True)
        return False

def delete_advert_db(advert_id, user_id):
    """
    Deletes an advert document from Firestore.
    """
    try:
        # Check if the advert exists and belongs to the user
        advert_doc_ref = db.collection('adverts').document(advert_id)
        advert_doc = advert_doc_ref.get()
        
        if not advert_doc.exists or advert_doc.to_dict().get('user_id') != user_id:
            logging.warning(f"Attempted to delete advert {advert_id} by unauthorized user {user_id}.")
            return False
            
        advert_doc_ref.delete()
        
        logging.info(f"Advert ID: {advert_id} deleted by user {user_id}.")
        return True
    except Exception as e:
        logging.error(f"Firestore error deleting advert {advert_id} for user {user_id}: {e}", exc_info=True)
        return False
        
def get_user_adverts(user_id):
    """
    Fetches all adverts for a specific user from Firestore.
    """
    adverts_list = []
    try:
        adverts_ref = db.collection('adverts').where('user_id', '==', user_id).order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        adverts_list = [{'id': doc.id, **doc.to_dict()} for doc in adverts_ref]
        return adverts_list
    except Exception as e:
        logging.error(f"Firestore error fetching adverts for user {user_id}: {e}", exc_info=True)
        return []
        
# The send_notification and get_free_advert_plan_details functions do not require changes
# as they do not interact with the database directly.

def get_referral_benefit_plan(user_referral_count):
    """
    Retrieves the highest referral benefit plan a user qualifies for from Firestore.
    """
    try:
        # Query for referral benefits where the count is less than or equal to the user's count,
        # ordered descending to get the highest one first.
        query = db.collection('referral_benefits').where('referral_count', '<=', user_referral_count).order_by('referral_count', direction=firestore.Query.DESCENDING).limit(1)
        benefit_doc = next(query.stream(), None)
        
        if benefit_doc:
            benefit_data = benefit_doc.to_dict()
            plan_id = benefit_data.get('plan_id')
            
            # Fetch the plan details using the plan_id
            plan_doc = db.collection('plans').document(plan_id).get()
            if plan_doc.exists:
                plan_details = plan_doc.to_dict()
                benefit_data.update({
                    'plan_name': plan_details.get('name'),
                    'max_adverts': plan_details.get('max_adverts'),
                    'advert_duration_days': plan_details.get('advert_duration_days'),
                    'visibility_level': plan_details.get('visibility_level'),
                    'plan_id': plan_id,
                    'type': 'referral',
                    'label': f"Referral Benefit: {plan_details.get('name')} (Cost: {benefit_data['referral_count']} referrals)",
                    'cost': benefit_data['referral_count'],
                    'subscription_id': None
                })
                return benefit_data
        
        return None
    except Exception as e:
        logging.error(f"Firestore error fetching referral benefit plan for count {user_referral_count}: {e}", exc_info=True)
        return None
        
def get_user_referral_count(user_id):
    """
    Retrieves the referral count for a given user from Firestore.
    """
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict().get('referral_count', 0)
        return 0
    except Exception as e:
        logging.error(f"Firestore error fetching referral count for user {user_id}: {e}", exc_info=True)
        return 0

def subtract_referral_counts(user_id, count_to_subtract, transaction=None):
    """
    Subtracts a specified number of referral counts from a user's total in a transaction.
    """
    def _update_in_transaction(transaction, user_doc_ref):
        user_doc = user_doc_ref.get(transaction=transaction)
        if not user_doc.exists:
            raise ValueError(f"User document with ID {user_id} not found.")

        current_count = user_doc.to_dict().get('referral_count', 0)
        new_count = max(0, current_count - count_to_subtract)
        
        transaction.update(user_doc_ref, {'referral_count': new_count})
        logging.info(f"Updated referral counts for user {user_id} by -{count_to_subtract} in transaction.")
    
    try:
        user_doc_ref = db.collection('users').document(user_id)
        if transaction:
            # Use the provided transaction
            _update_in_transaction(transaction, user_doc_ref)
        else:
            # Create a new transaction if one isn't provided
            new_transaction = db.transaction()
            new_transaction.run(_update_in_transaction, user_doc_ref)

        return True
    except Exception as e:
        logging.error(f"Firestore error subtracting referral counts for user {user_id}: {e}", exc_info=True)
        return False
           
            
            
def update_advert_status(advert_id, new_status):
    """
    Updates the status of an advert document in Firestore.
    """
    try:
        advert_ref = db.collection('adverts').document(advert_id)
        advert_ref.update({'status': new_status})
        logging.info(f"Advert {advert_id} status updated to {new_status}.")
        return True
    except Exception as e:
        logging.error(f"Failed to update status for advert {advert_id}: {e}", exc_info=True)
        return False

def get_locations_by_state_from_db(state_id):
    """
    Returns a list of locations (e.g., universities) for a given state ID from Firestore.
    """
    try:
        locations_ref = db.collection('locations').where('state_id', '==', state_id).order_by('name').stream()
        locations = [{'id': doc.id, **doc.to_dict()} for doc in locations_ref]
        return locations
    except Exception as e:
        logging.error(f"Firestore error fetching locations for state {state_id}: {e}", exc_info=True)
        return []

def get_sublocations_for_location_from_db(location_id):
    """
    Returns a list of sublocations for a given location ID from Firestore.
    """
    try:
        sublocations_ref = db.collection('sublocations').where('location_id', '==', location_id).order_by('name').stream()
        sublocations = [{'id': doc.id, **doc.to_dict()} for doc in sublocations_ref]
        return sublocations
    except Exception as e:
        logging.error(f"Firestore error fetching sublocations for location {location_id}: {e}", exc_info=True)
        return []

def get_location_acronym_and_sub_name(sub_location_id):
    """
    Fetches the acronym of the parent location and the name of the sublocation from Firestore.
    """
    if not sub_location_id:
        logging.warning("get_location_acronym_and_sub_name called with empty sub_location_id.")
        return None
    
    try:
        sublocation_doc = db.collection('sublocations').document(sub_location_id).get()
        if sublocation_doc.exists:
            sublocation_data = sublocation_doc.to_dict()
            location_id = sublocation_data.get('location_id')
            
            if location_id:
                location_doc = db.collection('locations').document(location_id).get()
                if location_doc.exists:
                    location_data = location_doc.to_dict()
                    acronym = location_data.get('acronym')
                    sub_name = sublocation_data.get('name')
                    
                    acronym_part = f"{acronym}>" if acronym else ""
                    return f"{acronym_part}{sub_name}"
        
        logging.warning(f"No result found for sub_location_id: {sub_location_id}")
        return None
    except Exception as e:
        logging.error(f"Firestore error fetching location details for sub-location ID {sub_location_id}: {e}", exc_info=True)
        return None


def send_notification(user_id, message, notification_type="info"):
    """
    A placeholder function to simulate sending a user notification.
    """
    logging.info(f"NOTIFICATION to user {user_id}: {message}")



def get_states_from_db():
    """
    Fetches all states from the 'states' collection in Firestore.
    """
    try:
        states_ref = db.collection('states').order_by('name').stream()
        states = [{'id': doc.id, **doc.to_dict()} for doc in states_ref]
        logging.info(f"{len(states)} states retrieved from the database.")
        return states
    except Exception as e:
        logging.error(f"Firestore error fetching states: {e}", exc_info=True)
        return []

# --- Flask Context Processor ---
@app.context_processor
def inject_utility_functions():
    """
    Injects Firestore-based utility functions into templates.
    """
    return dict(
        get_subcategories=get_subcategories_by_category_id,
        get_locations_by_state=get_locations_by_state_from_db,
        get_sublocations_for_location=get_sublocations_for_location_from_db
    )

# --- Flask Routes ---
@app.route('/adverts')
def list_adverts():
    """Displays a list of adverts for the logged-in user, showing all statuses."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to view your adverts.', 'error')
        return redirect(url_for('login'))

    adverts = get_user_adverts(user_id) 
    
    def sort_key(advert):
        status = advert.get('status', '')
        if status == 'rejected':
            return 0
        if status == 'pending_review':
            return 1
        if status == 'published':
            return 2
        return 3

    adverts.sort(key=sort_key)

    return render_template('adverts/list.html', adverts=adverts)

@app.route('/adverts/edit/<string:advert_id>', methods=['GET', 'POST'])
def edit_advert(advert_id):
    """Allows a user to edit an existing advert."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to edit adverts.', 'error')
        return redirect(url_for('login'))

    advert = get_advert_details(advert_id, user_id)
    if not advert:
        flash('Advert not found or you do not have permission to edit it.', 'error')
        return redirect(url_for('list_adverts'))

    if advert['status'] in ['deleted', 'expired']:
        flash('Cannot edit an expired or deleted advert. Please create a new one.', 'warning')
        return redirect(url_for('list_adverts'))

    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        # Assuming other fields are also handled
        
        if not title or not description:
            flash('Title and description are required.', 'error')
            return render_template('sell.html', advert=advert)

        if update_advert_db(advert_id, user_id, title, description, advert['main_image'], advert['status']):
            flash('Advert updated successfully!', 'success')
            send_notification(user_id, f"Your advert '{title}' was updated.")
            return redirect(url_for('list_adverts'))
        else:
            flash('Failed to update advert. Please try again.', 'error')

    categories = get_all_categories()
    subcategories = get_subcategories_by_category_id(advert.get('category_id')) if advert.get('category_id') else []
    return render_template('sell.html', advert=advert, categories=categories, subcategories=subcategories)


@app.route('/adverts/delete/<string:advert_id>', methods=['POST'])
def delete_advert(advert_id):
    """Allows a user to delete an advert."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to delete adverts.', 'error')
        return redirect(url_for('login'))

    advert = get_advert_details(advert_id, user_id)
    if not advert:
        flash('Advert not found or you do not have permission to delete it.', 'error')
        return redirect(url_for('list_adverts'))

    if delete_advert_db(advert_id, user_id):
        flash('Advert deleted successfully!', 'success')
        send_notification(user_id, f"Your advert '{advert['title']}' was deleted.")
    else:
        flash('Failed to delete advert. Please try again.', 'error')

    return redirect(url_for('list_adverts'))

@app.route('/adverts/pause/<string:advert_id>', methods=['POST'])
def pause_advert(advert_id):
    """Allows a user to pause a published advert."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to manage your adverts.', 'error')
        return redirect(url_for('login'))

    advert = get_advert_details(advert_id, user_id)
    if not advert or advert.get('status') != 'published':
        flash('Advert not found or cannot be paused.', 'error')
        return redirect(url_for('list_adverts'))

    if update_advert_status(advert_id, 'paused'):
        flash(f"Advert '{advert['title']}' has been paused.", 'success')
        send_notification(user_id, f"Your advert '{advert['title']}' was paused.")
    else:
        flash('Failed to pause advert. Please try again.', 'error')
    return redirect(url_for('list_adverts'))

@app.route('/adverts/resume/<string:advert_id>', methods=['POST'])
def resume_advert(advert_id):
    """Allows a user to resume a paused advert."""
    user_id = session.get('user_id')
    if not user_id:
        flash('Please login to manage your adverts.', 'error')
        return redirect(url_for('login'))

    advert = get_advert_details(advert_id, user_id)
    if not advert or advert.get('status') != 'paused':
        flash('Advert not found or cannot be resumed.', 'error')
        return redirect(url_for('list_adverts'))

    if update_advert_status(advert_id, 'published'):
        flash(f"Advert '{advert['title']}' has been resumed.", 'success')
        send_notification(user_id, f"Your advert '{advert['title']}' was resumed.")
    else:
        flash('Failed to resume advert. Please try again.', 'error')
    return redirect(url_for('list_adverts'))


# --- Flask Routes (cont.) ---
@app.route('/verify_referral', methods=['GET', 'POST'])
def verify_referral():
    if 'user_id' not in session:
        flash("You must be logged in to verify your referral.", "warning")
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_doc_ref = db.collection('users').document(user_id)

    try:
        user_doc = user_doc_ref.get()
        if not user_doc.exists:
            flash("User not found.", "danger")
            return redirect(url_for('login'))
        
        user_data = user_doc.to_dict()

        if user_data.get('is_referral_verified'):
            flash("Your device is already verified for referral benefits.", "info")
            return redirect(url_for('profile'))

        user_ip = request.remote_addr

        # Use a transaction for the update to ensure atomicity
        transaction = db.transaction()
        @firestore.transactional
        def update_user_referral_status(transaction, user_ref, user_ip):
            transaction.update(user_ref, {
                'is_referral_verified': True,
                'last_referral_verification_at': datetime.now(),
                'last_referral_verification_ip': user_ip
            })
        
        update_user_referral_status(transaction, user_doc_ref, user_ip)
        
        flash("Your device has been successfully verified for referral benefits!", "success")
        return redirect(url_for('profile'))

    except Exception as e:
        flash(f"An error occurred during referral verification: {e}", "error")
        logging.error(f"Error during referral verification for user {user_id}: {e}", exc_info=True)
        return redirect(url_for('profile'))


@app.route('/referral-benefit')
def referral_benefit():
    if 'user_id' not in session:
        flash("Please log in to use your referral benefit.", "error")
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_referral_count = get_user_referral_count(user_id)

    referral_benefits_list = []
    try:
        # Fetch all referral benefits and join with plans in Python
        referral_benefits_refs = db.collection('referral_benefits').order_by('referral_count').stream()
        for rb_doc in referral_benefits_refs:
            rb_data = rb_doc.to_dict()
            plan_doc = db.collection('plans').document(rb_data.get('plan_id')).get()
            if plan_doc.exists:
                plan_data = plan_doc.to_dict()
                referral_benefits_list.append({
                    'referral_count': rb_data.get('referral_count'),
                    'plan_name': plan_data.get('name'),
                    'max_adverts': plan_data.get('max_adverts'),
                    'advert_duration_days': plan_data.get('advert_duration_days')
                })
    except Exception as e:
        logging.error(f"Firestore error fetching all referral benefits: {e}", exc_info=True)

    current_benefit = None
    next_benefit = None

    for benefit in reversed(referral_benefits_list):
        if user_referral_count >= benefit['referral_count']:
            current_benefit = benefit
            break
            
    for benefit in referral_benefits_list:
        if benefit['referral_count'] > user_referral_count:
            next_benefit = benefit
            break

    return render_template('referral_benefit.html',
                           user_referral_count=user_referral_count,
                           referral_benefits_list=referral_benefits_list,
                           current_benefit=current_benefit,
                           next_benefit=next_benefit)




def get_user_role(user_id):
    """
    Fetches a user's role from Firestore.
    :param user_id: The ID of the user.
    :return: The user's role as a string, or None if not found.
    """
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict().get('role')
    except exceptions.NotFound:
        logger.warning(f"User document not found for ID: {user_id}")
    except Exception as e:
        logger.error(f"Error fetching user role for ID {user_id}: {e}", exc_info=True)
    return None

def get_advert_info(advert_id):
    """
    Fetches advert details from Firestore.
    :param advert_id: The ID of the advert.
    :return: A dictionary of advert data, or None if not found.
    """
    try:
        advert_doc = db.collection('adverts').document(advert_id).get()
        if advert_doc.exists:
            return advert_doc.to_dict()
    except exceptions.NotFound:
        logger.warning(f"Advert document not found for ID: {advert_id}")
    except Exception as e:
        logger.error(f"Error fetching advert info for ID {advert_id}: {e}", exc_info=True)
    return None

def get_full_report_details(report_id):
    """
    Fetches a single reported advert with full details of the reporter and advert.
    This replaces the complex SQL JOIN query.
    :param report_id: The ID of the reported advert document.
    :return: A dictionary containing all report details or None.
    """
    try:
        report_doc = db.collection('reported_adverts').document(report_id).get()
        if not report_doc.exists:
            return None
        
        report_data = report_doc.to_dict()
        
        # Fetch advert and user details separately
        advert_id = report_data.get('advert_id')
        reporter_id = report_data.get('reporter_id')
        
        advert_doc = db.collection('adverts').document(advert_id).get()
        reporter_doc = db.collection('users').document(reporter_id).get()

        if advert_doc.exists:
            advert_data = advert_doc.to_dict()
            report_data['advert'] = {
                'title': advert_data.get('title'),
                'description': advert_data.get('description'),
                'price': advert_data.get('price'),
                'status': advert_data.get('status'),
                'user_id': advert_data.get('user_id')
            }
        
        if reporter_doc.exists:
            reporter_data = reporter_doc.to_dict()
            report_data['reporter'] = {
                'username': reporter_data.get('username'),
                'email': reporter_data.get('email'),
                'account_status': reporter_data.get('account_status')
            }
        
        # Get advert owner details
        if report_data.get('advert', {}).get('user_id'):
            owner_doc = db.collection('users').document(report_data['advert']['user_id']).get()
            if owner_doc.exists:
                owner_data = owner_doc.to_dict()
                report_data['advert_owner'] = {
                    'username': owner_data.get('username'),
                    'email': owner_data.get('email'),
                    'account_status': owner_data.get('account_status')
                }
        
        return report_data

    except Exception as e:
        logger.error(f"Error fetching full report details for report ID {report_id}: {e}", exc_info=True)
        return None

def get_advert_reviews(advert_id):
    """
    Fetches all reviews for a given advert ID.
    :param advert_id: The ID of the advert.
    :return: A list of review dictionaries.
    """
    try:
        reviews_ref = db.collection('reviews').where(filter=FieldFilter('advert_id', '==', advert_id)).stream()
        return [{'id': doc.id, **doc.to_dict()} for doc in reviews_ref]
    except Exception as e:
        logger.error(f"Error fetching reviews for advert {advert_id}: {e}", exc_info=True)
        return []

def get_user_by_id(user_id):
    """
    Fetches a user document by their ID.
    :param user_id: The user's document ID.
    :return: A dictionary of user data, or None.
    """
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict()
    except Exception as e:
        logger.error(f"Error fetching user by ID {user_id}: {e}", exc_info=True)
    return None


# --- AUTHENTICATION DECORATORS (UPDATED FOR FIRESTORE) ---
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'user_id' not in session:
            flash('You need to log in first.', 'error')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return wrap

def admin_required(f):
    @wraps(f)
    @login_required
    def wrap(*args, **kwargs):
        user_id = session.get('user_id')
        user_role = get_user_role(user_id)
        if user_role == 'admin':
            return f(*args, **kwargs)
        else:
            flash('Access denied: You do not have administrator privileges.', 'error')
            return redirect(url_for('home'))
    return wrap


# --- Admin Reported Adverts List Route (UPDATED FOR FIRESTORE) ---
@app.route('/admin/reported_adverts')
@admin_required
def reported_adverts_admin():
    try:
        # Fetch all reported adverts, ordered by creation time
        reports_ref = db.collection('reported_adverts').order_by('reported_at', direction=firestore.Query.DESCENDING).stream()
        
        reported_adverts_list = []
        for report_doc in reports_ref:
            report_data = report_doc.to_dict()
            report_data['id'] = report_doc.id # Add document ID
            
            # Fetch advert and user details for each report (denormalization)
            advert = get_advert_info(report_data.get('advert_id'))
            reporter = get_user_by_id(report_data.get('reporter_id'))

            reported_adverts_list.append({
                'report_id': report_doc.id,
                'advert_id': report_data.get('advert_id'),
                'advert_title': advert.get('title') if advert else 'Advert not found',
                'reporter_id': report_data.get('reporter_id'),
                'reporter_username': reporter.get('username') if reporter else 'User not found',
                'reason': report_data.get('reason'),
                'reported_at': report_data.get('reported_at')
            })
        
        return render_template('reported_adverts_admin.html', reported_adverts=reported_adverts_list)

    except Exception as e:
        logger.error(f"Error fetching reported adverts from Firestore: {e}", exc_info=True)
        flash("An unexpected error occurred while fetching reports.", 'error')
        return redirect(url_for('home'))


# --- Admin Reported Advert Detail Page Route (UPDATED FOR FIRESTORE) ---
@app.route('/admin/reported_advert/<string:report_id>')
@admin_required
def admin_reported_advert_detail(report_id):
    report_data = get_full_report_details(report_id)
    
    if not report_data:
        flash("Report not found.", "error")
        return redirect(url_for('reported_adverts_admin'))

    # You would pass the full report_data to the template
    return render_template('reported_advert_detail_admin.html', report=report_data)


# --- Admin Action Routes (UPDATED FOR FIRESTORE) ---
@app.route('/admin/action/mark_resolved/<string:report_id>', methods=['POST'])
@admin_required
def admin_action_mark_resolved(report_id):
    try:
        report_ref = db.collection('reported_adverts').document(report_id)
        report_ref.update({
            'status': 'resolved',
            'resolved_at': datetime.now(timezone.utc)
        })
        logger.info(f"Admin Action: Report {report_id} marked as resolved.")
        return jsonify(success=True, message=f"Report {report_id} marked as resolved.")
    except Exception as e:
        logger.error(f"Error marking report {report_id} as resolved: {e}", exc_info=True)
        return jsonify(success=False, message="Failed to mark report as resolved."), 500


@app.route('/admin/action/suspend_user/<string:user_id>', methods=['POST'])
@admin_required
def admin_action_suspend_user(user_id):
    if user_id == session.get('user_id'):
        return jsonify(success=False, message="Cannot suspend yourself."), 400
    try:
        user_ref = db.collection('users').document(user_id)
        # Check if the user exists before updating
        if not user_ref.get().exists:
             return jsonify(success=False, message="User not found."), 404
        
        user_ref.update({'account_status': 'suspended'})
        logger.info(f"Admin Action: User {user_id} suspended.")
        return jsonify(success=True, message=f"User {user_id} account suspended.")
    except Exception as e:
        logger.error(f"Error suspending user {user_id}: {e}", exc_info=True)
        return jsonify(success=False, message="Failed to suspend user."), 500


@app.route('/admin/action/take_down_advert/<string:advert_id>', methods=['POST'])
@admin_required
def admin_action_take_down_advert(advert_id):
    try:
        advert_ref = db.collection('adverts').document(advert_id)
        # Check if the advert exists before updating
        if not advert_ref.get().exists:
             return jsonify(success=False, message="Advert not found."), 404
        
        advert_ref.update({'status': 'taken_down'})
        logger.info(f"Admin Action: Advert {advert_id} taken down.")
        return jsonify(success=True, message=f"Advert {advert_id} taken down.")
    except Exception as e:
        logger.error(f"Error taking down advert {advert_id}: {e}", exc_info=True)
        return jsonify(success=False, message="Failed to take down advert."), 500


# --- Review Route (UPDATED FOR FIRESTORE) ---
@app.route('/submit_review/<string:advert_id>', methods=['POST'])
@login_required
def submit_review(advert_id):
    current_reviewer_id = session.get('user_id')
    rating = request.form.get('rating')
    comment = request.form.get('comment')

    if not rating or not comment:
        flash('Rating and comment are required for a review.', 'error')
        return redirect(url_for('advert_detail', advert_id=advert_id))

    try:
        # Get the advert's seller_id (reviewee_id)
        advert_doc = db.collection('adverts').document(advert_id).get()
        if not advert_doc.exists:
            flash('Advert not found.', 'error')
            return redirect(url_for('home'))
        reviewee_id = advert_doc.to_dict().get('user_id')

        # Prevent reviewing own advert
        if current_reviewer_id == reviewee_id:
            flash("You cannot review your own advert.", "error")
            return redirect(url_for('advert_detail', advert_id=advert_id))

        # Check if user already reviewed this advert
        reviews_ref = db.collection('reviews').where(filter=FieldFilter('user_id', '==', current_reviewer_id)).where(filter=FieldFilter('advert_id', '==', advert_id)).limit(1).stream()
        existing_review = next(reviews_ref, None)
        if existing_review:
            flash("You have already reviewed this advert. You can edit your existing review.", "warning")
            return redirect(url_for('advert_detail', advert_id=advert_id))

        # Get reviewer's username
        reviewer_doc = db.collection('users').document(current_reviewer_id).get()
        reviewer_name = reviewer_doc.to_dict().get('username', "Anonymous") if reviewer_doc.exists else "Anonymous"

        # Add the new review to the 'reviews' collection
        db.collection('reviews').add({
            'advert_id': advert_id,
            'user_id': current_reviewer_id,
            'reviewee_id': reviewee_id,
            'rating': int(rating),
            'comment': comment,
            'reviewer_name': reviewer_name,
            'created_at': datetime.now(timezone.utc)
        })
        
        flash('Your review has been submitted successfully!', 'success')
        return redirect(url_for('advert_detail', advert_id=advert_id))

    except Exception as e:
        logger.error(f"Error submitting review for advert {advert_id}: {e}", exc_info=True)
        flash(f"An unexpected error occurred while submitting review: {e}", 'error')
        return redirect(url_for('advert_detail', advert_id=advert_id))


















@app.route('/advert/<string:advert_id>')
def advert_detail(advert_id):
    """
    Handles displaying a single advert detail page, migrating from MySQL to Firestore.
    - Increments view count using a Firestore transaction for safety.
    - Fetches advert, seller, reviews, and similar adverts from Firestore.
    """
    try:
        # Use a transaction to safely increment the view count
        # This prevents race conditions where two users view the advert at the same time.
        transaction = db.transaction()

        @firestore.transactional
        def update_view_count(transaction, doc_ref, is_owner):
            doc = doc_ref.get(transaction=transaction)
            if doc.exists:
                advert_data = doc.to_dict()
                is_published = advert_data.get('status') == 'published'
                expires_at = advert_data.get('expires_at')
                is_expired = expires_at and expires_at.date() < datetime.now().date()

                # Increment view count only if it's a public, non-expired, published view
                if is_published and not is_expired and not is_owner:
                    view_count = advert_data.get('view_count', 0) + 1
                    transaction.update(doc_ref, {'view_count': view_count})
            return doc # Return the advert document to use its data later

        # Get the advert reference
        advert_ref = db.collection('adverts').document(advert_id)
        advert_status_doc = update_view_count(transaction, advert_ref, is_owner=False)
        advert = advert_status_doc.to_dict() if advert_status_doc.exists else None

        if not advert:
            flash('The advert you are looking for does not exist.', 'error')
            return redirect(url_for('home'))

        # Check advert status and expiry
        current_user_id = session.get('user_id')
        is_owner = current_user_id == advert.get('user_id')

        # Allow owner to view non-published adverts
        if advert.get('status') != 'published' and not is_owner:
            flash('This advert is not currently available for public viewing.', 'error')
            return redirect(url_for('home'))

        # If advert is published, check for expiry date
        if advert.get('status') == 'published' and advert.get('expires_at') and advert.get('expires_at').date() < datetime.now().date():
            # Update status to expired
            advert_ref.update({'status': 'expired'})
            advert['status'] = 'expired'
            if not is_owner:
                flash('This advert has expired and is no longer active.', 'warning')
                return redirect(url_for('home'))
            else:
                flash('This advert has expired. Consider renewing it.', 'warning')

        user = {}
        is_following = False
        is_saved = False

        user_id_from_advert = advert.get('user_id')
        if user_id_from_advert:
            user_doc = db.collection('users').document(user_id_from_advert).get()
            if user_doc.exists:
                user = user_doc.to_dict()
                
                # Fetch reviews for the user to calculate average rating and count
                reviews_query = db.collection('reviews').where('reviewee_id', '==', user_id_from_advert).stream()
                total_rating = 0
                review_count = 0
                for review_doc in reviews_query:
                    review_data = review_doc.to_dict()
                    total_rating += review_data.get('rating', 0)
                    review_count += 1
                
                user['rating'] = total_rating / review_count if review_count > 0 else 0.0
                user['review_count'] = review_count

                # Check if current user is following this seller
                if current_user_id:
                    follower_doc = db.collection('followers').document(f"{current_user_id}_{user_id_from_advert}").get()
                    is_following = follower_doc.exists

            if not user:
                user = {
                    'id': user_id_from_advert,
                    'username': 'Unknown Seller',
                    'profile_picture': 'default_profile.png',
                    'account_status': 'inactive',
                    'badge': None,
                    'rating': 0.0,
                    'review_count': 0,
                    'subscription_status': 'N/A',
                    'phone_number': ''
                }
        
        # Check if the current advert is saved by the logged-in user
        if current_user_id:
            saved_advert_doc = db.collection('saved_adverts').document(f"{current_user_id}_{advert_id}").get()
            is_saved = saved_advert_doc.exists

        # Fetch reviews for the current advert
        reviews_query = db.collection('reviews').where('advert_id', '==', advert_id).order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        reviews = []
        for review_doc in reviews_query:
            review_data = review_doc.to_dict()
            # Fetch reviewer's profile picture
            reviewer_doc = db.collection('users').document(review_data['user_id']).get()
            if reviewer_doc.exists:
                reviewer_data = reviewer_doc.to_dict()
                review_data['reviewer_username'] = reviewer_data.get('username')
                review_data['reviewer_profile_picture'] = reviewer_data.get('profile_picture', 'default_profile.png')
            reviews.append(review_data)

        # --- Similar Adverts Logic ---
        similar_adverts = []
        advert_category_id = advert.get('category_id')
        seller_id = advert.get('user_id')
        
        if advert_category_id and seller_id:
            # 1. Fetch seller's other adverts in the same category
            seller_adverts_query = db.collection('adverts').where('user_id', '==', seller_id).where('category_id', '==', advert_category_id).where('id', '!=', advert_id).where('status', '==', 'published').stream()
            
            for doc in seller_adverts_query:
                similar_adverts.append(doc.to_dict())
            
            # 2. Fetch other sellers' adverts in the same category (to fill up to 6 if needed)
            remaining_limit = 6 - len(similar_adverts)
            if remaining_limit > 0:
                other_adverts_query = db.collection('adverts').where('category_id', '==', advert_category_id).where('user_id', '!=', seller_id).where('status', '==', 'published').limit(remaining_limit).stream()
                for doc in other_adverts_query:
                    similar_adverts.append(doc.to_dict())

        # Process media files
        media_files = []
        if advert.get('main_image'):
            media_files.append({'src': advert['main_image'], 'type': 'image'})
        
        additional_images = advert.get('additional_images', [])
        if isinstance(additional_images, str):
            image_paths = [img.strip() for img in additional_images.split(',') if img.strip()]
            additional_images = image_paths
        
        for img_path in additional_images:
            media_files.append({'src': img_path.strip(), 'type': 'image'})

        if advert.get('video'):
            media_files.append({'src': advert['video'], 'type': 'video'})

        advert['media_files'] = media_files
        
        if 'delivery' not in advert:
            advert['delivery'] = 'Not specified'

        return render_template('advert_detail.html',
                                advert=advert,
                                user=user,
                                reviews=reviews,
                                similar_adverts=similar_adverts,
                                is_following=is_following,
                                is_saved=is_saved,
                                current_user_id=current_user_id)

    except Exception as e:
        logger.error(f"Error fetching advert detail: {e}", exc_info=True)
        flash(f'An error occurred while loading the advert details: {str(e)}. Please try again later.', 'error')
        return redirect(url_for('home'))

@app.route('/saved', methods=['GET', 'POST'])
def saved_ads():
    """
    Handles saved adverts page, with options to clear all or clear sold.
    - Uses a Firestore WriteBatch for efficient deletion.
    - Fetches saved adverts by querying the saved_adverts collection.
    """
    current_user_id = session.get('user_id')
    if not current_user_id:
        flash('You must be logged in to view saved adverts.', 'error')
        return redirect(url_for('login'))

    if request.method == 'POST':
        action = request.form.get('action')
        try:
            batch = db.batch()
            saved_adverts_query = db.collection('saved_adverts').where('user_id', '==', current_user_id).stream()
            
            if action == 'clear_all':
                for doc in saved_adverts_query:
                    batch.delete(doc.reference)
                flash("All saved adverts cleared successfully.", 'success')
            elif action == 'clear_sold':
                for doc in saved_adverts_query:
                    advert_ref = doc.to_dict()['advert_ref']
                    advert_doc = advert_ref.get()
                    if advert_doc.exists and advert_doc.to_dict().get('status') == 'sold':
                        batch.delete(doc.reference)
                flash("Sold adverts cleared from saved list successfully.", 'success')
            
            batch.commit()
        except Exception as e:
            logger.error(f"Error clearing saved ads: {e}")
            flash(f"An error occurred while clearing saved adverts: {str(e)}", 'error')
        
        return redirect(url_for('saved_ads'))
    
    # GET request logic
    search_query = request.args.get('q', '')
    saved_ads_list = []
    
    # Query for saved adverts for the current user
    saved_adverts_query = db.collection('saved_adverts').where('user_id', '==', current_user_id).order_by('saved_at', direction=firestore.Query.DESCENDING).stream()
    
    for saved_advert_doc in saved_adverts_query:
        advert_ref = saved_advert_doc.to_dict()['advert_ref']
        advert_doc = advert_ref.get()
        if advert_doc.exists:
            advert_data = advert_doc.to_dict()
            # Filter based on search query, status and expiry date
            title_match = search_query.lower() in advert_data.get('title', '').lower()
            location_match = search_query.lower() in advert_data.get('location', '').lower()
            
            is_published = advert_data.get('status') == 'published'
            expires_at = advert_data.get('expires_at')
            is_not_expired = not expires_at or expires_at.date() > datetime.now().date()
            
            if (title_match or location_match) and is_published and is_not_expired:
                # Get the username for the advert seller
                user_ref = advert_data['user_ref']
                user_doc = user_ref.get()
                if user_doc.exists:
                    advert_data['username'] = user_doc.to_dict().get('username')
                saved_ads_list.append(advert_data)

    return render_template('saved.html', saved_ads=saved_ads_list, query=search_query)


@app.route('/toggle_saved_advert/<string:advert_id>', methods=['POST'])
def toggle_saved_advert(advert_id):
    """
    Toggles an advert as saved/unsaved for the current user.
    - Uses a Firestore transaction for atomic reads and writes.
    """
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({'status': 'error', 'message': 'You must be logged in to save adverts.'}), 401

    try:
        # Use a transaction to ensure atomic check-then-write logic
        transaction = db.transaction()
        saved_doc_ref = db.collection('saved_adverts').document(f"{current_user_id}_{advert_id}")
        
        @firestore.transactional
        def toggle_advert_in_transaction(transaction, saved_doc_ref):
            saved_doc = saved_doc_ref.get(transaction=transaction)
            
            if saved_doc.exists:
                # Unsave advert
                transaction.delete(saved_doc_ref)
                return {'status': 'success', 'action': 'unsaved', 'message': 'Advert removed from saved items.'}, 200
            else:
                # Save advert
                advert_ref = db.collection('adverts').document(advert_id)
                advert_doc = advert_ref.get(transaction=transaction)
                
                if not advert_doc.exists or advert_doc.to_dict().get('status') != 'published':
                    return {'status': 'error', 'message': 'Advert not found or is inactive.'}, 404
                
                # Check for expiry date
                expires_at = advert_doc.to_dict().get('expires_at')
                if expires_at and expires_at.date() < datetime.now().date():
                    return {'status': 'error', 'message': 'Advert has expired.'}, 404

                transaction.set(saved_doc_ref, {
                    'user_id': current_user_id,
                    'advert_id': advert_id,
                    'saved_at': datetime.now(),
                    'advert_ref': advert_ref  # Store a reference for easy lookup
                })
                return {'status': 'success', 'action': 'saved', 'message': 'Advert saved successfully!'}, 200

        return toggle_advert_in_transaction(transaction, saved_doc_ref)

    except Exception as e:
        logger.error(f"Unexpected error in toggle_saved_advert: {e}", exc_info=True)
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500

@app.route('/saved_adverts')
def saved_adverts():
    """
    Fetches and displays saved adverts. This is very similar to the GET logic in /saved.
    """
    user_id = session.get('user_id')
    if not user_id:
        flash('You must be logged in to view saved adverts.', 'error')
        return redirect(url_for('login'))

    saved_adverts_list = []
    try:
        saved_query = db.collection('saved_adverts').where('user_id', '==', user_id).order_by('saved_at', direction=firestore.Query.DESCENDING).stream()
        
        for saved_doc in saved_query:
            saved_data = saved_doc.to_dict()
            # Use the stored DocumentReference to get the advert data efficiently
            advert_ref = saved_data.get('advert_ref')
            if advert_ref:
                advert_doc = advert_ref.get()
                if advert_doc.exists:
                    advert_data = advert_doc.to_dict()
                    # Only show published and non-expired adverts
                    is_published = advert_data.get('status') == 'published'
                    expires_at = advert_data.get('expires_at')
                    is_not_expired = not expires_at or expires_at.date() > datetime.now().date()
                    
                    if is_published and is_not_expired:
                        advert_data['id'] = advert_doc.id # Add the document ID to the dict
                        saved_adverts_list.append(advert_data)
    except Exception as e:
        logger.error(f"Error fetching saved adverts: {e}", exc_info=True)
        flash('An error occurred while loading saved adverts.', 'error')
    
    return render_template('saved_adverts.html', saved_adverts=saved_adverts_list)


@app.route('/remove_saved_advert/<string:advert_id>', methods=['POST'])
def remove_saved_advert(advert_id):
    """
    Removes a single advert from the user's saved list.
    """
    user_id = session.get('user_id')
    if not user_id:
        return jsonify(status='error', message='You must be logged in to remove saved adverts.'), 401

    try:
        doc_ref = db.collection('saved_adverts').document(f"{user_id}_{advert_id}")
        doc = doc_ref.get()
        if doc.exists:
            doc_ref.delete()
            flash('Advert successfully removed from your saved list.', 'success')
            return jsonify(status='success', message='Advert removed.')
        else:
            flash('Advert not found in your saved list.', 'warning')
            return jsonify(status='error', message='Advert not found in saved list.'), 404
    except Exception as e:
        logger.error(f"Error removing saved advert: {e}", exc_info=True)
        flash(f'An error occurred while removing the advert: {str(e)}', 'error')
        return jsonify(status='error', message='An error occurred.'), 500

@app.route('/report_advert/<string:advert_id>', methods=['POST'])
def report_advert(advert_id):
    """
    Adds a new report document to the Firestore 'reports' collection.
    """
    if 'user_id' not in session:
        flash("You must be logged in to report abuse.")
        return redirect(url_for('login'))
    
    reason = request.form.get('reason')
    user_id = session.get('user_id')
    
    try:
        report_data = {
            'user_id': user_id,
            'advert_id': advert_id,
            'reason': reason,
            'created_at': datetime.now()
        }
        # Add a new document to the 'reports' collection with an auto-generated ID
        db.collection('reports').add(report_data)
        flash("Report submitted.", 'success')
    except Exception as e:
        flash(f"Error submitting report: {e}", "danger")
        logger.error(f"Error submitting report: {e}", exc_info=True)
    
    return redirect(request.referrer)











def get_document(collection_name, document_id):
    """Fetches a single document from a Firestore collection."""
    try:
        doc_ref = db.collection(collection_name).document(document_id)
        doc = doc_ref.get()
        if doc.exists:
            return doc.to_dict()
        else:
            return None
    except Exception as e:
        # Log the error for debugging purposes
        print(f"Error fetching document {document_id} from {collection_name}: {e}")
        return None




def get_user_adverts_count(user_id):
    """Count the number of active adverts for a user."""
    try:
        # 'status' is now a field in the advert document
        adverts_ref = db.collection("adverts").where("user_id", "==", user_id).where("status", "==", "active")
        adverts_count = len(adverts_ref.stream())
        return adverts_count
    except Exception as e:
        logger.error(f"Error counting adverts for user {user_id}: {e}")
        return 0

def get_active_subscription(user_id):
    """Get the user's active subscription."""
    try:
        # Assuming 'subscriptions' collection has documents with a 'user_id' and 'is_active' field
        subscriptions_ref = db.collection("subscriptions").where("user_id", "==", user_id).where("is_active", "==", True)
        # Assuming a user can only have one active subscription
        subscriptions = list(subscriptions_ref.stream())
        if subscriptions:
            sub = subscriptions[0].to_dict()
            sub["subscription_id"] = subscriptions[0].id # Add Firestore doc ID
            return sub
        return None
    except Exception as e:
        logger.error(f"Error fetching active subscription for user {user_id}: {e}")
        return None

def get_user_referral_count(user_id):
    """Get the referral count from the user document."""
    user = get_user_info(user_id)
    return user.get("referral_count", 0) if user else 0

def get_referral_benefit_plan(referral_count):
    """Get the referral benefit plan based on count."""
    try:
        # Assuming a 'referral_plans' collection with 'cost' field
        # This will fetch all plans and we'll check the condition in Python
        plans_ref = db.collection("referral_plans").order_by("cost").limit_to_last(1)
        plans = list(plans_ref.stream())
        if plans:
            plan = plans[0].to_dict()
            if referral_count >= plan.get("cost", 0):
                return plan
        return None
    except Exception as e:
        logger.error(f"Error fetching referral benefit plan: {e}")
        return None

def get_free_advert_plan_details():
    """Get details for the one-time free advert."""
    # Assuming a document 'free_advert_plan' in a 'plans' collection
    return get_document("plans", "free_advert_plan")

def get_all_categories():
    """Get all categories from Firestore."""
    try:
        categories_ref = db.collection("categories")
        categories = categories_ref.stream()
        return [doc.to_dict() for doc in categories]
    except Exception as e:
        logger.error(f"Error fetching all categories: {e}")
        return []

def get_subcategories_by_category_id(category_id):
    """Get subcategories for a given category ID."""
    try:
        subcategories_ref = db.collection("subcategories").where("category_id", "==", int(category_id))
        subcategories = subcategories_ref.stream()
        return [doc.to_dict() for doc in subcategories]
    except Exception as e:
        logger.error(f"Error fetching subcategories for category {category_id}: {e}")
        return []

def get_states_from_db():
    """Get all states from Firestore."""
    try:
        states_ref = db.collection("states")
        states = states_ref.stream()
        return [doc.to_dict() for doc in states]
    except Exception as e:
        logger.error(f"Error fetching states: {e}")
        return []

def get_locations_by_state_from_db(state_id):
    """Get locations (universities) for a given state ID."""
    try:
        locations_ref = db.collection("locations").where("state_id", "==", int(state_id))
        locations = locations_ref.stream()
        return [doc.to_dict() for doc in locations]
    except Exception as e:
        logger.error(f"Error fetching locations for state {state_id}: {e}")
        return []

def get_sublocations_for_location_from_db(location_id):
    """Get sub-locations (areas) for a given university location ID."""
    try:
        sublocations_ref = db.collection("sublocations").where("location_id", "==", int(location_id))
        sublocations = sublocations_ref.stream()
        return [doc.to_dict() for doc in sublocations]
    except Exception as e:
        logger.error(f"Error fetching sublocations for location {location_id}: {e}")
        return []

def get_advert_details(advert_id, user_id):
    """Get a specific advert by ID, ensuring it belongs to the user."""
    try:
        advert_ref = db.collection("adverts").document(str(advert_id))
        advert = advert_ref.get()
        if advert.exists and advert.to_dict().get("user_id") == user_id:
            ad_data = advert.to_dict()
            ad_data["id"] = advert.id # Add Firestore doc ID
            return ad_data
        return None
    except Exception as e:
        logger.error(f"Error fetching advert {advert_id}: {e}")
        return None

def get_location_acronym_and_sub_name(sublocation_id):
    """Get the formatted location string from sublocation ID."""
    try:
        sublocation_doc = get_document("sublocations", sublocation_id)
        if not sublocation_doc:
            return None
        location_id = sublocation_doc.get("location_id")
        location_doc = get_document("locations", location_id)
        if not location_doc:
            return None
        return f"{location_doc.get('acronym')} - {sublocation_doc.get('name')}"
    except Exception as e:
        logger.error(f"Error getting location string for sublocation {sublocation_id}: {e}")
        return None

def create_advert_db(
    user_id,
    subscription_id,
    category_id,
    subcategory_id,
    title,
    description,
    price,
    negotiable,
    condition,
    location_string,
    main_img,
    additional_imgs,
    video,
    duration_days,
    plan_name,
    visibility_level,
    state_id,
    location_id,
    sublocation_id,
):
    """Create a new advert document in Firestore."""
    try:
        advert_data = {
            "user_id": user_id,
            "subscription_id": subscription_id,
            "category_id": int(category_id),
            "subcategory_id": int(subcategory_id),
            "title": title,
            "description": description,
            "price": price,
            "negotiable": negotiable,
            "condition": condition,
            "location": location_string,
            "main_image": main_img,
            "additional_images": additional_imgs,
            "video": video,
            "status": "pending_review",
            "rejected_reason": None,
            "created_at": firestore.SERVER_TIMESTAMP,
            "published_at": None,
            "expires_at": None,
            "subscription_plan_name": plan_name,
            "visibility_level": visibility_level,
            "state_id": int(state_id),
            "location_id": int(location_id),
            "sublocation_id": int(sublocation_id),
        }
        update_time, advert_ref = db.collection("adverts").add(advert_data)
        return advert_ref.id
    except Exception as e:
        logger.error(f"Error creating advert for user {user_id}: {e}")
        return None


# --- Sell Route ---
# This is the main route, now using the Firestore helper functions.
@app.route("/sell", methods=["GET", "POST"])
def sell():
    # User authentication is assumed to be handled elsewhere, populating 'session'
    if "user_id" not in session:
        flash("You must be logged in to post an advert.", "error")
        return redirect(url_for("login"))

    user_id = session.get("user_id")
    user_data = get_user_info(user_id)
    if not user_data:
        flash("User data not found. Please log in again.", "error")
        session.clear()
        return redirect(url_for("login"))

    available_options = []
    current_adverts_count = get_user_adverts_count(user_id)

    active_sub = get_active_subscription(user_id)
    if active_sub:
        available_options.append(
            {
                "type": "subscription",
                "label": f"Active Subscription: {active_sub['plan_name']}",
                "max_adverts": active_sub.get("max_adverts"),
                "advert_duration_days": active_sub.get("advert_duration_days"),
                "visibility_level": active_sub.get("visibility_level", "Standard"),
                "subscription_id": active_sub["subscription_id"],
                "plan_name": active_sub["plan_name"],
                "cost": "N/A",
            }
        )

    user_referral_count = get_user_referral_count(user_id)
    referral_benefit_details = get_referral_benefit_plan(user_referral_count)

    if (
        referral_benefit_details
        and user_referral_count >= referral_benefit_details["cost"]
    ):
        available_options.append({
            "type": "referral",
            "label": f"Referral Benefit: {referral_benefit_details['plan_name']}",
            "max_adverts": referral_benefit_details["max_adverts"],
            "advert_duration_days": referral_benefit_details["advert_duration_days"],
            "visibility_level": referral_benefit_details.get("visibility_level", "Standard"),
            "subscription_id": None,
            "plan_name": referral_benefit_details["plan_name"],
            "cost": referral_benefit_details["cost"],
        })

    free_advert_details = get_free_advert_plan_details()
    if not user_data.get("has_used_free_advert"):
        available_options.append({
            "type": "free_advert",
            "label": f"One-Time Free Advert: {free_advert_details['plan_name']}",
            "max_adverts": free_advert_details["max_adverts"],
            "advert_duration_days": free_advert_details["advert_duration_days"],
            "visibility_level": free_advert_details.get("visibility_level", "Standard"),
            "subscription_id": None,
            "plan_name": free_advert_details["plan_name"],
            "cost": "N/A",
        })

    if not available_options:
        flash(
            "You have no available advert posting options. Please subscribe or earn referral benefits to post adverts.",
            "warning",
        )
        return redirect(url_for("subscribe"))

    def render_sell_template(user_data, available_options, current_adverts_count,
                             selected_option_type, form_data, advert=None, is_repost=False):
        selected_state_id = form_data.get('state_id') or (advert.get('state_id') if advert else None)
        selected_location_id = form_data.get('location_id') or (advert.get('location_id') if advert else None)
        
        return render_template(
            "sell.html",
            user_data=user_data,
            categories=get_all_categories(),
            subcategories=get_subcategories_by_category_id(
                form_data.get('category') or (advert.get('category_id') if advert else None)
            ) if (form_data.get('category') or (advert and advert.get('category_id'))) else [],
            states=get_states_from_db(),
            locations=get_locations_by_state_from_db(selected_state_id) if selected_state_id else [],
            sublocations=get_sublocations_for_location_from_db(selected_location_id) if selected_location_id else [],
            get_subcategories=get_subcategories_by_category_id,
            get_locations_by_state=get_locations_by_state_from_db,
            get_sublocations_for_location=get_sublocations_for_location_from_db,
            available_options=available_options,
            current_adverts_count=current_adverts_count,
            selected_option_type=selected_option_type,
            form_data=form_data,
            advert=advert,
            is_repost=is_repost,
            active_subscription=active_sub,
            referral_benefit_available=referral_benefit_details,
        )

    if request.method == "GET":
        advert_to_repost = None
        is_repost_flow = False
        repost_advert_id = request.args.get('repost_advert_id')

        form_data = {}

        if repost_advert_id:
            advert_to_repost = get_advert_details(repost_advert_id, user_id)
            if not advert_to_repost or advert_to_repost['status'] not in ['rejected', 'expired']:
                flash('Advert not found or cannot be reposted.', 'error')
                return redirect(url_for('list_adverts'))
            is_repost_flow = True
            selected_option_type = None
            form_data = advert_to_repost
        else:
            selected_option_type = available_options[0]["type"] if available_options else None
            form_data = {}

        return render_sell_template(
            user_data,
            available_options,
            current_adverts_count,
            selected_option_type,
            form_data,
            advert=advert_to_repost,
            is_repost=is_repost_flow
        )

    if request.method == "POST":
        benefit_choice_type = request.form.get("benefit_choice")
        repost_advert_id = request.form.get('repost_advert_id')
        
        chosen_option = next(
            (opt for opt in available_options if opt["type"] == benefit_choice_type),
            None,
        )

        if not chosen_option:
            flash("Invalid advert option selected. Please choose a valid option.", "error")
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

        max_adverts_allowed = chosen_option.get("max_adverts", 0)
        advert_duration_days = chosen_option.get("advert_duration_days", 0)
        subscription_id_for_ad = chosen_option.get("subscription_id")
        plan_name_for_advert = chosen_option.get("plan_name", "Unknown Plan")
        advert_visibility_level = chosen_option.get("visibility_level", "Standard")
        referral_cost = chosen_option.get("cost", 0)

        if current_adverts_count >= max_adverts_allowed:
            flash(
                f"You have reached your limit of {max_adverts_allowed} active adverts for your {plan_name_for_advert} option. Please choose another option or delete an existing advert.",
                "warning",
            )
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

        if chosen_option['type'] == 'free_advert' and user_data.get('has_used_free_advert'):
            flash('You have already used your one-time free advert.', 'error')
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )
        if chosen_option['type'] == 'referral' and user_referral_count < referral_cost:
            flash(f'You do not have enough referrals ({referral_cost} required). You have {user_referral_count}.', 'error')
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

        form_data = request.form.to_dict()
        category_id = form_data.get("category")
        subcategory_id = form_data.get("subcategory")
        title = form_data.get("title", "").strip()
        description = form_data.get("description", "").strip()
        price_str = form_data.get("price")
        negotiable_raw = form_data.get("negotiable")
        condition = form_data.get("condition")

        state_id_from_form = form_data.get("state_id")
        location_id_from_form = form_data.get("location_id")
        sub_location_id_from_form = form_data.get("sub_location_id")

        errors = []
        price = 0.0

        if not state_id_from_form:
            errors.append("State selection is required.")
        if not location_id_from_form:
            errors.append("Main Location (University) selection is required.")
        if not sub_location_id_from_form:
            errors.append("Sub-Location (Area) selection is required.")

        if sub_location_id_from_form:
            try:
                sub_location_doc = get_document("sublocations", sub_location_id_from_form)
                if not sub_location_doc:
                    errors.append("Selected sub-location does not exist.")
                elif str(sub_location_doc.get('location_id')) != location_id_from_form:
                    errors.append("Selected sub-location is invalid or does not belong to the chosen university.")
            except Exception as e:
                logger.error(f"Error validating sublocation {sub_location_id_from_form}: {e}", exc_info=True)
                errors.append("An error occurred during location validation.")

        formatted_location_string = get_location_acronym_and_sub_name(sub_location_id_from_form)
        if not formatted_location_string:
            errors.append("Failed to determine the complete location string. Please re-select locations.")

        negotiable_db_value = "Yes" if negotiable_raw == "yes" else "No"

        main_image = request.files.get("main_image")
        additional_images = request.files.getlist("additional_images")
        video = request.files.get("video")

        if not category_id:
            errors.append("Category is required.")
        if not subcategory_id:
            errors.append("Subcategory is required.")
        if not title:
            errors.append("Ad Title is required.")
        if not description:
            errors.append("Ad Description is required.")
        if not price_str:
            errors.append("Price is required.")
        else:
            try:
                price = float(price_str)
                if price < 0:
                    errors.append("Price cannot be negative.")
            except ValueError:
                errors.append("Invalid price format.")

        existing_advert_files = None
        if repost_advert_id:
            existing_advert_files = get_advert_details(repost_advert_id, user_id)
            if (not main_image or main_image.filename == "") and (not existing_advert_files or not existing_advert_files.get('main_image')):
                errors.append("Main Image is required if not provided previously.")
        else:
            if not main_image or main_image.filename == "":
                errors.append("Main Image is required.")

        if main_image and main_image.filename and not allowed_file(main_image.filename):
            errors.append("Main image has an unsupported format.")

        for img in additional_images:
            if img and img.filename and not allowed_file(img.filename):
                errors.append(f"Additional image '{img.filename}' has an unsupported format.")

        if video and video.filename and not allowed_file(video.filename):
            errors.append("Video file has an unsupported format.")

        if errors:
            for error in errors:
                flash(error, "error")
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, form_data,
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

        main_img_filename = None
        additional_img_filenames = []
        video_filename = None

        upload_folder = app.config.get("UPLOAD_FOLDER")
        os.makedirs(upload_folder, exist_ok=True)

        try:
            if main_image and main_image.filename != "":
                main_img_filename = secure_filename(f"{uuid.uuid4().hex}_{main_image.filename}")
                main_image.save(os.path.join(upload_folder, main_img_filename))
            elif existing_advert_files and existing_advert_files.get('main_image'):
                main_img_filename = existing_advert_files['main_image']
        except Exception as e:
            flash(f"Error saving main image: {str(e)}", "danger")
            logger.error(f"Error saving main image: {e}", exc_info=True)
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

        if repost_advert_id and existing_advert_files and existing_advert_files.get('additional_images'):
            additional_img_filenames.extend(existing_advert_files.get('additional_images', []))
        
        for img in additional_images:
            if img and img.filename and allowed_file(img.filename):
                try:
                    filename = secure_filename(f"{uuid.uuid4().hex}_{img.filename}")
                    img.save(os.path.join(upload_folder, filename))
                    additional_img_filenames.append(filename)
                except Exception as e:
                    flash(
                        f"Error saving additional image: {img.filename} - {str(e)}",
                        "warning",
                    )
                    logger.warning(f"Error saving additional image {img.filename}: {e}")
        
        additional_img_filenames = additional_img_filenames[:5]

        try:
            if video and video.filename != "":
                video_filename = secure_filename(f"{uuid.uuid4().hex}_{video.filename}")
                video.save(os.path.join(upload_folder, video_filename))
            elif existing_advert_files and existing_advert_files.get('video'):
                video_filename = existing_advert_files['video']
        except Exception as e:
            flash(f"Error saving video: {str(e)}", "warning")
            logger.warning(f"Error saving video: {e}")

        try:
            if chosen_option['type'] == 'free_advert':
                user_ref = db.collection("users").document(user_id)
                user_ref.update({"has_used_free_advert": True})
                logger.info(f"User {user_id} used their one-time free advert.")
            elif chosen_option['type'] == 'referral':
                user_ref = db.collection("users").document(user_id)
                user_ref.update({"referral_count": firestore.Increment(-referral_cost)})
                logger.info(f"User {user_id} used {referral_cost} referrals to post an advert.")

            if repost_advert_id:
                advert_ref = db.collection("adverts").document(repost_advert_id)
                advert_data = {
                    "category_id": int(category_id),
                    "subcategory_id": int(subcategory_id),
                    "title": title,
                    "description": description,
                    "price": price,
                    "negotiable": negotiable_db_value,
                    "condition": condition,
                    "location": formatted_location_string,
                    "main_image": main_img_filename,
                    "additional_images": additional_img_filenames, # Storing as a list
                    "video": video_filename,
                    "status": "pending_review",
                    "rejected_reason": None,
                    "subscription_id": subscription_id_for_ad,
                    "subscription_plan_name": plan_name_for_advert,
                    "visibility_level": advert_visibility_level,
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "published_at": None,
                    "expires_at": None,
                    "state_id": int(state_id_from_form),
                    "location_id": int(location_id_from_form),
                    "sublocation_id": int(sub_location_id_from_form)
                }
                advert_ref.update(advert_data)
                flash("Your advert has been successfully resubmitted for review and will be live once approved by an administrator.", "info")
                logger.info(f"Advert {repost_advert_id} by user {user_id} successfully reposted for review.")
            else:
                new_advert_id = create_advert_db(
                    user_id, subscription_id_for_ad, category_id, subcategory_id, title, description,
                    price, negotiable_db_value, condition, formatted_location_string, main_img_filename,
                    additional_img_filenames, video_filename,
                    advert_duration_days, plan_name_for_advert, advert_visibility_level,
                    state_id_from_form, location_id_from_form, sub_location_id_from_form
                )
                if not new_advert_id:
                    raise Exception("Failed to create advert in database.")

                flash("Your advert has been successfully submitted for review and will be live once approved by an administrator.", "info")
                logger.info(f"New advert {new_advert_id} by user {user_id} submitted for review.")
            
            return redirect(url_for("list_adverts"))

        except Exception as e:
            flash(f"An error occurred during advert submission: {str(e)}. Please try again.", "error")
            logger.error(f"Error during advert submission for user {user_id}: {e}", exc_info=True)
            return render_sell_template(
                user_data, available_options, current_adverts_count,
                benefit_choice_type, request.form.to_dict(),
                advert=get_advert_details(repost_advert_id, user_id) if repost_advert_id else None,
                is_repost=(repost_advert_id is not None)
            )

@app.route('/get_subcategories/<int:category_id>')
def get_subcategories(category_id):
    subcategories = get_subcategories_by_category_id(category_id)
    return jsonify(subcategories)
    
@app.route('/choose-advert-option', methods=['GET', 'POST'])
def choose_advert_option():
    if 'user_id' not in session:
        flash("Please log in to continue.", "error")
        return redirect(url_for('login'))
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'paid':
            return redirect(url_for('subscribe'))
        elif action == 'referral':
            return redirect(url_for('referral_benefit'))
        else:
            flash("Invalid option selected.", "error")
    return render_template('choose_advert_option.html')













def get_document(collection_name, document_id):
    """
    Fetches a single document from a Firestore collection.
    
    Args:
        collection_name (str): The name of the Firestore collection.
        document_id (str): The ID of the document to fetch.
        
    Returns:
        A dictionary of the document's data if it exists, otherwise None.
    """
    try:
        doc_ref = db.collection(collection_name).document(document_id)
        doc = doc_ref.get()
        if doc.exists:
            # We add the 'id' field to the document data for consistency
            doc_data = doc.to_dict()
            doc_data['id'] = doc.id
            return doc_data
        else:
            return None
    except Exception as e:
        # Log the error for debugging purposes
        app.logger.error(f"Error fetching document {document_id} from {collection_name}: {e}")
        return None

# --- Helper Functions (Refactored for Firestore) ---

def allowed_file(filename):
    # This function is fine as is, but it relies on a global variable `ALLOWED_EXTENSIONS`.
    # Make sure this variable is defined somewhere in your app config.
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov'} # Example
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_unique_filename(filename):
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S%f")
    if '.' in filename:
        name_part, ext = filename.rsplit('.', 1)
        ext = ext.lower()
    else:
        name_part = filename
        ext = ''

    secured_name = secure_filename(name_part)
    return f"{timestamp}_{secured_name}.{ext}" if ext else f"{timestamp}_{secured_name}"

def get_media_type_from_extension(file_path):
    # This function is already database-agnostic and does not need changes.
    if not file_path:
        return 'text'

    if file_path.startswith(('http://', 'https://')):
        extension = os.path.splitext(urlparse(file_path).path)[1].lower()
    else:
        extension = os.path.splitext(file_path)[1].lower()

    if extension in ('.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp'):
        return 'image'
    elif extension in ('.mp4', '.webm', '.ogg', '.avi', '.mov', '.flv'):
        return 'video'
    elif extension in ('.mp3', '.wav', '.ogg', '.aac', '.flac'):
        return 'audio'
    elif extension in ('.pdf', '.doc', '.docx', '.txt', '.ppt', '.pptx', '.xls', '.xlsx', '.zip', '.rar'):
        return 'document'
    else:
        return 'other'

def get_current_user_id():
    # This function is fine as it relies on the Flask session object.
    from flask import session # Assuming Flask is being used
    return session.get('user_id')

def get_current_username():
    # This function is fine as it relies on the Flask session object.
    from flask import session
    return session.get('username', 'Anonymous')

def get_user_role(user_id):
    """Fetches the role of a user from the 'users' collection."""
    if not user_id:
        return None
    user_doc = get_document("users", user_id)
    return user_doc.get('role') if user_doc else None

def is_admin(user_id):
    """Checks if a user is an admin."""
    return get_user_role(user_id) == 'admin'


def get_user_profile_info_by_username(username):
    """
    Fetches user ID and profile picture URL for a given username from Firestore.
    """
    try:
        users_ref = db.collection('users').where(filter=FieldFilter('username', '==', username))
        user_docs = users_ref.limit(1).get()
        if user_docs:
            user_doc = user_docs[0]
            user_data = user_doc.to_dict()
            return {
                'id': user_doc.id,
                'profile_picture_url': user_data.get('profile_picture_url', '/static/default_avatar.png')
            }
        return {}
    except Exception as e:
        current_app.logger.error(f"Error fetching user profile info by username {username}: {e}")
        return {}
        
        
def get_user_profile_info(user_id):
    """Fetches username and profile picture URL for a given user ID from 'users' collection."""
    user_doc = get_document("users", user_id)
    if user_doc:
        return {
            'username': user_doc.get('username', 'Unknown User'),
            'profile_picture_url': user_doc.get('profile_picture', '/static/default_avatar.png')
        }
    return {'username': 'Unknown User', 'profile_picture_url': '/static/default_avatar.png'}


def get_user_followers_count(user_id):
    """Gets the number of followers for a given user ID from 'followers' collection."""
    if not user_id:
        return 0
    try:
        query = db.collection("followers").where("followed_id", "==", user_id)
        docs = query.stream()
        count = sum(1 for _ in docs)
        return count
    except Exception as e:
        app.logger.error(f"Error getting followers count for user {user_id}: {e}")
        return 0

def is_following(follower_id, followed_id):
    """Checks if follower_id is following followed_id."""
    if not follower_id or not followed_id:
        return False
    try:
        # A single document query is more efficient than a stream and count.
        query = db.collection("followers") \
            .where("follower_id", "==", follower_id) \
            .where("followed_id", "==", followed_id) \
            .limit(1)
        
        docs = query.stream()
        return any(docs) # True if at least one doc exists, False otherwise
    except Exception as e:
        app.logger.error(f"Error checking follow status: {e}")
        return False

def get_average_user_rating(user_id):
    """
    Fetches ratings from the 'reviews' collection and calculates the average.
    
    NOTE: Firestore does not have a native AVG function. This implementation
    fetches all reviews for the user and calculates the average in-memory.
    For a production application with many reviews, you might consider
    storing the average rating as a field on the user document and updating it
    whenever a new review is added.
    """
    if not user_id:
        return 'N/A'
    try:
        ratings_query = db.collection("reviews").where("reviewee_id", "==", user_id)
        ratings_docs = ratings_query.stream()
        
        total_rating = 0
        count = 0
        for doc in ratings_docs:
            total_rating += doc.get('rating', 0)
            count += 1
            
        if count > 0:
            return round(total_rating / count, 1)
        else:
            return 'N/A'
    except Exception as e:
        app.logger.error(f"Error fetching average rating for user {user_id}: {e}")
        return 'N/A'

def get_study_materials_from_db(query=None, page=1, per_page=10):
    """
    Fetches study materials from Firestore with optional search and pagination.
    
    NOTE: Firestore pagination and advanced querying (like OR clauses) require
    special handling. This implementation performs a simple text search and
    manual pagination.
    """
    try:
        collection_ref = db.collection("study_materials")
        
        # Build the base query
        if query:
            # We can't use LIKE in Firestore, so we'll use a simple starts_with for now.
            # A full-text search solution would require a dedicated service like Algolia or a
            # more complex setup.
            query_ref = collection_ref.where("title", ">=", query).where("title", "<=", query + '\uf8ff')
        else:
            query_ref = collection_ref
            
        # Get total materials count (separate query needed)
        total_materials = len(list(query_ref.stream()))
        
        # Apply ordering and pagination
        offset = (page - 1) * per_page
        if offset > 0:
            # Firestore doesn't have a direct `offset` method for queries
            # For robust pagination, you should use start_at or start_after with a cursor
            # For this simple example, we'll fetch all and slice
            all_materials = list(query_ref.order_by("upload_date", direction=firestore.Query.DESCENDING).stream())
            materials = all_materials[offset:offset+per_page]
        else:
            materials = query_ref.order_by("upload_date", direction=firestore.Query.DESCENDING).limit(per_page).stream()
            
        return [doc.to_dict() for doc in materials], total_materials, None
    except Exception as e:
        app.logger.error(f"Error fetching study materials: {e}")
        return [], 0, str(e)

def get_study_material_by_id_from_db(material_id):
    """Fetches a single study material by ID."""
    material_doc = get_document("study_materials", material_id)
    return material_doc

def fetch_stories_for_followed_users(user_id):
    """
    Fetches active stories from users that the current user follows,
    AND includes the current user's own active stories.
    """
    try:
        # Step 1: Get the IDs of followed users
        followed_users_query = db.collection("followers").where("follower_id", "==", user_id)
        followed_users_docs = followed_users_query.stream()
        followed_users_ids = [doc.to_dict()['followed_id'] for doc in followed_users_docs]

        # Step 2: Combine current user's ID with followed users' IDs
        all_relevant_user_ids = list(set([user_id] + followed_users_ids))

        if not all_relevant_user_ids:
            return []

        # Step 3: Fetch stories using a batch read (IN query)
        stories_query = db.collection("stories") \
            .where("user_id", "in", all_relevant_user_ids) \
            .where("expires_at", ">", datetime.datetime.now()) \
            .order_by("created_at", direction=firestore.Query.DESCENDING)
        
        stories_docs = stories_query.stream()

        # Step 4: Group stories by user
        grouped_stories = {}
        for doc in stories_docs:
            story = doc.to_dict()
            story['id'] = doc.id
            
            user_id_key = story['user_id']
            if user_id_key not in grouped_stories:
                # Fetch user profile info in a separate, efficient call
                user_profile = get_user_profile_info(user_id_key)
                grouped_stories[user_id_key] = {
                    'user_id': user_id_key,
                    'username': user_profile['username'],
                    'profile_picture_url': user_profile['profile_picture_url'],
                    'stories': []
                }
            grouped_stories[user_id_key]['stories'].append({
                'id': story['id'],
                'media_url': story['media_url'],
                'media_type': story['media_type'],
                'caption': story['caption'],
                'created_at': story['created_at'] # Firestore datetime object
            })
        
        return list(grouped_stories.values())
    except Exception as e:
        app.logger.error(f"Error fetching stories for user {user_id} and followed users: {e}")
        return []

def fetch_posts_for_display(category_filter, search_query, page, per_page, current_user_id):
    """
    Fetches posts for display, including all associated media items,
    comments preview, reactions, and follower status.
    
    This function demonstrates how to handle the lack of SQL JOINs in Firestore
    by performing multiple queries.
    """
    try:
        posts_ref = db.collection("posts")
        
        # Step 1: Build the main query for posts
        query_ref = posts_ref.where("category", "==", category_filter) \
                             .where("post_date", ">", datetime.datetime.now() - datetime.timedelta(hours=24)) # Assuming 24 hour duration for simplicity

        # The search query part needs to be handled differently.
        # Firestore does not support full-text search. A simple `starts_with` filter is used here.
        # For more complex search, you'd need a dedicated search service.
        if search_query:
            query_ref = query_ref.where("title", ">=", search_query) \
                                 .where("title", "<=", search_query + '\uf8ff')
        
        # Step 2: Get total count and apply pagination
        total_posts = len(list(query_ref.stream()))
        
        offset = (page - 1) * per_page
        posts_query = query_ref.order_by("post_date", direction=firestore.Query.DESCENDING) \
                               .limit(per_page)
        
        # The offset here is a placeholder and would need a cursor for proper pagination
        if offset > 0:
            posts_docs = list(posts_query.stream())
            paged_posts = posts_docs[offset:]
        else:
            paged_posts = posts_query.stream()
            
        posts = []
        for doc in paged_posts:
            post = doc.to_dict()
            post['id'] = doc.id
            
            # Step 3: Fetch all related data for each post in separate, targeted queries
            # User data
            post_author_id = post.get('author_id')
            user_doc = get_document("users", post_author_id)
            if user_doc:
                post['author_user_id'] = user_doc['id']
                post['author_username'] = user_doc['username']
                post['profile_picture_url'] = user_doc.get('profile_picture', '/static/default_avatar.png')
            else:
                post['author_user_id'] = None
                post['author_username'] = 'Unknown User'
                post['profile_picture_url'] = '/static/default_avatar.png'
            
            # Media items
            media_query = db.collection("post_media_items").where("post_id", "==", post['id']) \
                                                        .order_by("order_index")
            post['post_media_items'] = [doc.to_dict() for doc in media_query.stream()]

            # Comments preview
            comments_query = db.collection("comments").where("post_id", "==", post['id']) \
                                                    .order_by("comment_date", direction=firestore.Query.DESCENDING) \
                                                    .limit(2)
            post['comments_preview'] = []
            for comment_doc in comments_query.stream():
                comment = comment_doc.to_dict()
                comment['id'] = comment_doc.id
                comment_author_id = comment.get('author_id')
                author_info = get_user_profile_info(comment_author_id)
                comment['author'] = author_info['username']
                comment['profile_picture_url'] = author_info['profile_picture_url']
                post['comments_preview'].append(comment)
                
            # Comments count
            comments_count_query = db.collection("comments").where("post_id", "==", post['id'])
            post['comments_count'] = len(list(comments_count_query.stream()))

            # Reactions breakdown
            reactions_query = db.collection("reactions").where("post_id", "==", post['id'])
            reactions_docs = reactions_query.stream()
            post['reactions_breakdown'] = {}
            for reaction_doc in reactions_docs:
                reaction_type = reaction_doc.get('reaction_type')
                post['reactions_breakdown'][reaction_type] = post['reactions_breakdown'].get(reaction_type, 0) + 1
            
            # Current user's reaction
            post['current_user_reaction'] = None
            if current_user_id:
                user_reaction_query = db.collection("reactions").where("post_id", "==", post['id']) \
                                                            .where("user_id", "==", current_user_id) \
                                                            .limit(1)
                user_reaction_doc = next(user_reaction_query.stream(), None)
                if user_reaction_doc:
                    post['current_user_reaction'] = user_reaction_doc.get('reaction_type')

            # Follower status
            post['is_followed_by_current_user'] = is_following(current_user_id, post['author_user_id'])
            
            # Author metadata
            post['author_followers_count'] = get_user_followers_count(post['author_user_id'])
            post['author_average_rating'] = get_average_user_rating(post['author_user_id'])
            
            posts.append(post)

        return posts, total_posts, None

    except Exception as e:
        app.logger.error(f"Error in fetch_posts_for_display: {e}", exc_info=True)
        return [], 0, str(e)


def get_post_by_id(post_id, current_user_id=None):
    """
    Fetches a single post and all its related data for a detailed view.
    """
    try:
        post = get_document("posts", post_id)
        if not post:
            return None, "Post not found."

        # Fetch all related data in separate queries
        
        # User data
        post_author_id = post.get('author_id')
        user_doc = get_document("users", post_author_id)
        if user_doc:
            post['author_user_id'] = user_doc['id']
            post['author_username'] = user_doc['username']
            post['profile_picture_url'] = user_doc.get('profile_picture', '/static/default_avatar.png')
        else:
            post['author_user_id'] = None
            post['author_username'] = 'Unknown User'
            post['profile_picture_url'] = '/static/default_avatar.png'

        # Media items
        media_query = db.collection("post_media_items").where("post_id", "==", post['id']) \
                                                      .order_by("order_index")
        post['post_media_items'] = [doc.to_dict() for doc in media_query.stream()]

        # Reactions
        reactions_query = db.collection("reactions").where("post_id", "==", post['id'])
        reactions_docs = reactions_query.stream()
        post['reactions_breakdown'] = {}
        for reaction_doc in reactions_docs:
            reaction_type = reaction_doc.get('reaction_type')
            post['reactions_breakdown'][reaction_type] = post['reactions_breakdown'].get(reaction_type, 0) + 1
        post['reactions_count'] = len(list(db.collection("reactions").where("post_id", "==", post['id']).stream()))

        # Current user's reaction
        post['current_user_reaction'] = None
        if current_user_id:
            user_reaction_query = db.collection("reactions").where("post_id", "==", post['id']) \
                                                        .where("user_id", "==", current_user_id) \
                                                        .limit(1)
            user_reaction_doc = next(user_reaction_query.stream(), None)
            if user_reaction_doc:
                post['current_user_reaction'] = user_reaction_doc.get('reaction_type')
        
        # Comments
        comments_query = db.collection("comments").where("post_id", "==", post['id']) \
                                                  .order_by("comment_date")
        post['comments'] = []
        for comment_doc in comments_query.stream():
            comment = comment_doc.to_dict()
            comment['id'] = comment_doc.id
            comment_author_id = comment.get('author_id')
            author_info = get_user_profile_info(comment_author_id)
            comment['author'] = author_info['username']
            comment['profile_picture_url'] = author_info['profile_picture_url']
            post['comments'].append(comment)
        post['comments_count'] = len(post['comments'])
        
        # Author metadata
        post['author_followers_count'] = get_user_followers_count(post['author_user_id'])
        post['is_followed_by_current_user'] = is_following(current_user_id, post['author_user_id'])
        post['author_average_rating'] = get_average_user_rating(post['author_user_id'])

        return post, None
    
    except Exception as e:
        app.logger.error(f"Error fetching single post (ID: {post_id}): {e}", exc_info=True)
        return None, str(e)


@app.route('/api/school_gist')
def api_school_gist():
    try:
        search_query = request.args.get('q')
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        current_user_id = get_current_user_id()

        # Call the updated fetch_posts_for_display that returns an error_message
        posts, total_posts, error_message = fetch_posts_for_display('School Gist', search_query, page, per_page, current_user_id)

        if error_message:
            # If an error occurred in fetch_posts_for_display, return a JSON error response
            return jsonify({
                'posts': [], 
                'total_posts': 0, 
                'page': page, 
                'per_page': per_page, 
                'total_pages': 0, 
                'error': True, # Custom flag to indicate an error
                'message': f"Failed to retrieve posts from the server: {error_message}"
            }), 500 # Return 500 Internal Server Error status

        posts_data = []
        for post in posts:
            # Ensure datetime objects are converted to strings for JSON serialization
            # CHANGED: datetime.datetime -> datetime
            post_date_str = post['post_date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(post.get('post_date'), datetime) else str(post.get('post_date', ''))

            comments_data = []
            if 'comments_preview' in post and post['comments_preview']:
                for comment in post['comments_preview']:
                    # CHANGED: datetime.datetime -> datetime
                    comment_date_str = comment['date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(comment.get('date'), datetime) else str(comment.get('date', ''))
                    comments_data.append({
                        'author': comment['author'],
                        'text': comment['text'],
                        'date': comment_date_str,
                        'profile_picture_url': comment.get('profile_picture_url', '/static/default_avatar.png')
                    })

            media_items_for_json = []
            if 'post_media_items' in post and post['post_media_items']:
                for media_item in post['post_media_items']:
                    media_items_for_json.append({
                        'id': media_item['id'],
                        'media_type': media_item['media_type'],
                        'media_path_or_url': media_item['media_path_or_url'],
                        'caption': media_item.get('caption'), 
                        'order_index': media_item['order_index']
                    })

            posts_data.append({
                'id': post['id'],
                'title': post['title'],
                'content': post['content'],
                'author_username': post['author_username'],
                'author_user_id': post['author_user_id'],
                'profile_picture_url': post.get('profile_picture_url', '/static/default_avatar.png'),
                'post_date': post_date_str,
                'post_media_items': media_items_for_json,
                'external_link_url': post.get('external_link_url'), 
                'reactions_count': post.get('reactions_count', 0),
                'reactions_breakdown': post.get('reactions_breakdown', {}),
                'current_user_reaction': post.get('current_user_reaction'),
                'comments_count': post.get('comments_count', 0),
                'comments_preview': comments_data,
                'duration_hours': post.get('duration_hours'),
                'author_followers_count': post.get('author_followers_count', 0),
                'is_followed_by_current_user': post.get('is_followed_by_current_user', False),
                'author_average_rating': post.get('author_average_rating', 'N/A')
            })

        return jsonify({
            'posts': posts_data,
            'total_posts': total_posts,
            'page': page,
            'per_page': per_page,
            'total_pages': (total_posts + per_page - 1) // per_page,
            'error': False, # Indicate success
            'message': "Posts loaded successfully."
        })
    except Exception as e:
        # This catches any errors occurring directly within the api_school_gist route itself
        # (e.g., during JSON serialization if a datetime object slips through, or other unexpected issues).
        app.logger.error(f"An unexpected error occurred in /api/school_gist: {e}", exc_info=True)
        return jsonify({
            'posts': [], 
            'total_posts': 0, 
            'page': page, 
            'per_page': per_page, 
            'total_pages': 0, 
            'error': True, 
            'message': f"An unexpected server error occurred: {e}" # General fallback error
        }), 500
        
        
@app.route('/api/stories')
def api_stories():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'message': 'No user logged in. Stories from followed users or your own stories cannot be fetched.'}), 401

    # In Firestore, we'll get the list of followed users first
    followed_users_ids = []
    # Using a composite key for follower documents for easy lookup
    followers_ref = db.collection('followers').where(filter=FieldFilter('follower_id', '==', current_user_id))
    for doc in followers_ref.stream():
        followed_users_ids.append(doc.to_dict().get('followed_id'))
    
    # Also include the current user's own stories
    followed_users_ids.append(current_user_id)

    # Now, fetch stories where the user_id is in our list of followed users
    stories_data = []
    if followed_users_ids:
        # Firestore's 'in' operator has a limit of 10. For more, multiple queries are needed.
        stories_ref = db.collection('stories').where(filter=FieldFilter('user_id', 'in', followed_users_ids)).order_by('story_date', direction=firestore.Query.DESCENDING)
        stories_docs = stories_ref.stream()
        for doc in stories_docs:
            story_data = doc.to_dict()
            story_data['id'] = doc.id
            stories_data.append(story_data)
            
    return jsonify(stories_data)


@app.route('/api/posts/<post_id>', methods=['DELETE'])
def delete_post(post_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401

    post_ref = db.collection('posts').document(post_id)
    post_doc = post_ref.get()

    if not post_doc.exists:
        return jsonify({'success': False, 'message': 'Post not found.'}), 404
        
    post_data = post_doc.to_dict()
    if post_data.get('author_user_id') != current_user_id:
        return jsonify({'success': False, 'message': 'You are not authorized to delete this post.'}), 403

    try:
        # Delete associated sub-collections first (comments and reactions)
        # Firestore doesn't have a built-in cascading delete for sub-collections.
        comments_ref = post_ref.collection('comments')
        for doc in comments_ref.stream():
            doc.reference.delete()
            
        reactions_ref = post_ref.collection('reactions')
        for doc in reactions_ref.stream():
            doc.reference.delete()
            
        # Delete media items (assuming they are a sub-collection)
        media_items_ref = post_ref.collection('post_media_items')
        for doc in media_items_ref.stream():
            doc.reference.delete()

        # Finally, delete the post document itself
        post_ref.delete()
        
        # Note: You may also need to update a user's post count via a transaction if you store it.
        
        return jsonify({'success': True, 'message': 'Post deleted successfully.'}), 200

    except Exception as e:
        current_app.logger.error(f"Error deleting post {post_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred while deleting the post.'}), 500

@app.route('/api/stories/<story_id>', methods=['DELETE'])
def delete_story(story_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401

    story_ref = db.collection('stories').document(story_id)
    story_doc = story_ref.get()

    if not story_doc.exists:
        return jsonify({'success': False, 'message': 'Story not found.'}), 404

    if story_doc.to_dict().get('user_id') != current_user_id:
        return jsonify({'success': False, 'message': 'You are not authorized to delete this story.'}), 403

    try:
        story_ref.delete()
        return jsonify({'success': True, 'message': 'Story deleted successfully.'}), 200

    except Exception as e:
        current_app.logger.error(f"Error deleting story {story_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An error occurred while deleting the story.'}), 500

@app.route('/post/<category>/<post_id>')
def view_single_post(category, post_id):
    current_user_id = get_current_user_id()
    # The get_post_by_id function has been updated to use Firestore
    post = get_post_by_id(post_id, current_user_id)
    
    if not post:
        abort(404, description=f"{category} post not found.")
    
    # Prepare comments for display, including profile pictures
    for comment in post.get('comments', []):
        author_username = comment.get('author')
        if author_username:
            author_profile_info = get_user_profile_info_by_username(author_username)
            comment['profile_picture_url'] = author_profile_info.get('profile_picture_url', '/static/default_avatar.png')

    return render_template('single_post.html', post=post, current_user_id=current_user_id)


@app.route('/api/add_reaction/<post_id>', methods=['POST'])
def api_add_reaction(post_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Please log in to react to posts.'}), 401

    data = request.get_json()
    reaction_type = data.get('reaction_type')

    if not reaction_type:
        return jsonify({'success': False, 'message': 'Reaction type is required.'}), 400

    post_ref = db.collection('posts').document(post_id)
    
    # We use a transaction to ensure atomic updates
    @firestore.transactional
    def update_reaction_in_transaction(transaction, post_reference):
        reactions_ref = post_reference.collection('reactions')
        
        # Check for an existing reaction from this user
        existing_reaction_query = reactions_ref.where(filter=FieldFilter('user_id', '==', current_user_id)).limit(1)
        existing_reaction_docs = existing_reaction_query.get()
        existing_reaction_doc = existing_reaction_docs[0] if existing_reaction_docs else None

        action = 'added'
        if existing_reaction_doc:
            existing_reaction_type = existing_reaction_doc.to_dict().get('reaction_type')
            if existing_reaction_type == reaction_type:
                # Same reaction type, so remove it (toggle off)
                transaction.delete(existing_reaction_doc.reference)
                action = 'removed'
            else:
                # Different reaction type, so delete the old one and add the new one
                transaction.delete(existing_reaction_doc.reference)
                new_reaction_doc_ref = reactions_ref.document(str(uuid.uuid4()))
                transaction.set(new_reaction_doc_ref, {
                    'user_id': current_user_id,
                    'reaction_type': reaction_type,
                    'reacted_at': datetime.now()
                })
        else:
            # No existing reaction, so add a new one
            new_reaction_doc_ref = reactions_ref.document(str(uuid.uuid4()))
            transaction.set(new_reaction_doc_ref, {
                'user_id': current_user_id,
                'reaction_type': reaction_type,
                'reacted_at': datetime.now()
            })
            
        return action
    
    try:
        transaction = db.transaction()
        action = update_reaction_in_transaction(transaction, post_ref)
        
        # After the transaction, fetch the updated counts for the response
        reactions_ref = post_ref.collection('reactions')
        reactions_docs = reactions_ref.stream()
        reactions_breakdown = {}
        for reaction_doc in reactions_docs:
            reaction_type = reaction_doc.to_dict().get('reaction_type')
            reactions_breakdown[reaction_type] = reactions_breakdown.get(reaction_type, 0) + 1
        
        current_user_reaction = None
        user_reaction_docs = reactions_ref.where(filter=FieldFilter('user_id', '==', current_user_id)).limit(1).get()
        if user_reaction_docs:
            current_user_reaction = user_reaction_docs[0].to_dict().get('reaction_type')
            
        return jsonify({
            'success': True,
            'action': action,
            'new_reactions_count': sum(reactions_breakdown.values()),
            'reactions_breakdown': reactions_breakdown,
            'current_user_reaction': current_user_reaction
        })

    except Exception as e:
        current_app.logger.error(f"Error adding/removing reaction to post {post_id}: {e}")
        return jsonify({'success': False, 'message': f'Server error: {e}'}), 500

@app.route('/api/add_comment/<post_id>', methods=['POST'])
def api_add_comment(post_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Please log in to comment.'}), 401

    data = request.get_json()
    comment_text = data.get('comment')
    comment_author_username = get_current_username()

    if not comment_text:
        return jsonify({'success': False, 'message': 'Comment text is required'}), 400

    post_ref = db.collection('posts').document(post_id)
    if not post_ref.get().exists:
        return jsonify({'success': False, 'message': 'Post not found'}), 404

    try:
        comments_ref = post_ref.collection('comments')
        new_comment_ref = comments_ref.document()
        new_comment_data = {
            'author': comment_author_username,
            'user_id': current_user_id,
            'text': comment_text,
            'comment_date': datetime.now()
        }
        new_comment_ref.set(new_comment_data)

        # Get updated comments count (using aggregation query for efficiency)
        new_comments_count = comments_ref.count().get().aggregate_results[0].value
        
        author_profile_info = get_user_profile_info_by_username(comment_author_username)
        
        new_comment_response = {
            'author': comment_author_username,
            'text': comment_text,
            'date': datetime.now().isoformat(),
            'profile_picture_url': author_profile_info.get('profile_picture_url', '/static/default_avatar.png')
        }

        return jsonify({
            'success': True,
            'comment': new_comment_response,
            'new_comments_count': new_comments_count
        })
    except Exception as e:
        current_app.logger.error(f"Error adding comment to post {post_id}: {e}")
        return jsonify({'success': False, 'message': 'An error occurred while adding your comment. Please try again.'}), 500


@app.route('/api/follow_user/<user_to_follow_id>', methods=['POST'])
def api_follow_user(user_to_follow_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Please log in to follow users.'}), 401
    
    if current_user_id == user_to_follow_id:
        return jsonify({'success': False, 'message': 'You cannot follow yourself.'}), 400

    # Using a composite document ID for the follower relationship
    # This prevents duplicate follow entries and allows for easy deletion
    follower_doc_id = f"{current_user_id}_{user_to_follow_id}"
    follower_doc_ref = db.collection('followers').document(follower_doc_id)
    
    try:
        # Check if user to follow exists
        user_to_follow_doc = db.collection('users').document(user_to_follow_id).get()
        if not user_to_follow_doc.exists:
            return jsonify({'success': False, 'message': 'User to follow not found.'}), 404

        # Check if already following
        if follower_doc_ref.get().exists:
            return jsonify({'success': False, 'message': 'Already following this user.'}), 409

        follower_doc_ref.set({
            'follower_id': current_user_id,
            'followed_id': user_to_follow_id,
            'followed_at': datetime.now()
        })
        
        # Get updated followers count (this can be slow, a counter field is better)
        new_followers_count = get_user_followers_count(user_to_follow_id)

        return jsonify({'success': True, 'action': 'followed', 'new_followers_count': new_followers_count})
    except Exception as e:
        current_app.logger.error(f"Error following user {user_to_follow_id}: {e}")
        return jsonify({'success': False, 'message': f'Server error: {e}'}), 500

@app.route('/api/unfollow_user/<user_to_unfollow_id>', methods=['POST'])
def api_unfollow_user(user_to_unfollow_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Please log in to unfollow users.'}), 401
    
    if current_user_id == user_to_unfollow_id:
        return jsonify({'success': False, 'message': 'You cannot unfollow yourself.'}), 400
        
    follower_doc_id = f"{current_user_id}_{user_to_unfollow_id}"
    follower_doc_ref = db.collection('followers').document(follower_doc_id)

    try:
        if not follower_doc_ref.get().exists:
            return jsonify({'success': False, 'message': 'Not currently following this user.'}), 409

        follower_doc_ref.delete()
        
        # Get updated followers count (this can be slow, a counter field is better)
        new_followers_count = get_user_followers_count(user_to_unfollow_id)

        return jsonify({'success': True, 'action': 'unfollowed', 'new_followers_count': new_followers_count})
    except Exception as e:
        current_app.logger.error(f"Error unfollowing user {user_to_unfollow_id}: {e}")
        return jsonify({'success': False, 'message': f'Server error: {e}'}), 500


@app.route('/download/<post_id>')
def download_media(post_id):
    post_doc = db.collection('posts').document(post_id).get()

    if not post_doc.exists:
        abort(404, description="Media not found for this post.")

    post_data = post_doc.to_dict()
    download_url = post_data.get('download_file_path')

    if download_url:
        return redirect(download_url)
    else:
        abort(404, description="Download link not found for this post.")
        
# The `school_gist` and `school_news` routes remain the same since they only render templates.
@app.route('/school_gist')
def school_gist():
    current_user_id = get_current_user_id()
    current_user_role = get_user_role(current_user_id)
    return render_template('school_gist.html', current_user_id=current_user_id, current_user_role=current_user_role)

@app.route("/school_news")
def school_news():
    current_user_id = get_current_user_id()
    current_user_role = get_user_role(current_user_id)
    return render_template("school_news.html", current_user_role=current_user_role)


@app.route("/api/school_news")
def api_school_news():
    search_query = request.args.get("q")
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 10, type=int)
    current_user_id = get_current_user_id()

    try:
        posts, total_posts, error = fetch_posts_for_display("School News", search_query, page, per_page, current_user_id)

        if error:
            current_app.logger.error(f"Error fetching posts for API: {error}")
            return (jsonify({"error": "Failed to fetch posts", "details": error}), 500)

        posts_data = []
        for post in posts:
            post_date_str = post.get("post_date").isoformat() if isinstance(post.get("post_date"), datetime) else str(post.get("post_date", ""))
            
            posts_data.append({
                "id": post["id"],
                "title": post.get("title"),
                "content": post.get("content"),
                "external_link_url": post.get("external_link_url"),
                "author_username": post.get("author_username"),
                "author_user_id": post.get("author_user_id"),
                "profile_picture_url": post.get("profile_picture_url", "/static/default_avatar.png"),
                "post_date": post_date_str,
                "media_type": post.get("media_type"),
                "media_url": post.get("media_url"),
                "reactions_count": post.get("reactions_count", 0),
                "comments_count": post.get("comments_count", 0),
                "download_file_path": post.get("download_file_path"),
            })

        return jsonify({
            "posts": posts_data,
            "total_posts": total_posts,
            "page": page,
            "per_page": per_page,
            "total_pages": (total_posts + per_page - 1) // per_page,
        })
    except Exception as e:
        current_app.logger.error(f"Error in api_school_news: {e}", exc_info=True)
        return jsonify({"error": "An unexpected error occurred."}), 500

def fetch_single_post(post_id, current_user_id):
    """
    Fetches a single news post from Firestore by its ID.
    The post ID is the document ID in the 'news_posts' collection.
    """
    if db is None:
        return None
    try:
        # Using a collection reference and get the document directly
        post_ref = db.collection("news_posts").document(str(post_id))
        doc = post_ref.get()
        if doc.exists:
            post_data = doc.to_dict()
            post_data['id'] = doc.id
            return post_data
    except Exception as e:
        app.logger.error(f"Error fetching post {post_id} from Firestore: {e}", exc_info=True)
    return None

def get_states_from_db():
    """
    Fetches all states from the 'states' collection in Firestore.
    """
    if db is None:
        return []
    try:
        # Get all documents in the 'states' collection
        states_ref = db.collection("states").stream()
        states = []
        for doc in states_ref:
            state_data = doc.to_dict()
            state_data['id'] = doc.id # Add document ID to the dictionary
            states.append(state_data)
        return states
    except Exception as e:
        app.logger.error(f"Error fetching states from Firestore: {e}", exc_info=True)
    return []

def get_study_material_by_id_from_db(material_id):
    """
    Fetches a single study material by its ID from Firestore.
    This also fetches the associated state and university names.
    """
    if db is None:
        return None
    try:
        material_ref = db.collection("study_materials").document(str(material_id))
        material_doc = material_ref.get()
        if material_doc.exists:
            material_data = material_doc.to_dict()
            material_data['id'] = material_doc.id

            # Since Firestore doesn't support JOINs, we need to fetch related data separately.
            location_id = material_data.get('location_id')
            if location_id:
                location_ref = db.collection('locations').document(str(location_id))
                location_doc = location_ref.get()
                if location_doc.exists:
                    location_data = location_doc.to_dict()
                    material_data['university_name'] = location_data.get('name')
                    state_id = location_data.get('state_id')
                    if state_id:
                        state_ref = db.collection('states').document(str(state_id))
                        state_doc = state_ref.get()
                        if state_doc.exists:
                            material_data['state_name'] = state_doc.to_dict().get('name')
            return material_data
    except Exception as e:
        app.logger.error(f"Error fetching study material {material_id}: {e}", exc_info=True)
    return None

def get_media_type_from_extension(file_path):
    # This is a placeholder function, you would have your own logic here
    if not file_path:
        return 'unknown'
    if file_path.endswith('.pdf'):
        return 'pdf'
    if file_path.endswith('.mp4'):
        return 'video'
    return 'document'

# ==============================================================================
# FLASK ROUTES
# These routes have been updated to use the Firestore helper functions.
# ==============================================================================

@app.route("/download_news_post_file/<string:post_id>")
def download_news_post_file(post_id):
    current_user_id = get_current_user_id()
    post = fetch_single_post(post_id, current_user_id)

    if not post:
        flash("Post not found or expired.", "error")
        return redirect(url_for("school_news"))

    download_file_path = post.get("download_file_path")
    if not download_file_path:
        flash("No downloadable file available for this post.", "error")
        return redirect(url_for("school_news"))

    try:
        # This part of the logic remains the same, assuming files are stored locally
        filename = os.path.basename(download_file_path)
        safe_filename = secure_filename(filename)

        full_path_check = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)
        # Check if the generated path is actually a file and starts with the UPLOAD_FOLDER path
        if not os.path.isfile(full_path_check) or not full_path_check.startswith(os.path.realpath(app.config['UPLOAD_FOLDER'])):
            app.logger.warning(f"Attempted to download suspicious file path: {safe_filename} outside UPLOAD_FOLDER. Full path: {full_path_check}")
            flash('Invalid file path or file not found.', 'error')
            return redirect(url_for('school_news'))

        # Assuming allowed_file() is a helper function you have
        def allowed_file(filename):
            # Example implementation
            ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx'}
            return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

        if not allowed_file(safe_filename):
            app.logger.warning(f"Attempted to download file with disallowed extension: {safe_filename}")
            flash("This file type is not allowed for download.", "error")
            return redirect(url_for("school_news"))

        app.logger.info(f"Serving file: {safe_filename} from {app.config['UPLOAD_FOLDER']}")
        return send_from_directory(app.config["UPLOAD_FOLDER"], safe_filename, as_attachment=True)
    except Exception as e:
        app.logger.error(
            f"Error serving file for post {post_id} (filename: {download_file_path}): {e}",
            exc_info=True,
        )
        flash("An error occurred while trying to download the file.", "error")
        return redirect(url_for("school_news"))

@app.route("/full_post/<string:category_name>/<string:post_id>")
def display_full_post(category_name, post_id):
    """
    Renders a dedicated page for a single post, displaying full content and all media.
    """
    current_user_id = get_current_user_id()
    current_user_role = get_user_role(current_user_id)

    # Use the Firestore helper function
    post = fetch_single_post(post_id, current_user_id)

    if not post:
        flash("Post not found.", "error")
        return redirect(url_for("school_news"))

    # Convert Firestore Timestamp to string for rendering
    if isinstance(post.get("post_date"), firestore.SERVER_TIMESTAMP):
        post["post_date_formatted"] = post["post_date"].strftime("%Y-%m-%d %H:%M:%S")
    else:
        post["post_date_formatted"] = str(post.get("post_date", ""))

    return render_template(
        "full_post_detail.html", # Changed to new template name
        post=post,
        category_name=category_name,
        current_user_role=current_user_role
    )

@app.route('/study_hub')
def study_hub():
    """Renders the main study hub page with initial data for filters."""
    current_user_id = get_current_user_id()
    current_user_role = get_user_role(current_user_id)

    states = []
    selected_state_id = request.args.get('state_id')
    selected_location_id = request.args.get('location_id')

    try:
        states = get_states_from_db()
    except Exception as e:
        flash(f"Error loading states: {str(e)}", "error")
        app.logger.error(f"Failed to load states for study_hub page: {e}", exc_info=True)

    return render_template(
        'study_hub.html',
        current_user_role=current_user_role,
        states=states,
        selected_state_id=selected_state_id,
        selected_location_id=selected_location_id,
    )

@app.route('/api/study_materials', methods=['GET'])
def api_study_materials():
    """API endpoint to fetch study materials with search, state, and location filters."""
    if db is None:
        return jsonify({"error": "Database not initialized"}), 500
    try:
        query_text = request.args.get('query', '').strip()
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        state_id = request.args.get('state_id')
        location_id = request.args.get('location_id')

        # Create a query reference to the 'study_materials' collection
        materials_ref = db.collection("study_materials")
        materials_query = materials_ref.order_by("upload_date", direction=firestore.Query.DESCENDING)

        # Apply filters as `where` clauses.
        # Note: Firestore does not support 'LIKE' for substring matching. This implementation
        # uses equality checks for `category` or `title` as a basic filter. For a more
        # robust search, you would need to use a dedicated search service like Algolia or Elasticsearch.
        # Here we'll just check for exact matches on title/category for demonstration.
        if query_text:
            materials_query = materials_query.where("title", "==", query_text) # or use a different field for search
            # Alternatively, if you want to search a specific category:
            # materials_query = materials_query.where("category", "==", query_text)

        if state_id:
            # First, find locations for the given state
            locations_ref = db.collection("locations").where("state_id", "==", state_id).stream()
            location_ids = [doc.id for doc in locations_ref]
            if location_ids:
                materials_query = materials_query.where("location_id", "in", location_ids)
            else:
                # No locations found, so no materials can match
                return jsonify({'materials': [], 'total_materials': 0, 'page': page, 'per_page': per_page, 'total_pages': 0})

        if location_id:
            materials_query = materials_query.where("location_id", "==", location_id)


        # To get the total count, we must perform a separate query.
        # Note: This is an extra read operation and can be inefficient for large datasets.
        # For a scalable solution, you might maintain a separate counter in a dedicated document.
        count_docs = materials_query.stream()
        total_materials = len(list(count_docs))

        # Handle pagination
        offset = (page - 1) * per_page
        if offset > 0:
            # To handle offset, we fetch the documents and then slice them in Python.
            # A more performant approach for large offsets is to use a cursor (start_after).
            # This implementation fetches all documents and then paginates. For a small
            # to medium-sized dataset, this is acceptable.
            # We'll use start_after for a better implementation.
            materials_query = materials_query.limit(per_page)
            if page > 1:
                last_doc_ref = list(materials_ref.order_by("upload_date", direction=firestore.Query.DESCENDING).limit(offset).stream())
                if last_doc_ref:
                    materials_query = materials_ref.order_by("upload_date", direction=firestore.Query.DESCENDING).start_after(last_doc_ref[-1]).limit(per_page)
            else:
                materials_query = materials_ref.order_by("upload_date", direction=firestore.Query.DESCENDING).limit(per_page)
            
            materials_docs = materials_query.stream()
            materials = []
            for doc in materials_docs:
                materials.append(doc)
            
        else:
            materials_docs = materials_query.limit(per_page).stream()
            materials = []
            for doc in materials_docs:
                materials.append(doc)

        materials_data = []
        for material_doc in materials:
            material = material_doc.to_dict()
            material['id'] = material_doc.id

            upload_date_str = material['upload_date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(material.get('upload_date'), firestore.SERVER_TIMESTAMP) else str(material.get('upload_date', ''))
            inferred_media_type = get_media_type_from_extension(material.get('file_path'))

            # Fetch related data (state and university name)
            state_name = "N/A"
            university_name = "N/A"
            location_id_doc = material.get('location_id')
            if location_id_doc:
                location_doc = db.collection('locations').document(str(location_id_doc)).get()
                if location_doc.exists:
                    location_data = location_doc.to_dict()
                    university_name = location_data.get('name', 'N/A')
                    state_id_doc = location_data.get('state_id')
                    if state_id_doc:
                        state_doc = db.collection('states').document(str(state_id_doc)).get()
                        if state_doc.exists:
                            state_name = state_doc.to_dict().get('name', 'N/A')

            materials_data.append({
                'id': material['id'],
                'title': material.get('title', ''),
                'content': material.get('content', ''),
                'category': material.get('category', ''),
                'upload_date': upload_date_str,
                'file_path': material.get('file_path', ''),
                'media_type': inferred_media_type,
                'state_name': state_name,
                'university_name': university_name,
                'view_url': url_for('api_study_material_detail', material_id=material['id']),
                'can_request': True
            })

        total_pages = (total_materials + per_page - 1) // per_page if total_materials > 0 else 0

        return jsonify({
            'materials': materials_data,
            'total_materials': total_materials,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        })

    except Exception as e:
        app.logger.error(f"API Error in /api/study_materials: {e}", exc_info=True)
        return jsonify({"error": f"Failed to load study materials: {str(e)}"}), 500

@app.route('/api/study_materials/<string:material_id>', methods=['GET'])
def api_study_material_detail(material_id):
    """API endpoint to fetch details for a single study material."""
    try:
        material = get_study_material_by_id_from_db(material_id)
        if material:
            # Handle timestamps
            if isinstance(material.get('upload_date'), firestore.SERVER_TIMESTAMP):
                 material['upload_date'] = material['upload_date'].strftime('%Y-%m-%d %H:%M:%S')
            else:
                 material['upload_date'] = str(material.get('upload_date', ''))

            material['media_type'] = get_media_type_from_extension(material.get('file_path'))
            # Ensure location names are passed if available
            return jsonify(material)
        return jsonify({"error": "Study material not found"}), 404
    except Exception as e:
        app.logger.error(f"API Error in /api/study_materials/{material_id}: {e}", exc_info=True)
        return jsonify({"error": f"Failed to retrieve study material: {str(e)}"}), 500

@app.route('/downloads/<path:filename>')
def download_file(filename):
    if 'UPLOAD_FOLDER' not in app.config:
        app.logger.error('UPLOAD_FOLDER is not configured in the application.')
        flash('Server configuration error: Upload folder not defined.', 'error')
        return redirect(url_for('study_hub'))

    try:
        safe_filename = secure_filename(filename)
        full_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)

        if not os.path.exists(full_path) or not os.path.isfile(full_path):
            app.logger.warning(f"Attempted to download non-existent file: {full_path}")
            flash('The requested file was not found.', 'error')
            return redirect(url_for('study_hub'))

        return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename, as_attachment=True)
    except Exception as e:
        app.logger.error(f"Error serving file {filename}: {e}")
        flash('An error occurred while trying to download the file.', 'error')
        return redirect(url_for('study_hub'))





@app.route("/admin/create_post", methods=["GET", "POST"])
@login_required # Assuming this decorator exists
def create_post():
    """Handles the creation of new posts, study materials, and stories."""
    current_user_id = get_current_user_id()
    if not current_user_id:
        flash("You must be logged in to create posts.", "error")
        return redirect(url_for("login"))

    user_is_admin = is_admin(current_user_id)
    post_data = request.form.to_dict() if request.method == "POST" else {}

    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        author_username = get_current_username()
        post_type = request.form.get("post_type")
        submitted_external_link_url = request.form.get("link_url", "").strip()
        display_on = request.form.getlist("display_on")

        is_story_post = post_type == "story"
        is_study_material_post = "Study Hub" in display_on

        if not user_is_admin and not is_story_post and "School Gist" not in display_on:
            display_on.append("School Gist")

        # --- VALIDATION ---
        # The validation logic remains the same, as it's client-side input validation.
        if not title or not title.strip():
            flash("Please enter a title for your post.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        if not content or not content.strip():
            flash("Content (or caption/description) cannot be empty for this post type.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        if not display_on and not is_story_post:
            flash("Please select at least one page to display the post on.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        # --- MEDIA PROCESSING ---
        media_items_to_save = []
        order_counter = 0

        media_files = request.files.getlist("media_files")
        has_uploaded_files = media_files and media_files[0].filename != ""

        if has_uploaded_files:
            for media_file in media_files:
                if media_file and allowed_file(media_file.filename):
                    try:
                        # Note: File saving logic is outside the scope of Firestore,
                        # you will need a separate file storage solution like Firebase Storage.
                        unique_filename = generate_unique_filename(media_file.filename)
                        # We are just using a placeholder path for now
                        uploaded_url = f"/downloads/{unique_filename}"

                        media_type_for_item = get_media_type_from_extension(unique_filename)
                        
                        media_items_to_save.append({
                            "media_type": media_type_for_item,
                            "media_path_or_url": uploaded_url,
                            "caption": "",
                            "order_index": order_counter,
                        })
                        order_counter += 1

                    except Exception as e:
                        # Log the error and flash a message
                        flash(f"Error uploading file {media_file.filename}: {e}", "error")
                        return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 500
                elif media_file and not allowed_file(media_file.filename):
                    flash(f"File type not allowed for {media_file.filename}.", "error")
                    return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        # Validate submitted_external_link_url if provided
        if submitted_external_link_url and not (submitted_external_link_url.startswith("http://") or submitted_external_link_url.startswith("https://")):
            flash("External link must start with http:// or https://", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        # Decide if a post needs content, media, or link at all
        if not content.strip() and not media_items_to_save and not submitted_external_link_url:
            flash("Post must have content, uploaded media, or an external link.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        try:
            redirect_url = url_for("home") # Default redirect
            
            if is_study_material_post:
                # Firestore will create the 'study_materials' collection if it doesn't exist
                study_materials_ref = db.collection("study_materials")
                study_material_doc = {
                    "title": title,
                    "content": content,
                    "category": "Study Material",
                    "upload_date": datetime.now(),
                    "file_path": media_items_to_save[0]["media_path_or_url"] if media_items_to_save else None,
                }
                study_materials_ref.add(study_material_doc)
                flash("Study Material uploaded successfully!", "success")
                redirect_url = url_for("study_hub")

            elif is_story_post:
                # Firestore will create the 'stories' collection if it doesn't exist
                stories_ref = db.collection("stories")
                expires_at = datetime.now() + timedelta(hours=24)
                story_media_item = media_items_to_save[0] if media_items_to_save else None
                story_doc = {
                    "user_id": current_user_id,
                    "media_url": story_media_item["media_path_or_url"] if story_media_item else None,
                    "media_type": story_media_item["media_type"] if story_media_item else "text",
                    "caption": content,
                    "created_at": datetime.now(),
                    "expires_at": expires_at,
                }
                stories_ref.add(story_doc)
                flash("Story created successfully (will last 24 hours)!","success")
                redirect_url = url_for("school_gist")

            else:  # Regular post for School Gist/News
                display_on_for_posts = [cat for cat in display_on if cat != "Study Hub"]
                if not display_on_for_posts:
                    flash("Please select a valid display page for a regular post (School Gist or School News).", "error")
                    return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

                # Firestore will create the 'posts' collection if it doesn't exist
                posts_ref = db.collection("posts")
                duration_hours = 48  # Default for regular posts
                
                post_doc = {
                    "title": title,
                    "content": content,
                    "categories": display_on_for_posts, # Store as an array
                    "author": author_username,
                    "author_id": current_user_id,
                    "post_date": datetime.now(),
                    "duration_hours": duration_hours,
                    "external_link_url": submitted_external_link_url,
                    "media_items": media_items_to_save, # Embed media items as a sub-array of objects
                    "comments_count": 0,
                    "reactions_breakdown": {},
                    "total_reactions": 0,
                }

                posts_ref.add(post_doc)
                
                flash(f"Post created successfully (will last {duration_hours} hours)!","success")
                if "School Gist" in display_on_for_posts:
                    redirect_url = url_for("school_gist")
                elif "School News" in display_on_for_posts:
                    redirect_url = url_for("school_news")
                
            return redirect(redirect_url)

        except FirebaseError as e:
            # Firestore client library handles most errors gracefully
            flash(f"A Firestore error occurred: {e}", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 500

    return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin)

def get_user_details(user_id):
    """Fetches user details from Firestore."""
    try:
        user_ref = db.collection('users').document(str(user_id))
        user_doc = user_ref.get()

        if not user_doc.exists:
            return None
        
        user = user_doc.to_dict()
        user['id'] = user_doc.id # Add the document ID to the dictionary
        
        # In Firestore, aggregation like COUNT and AVG should be pre-calculated
        # and stored in the user document to avoid expensive queries.
        # We'll assume these fields exist in the user document.
        user['followers_count'] = user.get('followers_count', 0)
        user['following_count'] = user.get('following_count', 0)
        user['average_rating'] = user.get('average_rating', 'N/A')
        user['profile_picture'] = user.get('profile_picture', '/static/default_avatar.png')
        
        return user
    except FirebaseError as e:
        # Log the error
        return None


@app.route('/user/<string:user_id>/content')
def display_user_posts_and_stories(user_id):
    current_user_id = get_current_user_id()
    user = get_user_details(user_id)

    if not user:
        return render_template('404.html', message="User not found"), 404

    is_owner = (str(current_user_id) == str(user_id))
    is_following_user = False
    if current_user_id and not is_owner:
        # Logic to check if following, assumes a `followers` collection exists
        # This is a placeholder; a more robust solution would be needed.
        follower_doc = db.collection('followers').document(f'{current_user_id}-{user_id}').get()
        is_following_user = follower_doc.exists

    return render_template(
        'user_profile.html',
        profile_user=user,
        current_user_id=current_user_id,
        is_owner=is_owner,
        is_following_user=is_following_user
    )


def fetch_user_specific_posts(user_id, search_query, page, per_page, current_user_id):
    """Fetches posts for a specific user from Firestore with pagination and search."""
    posts_ref = db.collection('posts').where('author_id', '==', str(user_id))
    
    # Filter by expiry date
    posts_ref = posts_ref.where('post_date', '>', datetime.now() - timedelta(hours=48))
    
    if search_query:
        # Firestore does not support full-text search directly.
        # This would require an external search index like Algolia or a different approach.
        # For simplicity, we will skip the search query for now, or you could do a
        # basic client-side filter after fetching.
        # For a full-featured search, you would need a different architecture.
        pass

    # Total post count (Firestore doesn't have a simple count for filtered queries)
    # The best practice is to manage a counter field in the user document.
    total_posts = 0 # Placeholder; requires a separate counter field
    
    # Order by date
    posts_ref = posts_ref.order_by('post_date', direction=firestore.Query.DESCENDING)

    # Pagination
    offset = (page - 1) * per_page
    posts_ref = posts_ref.limit(per_page).offset(offset)
    
    try:
        posts = []
        for doc in posts_ref.stream():
            post = doc.to_dict()
            post['id'] = doc.id
            
            # Fetch author details from the users collection
            author_ref = db.collection('users').document(str(user_id))
            author_doc = author_ref.get()
            author_details = author_doc.to_dict() if author_doc.exists else {}
            
            post['author_username'] = author_details.get('username', 'Unknown User')
            post['profile_picture_url'] = author_details.get('profile_picture', '/static/default_avatar.png')
            post['author_followers_count'] = author_details.get('followers_count', 0)
            post['author_average_rating'] = author_details.get('average_rating', 'N/A')
            
            # Fetch a preview of the comments
            comments_preview = []
            comments_ref = db.collection('posts').document(post['id']).collection('comments')
            comments_query = comments_ref.order_by('comment_date', direction=firestore.Query.DESCENDING).limit(2).stream()
            
            for comment_doc in comments_query:
                comment = comment_doc.to_dict()
                # You would need to fetch the comment author's details similarly
                comments_preview.append({
                    'text': comment.get('text'),
                    'date': comment.get('comment_date'),
                    'author': comment.get('author_username'), # Assumes this is stored in the comment doc
                    'profile_picture_url': comment.get('profile_picture_url', '/static/default_avatar.png')
                })
            
            post['comments_preview'] = comments_preview
            
            posts.append(post)
            
        return posts, total_posts, None
    except FirebaseError as e:
        # Log the error
        return [], 0, str(e)


@app.route('/api/user/<string:user_id>/posts')
def api_user_posts(user_id):
    search_query = request.args.get('q')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    current_user_id = get_current_user_id()

    # The total_posts count is an issue with Firestore's lack of aggregate queries.
    # The best practice is to maintain a counter in the user document.
    posts, total_posts, error_message = fetch_user_specific_posts(
        user_id, search_query, page, per_page, current_user_id
    )

    if error_message:
        return jsonify({
            'posts': [],
            'total_posts': 0,
            'page': page,
            'per_page': per_page,
            'total_pages': 0,
            'error': True,
            'message': f"Failed to retrieve user posts: {error_message}"
        }), 500

    posts_data = []
    for post in posts:
        post_date_str = post['post_date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(post.get('post_date'), datetime) else str(post.get('post_date', ''))
        
        comments_data = []
        if 'comments_preview' in post:
            for comment in post['comments_preview']:
                comment_date_str = comment['date'].strftime('%Y-%m-%d %H:%M:%S') if isinstance(comment.get('date'), datetime) else str(comment.get('date', ''))
                comments_data.append({
                    'author': comment['author'],
                    'text': comment['text'],
                    'date': comment_date_str,
                    'profile_picture_url': comment.get('profile_picture_url', '/static/default_avatar.png')
                })
        
        posts_data.append({
            'id': post['id'],
            'title': post['title'],
            'content': post['content'],
            'author_username': post.get('author_username'),
            'author_user_id': post.get('author_id'),
            'profile_picture_url': post.get('profile_picture_url', '/static/default_avatar.png'),
            'post_date': post_date_str,
            'media_items': post.get('media_items', []),
            'external_link_url': post.get('external_link_url'),
            'total_reactions': post.get('total_reactions', 0),
            'reactions_breakdown': post.get('reactions_breakdown', {}),
            'comments_count': post.get('comments_count', 0),
            'comments_preview': comments_data,
            'duration_hours': post.get('duration_hours'),
            'author_followers_count': post.get('author_followers_count', 0),
            'is_followed_by_current_user': post.get('is_followed_by_current_user', False),
            'author_average_rating': post.get('author_average_rating', 'N/A')
        })

    return jsonify({
        'posts': posts_data,
        'total_posts': total_posts, # This will be 0 as explained above
        'page': page,
        'per_page': per_page,
        'total_pages': (total_posts + per_page - 1) // per_page,
        'error': False,
        'message': "User posts loaded successfully."
    })

def fetch_single_user_stories(user_id):
    """Fetches a single user's stories from Firestore, filtering by expiry date."""
    try:
        stories_ref = db.collection('stories').where('user_id', '==', str(user_id)).where('expires_at', '>', datetime.now()).order_by('created_at', direction=firestore.Query.DESCENDING)
        
        stories_docs = stories_ref.stream()
        
        formatted_stories = []
        for doc in stories_docs:
            story = doc.to_dict()
            formatted_stories.append({
                'id': doc.id,
                'media_url': story.get('media_url'),
                'media_type': story.get('media_type'),
                'caption': story.get('caption'),
                'created_at': story.get('created_at').strftime('%Y-%m-%d %H:%M:%S')
            })
        return formatted_stories
    except FirebaseError as e:
        # Log the error
        return []


@app.route('/api/user/<string:user_id>/stories')
def api_user_stories(user_id):
    """
    Fetches user stories from Firestore.
    """
    # In Firestore, document IDs are strings, so we change the route parameter type.
    try:
        # Query the 'stories' collection for documents where 'user_id' matches.
        stories_ref = db.collection('stories').where('user_id', '==', user_id)
        docs = stories_ref.stream()
        stories = []
        for doc in docs:
            story_data = doc.to_dict()
            story_data['id'] = doc.id # Add the document ID to the dictionary
            stories.append(story_data)
        return jsonify(stories)
    except Exception as e:
        logger.error(f"Error fetching user stories for user {user_id}: {e}")
        return jsonify({'message': 'Error fetching stories'}), 500

# --- Function to delete expired posts and stories ---
def delete_expired_posts_and_stories():
    """
    Deletes expired posts and stories from Firestore. This function
    can be called by a scheduler.
    """
    try:
        now = datetime.now(UTC)

        # Delete expired regular posts
        # We need to query for posts where the expiration time has passed.
        # This assumes 'expires_at' is a Firestore Timestamp object.
        posts_ref = db.collection('posts').where('expires_at', '<', now)
        expired_posts = posts_ref.stream()
        
        for post in expired_posts:
            post_data = post.to_dict()
            # Clean up associated media files (media_url should be a list of strings)
            if 'media_url' in post_data and post_data['media_url']:
                for url in post_data['media_url']:
                    filename = url.strip().replace('/downloads/', '')
                    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                        logger.info(f"Deleted expired post media file: {file_path}")
            
            # Use a transaction or batch write for atomicity if needed.
            # Here, we just delete the document.
            post.reference.delete()
        logger.info("Deleted expired posts.")

        # Delete expired stories
        stories_ref = db.collection('stories').where('expires_at', '<', now)
        expired_stories = stories_ref.stream()
        
        for story in expired_stories:
            story_data = story.to_dict()
            # Clean up associated media file
            if 'media_url' in story_data and story_data['media_url']:
                filename = story_data['media_url'].strip().replace('/downloads/', '')
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                    logger.info(f"Deleted expired story media file: {file_path}")
            
            story.reference.delete()
        logger.info("Deleted expired stories.")

    except Exception as e:
        logger.error(f"Error during expired post/story deletion: {e}", exc_info=True)


@app.route('/cgpa_calculator')
def cgpa_calculator_page():
    """Renders the CGPA calculation page."""
    return render_template('cgpa_calculator.html')

# This function does not use a database, so no changes are needed.
@app.route('/api/calculate_cgpa', methods=['POST'])
def api_calculate_cgpa():
    data = request.get_json()
    courses = data.get('courses', [])

    total_grade_points = 0
    total_credit_units = 0

    grading_scale = {
        'A': 5.0, 'B': 4.0, 'C': 3.0, 'D': 2.0, 'E': 1.0, 'F': 0.0
    }

    for course in courses:
        grade = course.get('grade', '').upper()
        credit_unit = float(course.get('credit_unit', 0))

        if grade in grading_scale:
            grade_point = grading_scale[grade]
            total_grade_points += (grade_point * credit_unit)
            total_credit_units += credit_unit
        else:
            logger.warning(f"Invalid grade encountered: {grade}")

    if total_credit_units == 0:
        cgpa = 0.0
    else:
        cgpa = total_grade_points / total_credit_units

    return jsonify({'success': True, 'cgpa': round(cgpa, 2)})



@app.route('/admin/post-airtime', methods=['GET', 'POST'])
def admin_post_airtime():
    if 'loggedin' not in session or 'user_id' not in session:
        flash('You need to be logged in to access this page.', 'error')
        return redirect(url_for('login'))

    if session.get('role') != 'admin':
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('home'))

    if request.method == 'POST':
        network = request.form.get('network')
        amount_raw = request.form.get('amount')
        digits = request.form.get('digits')
        instructions = request.form.get('instructions')
        duration_value = request.form.get('duration_value', type=int)
        duration_unit = request.form.get('duration_unit')

        # --- Input Validation and Cleaning ---
        amount = None
        if amount_raw:
            cleaned_amount = re.sub(r'[^\d]', '', amount_raw)
            if cleaned_amount.isdigit():
                amount = int(cleaned_amount)
            else:
                flash('Invalid amount format. Please enter numbers only (e.g., 500, 1000).', 'error')
                return render_template('admin_post_airtime.html')

        cleaned_digits = None
        if digits:
            cleaned_digits = re.sub(r'[^\d]', '', digits)
            if not cleaned_digits.isdigit():
                flash('Airtime Digits must contain only numbers if provided.', 'error')
                return render_template('admin_post_airtime.html')

        if not duration_value or not duration_unit:
            flash('Duration Value and Duration Unit are required.', 'error')
            return render_template('admin_post_airtime.html')

        # Calculate expires_at
        expires_at = datetime.now(UTC)
        if duration_unit == 'seconds':
            expires_at += timedelta(seconds=duration_value)
        elif duration_unit == 'minutes':
            expires_at += timedelta(minutes=duration_value)
        elif duration_unit == 'hours':
            expires_at += timedelta(hours=duration_value)
        elif duration_unit == 'days':
            expires_at += timedelta(days=duration_value)
        else:
            flash('Invalid duration unit provided.', 'error')
            return render_template('admin_post_airtime.html')

        image_url = None
        if 'airtime_image' in request.files:
            file = request.files['airtime_image']
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                file.save(file_path)
                image_url = url_for('static', filename=f'uploads/{filename}')

        # --- Firestore database interaction ---
        try:
            airtime_post_data = {
                'network': network,
                'amount': amount,
                'digits': cleaned_digits,
                'instructions': instructions,
                'image_url': image_url,
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': expires_at
            }
            db.collection('airtime_post').add(airtime_post_data)

            flash('Airtime post created successfully!', 'success')
            return redirect(url_for('home'))
        except Exception as e:
            flash(f'Error creating airtime post: {str(e)}', 'error')
            logger.error(f"Error posting airtime: {e}")
            return render_template('admin_post_airtime.html')

    return render_template('admin_post_airtime.html')


# --- API Route to Fetch Active Airtime Posts (MODIFIED) ---
# --- API Route to Fetch Active Airtime Posts (Modified for new syntax) ---
@app.route('/api/airtime-posts', methods=['GET'])
def get_airtime_posts():
    try:
        now = datetime.now(UTC)
        # Using the recommended 'filter' keyword argument to avoid the UserWarning.
        # This still avoids the composite index and sorts in memory.
        posts_ref = db.collection('airtime_post')\
            .where(filter=firestore.FieldFilter('expires_at', '>', now))

        docs = posts_ref.stream()
        posts_data = []

        for doc in docs:
            post = doc.to_dict()
            post['id'] = doc.id
            post['digits'] = str(post.get('digits')) if post.get('digits') is not None else ''

            if 'created_at' in post and isinstance(post['created_at'], firestore.Timestamp):
                post['created_at'] = post['created_at'].isoformat()
            if 'expires_at' in post and isinstance(post['expires_at'], firestore.Timestamp):
                post['expires_at'] = post['expires_at'].isoformat()

            posts_data.append(post)

        # Manually sort the posts by created_at in descending order after fetching them
        sorted_posts = sorted(posts_data, key=lambda p: p['created_at'], reverse=True)

        # Return only the single most recent post
        if sorted_posts:
            return jsonify([sorted_posts[0]])
        else:
            return jsonify([])

    except Exception as e:
        logger.error(f"Error fetching airtime posts: {e}")
        return jsonify({'message': 'Error fetching posts'}), 500

# The other routes remain unchanged.
# ... (admin_post_airtime, delete_expired_airtime_post)


# --- API Route to Delete Expired Airtime Posts (Triggered by Frontend JS) ---
@app.route('/api/airtime-posts/<string:post_id>/delete', methods=['POST'])
def delete_expired_airtime_post(post_id):
    if 'loggedin' not in session or 'user_id' not in session or session.get('role') != 'admin':
        return jsonify({'message': 'Unauthorized'}), 403

    try:
        post_ref = db.collection('airtime_post').document(post_id)
        post = post_ref.get()

        if not post.exists:
            return jsonify({'message': 'Post not found'}), 404

        post_data = post.to_dict()
        if post_data.get('image_url'):
            base_filename = os.path.basename(post_data['image_url'])
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], base_filename)
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"Deleted image file: {file_path}")

        post_ref.delete()
        return jsonify({'message': 'Airtime post deleted successfully'}), 200
    except Exception as e:
        logger.error(f"Error deleting post {post_id}: {e}")
        return jsonify({'message': f'Error deleting post: {str(e)}'}), 500


# --- NEW CUSTOMER CARE CHAT ROUTES ---
@app.route('/chat/customer_care')
def live_admins_list():
    current_user_id = session.get('user_id')
    current_user_role = session.get('role')

    if not current_user_id:
        flash('You must be logged in to chat with customer care. Please login.', 'error')
        return redirect(url_for('login'))

    online_admins = []
    try:
        # Query the 'users' collection for online admins.
        admins_ref = db.collection('users').where('role', '==', 'admin').where('is_online', '==', True).order_by('username')
        docs = admins_ref.stream()

        online_admins = [doc.to_dict() for doc in docs]
        for admin in online_admins:
            # Firestore document ID can be used as the user ID.
            admin['id'] = admin.get('id') or 'ID not found'
            
    except Exception as e:
        logger.error(f"Error fetching online admins: {e}", exc_info=True)
        flash('Could not load online customer care agents. Please try again later.', 'error')
    
    return render_template('live_admins.html',
                            online_admins=online_admins,
                            current_user_id=current_user_id,
                            current_user_role=current_user_role)

@app.route('/chat/customer_care/<string:other_user_id>')
def customer_care_chat(other_user_id):
    current_user_id = session.get('user_id')
    current_user_role = session.get('role')

    if not current_user_id:
        flash('You must be logged in to chat.', 'error')
        return redirect(url_for('login'))
    
    chat_partner_info = None
    messages = []
    
    try:
        # Determine who the 'other_user' is based on current_user_role
        user_ref = db.collection('users').document(other_user_id)
        chat_partner_doc = user_ref.get()

        if not chat_partner_doc.exists:
            flash('Selected user not found.', 'error')
            return redirect(url_for('admin_inbox') if current_user_role == 'admin' else url_for('live_admins_list'))
        
        chat_partner_info = chat_partner_doc.to_dict()
        chat_partner_info['id'] = chat_partner_doc.id

        if current_user_role == 'admin' and chat_partner_info.get('role') != 'user':
            flash('Selected user is not a customer.', 'error')
            return redirect(url_for('admin_inbox'))
        elif current_user_role == 'user' and chat_partner_info.get('role') != 'admin':
            flash('Selected customer care agent is not an administrator.', 'error')
            return redirect(url_for('live_admins_list'))
        
        # Fetch messages between current_user_id and other_user_id from admin_messages
        # Firestore query needs to check for both sender-receiver combinations.
        # This is handled by a compound query with 'or', which can be done manually
        # by performing two separate queries and merging the results.
        
        # Query 1: Messages sent by current user to other user
        query1 = db.collection('admin_messages').where('sender_id', '==', current_user_id).where('receiver_id', '==', other_user_id)
        # Query 2: Messages sent by other user to current user
        query2 = db.collection('admin_messages').where('sender_id', '==', other_user_id).where('receiver_id', '==', current_user_id)
        
        docs1 = query1.stream()
        docs2 = query2.stream()
        
        messages = []
        messages.extend(doc.to_dict() for doc in docs1)
        messages.extend(doc.to_dict() for doc in docs2)
        
        # Sort messages by timestamp
        messages.sort(key=lambda msg: msg.get('timestamp'))
        
        # You'll also need to fetch sender info (username, profile_picture) for each message if not stored in the message doc.
        # The original code joined with the users table. A better Firestore approach is to embed this data or do a separate fetch per message.
        # For simplicity, let's assume sender username and profile picture are fetched in a separate step or are stored with the message.
        for msg in messages:
            if 'timestamp' in msg and isinstance(msg['timestamp'], firestore.Timestamp):
                msg['timestamp'] = msg['timestamp'].isoformat()


    except Exception as e:
        logger.error(f"Error loading chat for {current_user_id} with {other_user_id}: {e}", exc_info=True)
        flash('Could not load chat history. Please try again.', 'error')
        return redirect(url_for('admin_inbox') if current_user_role == 'admin' else url_for('live_admins_list'))
    
    return render_template('customer_care_chat.html', 
                            chat_partner_info=chat_partner_info,
                            messages=messages, 
                            current_user_id=current_user_id,
                            current_username=session.get('username'),
                            current_user_profile_picture_url=session.get('profile_picture_url'),
                            current_user_role=current_user_role)


@app.route('/api/chat/send_message', methods=['POST'])
def api_send_message():
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required to send messages.'}), 401

    data = request.get_json()
    receiver_id = data.get('receiver_id')
    message_text = data.get('message_text', '').strip()

    if not receiver_id or not message_text:
        return jsonify({'success': False, 'message': 'Receiver and message text are required.'}), 400

    try:
        # 1. Get the sender's role and other info from Firestore
        sender_ref = db.collection('users').document(current_user_id)
        sender_doc = sender_ref.get()
        if not sender_doc.exists:
            return jsonify({'success': False, 'message': 'Invalid sender ID or role not found.'}), 403
        
        sender_info = sender_doc.to_dict()
        sender_role = sender_info.get('role')

        # 2. Determine the expected role of the receiver based on the sender's role
        expected_receiver_role = None
        if sender_role == 'user':
            expected_receiver_role = 'admin'
        elif sender_role == 'admin':
            expected_receiver_role = 'user'
        
        if expected_receiver_role is None:
            return jsonify({'success': False, 'message': 'Unauthorized sender role for this chat type.'}), 403

        # 3. Validate the receiver: Check if the receiver_id exists and has the expected role
        receiver_ref = db.collection('users').document(receiver_id)
        receiver_doc = receiver_ref.get()
        if not receiver_doc.exists or receiver_doc.to_dict().get('role') != expected_receiver_role:
            return jsonify({'success': False, 'message': f'Cannot send message: Recipient not found or has an incorrect role ({expected_receiver_role} expected).'}), 403

        # Proceed with inserting the message if validation passes
        # We embed sender information directly into the message document
        # to avoid needing a separate query (like a JOIN) later.
        new_message_data = {
            'sender_id': current_user_id,
            'receiver_id': receiver_id,
            'message_text': message_text,
            'timestamp': firestore.SERVER_TIMESTAMP,
            'sender_username': sender_info.get('username'),
            'sender_profile_picture': sender_info.get('profile_picture')
        }
        
        # Add a new document to the 'admin_messages' collection
        new_message_ref = db.collection('admin_messages').add(new_message_data)
        
        new_message = new_message_data
        new_message['id'] = new_message_ref[1].id
        
        return jsonify({'success': True, 'message': 'Message sent.', 'new_message': new_message})

    except Exception as e:
        logger.error(f"Error sending message from {current_user_id} to {receiver_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to send message. An internal error occurred.'}), 500

@app.route('/api/chat/get_messages/<string:other_user_id>', methods=['GET'])
def api_get_messages(other_user_id):
    current_user_id = session.get('user_id')
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required to fetch messages.'}), 401
    
    try:
        # Validate that the chat partner is an admin (as in original logic)
        other_user_ref = db.collection('users').document(other_user_id)
        other_user_doc = other_user_ref.get()
        if not other_user_doc.exists or other_user_doc.to_dict().get('role') != 'admin':
            return jsonify({'success': False, 'message': 'Invalid chat partner.'}), 403

        # Fetch all messages between the two users.
        # This requires two separate queries as Firestore does not support 'OR' queries on different fields.
        query1 = db.collection('admin_messages').where('sender_id', '==', current_user_id).where('receiver_id', '==', other_user_id)
        query2 = db.collection('admin_messages').where('sender_id', '==', other_user_id).where('receiver_id', '==', current_user_id)

        docs1 = query1.stream()
        docs2 = query2.stream()

        messages = []
        messages.extend(doc.to_dict() for doc in docs1)
        messages.extend(doc.to_dict() for doc in docs2)

        # Sort the combined list of messages by their timestamp.
        messages.sort(key=lambda msg: msg.get('timestamp'))

        # Add the document ID to each message and format the timestamp.
        for msg in messages:
            if isinstance(msg['timestamp'], firestore.Timestamp):
                msg['timestamp'] = msg['timestamp'].isoformat()

        return jsonify({'success': True, 'messages': messages})

    except Exception as e:
        logger.error(f"Error fetching messages for chat between {current_user_id} and {other_user_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'Failed to fetch messages.'}), 500


@app.route('/admin/inbox')
def admin_inbox():
    current_user_id = session.get('user_id')
    current_user_role = session.get('role')

    # Authorization: Only allow admins to access this inbox
    if not current_user_id or current_user_role != 'admin':
        flash('Access denied. You must be an administrator to view the admin inbox.', 'error')
        return redirect(url_for('login'))

    received_messages = []
    try:
        # Fetch all messages where the current admin is the receiver.
        # Firestore queries are simpler as we've already embedded sender info.
        messages_ref = db.collection('admin_messages').where('receiver_id', '==', current_user_id)
        docs = messages_ref.order_by('timestamp', direction=firestore.Query.DESCENDING).stream()
        
        # We need to manually handle the sender's role check if needed, but in this case
        # the chat logic already ensures the sender is a user.
        received_messages = [doc.to_dict() for doc in docs]

        # Format timestamps for display
        for msg in received_messages:
            if isinstance(msg.get('timestamp'), firestore.Timestamp):
                msg['timestamp'] = msg['timestamp'].isoformat()
                
    except Exception as e:
        logger.error(f"Error fetching admin inbox messages for admin {current_user_id}: {e}", exc_info=True)
        flash('Could not load inbox messages. Please try again later.', 'error')

    return render_template('admin_inbox.html',
                            received_messages=received_messages,
                            current_user_id=current_user_id,
                            current_username=session.get('username'),
                            current_user_profile_picture_url=session.get('profile_picture_url'))



















































         
            
            
            
            
            
            
            













def get_followers_of_user(user_id):
    followers_ref = db.collection('user_followers').document(str(user_id)).collection('followers')
    follower_docs = followers_ref.stream()
    return [doc.id for doc in follower_docs]

# Helper function to check if a user is an admin
def is_admin(user_id):
    user_info = get_user_info(user_id)
    return user_info and user_info.get('role') == 'admin'

# --- NEW: Helper function to send an email notification ---
def send_email_notification(recipient_email: str, subject: str, body: str):
    try:
        msg = Message(subject, recipients=[recipient_email])
        msg.body = body
        mail.send(msg)
        logger.info(f"Email notification sent to {recipient_email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send email to {recipient_email}: {e}", exc_info=True)
        return False

# --- UPDATED: create_notification function to use Firestore ---
def create_notification(user_id: int, notification_type: str, message: str, related_id: int = None) -> bool:
    """
    Triggers a notification for a specific user, checking their preferences and sending an email.
    """
    try:
        user_id_str = str(user_id)
        # 1. Check user's notification preferences from Firestore
        preferences_ref = db.collection('user_notification_preferences').document(user_id_str)
        preferences_doc = preferences_ref.get()
        preferences = preferences_doc.to_dict() if preferences_doc.exists else {}

        # Default to enabled if preference is not explicitly set to False
        enabled_for_type = preferences.get(notification_type, True)
        
        # We also need an email-specific preference
        email_enabled = preferences.get('email_notifications', True)

        if enabled_for_type:
            # 2. Add the new notification to Firestore
            notification_data = {
                'user_id': user_id,
                'notification_type': notification_type,
                'notification_message': message,
                'is_read': False,
                'created_at': firestore.SERVER_TIMESTAMP,
                'related_id': related_id
            }
            db.collection('notifications').add(notification_data)
            print(f"Notification triggered for user {user_id}: Type='{notification_type}', Message='{message}', Related ID='{related_id}'")

        # 3. Send email if enabled
        if email_enabled:
            user_info = get_user_info(user_id_str)
            if user_info and user_info.get('email'):
                subject = f"New Notification: {notification_type.replace('_', ' ').title()}"
                send_email_notification(user_info['email'], subject, message)
        
        return True
    except Exception as e:
        logger.error(f"Error creating notification for user {user_id}: {e}", exc_info=True)
        return False

# --- UPDATED: get_user_notification_preferences function to use Firestore ---
def get_user_notification_preferences(user_id: int) -> dict:
    """
    Retrieves a dictionary of notification preferences for a given user from Firestore.
    """
    try:
        preferences_ref = db.collection('user_notification_preferences').document(str(user_id))
        preferences_doc = preferences_ref.get()

        if preferences_doc.exists:
            preferences = preferences_doc.to_dict()
        else:
            preferences = {}

        # Define all possible notification types in your application
        all_notification_types = [
            'advert_published',
            'new_advert_from_followed_seller',
            'advert_rejected',
            'new_message',
            'subscription_activated',
            'email_notifications', # Add email as a manageable preference
        ]

        full_preferences = {}
        for notif_type in all_notification_types:
            full_preferences[notif_type] = preferences.get(notif_type, True)
            
        return full_preferences
    except Exception as e:
        logger.error(f"Error retrieving notification preferences for user {user_id}: {e}", exc_info=True)
        return {}

# --- UPDATED: update_user_notification_preference function to use Firestore ---
def update_user_notification_preference(user_id: int, notification_type: str, enabled: bool) -> bool:
    """
    Inserts or updates a user's preference for a specific notification type in Firestore.
    """
    try:
        preferences_ref = db.collection('user_notification_preferences').document(str(user_id))
        preferences_ref.set({notification_type: enabled}, merge=True)
        print(f"User {user_id} preference for '{notification_type}' set to {'enabled' if enabled else 'disabled'}.")
        return True
    except Exception as e:
        logger.error(f"Error updating notification preference for user {user_id}: {e}", exc_info=True)
        return False

# --- UPDATED: get_user_notifications function to use Firestore ---
def get_user_notifications(user_id: int, limit: int = 10, include_read: bool = False) -> list:
    """
    Retrieves notifications for a specific user from Firestore.
    Note: Firestore does not support offset, so we will not include it in this implementation.
    """
    try:
        query = db.collection('notifications').where('user_id', '==', user_id)
        if not include_read:
            query = query.where('is_read', '==', False)
        
        docs = query.order_by('created_at', direction=firestore.Query.DESCENDING).limit(limit).stream()
        
        notifications = []
        for doc in docs:
            notif_data = doc.to_dict()
            notif_data['id'] = doc.id
            if isinstance(notif_data.get('created_at'), firestore.Timestamp):
                notif_data['created_at'] = notif_data['created_at'].isoformat()
            notifications.append(notif_data)
            
        return notifications
    except Exception as e:
        logger.error(f"Error retrieving notifications for user {user_id}: {e}", exc_info=True)
        return []

# --- UPDATED: mark_notification_as_read function to use Firestore ---
def mark_notification_as_read(notification_id: str, user_id: int = None) -> bool:
    """
    Marks a specific notification as read in Firestore.
    """
    try:
        notification_ref = db.collection('notifications').document(notification_id)
        notification_doc = notification_ref.get()

        if notification_doc.exists:
            notif_data = notification_doc.to_dict()
            # Ensure the user has permission to update this notification
            if user_id is None or notif_data.get('user_id') == user_id:
                notification_ref.update({'is_read': True})
                print(f"Notification {notification_id} marked as read.")
                return True
            else:
                print(f"Notification {notification_id} not owned by user {user_id}.")
                return False
        else:
            print(f"Notification {notification_id} not found.")
            return False
    except Exception as e:
        logger.error(f"Error marking notification {notification_id} as read: {e}", exc_info=True)
        return False

# --- UPDATED: Mark All As Read API Route ---
@app.route('/api/notifications/mark_all_read', methods=['POST'])
def api_mark_all_notifications_read():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401
    
    try:
        query = db.collection('notifications').where('user_id', '==', current_user_id).where('is_read', '==', False)
        docs_to_update = query.stream()
        
        batch = db.batch()
        count = 0
        for doc in docs_to_update:
            batch.update(doc.reference, {'is_read': True})
            count += 1
            
        if count > 0:
            batch.commit()
            message = f"{count} notifications marked as read."
            print(message)
            return jsonify({'success': True, 'message': message})
        else:
            message = "No unread notifications to mark as read."
            print(message)
            return jsonify({'success': True, 'message': message})
    except Exception as e:
        logger.error(f"Error marking all notifications as read for user {current_user_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': f'Failed to mark all as read: {str(e)}'}), 500

# --- UPDATED: Delete All Notifications API Route ---
@app.route('/api/notifications/delete_all', methods=['POST'])
def api_delete_all_notifications():
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401
    
    try:
        query = db.collection('notifications').where('user_id', '==', current_user_id)
        docs_to_delete = query.stream()
        
        batch = db.batch()
        count = 0
        for doc in docs_to_delete:
            batch.delete(doc.reference)
            count += 1
        
        if count > 0:
            batch.commit()
            message = f"{count} notifications deleted."
            print(message)
            return jsonify({'success': True, 'message': message})
        else:
            message = "No notifications to delete."
            print(message)
            return jsonify({'success': True, 'message': message})
    except Exception as e:
        logger.error(f"Error deleting all notifications for user {current_user_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': f'Failed to delete all notifications: {str(e)}'}), 500

# --- Flask Routes (Updated notifications route to pass current_user_id to template) ---
@app.route('/notifications')
def user_notifications():
    current_user_id = get_current_user_id()
    if not current_user_id:
        flash('Please log in to view notifications.', 'info')
        return redirect(url_for('login_page')) 

    notifications = get_user_notifications(current_user_id) 
    return render_template('notifications.html', notifications=notifications, current_user_id=current_user_id)

@app.route('/api/notifications/<string:notification_id>/read', methods=['POST'])
def api_mark_notification_read(notification_id):
    current_user_id = get_current_user_id()
    if not current_user_id:
        return jsonify({'success': False, 'message': 'Authentication required.'}), 401
    
    if mark_notification_as_read(notification_id, current_user_id):
        return jsonify({'success': True, 'message': 'Notification marked as read.'})
    else:
        return jsonify({'success': False, 'message': 'Failed to mark notification as read or not authorized.'}), 400

# --- NEW ROUTE: Notification Settings ---
@app.route('/settings/notifications', methods=['GET', 'POST'])
def notification_settings():
    current_user_id = session.get('user_id')
    if not current_user_id:
        flash('Please log in to manage preferences.', 'info')
        return redirect(url_for('login_page'))

    if request.method == 'POST':
        all_manageable_types = [
            'advert_published',
            'new_advert_from_followed_seller',
            'advert_rejected',
            'new_message',
            'subscription_activated',
            'email_notifications',
        ]
        
        for notif_type in all_manageable_types:
            is_enabled = request.form.get(f'pref_{notif_type}') == 'on'
            update_user_notification_preference(current_user_id, notif_type, is_enabled)

        flash('Notification preferences updated.', 'success')
        return redirect(url_for('notification_settings'))

    preferences = get_user_notification_preferences(current_user_id)
    return render_template('notification_settings.html', preferences=preferences)

# --- Routes that trigger notifications have been updated to call the new function ---
@app.route('/send_message', methods=['POST'])
def send_message():
    sender_id = get_current_user_id()
    # Assuming recipient_id is now a string to match Firestore IDs
    recipient_id = request.form.get('recipient_id') 
    message_content = request.form.get('message_content')

    if recipient_id:
        sender_username = get_user_info(sender_id).get('username', 'Someone')
        
        create_notification(
            int(recipient_id), 
            'new_message', 
            f"{sender_username} sent you a new message: '{message_content[:50]}...'",
            related_id=int(sender_id) 
        )
        flash('Message sent!', 'success')
    else:
        flash('Recipient not found.', 'error')
    return redirect(url_for('some_page')) 

@app.route('/admin/adverts/publish/<int:advert_id>', methods=['POST'])
def publish_advert(advert_id):
    # ... existing authorization and data retrieval ...

    # The code below assumes you have functions to get advert data, etc. from Firestore.
    # The original SQL queries here have been replaced with a more direct example.
    advert_data = get_advert_info_from_firestore(advert_id)
    if not advert_data:
        flash('Advert not found or not in pending review status.', 'danger')
        return redirect(url_for('admin_adverts_review'))

    post_owner_id = advert_data.get('user_id')
    advert_title = advert_data.get('title')

    # Update advert status in Firestore
    db.collection('adverts').document(str(advert_id)).update({
        'status': 'published', 
        'published_at': firestore.SERVER_TIMESTAMP
    })
    
    # --- NOTIFICATION LOGIC ---
    # 1. Notify the Post Owner (the user who created the advert)
    create_notification(
        post_owner_id,
        'advert_published',
        f"Your advert '{advert_title}' has been approved and published!",
        related_id=advert_id
    )

    # 2. Notify Followers of the Post Owner (seller)
    seller_info = get_user_info(str(post_owner_id))
    if seller_info:
        seller_username = seller_info.get('username', 'A seller')
        followers_ids = get_followers_of_user(post_owner_id)

        notification_message_for_followers = f"New advert from your followed seller, {seller_username}: '{advert_title}'. Check it out!"
        
        for follower_id in followers_ids:
            create_notification(
                int(follower_id), # Cast to int if needed by your notification function
                'new_advert_from_followed_seller',
                notification_message_for_followers,
                related_id=advert_id
            )

    flash('Advert published successfully and users notified!', 'success')
    return redirect(url_for('admin_adverts_review'))

# --- NEW ROUTE: Reject Advert ---
@app.route('/admin/adverts/reject/<int:advert_id>', methods=['POST'])
def reject_advert(advert_id):
    current_admin_user_id = get_current_user_id()
    if not current_admin_user_id or not is_admin(current_admin_user_id):
        flash('Unauthorized access.', 'error')
        return redirect(url_for('home'))

    rejected_reason = request.form.get('rejected_reason')
    
    advert_data = get_advert_info_from_firestore(advert_id)
    if not advert_data:
        flash('Advert not found or not in pending review status.', 'error')
        return redirect(url_for('admin_adverts_review'))

    user_id = advert_data.get('user_id')
    advert_title = advert_data.get('title')
    plan_name = advert_data.get('subscription_plan_name', 'Unknown Plan')
    
    # Update advert status in Firestore
    db.collection('adverts').document(str(advert_id)).update({
        'status': 'rejected',
        'rejected_reason': rejected_reason
    })
    
    # Logic for refunding advert slots/benefits needs to be adapted for Firestore
    # This is a conceptual example based on your original SQL logic
    if plan_name == "One-Time Free Advert":
        db.collection('users').document(str(user_id)).update({
            'has_used_free_advert': False
        })
    # Add other refund logic here based on your data structure

    notification_message = f"Your advert '{advert_title}' ({plan_name}) has been rejected."
    if rejected_reason:
        notification_message += f" Reason: {rejected_reason}."
    notification_message += " You can edit and resubmit it."
    
    create_notification(
        user_id,
        'advert_rejected',
        notification_message,
        related_id=advert_id
    )

    flash('Advert rejected successfully! User has been notified and their advert slot/benefit refunded.', 'success')
    return redirect(url_for('admin_adverts_review'))

# --- Mock functions for demonstration. You should replace these with your actual Firestore retrieval functions.
def get_advert_info_from_firestore(advert_id):
    advert_ref = db.collection('adverts').document(str(advert_id))
    advert_doc = advert_ref.get()
    if advert_doc.exists and advert_doc.to_dict().get('status') == 'pending_review':
        return advert_doc.to_dict()
    return None

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)































