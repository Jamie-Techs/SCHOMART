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
import flask
from io import BytesIO
from urllib.parse import urlparse
from functools import wraps
from datetime import timedelta, date, timezone, datetime
from datetime import datetime, timedelta
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
from google.cloud import storage

from firebase_functions import https_fn
from datetime import datetime, timezone, timedelta
from dotenv import load_dotenv
from botocore.exceptions import ClientError
import boto3
import re
from google.oauth2 import service_account
from firebase_admin import credentials, firestore as admin_firestore, initialize_app
import tempfile
from urllib.parse import quote



 

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'Jamiecoo15012004')

bcrypt = Bcrypt(app)
mail = Mail(app)
oauth = OAuth(app)
socketio = SocketIO(app)

try:
    raw_json = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if not raw_json:
        raise ValueError("FIREBASE_CREDENTIALS_JSON environment variable not set.")

    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as temp:
        temp.write(raw_json)
        temp.flush()
        temp_path = temp.name

    cred = credentials.Certificate(temp_path)
    initialize_app(cred, {'storageBucket': 'schomart-7a743.com'})

    # --- THIS LINE WAS THE ISSUE. REVERTED TO YOUR ORIGINAL CORRECT CODE. ---
    db = admin_firestore.client()

    # --- THIS LINE IS THE CORRECT ADDITION FOR YOUR STORAGE CLIENT. ---
    admin_storage = storage.bucket()
    
    logging.info("Firebase Firestore and Storage clients initialized successfully.")

except Exception as e:
    logging.error(f"Failed to initialize Firebase: {e}")
    raise RuntimeError("Firebase initialization failed. Check your credentials and environment setup.")
finally:
    if 'temp_path' in locals() and os.path.exists(temp_path):
        os.remove(temp_path)
        
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
                                        
logger = logging.getLogger(__name__)

# Note: Local file storage configurations are now obsolete, but kept for context.
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'mp3', 'wav', 'mp4'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']





















# --- User Model Class ---
class User:
    """
    User data model that retrieves and represents a user from Firestore.
    """
    def __init__(self, uid, **kwargs):
        self.id = str(uid)
        
        # Populate the attributes from the 'kwargs' dictionary
        self.username = kwargs.get('username', '')
        self.email = kwargs.get('email', '')
        self.profile_picture = kwargs.get('profile_picture')
        self.cover_photo = kwargs.get('cover_photo')
        self.state = kwargs.get('state', '')
        self.school = kwargs.get('school', '')
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

    @staticmethod
    def get(uid):
        """
        Retrieves a user document from Firestore and returns a User object.
        """
        if not db or not uid:
            return None
        try:
            doc_ref = db.collection('users').document(str(uid))
            doc = doc_ref.get()
            if doc.exists:
                return User(doc.id, **doc.to_dict())
            return None
        except Exception as e:
            # Note: If you have a logger, ensure it's imported
            # import logging
            # logging.error(f"Error fetching user by ID {uid}: {e}", exc_info=True)
            return None

# --- login_required Decorator ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user_id = session.get('user')
        if not user_id:
            flash('You must be logged in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        # Check if the user object is already in the global 'g' object
        if 'current_user' not in g or g.current_user.id != user_id:
            user_doc_ref = db.collection('users').document(user_id)
            user_doc = user_doc_ref.get()

            if not user_doc.exists:
                logging.error(f"User document does not exist for UID: {user_id}")
                flash('User data not found. Please log in again.', 'error')
                session.pop('user', None)
                return redirect(url_for('login'))
            
            # Get the dictionary from Firestore
            user_data = user_doc.to_dict()
            # Safely remove the 'uid' key from the dictionary before unpacking
            user_data.pop('uid', None)

            # Now, call the constructor with the cleaned dictionary
            g.current_user = User(user_doc.id, **user_data)

        return f(*args, **kwargs)
    return decorated_function




def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # The login_required decorator ensures g.current_user exists.
        # So we only need to check the admin status.
        if not getattr(g.current_user, 'is_admin', False):
            flash("You do not have permission to access this page.", "error")
            return redirect(url_for('home'))
        
        return f(*args, **kwargs)
    return decorated_function







def update_online_status(user_id, is_online):
    # This is the function we generated previously
    try:
        user_ref = db.collection('users').document(user_id)
        user_ref.update({'is_online': is_online, 'last_online': firestore.SERVER_TIMESTAMP})
        logger.info(f"User {user_id} online status updated to {is_online}.")
    except Exception as e:
        logger.error(f"Failed to update online status for user {user_id}: {e}", exc_info=True)

     


# --- Routes for Authentication ---

@app.route('/login', methods=['GET'])
def login_page():
    """Serves the login/signup HTML page."""
    if session.get('user'):
        return redirect(url_for('profile')) # If already logged in, redirect to index
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login_session():
    """
    Receives the Firebase ID Token from the frontend and verifies it.
    If the token is valid, it creates a secure Flask session.
    """
    try:
        id_token = request.json['idToken']
        
        # Verify the Firebase ID Token using the Admin SDK
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']

        # The token is valid. Now, create the Flask session.
        session['user'] = uid
        return jsonify({'message': 'Session created successfully'}), 200

    except Exception as e:
        logging.error(f"Failed to create session: {e}")
        return jsonify({'error': 'Failed to authenticate. Please try again.'}), 401








@app.route('/login')
def login():
    return render_template('login.html')




@app.route('/signup')
def signup():
    return render_template('signup.html')



# --- Helper Functions for Referral Code Generation ---
def generate_referral_code():
    """
    Generates a 6-digit numeric referral code as a string.
    """
    return f"{random.randint(0, 999999):06d}"

def generate_unique_referral_code(db):
    """
    Generates a unique 6-digit numeric referral code.
    It checks Firestore to ensure the code does not already exist.
    """
    while True:
        code = generate_referral_code()
        # Check if the code already exists in the 'users' collection
        existing = db.collection('users').where('referral_code', '==', code).limit(1).stream()
        if not any(existing):
            return code






@app.route('/logout')
def logout():
    """
    Logs the user out by clearing their session data and
    redirecting them to the login page.
    """
    # Safely remove the 'user' key from the session
    session.pop('user', None)

    # Flash a success message to the user
    flash('You have been logged out successfully.', 'success')

    # Redirect the user to the login page
    return redirect(url_for('login'))










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
        user_ref = db.collection('users').document(uid)
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




@app.route('/account_settings')
def account_settings():
    """Serves the account settings page."""
    return render_template('account_settings.html')









def get_user_info(user_id):
    """
    Fetches user information and calculates their rating, review count, and advert count.
    
    Args:
        user_id (str): The ID of the user to retrieve.
        
    Returns:
        dict: A dictionary containing user data, or None if the user does not exist.
    """
    if not user_id:
        return None

    user_doc = db.collection('users').document(user_id).get()

    if not user_doc.exists:
        return None

    user_data = user_doc.to_dict()
    user_data['id'] = user_doc.id

    # 1. Calculate and attach the user's average rating and total review count
    reviews_query = db.collection('reviews').where('reviewee_id', '==', user_id).stream()
    total_rating = 0
    review_count = 0
    for review_doc in reviews_query:
        review_data = review_doc.to_dict()
        total_rating += review_data.get('rating', 0)
        review_count += 1
    
    user_data['rating'] = total_rating / review_count if review_count > 0 else 0.0
    user_data['review_count'] = review_count

    # 2. Add advert count
    adverts_count_query = db.collection('adverts').where('user_id', '==', user_id).stream()
    adverts_count = sum(1 for _ in adverts_count_query)
    user_data['adverts_count'] = adverts_count

    return user_data



    

# --- Helper Functions ---
def get_unique_id():
    """Generates a unique ID for files or other items."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))




# Assuming 'admin_storage' and 'db' are initialized globally

def get_profile_picture_url(profile_picture_filename):
    """
    Generates a signed URL for a profile picture from a Cloud Storage filename.
    """
    if not profile_picture_filename:
        # Return a default image if no filename is provided
        return url_for('static', filename='images/default_profile.png')

    try:
        # Use the correct variable name 'admin_storage'
        blob = admin_storage.blob(profile_picture_filename)
        if blob.exists():
            return blob.generate_signed_url(timedelta(minutes=15), method='GET')
        else:
            return url_for('static', filename='images/default_profile.png')
    except Exception as e:
        logger.error(f"Error generating profile pic URL for {profile_picture_filename}: {e}")
        return url_for('static', filename='images/default_profile.png')


def get_cover_photo_url(cover_photo_filename_str):
    """Generates a public URL for a cover photo from Firebase Storage."""
    if not cover_photo_filename_str:
        return url_for('static', filename='images/no-photo-selected.png')
        
    try:
        # Use the correct variable name 'admin_storage'
        # The path should match how you saved it in the personal_details route.
        blob_path = cover_photo_filename_str 
        blob = admin_storage.blob(blob_path)
    
        if blob.exists():
            # Generate a signed URL for a limited time
            return blob.generate_signed_url(timedelta(minutes=15), method='GET')
        else:
            return url_for('static', filename='images/no-photo-selected.png')
    except Exception as e:
        logging.error(f"Error generating cover photo URL for {cover_photo_filename_str}: {e}")
        return url_for('static', filename='images/no-photo-selected.png')






# Helper function to format Firestore Timestamps
def format_timestamp(ts):
    """
    Formats a Firestore Timestamp object into a readable string.
    Returns an empty string if the timestamp is None or invalid.
    """
    if ts:
        try:
            return ts.strftime('%Y-%m-%d %H:%M:%S')
        except (AttributeError, ValueError):
            return ""
    return ""






# Assuming you have Flask and other necessary imports

# Hardcoded data for Nigerian states and schools
# You can extend these dictionaries with more data
NIGERIAN_STATES = [
    'Abia', 'Adamawa', 'Akwa Ibom', 'Anambra', 'Bauchi', 'Bayelsa', 'Benue', 'Borno',
    'Cross River', 'Delta', 'Ebonyi', 'Edo', 'Ekiti', 'Enugu', 'Gombe', 'Imo',
    'Jigawa', 'Kaduna', 'Kano', 'Katsina', 'Kebbi', 'Kogi', 'Kwara', 'Lagos',
    'Nasarawa', 'Niger', 'Ogun', 'Ondo', 'Osun', 'Oyo', 'Plateau', 'Rivers',
    'Sokoto', 'Taraba', 'Yobe', 'Zamfara'
]

NIGERIAN_SCHOOLS = {
    'Abia': [
        {'name': 'Abia State University', 'acronym': 'ABSU'},
        {'name': 'Michael Okpara University of Agriculture', 'acronym': 'MOUAU'},
        {'name': 'Abia State Polytechnic', 'acronym': 'ABIAPOLY'}
    ],
    'Adamawa': [
        {'name': 'Adamawa State University', 'acronym': 'ADSU'},
        {'name': 'American University of Nigeria', 'acronym': 'AUN'},
        {'name': 'Modibbo Adama University of Technology', 'acronym': 'MAUTECH'}
    ],
    'Akwa Ibom': [
        {'name': 'Akwa Ibom State University', 'acronym': 'AKSU'},
        {'name': 'University of Uyo', 'acronym': 'UNIUYO'},
        {'name': 'Akwa Ibom State Polytechnic', 'acronym': 'AKWAPOLY'}
    ],
    'Anambra': [
        {'name': 'Nnamdi Azikiwe University', 'acronym': 'UNIZIK'},
        {'name': 'Chukwuemeka Odumegwu Ojukwu University', 'acronym': 'COOU'},
        {'name': 'Federal Polytechnic, Oko', 'acronym': 'OKOPOLY'}
    ],
    'Bauchi': [
        {'name': 'Abubakar Tafawa Balewa University', 'acronym': 'ATBU'},
        {'name': 'Bauchi State University', 'acronym': 'BASUG'},
        {'name': 'Federal Polytechnic, Bauchi', 'acronym': 'FPTB'}
    ],
    'Bayelsa': [
        {'name': 'Niger Delta University', 'acronym': 'NDU'},
        {'name': 'Bayelsa Medical University', 'acronym': 'BMU'},
        {'name': 'Federal Polytechnic of Oil and Gas, Ekowe', 'acronym': 'FEPOGA'}
    ],
    'Benue': [
        {'name': 'Benue State University', 'acronym': 'BSU'},
        {'name': 'Federal University of Agriculture, Makurdi', 'acronym': 'FUAM'},
        {'name': 'Akperan Orshi College of Agriculture', 'acronym': 'AOCOA'}
    ],
    'Borno': [
        {'name': 'University of Maiduguri', 'acronym': 'UNIMAID'},
        {'name': 'Borno State University', 'acronym': 'BOSU'},
        {'name': 'Ramsey Nouah University, Borno', 'acronym': 'RNUB'}
    ],
    'Cross River': [
        {'name': 'University of Calabar', 'acronym': 'UNICAL'},
        {'name': 'Cross River University of Technology', 'acronym': 'CRUTECH'},
        {'name': 'Federal Polytechnic, Calabar', 'acronym': 'CALABARPOLY'}
    ],
    'Delta': [
        {'name': 'Delta State University', 'acronym': 'DELSU'},
        {'name': 'Federal University of Petroleum Resources Effurun', 'acronym': 'FUPRE'},
        {'name': 'Delta State Polytechnic, Otefe-Oghara', 'acronym': 'DESPO'}
    ],
    'Ebonyi': [
        {'name': 'Ebonyi State University', 'acronym': 'EBSU'},
        {'name': 'Federal University, Ndufu-Alike Ikwo', 'acronym': 'FUNAI'},
        {'name': 'Ebonyi State College of Health Sciences', 'acronym': 'EBSCHS'}
    ],
    'Edo': [
        {'name': 'University of Benin', 'acronym': 'UNIBEN'},
        {'name': 'Ambrose Alli University', 'acronym': 'AAU'},
        {'name': 'Auchi Polytechnic', 'acronym': 'AUCHIPOLY'}
    ],
    'Ekiti': [
        {'name': 'Federal University, Oye-Ekiti', 'acronym': 'FUOYE'},
        {'name': 'Ekiti State University', 'acronym': 'EKSU'},
        {'name': 'Afe Babalola University', 'acronym': 'ABUAD'}
    ],
    'Enugu': [
        {'name': 'University of Nigeria, Nsukka', 'acronym': 'UNN'},
        {'name': 'Enugu State University of Science and Technology', 'acronym': 'ESUT'},
        {'name': 'Institute of Management and Technology', 'acronym': 'IMT'}
    ],
    'Gombe': [
        {'name': 'Gombe State University', 'acronym': 'GSU'},
        {'name': 'Federal University of Gombe', 'acronym': 'FUGOM'},
        {'name': 'Gombe State Polytechnic, Bajoga', 'acronym': 'GSPB'}
    ],
    'Imo': [
        {'name': 'Federal University of Technology, Owerri', 'acronym': 'FUTO'},
        {'name': 'Imo State University', 'acronym': 'IMSU'},
        {'name': 'Alvan Ikoku Federal College of Education', 'acronym': 'AIFCE'}
    ],
    'Jigawa': [
        {'name': 'Jigawa State University', 'acronym': 'JSU'},
        {'name': 'Federal University Dutse', 'acronym': 'FUD'},
        {'name': 'Jigawa State Polytechnic', 'acronym': 'JIGPOLY'}
    ],
    'Kaduna': [
        {'name': 'Ahmadu Bello University', 'acronym': 'ABU'},
        {'name': 'Kaduna State University', 'acronym': 'KASU'},
        {'name': 'Federal Polytechnic, Kaduna', 'acronym': 'FPTK'}
    ],
    'Kano': [
        {'name': 'Bayero University, Kano', 'acronym': 'BUK'},
        {'name': 'Kano University of Science and Technology', 'acronym': 'KUST'},
        {'name': 'Federal College of Education, Kano', 'acronym': 'FCEKANO'}
    ],
    'Katsina': [
        {'name': 'Umaru Musa Yar\'adua University', 'acronym': 'UMYU'},
        {'name': 'Federal University, Dutsin-Ma', 'acronym': 'FUDMA'},
        {'name': 'Hassan Usman Katsina Polytechnic', 'acronym': 'HUKPOLY'}
    ],
    'Kebbi': [
        {'name': 'Kebbi State University of Science and Technology', 'acronym': 'KSUSTA'},
        {'name': 'Federal University Birnin-Kebbi', 'acronym': 'FUBK'},
        {'name': 'Waziri Umaru Federal Polytechnic Birnin Kebbi', 'acronym': 'WUFPBK'}
    ],
    'Kogi': [
        {'name': 'Kogi State University', 'acronym': 'KSU'},
        {'name': 'Federal University, Lokoja', 'acronym': 'FULOKOJA'},
        {'name': 'Kogi State Polytechnic', 'acronym': 'KOGIPOLY'}
    ],
    'Kwara': [
        {'name': 'University of Ilorin', 'acronym': 'UNILORIN'},
        {'name': 'Kwara State University', 'acronym': 'KWASU'},
        {'name': 'Kwara State Polytechnic', 'acronym': 'KWARAPOLY'}
    ],
    'Lagos': [
        {'name': 'University of Lagos', 'acronym': 'UNILAG'},
        {'name': 'Lagos State University', 'acronym': 'LASU'},
        {'name': 'Yaba College of Technology', 'acronym': 'YABATECH'}
    ],
    'Nasarawa': [
        {'name': 'Nasarawa State University', 'acronym': 'NSUK'},
        {'name': 'Federal University of Lafia', 'acronym': 'FULAFIA'},
        {'name': 'Federal Polytechnic, Nasarawa', 'acronym': 'FPN'}
    ],
    'Niger': [
        {'name': 'Federal University of Technology, Minna', 'acronym': 'FUTMINNA'},
        {'name': 'Ibrahim Badamasi Babangida University', 'acronym': 'IBBU'},
        {'name': 'Niger State Polytechnic', 'acronym': 'NIGPOLY'}
    ],
    'Ogun': [
        {'name': 'Federal University of Agriculture, Abeokuta', 'acronym': 'FUNAAB'},
        {'name': 'Olabisi Onabanjo University', 'acronym': 'OOU'},
        {'name': 'Tai Solarin University of Education', 'acronym': 'TASUED'}
    ],
    'Ondo': [
        {'name': 'Federal University of Technology, Akure', 'acronym': 'FUTA'},
        {'name': 'Adekunle Ajasin University', 'acronym': 'AAUA'},
        {'name': 'Ondo State University of Science and Technology', 'acronym': 'OSUSTECH'}
    ],
    'Osun': [
        {'name': 'Obafemi Awolowo University', 'acronym': 'OAU'},
        {'name': 'Osun State University', 'acronym': 'UNIOSUN'},
        {'name': 'Osun State Polytechnic', 'acronym': 'OSUNPOLY'}
    ],
    'Oyo': [
        {'name': 'University of Ibadan', 'acronym': 'UI'},
        {'name': 'Ladoke Akintola University of Technology', 'acronym': 'LAUTECH'},
        {'name': 'The Polytechnic, Ibadan', 'acronym': 'IBADANPOLY'}
    ],
    'Plateau': [
        {'name': 'University of Jos', 'acronym': 'UNIJOS'},
        {'name': 'Plateau State University', 'acronym': 'PLASU'},
        {'name': 'Plateau State Polytechnic', 'acronym': 'PLAPOLY'}
    ],
    'Rivers': [
        {'name': 'University of Port Harcourt', 'acronym': 'UNIPORT'},
        {'name': 'Rivers State University', 'acronym': 'RSU'},
        {'name': 'Port Harcourt Polytechnic', 'acronym': 'PHPOLY'}
    ],
    'Sokoto': [
        {'name': 'Usmanu Danfodiyo University', 'acronym': 'UDUS'},
        {'name': 'Sokoto State University', 'acronym': 'SSU'},
        {'name': 'Umaru Ali Shinkafi Polytechnic', 'acronym': 'UASPOLY'}
    ],
    'Taraba': [
        {'name': 'Taraba State University', 'acronym': 'TSU'},
        {'name': 'Federal University Wukari', 'acronym': 'FUWUKARI'},
        {'name': 'Taraba State Polytechnic', 'acronym': 'TARAPOLY'}
    ],
    'Yobe': [
        {'name': 'Yobe State University', 'acronym': 'YSU'},
        {'name': 'Federal Polytechnic, Damaturu', 'acronym': 'FPD'},
        {'name': 'College of Agriculture, Gujba', 'acronym': 'COAG'}
    ],
    'Zamfara': [
        {'name': 'Federal University, Gusau', 'acronym': 'FUGUS'},
        {'name': 'Zamfara State University', 'acronym': 'ZAMSU'},
        {'name': 'Abdu Gusau Polytechnic', 'acronym': 'AGPOLY'}
    ],
    'F.C.T.': [
        {'name': 'University of Abuja', 'acronym': 'UNIABUJA'},
        {'name': 'Nigerian Turkish Nile University', 'acronym': 'NTNU'},
        {'name': 'Baze University', 'acronym': 'BAZEU'}
    ]
}



@app.route('/profile')
@login_required
def profile():
    """
    Renders the user's profile page by fetching the latest data from Firestore
    and generating signed URLs for profile pictures.
    """
    try:
        # CORRECTED: Get the user's UID from the Flask session, which is where
        # your login route stores it.
        user_uid = session.get('user')
        
        if not user_uid:
            # This check is a failsafe; the decorator should prevent this.
            flash("User authentication failed. Please log in again.", "error")
            return redirect(url_for('signup'))
            
        # Fetch the latest user data from Firestore to avoid using stale session data.
        user_doc_ref = db.collection('users').document(user_uid)
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            flash("User data not found. Please log in again.", "error")
            logging.error(f"User document does not exist for UID: {user_uid}")
            return redirect(url_for('signup'))

        user_data = user_doc.to_dict()

        # REMOVED: The email verification check is no longer needed here.

        # Assuming you have a format_timestamp function defined somewhere
        user_data['last_active'] = format_timestamp(user_data.get('last_active'))
        user_data['created_at'] = format_timestamp(user_data.get('created_at'))

        # Generate signed URLs for profile and cover photos from Firebase Storage
        profile_pic_url = ""
        cover_photo_url = ""

        try:
            profile_blob = admin_storage.blob(f"users/{user_uid}/profile.jpg")
            if profile_blob.exists():
                profile_pic_url = profile_blob.generate_signed_url(
                    timedelta(minutes=15), method='GET'
                )
        except Exception as e:
            logging.error(f"Error generating profile pic URL for {user_uid}: {e}")
            flash(f"Error loading profile picture: {str(e)}", "error")

        try:
            cover_blob = admin_storage.blob(f"users/{user_uid}/cover.jpg")
            if cover_blob.exists():
                cover_photo_url = cover_blob.generate_signed_url(
                    timedelta(minutes=15), method='GET'
                )
        except Exception as e:
            logging.error(f"Error generating cover photo URL for {user_uid}: {e}")
            flash(f"Error loading cover photo: {str(e)}", "error")
            
        referral_link = f"https://schomart.onrender.com/signup?ref={user_uid}"

        return render_template('profile.html',
                               user=user_data,
                               profile_pic_url=profile_pic_url,
                               cover_photo_url=cover_photo_url,
                               referral_link=referral_link)

    except Exception as e:
        logging.error(f"An unexpected error occurred in profile route: {e}", exc_info=True)
        flash(f"An unexpected error occurred: {str(e)}. Please try again.", "error")
        return redirect(url_for('signup'))






# Assuming your other imports and setup are already in place
# ...

@app.route('/profile/personal', methods=['GET', 'POST'])
@login_required
def personal_details():
    """
    Handles displaying and updating a user's personal details.
    """
    try:
        # Correctly get the user ID from the session, as done in the working profile route
        user_uid = session.get('user_id')
        if not user_uid:
            flash("User session expired. Please log in again.", "error")
            return redirect(url_for('signup'))
        
        user_doc_ref = db.collection('users').document(user_uid)
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            logger.error(f"User document does not exist for UID: {user_uid}")
            flash("User data not found. Please log in again.", "error")
            return redirect(url_for('signup'))

        user_data = user_doc.to_dict()

        if request.method == 'POST':
            # Extract form data
            first_name = request.form.get('first_name', '')
            last_name = request.form.get('last_name', '')
            businessname = request.form.get('businessname', '')
            
            # 🐞 CORRECTED: Use the `name` attributes from the form
            state = request.form.get('state', '')
            school = request.form.get('school', '')
            location = request.form.get('location', '')

            birthday = request.form.get('birthday', '')
            sex = request.form.get('sex', '')
            delivery_methods = request.form.getlist('delivery_methods')
            working_days = request.form.getlist('working_days')
            
            working_times = {}
            for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
                if day in working_days:
                    working_times[day] = {
                        'open': request.form.get(f'{day}_open'),
                        'close': request.form.get(f'{day}_close')
                    }
            
            social_links = {
                'website': request.form.get('social_links[website]', ''),
                'instagram': request.form.get('social_links[instagram]', ''),
                'facebook': request.form.get('social_links[facebook]', ''),
                'linkedin': request.form.get('social_links[linkedin]', ''),
                'twitter': request.form.get('social_links[twitter]', '')
            }
            
            # Construct the combined location string
            combined_location = f"{state} > {school} > {location}"
            if not state:
                combined_location = ''
            elif not school:
                combined_location = f"{state} > {location}"
            elif not location:
                combined_location = f"{state} > {school}"

            update_data = {
                'first_name': first_name,
                'last_name': last_name,
                'businessname': businessname,
                'state': state,
                'school': school,
                'location': location,
                'full_location': combined_location,
                'birthday': birthday,
                'sex': sex,
                'working_days': working_days,
                'working_times': working_times,
                'delivery_methods': delivery_methods,
                'social_links': social_links,
            }
            
            try:
                # Handle image uploads
                profile_picture_file = request.files.get('profile_picture')
                if profile_picture_file and profile_picture_file.filename and allowed_file(profile_picture_file.filename):
                    blob_path = f"users/{user_uid}/profile.jpg"
                    blob = admin_storage.blob(blob_path)
                    blob.upload_from_file(profile_picture_file, content_type=profile_picture_file.content_type)
                    
                    # ✨ CRITICAL FIX: Add the Cloud Storage path to the update data
                    update_data['profile_picture'] = blob_path
                
                cover_photo_file = request.files.get('cover_photo')
                if cover_photo_file and cover_photo_file.filename and allowed_file(cover_photo_file.filename):
                    blob_path_cover = f"users/{user_uid}/cover.jpg"
                    blob = admin_storage.blob(blob_path_cover)
                    blob.upload_from_file(cover_photo_file, content_type=cover_photo_file.content_type)
                    
                    # ✨ CRITICAL FIX: Add the Cloud Storage path to the update data
                    update_data['cover_photo'] = blob_path_cover

                user_doc_ref.update(update_data)
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('personal_details'))
            except Exception as e:
                logger.error(f"Error updating user profile for UID {user_uid}: {e}", exc_info=True)
                flash(f'An error occurred while updating your profile: {e}', 'error')
                return redirect(url_for('personal_details'))

        # GET request handling
        profile_pic_url = ""
        cover_photo_url = ""
        
        try:
            profile_blob = admin_storage.blob(f"users/{user_uid}/profile.jpg")
            if profile_blob.exists():
                profile_pic_url = profile_blob.generate_signed_url(timedelta(minutes=15), method='GET')
        except Exception as e:
            logger.error(f"Error generating profile pic URL for {user_uid}: {e}")
            
        try:
            cover_blob = admin_storage.blob(f"users/{user_uid}/cover.jpg")
            if cover_blob.exists():
                cover_photo_url = cover_blob.generate_signed_url(timedelta(minutes=15), method='GET')
        except Exception as e:
            logger.error(f"Error generating cover photo URL for {user_uid}: {e}")

        user_data['profile_picture_url'] = profile_pic_url
        user_data['cover_photo_url'] = cover_photo_url
        
        # Ensure template variables are passed for the GET request
        NIGERIAN_STATES = list(NIGERIAN_SCHOOLS.keys())
        
        return render_template(
            'personal_details.html',
            user=user_data,
            NIGERIAN_STATES=NIGERIAN_STATES,
            NIGERIAN_SCHOOLS=NIGERIAN_SCHOOLS
        )

    except Exception as e:
        logger.error(f"An unexpected error occurred in personal details route: {e}", exc_info=True)
        flash(f"An unexpected error occurred: {str(e)}. Please try again.", "error")
        return redirect(url_for('signup'))







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






def get_followers_of_user(user_id):
    """Fetches list of user's followers."""
    # Placeholder for your actual logic
    return []


@app.route('/add_category', methods=['GET', 'POST'])
@login_required 
@admin_required
def add_category():
    """
    Handles adding a new category and uploading its image to Firebase Storage.
    """
    if request.method == 'POST':
        category_name = request.form.get('category_name')
        file = request.files.get('category_image')

        if not category_name or not file:
            flash("Category name and image are required.", "error")
            return redirect(url_for('add_category'))

        if file.filename == '' or not allowed_file(file.filename):
            flash("Invalid or missing image file. Please upload a .jpg, .jpeg, or .png file.", "error")
            return redirect(url_for('add_category'))
        
        try:
            # Sanitize the category name to create a safe filename
            base_filename = secure_filename(category_name.replace(' ', '_').lower())
            file_extension = file.filename.rsplit('.', 1)[1].lower()
            filename = f"{base_filename}.{file_extension}"
            
            # The path where the file will be stored in your bucket
            blob_path = f"static/category/{filename}"
            blob = admin_storage.blob(blob_path)
            
            # Upload the file to Firebase Storage
            blob.upload_from_file(file)
            
            # Add or update the category in Firestore
            db.collection('categories').document(category_name).set({
                'name': category_name,
                'image_filename': filename,
                'created_at': datetime.now(timezone.utc)
            })

            flash(f"Category '{category_name}' added successfully!", "success")
            return redirect(url_for('home'))

        except Exception as e:
            logger.error(f"Error uploading category image: {e}", exc_info=True)
            flash(f"An error occurred during upload: {str(e)}", "error")
            return redirect(url_for('add_category'))
    
    return render_template('add_category.html')






@app.route('/')
def home():
    """
    Renders the homepage, fetches data, generates signed URLs for images,
    and sorts adverts based on new priority rules.
    """
    try:
        # Pass the global NIGERIAN_STATES and NIGERIAN_SCHOOLS to the template
        locations_data = {
            'NIGERIAN_STATES': NIGERIAN_STATES,
            'NIGERIAN_SCHOOLS': NIGERIAN_SCHOOLS
        }

        categories_ref = db.collection('categories').stream()
        categories_data = []
        for doc in categories_ref:
            category = doc.to_dict()
            category['id'] = doc.id
            
            # Fetch the filename from Firestore, which was saved during upload
            image_filename = category.get('image_filename')
            image_url = 'https://placehold.co/100x100/e0e0e0/777777?text=No+Image'
            
            if image_filename:
                # Construct the blob path using the saved filename
                blob_path = f"static/category/{image_filename}"
                blob = admin_storage.blob(blob_path)
                
                if blob.exists():
                    image_url = blob.generate_signed_url(timedelta(minutes=15), method='GET')
            
            category['image_url'] = image_url
            categories_data.append(category)

        # --- Adverts Logic ---
        user_id = session.get('user_id')
        view_following_priority = False
        followed_user_ids = []

        if user_id:
            user_settings = get_user_info(user_id)
            if user_settings and user_settings.get('view_following_users_advert_first'):
                view_following_priority = True
                followed_user_ids = get_followers_of_user(user_id)

        # Get the visibility order from SUBSCRIPTION_PLANS
        visibility_order = {plan['visibility_level']: i for i, plan in enumerate(SUBSCRIPTION_PLANS.values())}
        
        adverts_ref = db.collection('adverts').where('status', '==', 'published').stream()
        all_published_adverts = []
        now = datetime.now(timezone.utc)

        for advert_doc in adverts_ref:
            advert_data = advert_doc.to_dict()
            advert_data['id'] = advert_doc.id
            
            expires_at = advert_data.get('expires_at')
            if expires_at and expires_at.replace(tzinfo=timezone.utc) > now:
                
                # Fetch poster user data
                poster_user_ref = db.collection('users').document(advert_data['user_id'])
                poster_user_doc = poster_user_ref.get()
                if poster_user_doc.exists:
                    poster_user_data = poster_user_doc.to_dict()
                    advert_data['poster_username'] = poster_user_data.get('username')
                    advert_data['poster_role'] = poster_user_data.get('role')
                else:
                    advert_data['poster_username'] = 'Unknown'
                    advert_data['poster_role'] = 'standard'
                
                # Correctly fetch the image URL from the 'main_image' key
                main_image_url = advert_data.get('main_image')
                if main_image_url:
                    advert_data['display_image'] = main_image_url
                else:
                    advert_data['display_image'] = 'https://placehold.co/400x250/E0E0E0/333333?text=No+Image'
                
                all_published_adverts.append(advert_data)

        # Separate admin/featured ads and general ads
        admin_ads_for_display = sorted([
            ad for ad in all_published_adverts if ad.get('featured') or ad.get('poster_role') == 'admin'
        ], key=lambda ad: visibility_order.get(ad.get('visibility_level', 'Standard'), 99))
        
        # Sort remaining adverts based on visibility and followed users
        regular_adverts = [
            ad for ad in all_published_adverts if not ad.get('featured') and ad.get('poster_role') != 'admin'
        ]

        def sort_trending_ads(ad):
            is_followed = 0 if view_following_priority and ad.get('user_id') in followed_user_ids else 1
            visibility_rank = visibility_order.get(ad.get('visibility_level', 'Standard'), 99)
            created_at_ts = ad.get('created_at', datetime.min).timestamp()
            return (is_followed, visibility_rank, -created_at_ts)

        adverts = sorted(regular_adverts, key=sort_trending_ads)
        
        # Merge the lists, giving admin ads top priority
        final_adverts_list = admin_ads_for_display + adverts
        
        return render_template('home.html',
                               locations=locations_data,
                               categories=categories_data,
                               adverts=final_adverts_list,
                               NIGERIAN_STATES=NIGERIAN_STATES,
                               NIGERIAN_SCHOOLS=NIGERIAN_SCHOOLS
                               )

    except Exception as e:
        logger.error(f"An unexpected error occurred in home route: {e}", exc_info=True)
        flash(f"An unexpected error occurred: {str(e)}. Please try again later.", "danger")
        return render_template('home.html', adverts=[], categories=[], locations=[])





@app.route('/followers')
@login_required
def followers():
    """
    Renders the followers page for the currently logged-in user.
    This route fetches the list of users who are following the current user.
    """
    try:
        user_uid = session.get('user_id')

        # Assuming your Firestore 'followers' collection stores follower relationships
        # You'll need to adjust this query based on your actual data structure.
        # Example: 'followers' collection where each document represents a follower relationship.
        # The document ID or a field in the document should be the UID of the user being followed.
        # For example, a document might have a 'following_uid' field that matches user_uid.
        
        # A more common structure is a subcollection:
        # users/{user_id}/followers/{follower_id}
        # To get the followers, you would query the subcollection for the current user.
        
        followers_ref = admin_db.collection('users').document(user_uid).collection('followers')
        followers_docs = followers_ref.stream()

        follower_list = []
        for doc in followers_docs:
            # You can fetch more details about each follower from the 'users' collection
            follower_data = admin_db.collection('users').document(doc.id).get().to_dict()
            if follower_data:
                follower_list.append({
                    'id': doc.id,
                    'username': follower_data.get('username'),
                    'profile_pic_url': "" # You can add logic to get the profile pic URL here
                })
        
        # It is good practice to add a logger to check the data
        logger.info(f"Found {len(follower_list)} followers for user {user_uid}")

        return render_template('followers.html', followers=follower_list)

    except Exception as e:
        logger.error(f"Error in followers route: {e}", exc_info=True)
        flash("An error occurred while fetching your followers. Please try again.", "error")
        return redirect(url_for('profile'))








# Plan details based on your instructions
SUBSCRIPTION_PLANS = {
    "starter": {"plan_name": "Starter", "cost_naira": 500, "advert_duration_days": 7, "max_adverts": 1, "visibility_level": "Standard"},
    "basic": {"plan_name": "Basic", "cost_naira": 1000, "advert_duration_days": 14, "max_adverts": 2, "visibility_level": "Standard"},
    "premium": {"plan_name": "Premium", "cost_naira": 1500, "advert_duration_days": 30, "max_adverts": 3, "visibility_level": "Featured"},
    "small_business": {"plan_name": "Small Business", "cost_naira": 3000, "advert_duration_days": 30, "max_adverts": 4, "visibility_level": "Featured"},
    "medium_business": {"plan_name": "Medium Business", "cost_naira": 5000, "advert_duration_days": 60, "max_adverts": 5, "visibility_level": "Featured"},
    "large_business": {"plan_name": "Large Business", "cost_naira": 8000, "advert_duration_days": 90, "max_adverts": 6, "visibility_level": "Premium"},
    "enterprise": {"plan_name": "Enterprise", "cost_naira": 10000, "advert_duration_days": 180, "max_adverts": 7, "visibility_level": "Premium"},
}

# The referral plans and their costs (in referrals)
REFERRAL_PLANS = {
    5: SUBSCRIPTION_PLANS["starter"],
    10: SUBSCRIPTION_PLANS["basic"],
    15: SUBSCRIPTION_PLANS["premium"],
    20: SUBSCRIPTION_PLANS["small_business"],
    30: SUBSCRIPTION_PLANS["medium_business"],
    40: SUBSCRIPTION_PLANS["large_business"],
    50: SUBSCRIPTION_PLANS["enterprise"],
}

# The one-time free advert plan, distinct from others
FREE_ADVERT_PLAN = {
    "plan_name": "Free Advert",
    "advert_duration_days": 7,
    "visibility_level": "Standard"
}



CATEGORIES = {
    "Accomodations": {"id": 1},
    "Electronics": {"id": 2},
    "Employment": {"id": 3},
    "Equipments": {"id": 4},
    "Fashion": {"id": 5},
    "Food & Agriculture": {"id": 6},
    "Furniture & Appliances": {"id": 7},
    "Mobile Devices": {"id": 8},
    "Parenting": {"id": 9},
    "Pets": {"id": 10},
    "Real Estate": {"id": 11},
    "Recreation": {"id": 12},
    "Services": {"id": 13},
    "Transportation": {"id": 14},
    "Wellness": {"id": 15}
}



# Assuming this is the function causing the error
def get_advert_count(user_id):
    """
    Counts the number of active adverts for a specific user.
    """
    try:
        # Check for active adverts
        now = datetime.now(timezone.utc)
        
        # Use a proper query to get documents
        active_adverts = db.collection('adverts').where('user_id', '==', user_id).stream()
        
        count = 0
        for advert_doc in active_adverts:
            advert_data = advert_doc.to_dict()
            expires_at = advert_data.get('expires_at')
            # Only count adverts that have not expired
            if expires_at and expires_at.replace(tzinfo=timezone.utc) > now:
                count += 1

        return count
    except Exception as e:
        logger.error(f"Error getting advert count for user {user_id}: {e}", exc_info=True)
        return 0



def get_referral_plan(user_id):
    """
    Fetches the referral benefit plan for a user.
    """
    try:
        # Correctly using positional arguments for the where method
        subscriptions_ref = (
            db.collection("subscriptions")
            .where("user_id", "==", user_id)
            .where("is_active", "==", True)
            .get()
        )

        if subscriptions_ref:
            for doc in subscriptions_ref:
                plan_data = doc.to_dict()
                # Do something with plan_data
                return plan_data

        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


def get_document(collection_name, doc_id):
    """Fetches a single document from a Firestore collection."""
    try:
        doc_ref = db.collection(collection_name).document(str(doc_id))
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            data['id'] = doc.id
            return data
    except Exception as e:
        logger.error(f"Error fetching document '{doc_id}' from '{collection_name}': {e}")
    return None

def get_user_info(user_id):
    """Fetches user data, including the number of adverts."""
    user_data = get_document("users", user_id)
    if user_data:
        try:
            # Get the count of adverts for the user
            adverts_count = db.collection("adverts").where("user_id", "==", user_id).count().get()[0].value
            user_data['adverts_count'] = adverts_count
        except Exception as e:
            logger.error(f"Error getting advert count for user {user_id}: {e}")
            user_data['adverts_count'] = 0
    return user_data

def get_active_subscription(user_id):
    """Finds the user's most recent active subscription."""
    try:
        subscriptions_ref = db.collection("subscriptions").where("user_id", "==", user_id).order_by("expires_at", direction=firestore.Query.DESCENDING).limit(1)
        sub_docs = subscriptions_ref.get()
        if sub_docs:
            sub_doc = sub_docs[0]
            if sub_doc.exists and sub_doc.to_dict().get("status") == "active":
                return sub_doc.to_dict()
    except Exception as e:
        logger.error(f"Error fetching active subscription for user {user_id}: {e}")
    return None

def get_user_referral_count(user_id):
    """Gets the number of successful referrals for a user."""
    try:
        referrals_count_doc = db.collection("referral_counts").document(user_id).get()
        if referrals_count_doc.exists:
            return referrals_count_doc.to_dict().get("count", 0)
    except Exception as e:
        logger.error(f"Error fetching referral count for user {user_id}: {e}")
    return 0

def get_referral_benefit_plan(referral_count):
    """Determines the referral benefit plan based on the count."""
    eligible_plans = [
        plan for cost, plan in REFERRAL_PLANS.items() if referral_count >= cost
    ]
    if eligible_plans:
        # Find the best plan, assuming REFERRAL_PLANS is sorted by cost
        return max(eligible_plans, key=lambda p: p['advert_duration_days'])
    return None


def get_advert_details(advert_id, user_id):
    """Fetches details of a specific advert, ensuring it belongs to the user."""
    try:
        advert = get_document("adverts", advert_id)
        if advert and advert.get("user_id") == user_id:
            return advert
    except Exception as e:
        logger.error(f"Error fetching advert {advert_id} for user {user_id}: {e}")
    return None


def get_state_name(state_id):
    """Fetches the name of a state from its ID."""
    if not state_id:
        return 'N/A'
    
    state_ref = db.collection('states').document(state_id)
    state_doc = state_ref.get()

    if state_doc.exists:
        return state_doc.to_dict().get('name', 'Unknown State')
    else:
        return 'Unknown State'


def get_school_acronym(state, school):
    """Finds the acronym for a school from the hardcoded data."""
    try:
        state_schools = NIGERIAN_SCHOOLS.get(state, [])
        for s in state_schools:
            if s["name"] == school:
                return s["acronym"]
    except Exception as e:
        logger.error(f"Error getting school acronym for {school} in {state}: {e}")
    return None




def get_category_id_from_name(category_name):
    # This logic assumes your CATEGORIES variable is a dictionary where keys are category names
    for name, data in CATEGORIES.items():
        if name == category_name:
            return data["id"]
    return None

def get_all_categories():
    # Placeholder for fetching categories from a database if they are not static
    categories_list = []
    for name, data in CATEGORIES.items():
        categories_list.append({"id": data["id"], "name": name})
    return categories_list

def get_category_name(category_id):
    for name, data in CATEGORIES.items():
        if data["id"] == category_id:
            return name
    return "Unknown"

def get_subscription_plan(plan_type):
    return SUBSCRIPTION_PLANS.get(plan_type)

def get_user_advert_options(user_id):
    options = []
    
    # Add all subscription plans as a permanent option
    for plan_type, plan_details in SUBSCRIPTION_PLANS.items():
        options.append({
            "type": plan_type,
            "label": f"Subscription: {plan_details['plan_name']}",
            "plan_name": plan_details['plan_name'],
            "cost_naira": plan_details['cost_naira'],
            "advert_duration_days": plan_details['advert_duration_days'],
            "visibility_level": plan_details['visibility_level'],
            "cost_description": f"₦{plan_details['cost_naira']}"
        })

    # Check for one-time free advert benefit.
    user_info = get_user_info(user_id)
    if not user_info.get("has_posted_free_ad", False):
        options.append({
            "type": "free_advert",
            "label": f"Free Advert",
            "plan_name": FREE_ADVERT_PLAN["plan_name"],
            "advert_duration_days": FREE_ADVERT_PLAN["advert_duration_days"],
            "visibility_level": FREE_ADVERT_PLAN["visibility_level"],
            "cost_description": "One-time Free"
        })

    # Check for referral-based options.
    referral_count = get_user_referral_count(user_id)
    for cost, plan_details in REFERRAL_PLANS.items():
        if referral_count >= cost and not user_info.get(f"used_referral_{cost}_benefit", False):
            options.append({
                "type": f"referral_{cost}",
                "label": f"Referral Benefit: {plan_details['plan_name']} ({cost} referrals)",
                "plan_name": plan_details['plan_name'],
                "advert_duration_days": plan_details['advert_duration_days'],
                "visibility_level": plan_details['visibility_level'],
                "cost_description": f"{cost} Referrals"
            })
            
    return options


def upload_file_to_firebase(file, folder, allowed_extensions=None):
    """
    Uploads a file to Firebase Storage.
    Returns the public URL and filename on success, None otherwise.
    """
    if not file or not file.filename:
        return None, None

    if allowed_extensions and '.' in file.filename and \
       file.filename.rsplit('.', 1)[1].lower() not in allowed_extensions:
        logger.warning(f"File upload rejected due to unsupported extension: {file.filename}")
        raise ValueError("Unsupported file type.")

    filename = secure_filename(file.filename)
    extension = os.path.splitext(filename)[1]
    unique_filename = f"{uuid.uuid4()}{extension}"
    destination_path = f"{folder}/{unique_filename}"

    try:
        blob = admin_storage.blob(destination_path)
        blob.upload_from_file(file, content_type=file.content_type)
        blob.make_public()
        return blob.public_url, unique_filename
    except Exception as e:
        logger.error(f"Failed to upload file to Firebase Storage: {e}")

        return None, None







def validate_sell_form(form_data, files):
    errors = []
    if not form_data.get('title'):
        errors.append("Advert title is required.")

    category_name = form_data.get('category')
    if not category_name:
        errors.append("Category is required.")
    else:
        # This checks if the submitted category name exists in your CATEGORIES data
        category_id = get_category_id_from_name(category_name)
        if not category_id:
            errors.append("Invalid category selected. Please choose from the list.")

    if not form_data.get('description'):
        errors.append("Description is required.")
    if not form_data.get('price'):
        errors.append("Price is required.")
    if not form_data.get('state'):
        errors.append("State is required.")
    if not form_data.get('school'):
        errors.append("School is required.")
    if not files.get('main_image') and not form_data.get('existing_main_image'):
        errors.append("A main image is required.")
    
    return errors


def check_if_following(follower_id, followee_id):
    """
    Checks if a user is following another user.
    """
    if not follower_id or not followee_id:
        return False
    
    # Follower documents are named using the pattern "follower_id_followee_id"
    doc_id = f"{follower_id}_{followee_id}"
    follower_doc = db.collection('followers').document(doc_id).get()
    
    return follower_doc.exists

def check_if_saved(user_id, advert_id):
    """
    Checks if a user has saved a specific advert.
    """
    if not user_id or not advert_id:
        return False

    # Saved advert documents are named using the pattern "user_id_advert_id"
    doc_id = f"{user_id}_{advert_id}"
    saved_advert_doc = db.collection('saved_adverts').document(doc_id).get()
    
    return saved_advert_doc.exists



@app.route('/sell', methods=['GET', 'POST'])
@app.route('/sell/<advert_id>', methods=['GET', 'POST'])
@login_required
def sell(advert_id=None):
    advert = None
    if advert_id:
        # Corrected line to get the advert from Firestore
        advert_doc_ref = db.collection("adverts").document(advert_id)
        advert_doc = advert_doc_ref.get()
        if advert_doc.exists:
            advert = advert_doc.to_dict()
    
    user_id = g.current_user.id
    user_data = get_user_info(user_id)
    available_options = get_user_advert_options(user_id)
    
    advert_data = {}
    is_repost = False
    
    # Initialize form_data for both GET and POST requests
    form_data = {}

    if advert_id:
        # This part is redundant as we already got the advert
        if not advert or advert.get('user_id') != user_id:
            flash("Advert not found or you don't have permission to edit.", "error")
            return redirect(url_for('list_adverts'))
        
        advert_data = advert
        is_repost = True
        # If editing an existing advert (GET request with advert_id),
        # populate the form_data with the advert's data.
        form_data = advert
    
    if request.method == 'POST':
        # Overwrite form_data with POST data
        form_data = request.form.to_dict()
        files = request.files
        
        errors = validate_sell_form(form_data, files)
        
        selected_option_type = form_data.get("posting_option")
        selected_option = next((opt for opt in available_options if opt['type'] == selected_option_type), None)
        
        if not selected_option:
            # Append the error message to the list of errors
            errors.append("Invalid advert plan selected. Please choose a valid plan.")

        if errors:
            for error_msg in errors:
                flash(error_msg, 'error')
            
            # Re-render the form with the user's input and errors
            return render_template(
                "sell.html",
                user_data=user_data,
                categories=get_all_categories(),
                NIGERIAN_STATES=NIGERIAN_STATES,
                NIGERIAN_SCHOOLS=NIGERIAN_SCHOOLS,
                available_options=available_options,
                form_data=form_data,
                advert_data=advert_data,
                is_repost=is_repost,
                errors=errors
            )
        
        try:
            main_image_url, additional_images_urls, video_url = handle_file_uploads(files, user_id, advert_data)
            
            # --- The updated section to use the new category logic ---
            # Get the category ID from the submitted category name
            category_name = form_data.get('category')
            category_id = get_category_id_from_name(category_name)
            
            advert_payload = {
                "user_id": user_id,
                "category_id": category_id, # This is the corrected line
                "title": form_data.get('title'),
                "description": form_data.get("description"),
                "price": float(form_data.get('price')),
                "negotiable": form_data.get("negotiable") == "on",
                "condition": form_data.get("condition"),
                "state": form_data.get('state'),
                "school": form_data.get('school'),
                "specific_location": form_data.get("specific_location"),
                "main_image": main_image_url,
                "additional_images": additional_images_urls,
                "video": video_url,
                "plan_name": selected_option.get("plan_name"),
                "advert_duration_days": selected_option.get("advert_duration_days"),
                "visibility_level": selected_option.get("visibility_level"),
                "created_at": firestore.SERVER_TIMESTAMP
            }
            # --- End of updated section ---

            is_subscription = "cost_naira" in selected_option
            
            if is_subscription:
                advert_payload["status"] = "pending_payment"
                new_advert_ref = db.collection("adverts").document()
                new_advert_ref.set(advert_payload)
                advert_id_for_payment = new_advert_ref.id
                
                return redirect(url_for('payment', advert_id=advert_id_for_payment, plan_name=selected_option['plan_name']))
            else:
                advert_payload["status"] = "pending_review"
                # Use update() if reposting, set() for a new post
                if is_repost:
                    db.collection("adverts").document(advert_id).update(advert_payload)
                else:
                    new_advert_ref = db.collection("adverts").document()
                    new_advert_ref.set(advert_payload)
                
                if selected_option_type == "free_advert":
                    db.collection("users").document(user_id).update({"has_posted_free_ad": True})
                elif selected_option_type.startswith("referral_"):
                    cost = int(selected_option_type.split('_')[1])
                    db.collection("users").document(user_id).update({f"used_referral_{cost}_benefit": True})
                
                flash("Your advert has been submitted for review.", "success")
                return redirect(url_for('list_adverts'))
        
        except Exception as e:
            logger.error(f"Error during advert submission for user {user_id}: {e}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "error")
            return redirect(url_for('sell'))

    # This is the return for GET requests, which was the original missing piece
    return render_template(
        "sell.html",
        user_data=user_data,
        categories=get_all_categories(),
        NIGERIAN_STATES=NIGERIAN_STATES,
        NIGERIAN_SCHOOLS=NIGERIAN_SCHOOLS,
        available_options=available_options,
        form_data=form_data,
        advert_data=advert_data,
        is_repost=is_repost
    )
















@app.route('/payment/<advert_id>', methods=['GET'])
@login_required
def payment(advert_id):
    advert = get_document("adverts", advert_id)
    if not advert or advert.get('user_id') != g.current_user.id or advert.get('status') != 'pending_payment':
        flash("Invalid payment request.", "error")
        return redirect(url_for('list_adverts'))

    plan_name = advert.get('plan_name')
    plan = next((p for p in SUBSCRIPTION_PLANS.values() if p['plan_name'] == plan_name), None)
    if not plan:
        flash("Invalid subscription plan.", "error")
        return redirect(url_for('list_adverts'))
        
    payment_reference = f"ADVERT-{advert_id}-{uuid.uuid4().hex[:6].upper()}"
    
    db.collection("adverts").document(advert_id).update({
        "payment_reference": payment_reference,
        "payment_status": "awaiting_confirmation",
        "plan_cost": plan['cost_naira']
    })
    
    account_details = {
        "account_name": "James Nwoke",
        "account_number": "2266701415",
        "bank_name": "ZENITH",
        "currency": "NGN"
    }

    return render_template(
        "payment.html",
        plan_name=plan_name,
        amount=plan['cost_naira'],
        payment_reference=payment_reference,
        account_details=account_details,
        advert_id=advert_id
    )








@app.route('/submit-advert/<advert_id>', methods=['POST'])
@login_required
def submit_advert(advert_id):
    advert = get_document("adverts", advert_id)
    if not advert or advert.get('user_id') != g.current_user.id:
        flash("Invalid submission.", "error")
        return redirect(url_for('list_adverts'))
    
    # Check if the advert is in a valid state to be submitted for review
    if advert.get('status') != 'pending_payment':
        flash("Advert is not in a valid state for submission.", "error")
        return redirect(url_for('list_adverts'))

    # Get the plan duration for expiration calculation
    plan_name = advert.get('plan_name')
    plan = next((p for p in SUBSCRIPTION_PLANS.values() if p['plan_name'] == plan_name), None)
    
    if not plan:
        flash("Invalid subscription plan details.", "error")
        return redirect(url_for('list_adverts'))

    duration_days = plan.get("advert_duration_days", 0) 
    expires_at = datetime.now() + timedelta(days=duration_days)
    
    db.collection("adverts").document(advert_id).update({
        # Only update the status and expiration date
        "status": "pending_review",
        "published_at": firestore.SERVER_TIMESTAMP,
        "expires_at": expires_at
    })
    
    flash("Your advert has been submitted for review. Thank you for your payment!", "success")
    return redirect(url_for('list_adverts'))



@app.route('/adverts')
@login_required
def list_adverts():
    user_id = g.current_user.id
    adverts_ref = db.collection('adverts').where('user_id', '==', user_id).stream()
    adverts = []
    
    # Get a list of advert IDs to process for deletion
    adverts_to_delete = []

    for doc in adverts_ref:
        advert_data = doc.to_dict()
        advert_data['id'] = doc.id
        
        # Determine the advert status based on new logic
        status = advert_data.get('status', 'pending_review') # Default to pending_review
        
        # Check for expiration if the advert is published
        if status == 'published' and 'published_at' in advert_data and advert_data['published_at']:
            plan_name = advert_data.get('plan_name')
            plan_details = SUBSCRIPTION_PLANS.get(plan_name)
            
            if plan_details:
                duration_days = plan_details.get('advert_duration_days', 0)
                published_at = advert_data['published_at']
                
                # Check if published_at is a datetime object, convert if necessary
                if not isinstance(published_at, datetime):
                    # Assuming it's a Firestore Timestamp, convert it
                    published_at = published_at.to_datetime()
                
                # Use timedelta correctly
                expiration_date = published_at + timedelta(days=duration_days)
                now = datetime.now(timezone.utc) # Ensure timezone awareness
                
                if now > expiration_date:
                    # Update status to 'expired' in Firestore
                    doc.reference.update({'status': 'expired', 'expired_at': firestore.SERVER_TIMESTAMP})
                    status = 'expired'
            
        # Check if the advert is expired and passed the 2-day grace period
        if status == 'expired' and 'expired_at' in advert_data and advert_data['expired_at']:
            expired_at = advert_data['expired_at'].to_datetime()
            deletion_date = expired_at + timedelta(days=2)
            now = datetime.now(timezone.utc)
            
            if now > deletion_date:
                # Add to a list for batch deletion
                adverts_to_delete.append(doc.id)
                # Skip this advert in the display list as it will be deleted
                continue
            
        advert_data['status'] = status
        
        # Enrich advert data for display
        advert_data['category_name'] = get_category_name(advert_data.get('category_id'))
        advert_data['location'] = f"{advert_data.get('school', '')}, {advert_data.get('state', '')}"
        
        # Check and format 'created_at' using the correct datetime reference
        advert_data['created_at'] = advert_data.get('created_at', 'N/A')
        if advert_data['created_at'] != 'N/A' and isinstance(advert_data['created_at'], datetime):
            advert_data['created_at'] = advert_data['created_at'].strftime('%Y-%m-%d %H:%M')
            
        adverts.append(advert_data)
    
    # Process the batch deletion of expired adverts
    for advert_id in adverts_to_delete:
        delete_advert_and_data(advert_id) # Call a new helper function
        
    return render_template("list_adverts.html", adverts=adverts)
    
def delete_advert_and_data(advert_id):
    """Deletes an advert document and its associated images."""
    try:
        advert_ref = db.collection('adverts').document(advert_id)
        advert_doc = advert_ref.get()
        if not advert_doc.exists:
            return False, 'Advert not found.'

        advert_data = advert_doc.to_dict()
        main_image = advert_data.get('main_image')
        other_images = advert_data.get('other_images', [])

        bucket = storage.bucket()
        # Delete main image if it exists
        if main_image:
            main_image_path = main_image.split('/')[-1]
            blob = bucket.blob(main_image_path)
            if blob.exists():
                blob.delete()
        
        # Delete other images
        for img_url in other_images:
            img_path = img_url.split('/')[-1]
            blob = bucket.blob(img_path)
            if blob.exists():
                blob.delete()
        
        # Delete Firestore document
        advert_ref.delete()
        return True, 'Advert and images deleted successfully.'

    except Exception as e:
        print(f"Error deleting advert {advert_id}: {e}")
        return False, f'An error occurred: {e}'

@app.route('/advert/pause/<advert_id>', methods=['POST'])
@login_required
def pause_advert(advert_id):
    advert = get_document("adverts", advert_id)
    if not advert or advert.get('user_id') != g.current_user.id or advert.get('status') != 'published':
        flash("Cannot pause this advert.", "error")
    else:
        db.collection("adverts").document(advert_id).update({"status": "paused"})
        flash("Advert paused successfully.", "success")
    return redirect(url_for('list_adverts'))

@app.route('/advert/resume/<advert_id>', methods=['POST'])
@login_required
def resume_advert(advert_id):
    advert = get_document("adverts", advert_id)
    if not advert or advert.get('user_id') != g.current_user.id or advert.get('status') != 'paused':
        flash("Cannot resume this advert.", "error")
    else:
        db.collection("adverts").document(advert_id).update({"status": "pending_review"})
        flash("Advert submitted for review. It will be live again shortly.", "success")
    return redirect(url_for('list_adverts'))


# A new route for reposting an advert
@app.route('/repost_advert/<advert_id>', methods=['GET', 'POST'])
@login_required
def repost_advert(advert_id):
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists or advert_doc.to_dict()['user_id'] != g.current_user.id:
        flash('Advert not found or you do not have permission to repost it.', 'error')
        return redirect(url_for('list_adverts'))
        
    try:
        # Update the advert's status and timestamp
        advert_ref.update({
            'status': 'published',
            'published_at': firestore.SERVER_TIMESTAMP,
            'expired_at': firestore.DELETE_FIELD # Remove the expired_at field
        })
        flash('Advert successfully reposted!', 'success')
    except Exception as e:
        flash(f'An error occurred while reposting the advert: {e}', 'error')

    return redirect(url_for('list_adverts'))

# The delete route should be modified to use the new helper function
@app.route('/delete_advert/<advert_id>', methods=['POST'])
@login_required
def delete_advert(advert_id):
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()
    
    if not advert_doc.exists or advert_doc.to_dict()['user_id'] != g.current_user.id:
        flash('Advert not found or you do not have permission to delete it.', 'error')
        return redirect(url_for('list_adverts'))

    success, message = delete_advert_and_data(advert_id)
    if success:
        flash('Advert and associated data deleted successfully!', 'success')
    else:
        flash(message, 'error')
        
    return redirect(url_for('list_adverts'))




@app.route('/admin/adverts/review')
@login_required  # This decorator runs first, populating g.current_user
@admin_required  # This decorator runs second, after g.current_user is available
def admin_advert_review():
    """
    Renders the admin review page with adverts awaiting review,
    correctly displaying the main image.
    """
    adverts_ref = db.collection("adverts")
    query = adverts_ref.where("status", "==", "pending_review").stream()
    pending_adverts = []

    for doc in query:
        advert = doc.to_dict()
        advert['id'] = doc.id

        user_info = get_user_info(advert['user_id'])
        advert['seller_username'] = user_info.get('username', 'N/A')
        advert['seller_email'] = user_info.get('email', 'N/A')

        advert['category_name'] = get_category_name(advert.get('category_id'))

        duration_days = advert.get("advert_duration_days")
        if duration_days and advert.get("created_at"):
            advert['calculated_expiry'] = datetime.now() + timedelta(days=duration_days)
        else:
            advert['calculated_expiry'] = None

        main_image_url = advert.get('main_image')
        if main_image_url:
            advert['display_image'] = main_image_url
        else:
            advert['display_image'] = 'https://placehold.co/400x250/E0E0E0/333333?text=No+Image'

        advert['payment_reference'] = advert.get('payment_reference', 'N/A')
        
        pending_adverts.append(advert)

    return render_template('admin_review.html', adverts=pending_adverts)




@app.route('/admin/adverts/approve', methods=['POST'])
@login_required
@admin_required
def admin_advert_approve():
    """
    Handles the approval of an advert.

    Updates the advert's status to 'approved', sets the publication date,
    and calculates the final expiry date.
    """
    advert_id = request.form.get('advert_id')
    if not advert_id:
        return redirect(url_for('admin_advert_review'))

    advert_ref = db.collection("adverts").document(advert_id)
    advert_doc = advert_ref.get()

    if advert_doc.exists:
        advert_data = advert_doc.to_dict()
        duration_days = advert_data.get("advert_duration_days", 30) # Default to 30 days if not set

        advert_ref.update({
            'status': 'approved',
            'is_published': True,
            'published_at': datetime.now(),
            'expiry_date': datetime.now() + timedelta(days=duration_days)
        })

    return redirect(url_for('admin_advert_review'))


@app.route('/admin/adverts/reject', methods=['POST'])
@login_required
@admin_required
def admin_advert_reject():
    """
    Handles the rejection of an advert.

    Updates the advert's status to 'rejected' and stores the reason
    provided by the admin for the user to see.
    """
    advert_id = request.form.get('advert_id')
    rejection_reason = request.form.get('rejection_reason', 'No reason provided.')

    if not advert_id:
        return redirect(url_for('admin_advert_review'))

    advert_ref = db.collection("adverts").document(advert_id)
    advert_doc = advert_ref.get()

    if advert_doc.exists:
        advert_ref.update({
            'status': 'rejected',
            'rejection_reason': rejection_reason,
            'is_published': False
        })

    return redirect(url_for('admin_advert_review'))







@app.route('/admin/reported_advert/<report_id>')
@login_required
@admin_required
def reported_advert_details(report_id):
    """
    Displays detailed information about a single reported advert for admin review.
    """
    # 1. Fetch the report document
    report_doc = db.collection('reports').document(report_id).get()
    
    if not report_doc.exists:
        flash("Report not found.", "error")
        return redirect(url_for('reported_adverts_admin'))

    report = report_doc.to_dict()
    report['report_id'] = report_doc.id

    # 2. Fetch the advert and its owner's information
    advert_id = report.get('advert_id')
    advert_doc = db.collection('adverts').document(advert_id).get()
    
    if advert_doc.exists:
        advert = advert_doc.to_dict()
        report['advert_title'] = advert.get('title')
        report['advert_description'] = advert.get('description')
        report['advert_price'] = advert.get('price')
        report['advert_status'] = advert.get('status')
        report['advert_owner_id'] = advert.get('user_id')
    else:
        # Handle cases where the advert was already deleted
        report['advert_title'] = 'Advert Not Found'
        report['advert_description'] = 'N/A'
        report['advert_price'] = 0
        report['advert_status'] = 'deleted'
        report['advert_owner_id'] = None

    # 3. Fetch the advert owner's information
    owner_info = get_user_info(report.get('advert_owner_id'))
    if owner_info:
        report['advert_owner_username'] = owner_info.get('username')
        report['advert_owner_email'] = owner_info.get('email')
        report['advert_owner_account_status'] = owner_info.get('account_status', 'active')
    else:
        report['advert_owner_username'] = 'N/A'
        report['advert_owner_email'] = 'N/A'
        report['advert_owner_account_status'] = 'N/A'

    # 4. Fetch the reporter's information
    reporter_id = report.get('reporter_id')
    reporter_info = get_user_info(reporter_id)
    if reporter_info:
        report['reporter_username'] = reporter_info.get('username')
        report['reporter_email'] = reporter_info.get('email')
        report['reporter_account_status'] = reporter_info.get('account_status', 'active')
    else:
        report['reporter_username'] = 'N/A'
        report['reporter_email'] = 'N/A'
        report['reporter_account_status'] = 'N/A'
        
    return render_template('admin_reported_advert_details.html', report=report)

@app.route('/admin/action/mark_resolved/<report_id>', methods=['POST'])
@login_required
@admin_required
def mark_report_resolved(report_id):
    """Admin action to mark a report as resolved."""
    report_ref = db.collection('reports').document(report_id)
    report_doc = report_ref.get()

    if not report_doc.exists:
        return jsonify({"message": "Report not found."}), 404

    report_ref.update({
        'status': 'resolved',
        'resolved_at': firestore.SERVER_TIMESTAMP
    })

    return jsonify({"message": "Report marked as resolved successfully!"}), 200


@app.route('/admin/action/suspend_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def suspend_user_account(user_id):
    """Admin action to suspend a user's account."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({"message": "User not found."}), 404
        
    user_ref.update({
        'is_active': False,
        'account_status': 'suspended'
    })
    
    return jsonify({"message": "User account suspended successfully!"}), 200


@app.route('/admin/action/take_down_advert/<advert_id>', methods=['POST'])
@login_required
@admin_required
def take_down_advert(advert_id):
    """Admin action to take down an advert."""
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists:
        return jsonify({"message": "Advert not found."}), 404

    advert_ref.update({
        'status': 'taken_down',
        'taken_down_at': firestore.SERVER_TIMESTAMP
    })
    
    return jsonify({"message": "Advert taken down successfully!"}), 200








@app.route('/admin/reported_adverts')
@login_required
@admin_required
def reported_adverts_admin():
    """
    Renders a page with a list of all reported adverts awaiting admin review.
    """
    reports_ref = db.collection('reports')
    
    # Fetch all reports that are 'pending'
    # This is the default status for a new report
    query = reports_ref.where('status', '==', 'pending').stream()
    
    reported_adverts = []
    for doc in query:
        report = doc.to_dict()
        report['report_id'] = doc.id
        
        # Fetch the advert details
        advert_doc = db.collection('adverts').document(report.get('advert_id')).get()
        if advert_doc.exists:
            advert_data = advert_doc.to_dict()
            report['advert_title'] = advert_data.get('title', 'N/A')
            report['advert_owner_id'] = advert_data.get('user_id')
        else:
            report['advert_title'] = 'Advert Not Found'
            report['advert_owner_id'] = None

        # Fetch the reporter's username
        reporter_info = get_user_info(report.get('reporter_id'))
        if reporter_info:
            report['reporter_username'] = reporter_info.get('username', 'N/A')
        else:
            report['reporter_username'] = 'N/A'
            
        reported_adverts.append(report)
    
    return render_template('admin_reported_adverts.html', reported_adverts=reported_adverts)









# --- Admin Function to Post New Airtime ---
@app.route('/admin/post_airtime', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_post_airtime():
    """
    Handles the creation of a new airtime post by an admin.
    Processes form data, uploads an optional image to Firebase Storage,
    and saves the post details to Firestore with a calculated expiry time.
    """
    if request.method == 'POST':
        network = request.form.get('network')
        amount_raw = request.form.get('amount')
        digits = request.form.get('digits')
        instructions = request.form.get('instructions')
        
        # Using a type conversion to handle duration_value directly
        duration_value = request.form.get('duration_value', type=int)
        duration_unit = request.form.get('duration_unit')

        # --- Input Validation and Cleaning ---
        amount = None
        if amount_raw:
            # Clean non-digit characters from the amount input
            cleaned_amount = re.sub(r'[^\d]', '', amount_raw)
            if cleaned_amount.isdigit():
                amount = int(cleaned_amount)
            else:
                flask.flash('Invalid amount format. Please enter numbers only (e.g., 500, 1000).', 'error')
                return render_template('admin_post_airtime.html')

        cleaned_digits = None
        if digits:
            # Clean non-digit characters from the digits input
            cleaned_digits = re.sub(r'[^\d\s]', '', digits)

        # Check if at least one of digits or image is provided
        if not cleaned_digits and not 'airtime_image' in request.files:
            flask.flash("You must provide either the airtime digits or an image.", "error")
            return redirect(url_for('admin_post_airtime'))

        if not duration_value or not duration_unit:
            flask.flash('Duration value and unit are required.', 'error')
            return redirect(url_for('admin_post_airtime'))

        # Calculate expiry time
        # Corrected: Use datetime.utcnow() directly
        now = datetime.utcnow()
        if duration_unit == 'seconds':
            expiry_time = now + timedelta(seconds=duration_value)
        elif duration_unit == 'minutes':
            expiry_time = now + timedelta(minutes=duration_value)
        elif duration_unit == 'hours':
            expiry_time = now + timedelta(hours=duration_value)
        elif duration_unit == 'days':
            expiry_time = now + timedelta(days=duration_value)
        else:
            flask.flash('Invalid duration unit provided.', 'error')
            return redirect(url_for('admin_post_airtime'))

        # Handle image upload to Firebase Storage
        image_url = None
        if 'airtime_image' in request.files:
            file = request.files['airtime_image']
            if file and allowed_file(file.filename):
                try:
                    # Generate a unique filename using UUID to prevent conflicts
                    filename = secure_filename(file.filename)
                    unique_filename = f"{uuid.uuid4()}_{filename}"
                    blob = bucket.blob(f"airtime_images/{unique_filename}")
                    
                    # Upload file from the in-memory stream
                    blob.upload_from_file(file, content_type=file.content_type)
                    
                    # Make the image publicly accessible
                    blob.make_public()
                    image_url = blob.public_url
                    logger.info(f"Image uploaded to: {image_url}")
                except Exception as e:
                    flask.flash(f"Error uploading image: {e}", "error")
                    logger.error(f"Image upload failed: {e}")
                    return redirect(url_for('admin_post_airtime'))

        # Create a new document in the 'airtime_posts' collection
        airtime_post_data = {
            'network': network,
            'amount': amount,
            'digits': cleaned_digits,
            'instructions': instructions,
            'image_url': image_url,
            'created_at': firestore.SERVER_TIMESTAMP,
            'expires_at': expiry_time,
            # Corrected: Use flask.g.user['uid'] as set by the session_required decorator
            'posted_by': flask.g.user.get('uid')
        }

        db.collection('airtime_posts').add(airtime_post_data)

        flask.flash('Airtime post created successfully!', 'success')
        return redirect(url_for('admin_post_airtime'))

   
    # If it's a GET request, render the template
    return render_template('admin_post_airtime.html')

# --- API Route to Fetch Active Airtime Posts ---
@app.route('/api/airtime-posts', methods=['GET'])
def get_airtime_posts():
    """
    Fetches the single most recent active airtime post.
    Filters by expiry time and sorts manually to get the newest post.
    """
    try:
        # Corrected: Use datetime.utcnow() directly
        now = datetime.utcnow()
        
        # Use a Firestore query to get active posts
        # We need to filter for posts that have not expired.
        # Note: 'created_at' and 'expires_at' fields must be indexed in Firestore.
        posts_ref = db.collection('airtime_posts')\
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

        # Manually sort the posts by created_at in descending order
        # This is required because we cannot filter and order by different fields in Firestore
        sorted_posts = sorted(posts_data, key=lambda p: p['created_at'], reverse=True)

        # Return only the single most recent post
        if sorted_posts:
            return jsonify([sorted_posts[0]])
        else:
            return jsonify([])

    except Exception as e:
        logger.error(f"Error fetching airtime posts: {e}")
        return jsonify({'message': f'Error fetching posts: {str(e)}'}), 500



 
# --- API Route to Delete Expired Airtime Posts (Triggered by Frontend JS) ---
@app.route('/api/airtime-posts/<string:post_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_airtime_post_api(post_id):
    """
    Deletes an airtime post from Firestore and its associated image from Firebase Storage.
    This is an API endpoint typically triggered by a frontend script.
    """
    try:
        post_ref = db.collection('airtime_posts').document(post_id)
        post = post_ref.get()

        if not post.exists:
            logger.warning(f"Attempted to delete non-existent post: {post_id}")
            return jsonify({'message': 'Post not found'}), 404

        post_data = post.to_dict()
        
        # Delete the image from Firebase Storage if it exists
        if post_data.get('image_url'):
            try:
                # The filename is the last part of the URL before any query parameters
                image_path = post_data['image_url'].split('?')[0].split('/')[-1]
                # Reconstruct the blob path (it's in the 'airtime_images' folder)
                blob = bucket.blob(f"airtime_images/{image_path}")
                blob.delete()
                logger.info(f"Deleted image from storage: {post_data['image_url']}")
            except Exception as e:
                logger.error(f"Error deleting image from storage: {e}")
                # We log the error but continue to delete the document to maintain data consistency

        # Delete the Firestore document
        post_ref.delete()
        logger.info(f"Deleted Firestore document: {post_id}")
        return jsonify({'message': 'Airtime post deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error deleting post {post_id}: {e}")
        return jsonify({'message': f'Error deleting post: {str(e)}'}), 500

# --- Function to Clean Up Expired Posts from the Backend ---
@app.route('/admin/clean_expired_posts', methods=['POST'])
@login_required
@admin_required
def clean_expired_posts():
    """
    A backend endpoint for the admin to manually trigger the cleanup
    of all expired airtime posts. This is an alternative to a cron job.
    """
    try:
        now = datetime.datetime.utcnow()
        expired_posts_ref = db.collection('airtime_posts').where(filter=firestore.FieldFilter('expires_at', '<', now))
        expired_docs = expired_posts_ref.stream()
        
        deleted_count = 0
        for doc in expired_docs:
            post_id = doc.id
            post_data = doc.to_dict()
            
            # Delete the image from Firebase Storage if it exists
            if post_data.get('image_url'):
                try:
                    image_path = post_data['image_url'].split('?')[0].split('/')[-1]
                    blob = bucket.blob(f"airtime_images/{image_path}")
                    blob.delete()
                except Exception as e:
                    logger.error(f"Error deleting image for post {post_id}: {e}")
            
            # Delete the Firestore document
            db.collection('airtime_posts').document(post_id).delete()
            deleted_count += 1
        
        flash(f'Successfully cleaned up {deleted_count} expired airtime posts.', 'success')
        return redirect(url_for('admin_post_airtime'))

    except Exception as e:
        logger.error(f"Error during expired post cleanup: {e}")
        flash(f'An error occurred during cleanup: {str(e)}', 'error')
        return redirect(url_for('admin_post_airtime'))

    
@app.route('/admin_users_management')
@login_required
@admin_required
def admin_users_management():
    return render_template('admin_users_management.html')



@app.route('/referral-benefit')
def referral_benefit():
    return render_template('referral_benefit.html')




@app.route('/advert/<string:advert_id>')
def advert_detail(advert_id):
    """
    Handles displaying a single advert detail page.
    """
    current_user_id = g.current_user.id if hasattr(g, 'current_user') and g.current_user else None

    try:
        # Step 1: Fetch the advert document.
        advert_ref = db.collection('adverts').document(advert_id)
        advert_doc = advert_ref.get()

        if not advert_doc.exists:
            abort(404)
        
        advert = advert_doc.to_dict()
        advert['id'] = advert_doc.id

        is_owner = current_user_id == advert.get('user_id')
        if advert.get('status') != 'published' and not is_owner:
            abort(404)

        # Step 2: Fetch seller info and attach the profile picture URL.
        seller_id = advert.get('user_id')
        seller_doc = db.collection('users').document(seller_id).get()

        if not seller_doc.exists:
            seller = {'id': seller_id, 'full_name': 'Unknown Seller', 'rating': 0.0, 'review_count': 0}
            seller['profile_picture'] = url_for('static', filename='images/default_profile.png')
        else:
            seller = seller_doc.to_dict()
            seller['id'] = seller_doc.id

            # This is the critical line that fixes the issue.
            # It takes the filename and generates a full URL.
            profile_picture_filename = seller.get('profile_picture')
            seller['profile_picture'] = get_profile_picture_url(profile_picture_filename)

            # Calculate and attach the seller's rating and review count
            reviews_query = db.collection('reviews').where('reviewee_id', '==', seller_id).stream()
            total_rating = 0
            review_count = 0
            for review_doc in reviews_query:
                review_data = review_doc.to_dict()
                total_rating += review_data.get('rating', 0)
                review_count += 1
            
            seller['rating'] = total_rating / review_count if review_count > 0 else 0.0
            seller['review_count'] = review_count

        # Step 3: Fetch related advert data.
        advert['category_name'] = get_category_name(advert.get('category_id'))
        advert['state_name'] = get_state_name(advert.get('state'))
        
        # Step 4: Check if the current user is following the seller or has saved the advert
        is_following = False
        is_saved = False
        if current_user_id:
            is_following = check_if_following(current_user_id, seller['id'])
            is_saved = check_if_saved(current_user_id, advert_id)

        # Step 5: Fetch reviews for the current advert and process reviewer images
        reviews_ref = db.collection('reviews').where('advert_id', '==', advert_id).order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        reviews = []
        for review_doc in reviews_ref:
            review_data = review_doc.to_dict()
            reviewer_info = db.collection('users').document(review_data['user_id']).get()
            if reviewer_info.exists:
                reviewer_data = reviewer_info.to_dict()
                review_data['reviewer_username'] = reviewer_data.get('full_name', 'Anonymous')
                reviewer_profile_filename = reviewer_data.get('profile_picture')
                review_data['reviewer_profile_picture'] = get_profile_picture_url(reviewer_profile_filename)
            reviews.append(review_data)

        # Step 6: Render the template with all the necessary data
        return render_template(
            'advert_detail.html',
            advert=advert,
            seller=seller,
            reviews=reviews,
            is_following=is_following,
            is_saved=is_saved,
            current_user_id=current_user_id,
            is_owner=is_owner
        )

    except Exception as e:
        logging.error(f"Error fetching advert detail: {e}", exc_info=True)
        return abort(500)




# Assuming your other imports and setup are already in place
# ...

@app.route('/seller_profile/<seller_id>')
def seller_profile_view(seller_id):
    current_user_id = session.get('user_id')
    seller_info = None
    seller_adverts = []
    is_following = False

    try:
        seller_doc_ref = db.collection('users').document(seller_id)
        seller_doc = seller_doc_ref.get()

        if not seller_doc.exists:
            flash("Seller profile not found.", "error")
            return redirect(url_for('home'))
        
        seller_info = seller_doc.to_dict()

        profile_picture_filename = seller_info.get('profile_picture')
        seller_info['profile_picture_url'] = get_profile_picture_url(profile_picture_filename)
        
        cover_photo_filename = seller_info.get('cover_photo')
        seller_info['cover_photo_url'] = get_cover_photo_url(cover_photo_filename)
        
        # Add the seller's WhatsApp link to their info dictionary
        seller_phone = seller_info.get('phone_number')
        if seller_phone:
            # We'll generate a simple message link here
            seller_info['whatsapp_link'] = f"https://wa.me/{seller_phone}"

        if seller_info.get('created_at') and hasattr(seller_info['created_at'], 'to_datetime'):
            seller_info['created_at'] = seller_info['created_at'].strftime('%Y-%m-%d %H:%M')

        # ... (rest of your existing code for reviews, etc.)

        if current_user_id:
            followers_query = db.collection('followers').where('follower_id', '==', current_user_id).where('followed_id', '==', seller_id).limit(1)
            is_following = len(list(followers_query.stream())) > 0

        # ✨ REVISED QUERY: Use .where() to filter by published status
        adverts_ref = db.collection('adverts').where('user_id', '==', seller_id).where('status', '==', 'published').order_by('created_at', direction=firestore.Query.DESCENDING)
        
        seller_adverts = []
        for advert_doc in adverts_ref.stream():
            advert = advert_doc.to_dict()
            advert['id'] = advert_doc.id
            
            if advert.get('main_image'):
                blob = admin_storage.blob(advert['main_image'])
                if blob.exists():
                    advert['display_image'] = blob.generate_signed_url(timedelta(minutes=15), method='GET')
                else:
                    advert['display_image'] = url_for('static', filename='images/default_advert_image.png')
            else:
                advert['display_image'] = url_for('static', filename='images/default_advert_image.png')

            if advert.get('created_at') and hasattr(advert['created_at'], 'to_datetime'):
                advert['created_at'] = advert['created_at'].strftime('%Y-%m-%d %H:%M')
            if advert.get('expires_at') and hasattr(advert['expires_at'], 'to_datetime'):
                advert['expires_at'] = advert['expires_at'].strftime('%Y-%m-%d %H:%M')

            # We'll use the URL of the advert details page as the message content
            advert_url = url_for('advert_detail', advert_id=advert['id'], _external=True)
            pre_filled_message = f"Hello, I am interested in this advert from your profile: {advert_url}"
            advert['whatsapp_link_with_message'] = f"https://wa.me/{seller_phone}?text={quote(pre_filled_message)}"
            
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
        
        
        
        
   
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
            
   @app.route('/subscribe')
def subscribe():
    # Your subscription logic here
    return render_template('subscribe.html')


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





    
def get_followers_of_user(user_id):
    """Fetches the user IDs that the given user is following."""
    # This assumes a 'followers' subcollection or similar structure.
    # We will simulate this for now, but a proper implementation would query a 'followings' collection.
    # For this example, we'll return a hardcoded list.
    # In a real app, you would query a 'following' collection for documents where the 'follower_id' is the current user's ID.
    return []


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




def send_notification(user_id, message, notification_type="info"):
    """
    A placeholder function to simulate sending a user notification.
    """
    logging.info(f"NOTIFICATION to user {user_id}: {message}")









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





@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    """
    Handles the submission of a new review for an advert.
    This route requires a POST request with form data.
    """
    try:
        # Get data from the form
        advert_id = request.form.get('advert_id')
        rating_str = request.form.get('rating')
        comment = request.form.get('comment')
        reviewee_id = request.form.get('reviewee_id')

        # Basic input validation
        if not all([advert_id, rating_str, comment, reviewee_id]):
            flash('All fields are required to submit a review.', 'error')
            return redirect(url_for('advert_detail', advert_id=advert_id))

        try:
            rating = int(rating_str)
            if not 1 <= rating <= 5:
                flash('Rating must be between 1 and 5.', 'error')
                return redirect(url_for('advert_detail', advert_id=advert_id))
        except ValueError:
            flash('Invalid rating value.', 'error')
            return redirect(url_for('advert_detail', advert_id=advert_id))

        current_user_id = g.current_user.id
        
        # Prevent users from reviewing their own ads
        if current_user_id == reviewee_id:
            flash('You cannot review your own advert.', 'error')
            return redirect(url_for('advert_detail', advert_id=advert_id))

        # Check if the user has already submitted a review for this advert
        existing_review_query = db.collection('reviews').where('user_id', '==', current_user_id).where('advert_id', '==', advert_id).limit(1).stream()
        existing_review = next(existing_review_query, None)
        if existing_review:
            flash('You have already submitted a review for this advert.', 'error')
            return redirect(url_for('advert_detail', advert_id=advert_id))

        # Data for the new review document
        new_review_data = {
            'advert_id': advert_id,
            'user_id': current_user_id,
            'reviewee_id': reviewee_id,
            'rating': rating,
            'comment': comment,
            'created_at': datetime.now()
        }

        # Add the new review document to the 'reviews' collection
        db.collection('reviews').add(new_review_data)

        flash('Your review has been submitted successfully!', 'success')
        
    except Exception as e:
        logging.error(f"Error submitting review: {e}", exc_info=True)
        flash('An unexpected error occurred. Please try again.', 'error')
        
    return redirect(url_for('advert_detail', advert_id=advert_id))













 




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







if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))  # Render gives you the port in $PORT
    app.run(host="0.0.0.0", port=port)


































































































































































































































