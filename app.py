import os
from flask import after_this_request
import random
import string
import re
import uuid
import secrets
import time
import hashlib
import logging
import requests
import json
import tempfile
from io import BytesIO
from urllib.parse import urlparse, quote
from functools import wraps
from datetime import datetime, timedelta, date, timezone, UTC

import flask
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
    send_file,
)

from collections import defaultdict
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

import firebase_admin
from firebase_admin import credentials, storage, firestore, auth, initialize_app
from firebase_admin.exceptions import FirebaseError
from google.cloud.firestore_v1.base_query import FieldFilter, BaseCompositeFilter
from google.cloud.firestore_v1 import Increment
from google.cloud.firestore_v1.transaction import Transaction
from google.oauth2 import service_account
from google.cloud import storage as gcp_storage
from firebase_functions import https_fn
from werkzeug.datastructures import FileStorage

import boto3
from botocore.exceptions import ClientError
from authlib.integrations.flask_client import OAuth




# --- Application setup ---
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'Jamiecoo15012004')


bcrypt = Bcrypt(app)
mail = Mail(app)
oauth = OAuth(app)
socketio = SocketIO(app)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# --- Firebase initialization ---
try:
    raw_json = os.environ.get("FIREBASE_CREDENTIALS_JSON")
    if not raw_json:
        raise ValueError("FIREBASE_CREDENTIALS_JSON environment variable not set.")

    # Use a temporary file to store credentials for Firebase SDK
    with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.json') as temp:
        temp.write(raw_json)
        temp.flush()
        temp_path = temp.name

    # Initialize the Firebase Admin SDK with the credentials
    cred = credentials.Certificate(temp_path)
    initialize_app(cred, {'storageBucket': 'schomart-7a743.firebasestorage.app'})

    # Get a reference to the Firestore and Storage clients
    db = firestore.client()
    bucket = storage.bucket()
    
    logger.info("Firebase Firestore and Storage clients initialized successfully.")

except Exception as e:
    logger.error(f"Failed to initialize Firebase: {e}")
    raise RuntimeError("Firebase initialization failed. Check your credentials and environment setup.")
finally:
    # Clean up the temporary file
    if 'temp_path' in locals() and os.path.exists(temp_path):
        os.remove(temp_path)


# Note: Local file storage configurations are now obsolete, but kept for context.
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf', 'docx', 'mp3', 'wav', 'mp4'}

def allowed_file(filename):
    """
    Checks if a file has an allowed extension.
    """
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


# --- New API route to delete user data from Firestore ---
@app.route('/api/delete-user-data', methods=['POST'])
@login_required # Ensures the user is logged in
def delete_user_data_api():
    try:
        # The login_required decorator already ensures g.current_user exists
        user_id = g.current_user.id
        
        # You can add logic here to delete other data associated with the user
        # For example, delete all their adverts
        # db.collection('adverts').where('user_id', '==', user_id).stream() -> loop and delete

        # Delete the user's document from the 'users' collection
        db.collection('users').document(user_id).delete()
        
        return jsonify({'message': 'User data deleted successfully.'}), 200

    except Exception as e:
        logger.error(f"Failed to delete Firestore data for user {user_id}: {e}", exc_info=True)
        return jsonify({'message': f'Server error during data cleanup: {str(e)}'}), 500





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







# Your provided get_user_info function
def get_user_info(user_id):
    """
    Fetches user information and calculates their rating, review count, and advert count.
    """
    if not user_id:
        return None

    user_doc = db.collection('users').document(user_id).get()

    if not user_doc.exists:
        return None

    user_data = user_doc.to_dict()
    user_data['id'] = user_doc.id

    reviews_query = db.collection('reviews').where('reviewee_id', '==', user_id).stream()
    total_rating = 0
    review_count = 0
    for review_doc in reviews_query:
        review_data = review_doc.to_dict()
        total_rating += review_data.get('rating', 0)
        review_count += 1
    
    user_data['rating'] = total_rating / review_count if review_count > 0 else 0.0
    user_data['review_count'] = review_count

    adverts_count_query = db.collection('adverts').where('user_id', '==', user_id).stream()
    adverts_count = sum(1 for _ in adverts_count_query)
    user_data['adverts_count'] = adverts_count

    return user_data







    

# --- Helper Functions ---
def get_unique_id():
    """Generates a unique ID for files or other items."""
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))



def get_profile_picture_url(user_id):
    """
    Generates a signed URL for a user's profile picture from their user ID.
    It returns a default image URL if the picture does not exist or an error occurs.
    """
    try:
        # Construct the expected filename from the user ID
        profile_picture_filename = f"users/{user_id}/profile.jpg"
        
        # Get the blob object for the profile picture
        blob = bucket.blob(profile_picture_filename)
        
        # Check if the file actually exists in Firebase Storage
        if blob.exists():
            # If it exists, generate a signed URL
            return blob.generate_signed_url(timedelta(minutes=15), method='GET')
        else:
            # If the file does not exist, return the default image URL
            return url_for('static', filename='images/default_profile.png')
            
    except Exception as e:
        # Log any errors and return the default image URL as a failsafe
        logging.error(f"Error generating profile pic URL for user {user_id}: {e}")
        return url_for('static', filename='images/default_profile.png')


def get_cover_photo_url(cover_photo_filename_str):
    """Generates a public URL for a cover photo from Firebase Storage."""
    if not cover_photo_filename_str:
        return url_for('static', filename='images/no-photo-selected.png')
        
    try:
        # Use the correct variable name 'admin_storage'
        # The path should match how you saved it in the personal_details route.
        blob_path = cover_photo_filename_str 
        blob = bucket.blob(blob_path)
    
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
        user_uid = session.get('user')
        
        if not user_uid:
            flash("User authentication failed. Please log in again.", "error")
            return redirect(url_for('signup'))
            
        user_doc_ref = db.collection('users').document(user_uid)
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            flash("User data not found. Please log in again.", "error")
            logging.error(f"User document does not exist for UID: {user_uid}")
            return redirect(url_for('signup'))

        user_data = user_doc.to_dict()

        user_data['last_active'] = format_timestamp(user_data.get('last_active'))
        user_data['created_at'] = format_timestamp(user_data.get('created_at'))

        profile_pic_url = ""
        cover_photo_url = ""

        try:
            profile_blob = bucket.blob(f"users/{user_uid}/profile.jpg")
            if profile_blob.exists():
                profile_pic_url = profile_blob.generate_signed_url(
                    timedelta(minutes=15), method='GET'
                )
        except Exception as e:
            logging.error(f"Error generating profile pic URL for {user_uid}: {e}")
            flash(f"Error loading profile picture: {str(e)}", "error")

        try:
            cover_blob = bucket.blob(f"users/{user_uid}/cover.jpg")
            if cover_blob.exists():
                cover_photo_url = cover_blob.generate_signed_url(
                    timedelta(minutes=15), method='GET'
                )
        except Exception as e:
            logging.error(f"Error generating cover photo URL for {user_uid}: {e}")
            flash(f"Error loading cover photo: {str(e)}", "error")
            
        referral_link = f"https://schomart.onrender.com/signup?ref={user_uid}"

        # Fetch the referral count directly from the user_data dictionary
        referral_count = user_data.get('referral_count', 0)

        return render_template('profile.html',
                               user=user_data,
                               profile_pic_url=profile_pic_url,
                               cover_photo_url=cover_photo_url,
                               referral_link=referral_link,
                               referral_count=referral_count) # Pass the count to the template

    except Exception as e:
        logging.error(f"An unexpected error occurred in profile route: {e}", exc_info=True)
        flash(f"An unexpected error occurred: {str(e)}. Please try again.", "error")
        return redirect(url_for('signup'))







@app.route('/profile/personal', methods=['GET', 'POST'])
@login_required
def personal_details():
    """
    Handles displaying and updating a user's personal details.
    """
    try:
        user_uid = g.current_user.id
        
        user_doc_ref = db.collection('users').document(user_uid)
        user_doc = user_doc_ref.get()

        if not user_doc.exists:
            logging.error(f"User document does not exist for UID: {user_uid}")
            flash("User data not found. Please log in again.", "error")
            return redirect(url_for('signup'))

        user_data = user_doc.to_dict()

        # 🐛 THE FIX: Provide default empty values for missing fields
        # This prevents the 'UndefinedError' if a user document is missing these fields.
        user_data['working_times'] = user_data.get('working_times', {})
        user_data['working_days'] = user_data.get('working_days', [])
        user_data['social_links'] = user_data.get('social_links', {})

        if request.method == 'POST':
            # ... (rest of your POST logic remains unchanged)
            first_name = request.form.get('first_name', '')
            last_name = request.form.get('last_name', '')
            businessname = request.form.get('businessname', '')
            
            state = request.form.get('state', '')
            school = request.form.get('school', '')
            location = request.form.get('location', '')

            birthday = request.form.get('birthday', '')
            sex = request.form.get('sex', '')
            delivery_methods = request.form.getlist('delivery_methods')
            working_days_form = request.form.getlist('working_days') # Use a different variable name
            
            working_times_form = {}
            for day in ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']:
                if day in working_days_form:
                    working_times_form[day] = {
                        'open': request.form.get(f'{day}_open'),
                        'close': request.form.get(f'{day}_close')
                    }
            
            social_links_form = {
                'website': request.form.get('social_links[website]', ''),
                'instagram': request.form.get('social_links[instagram]', ''),
                'facebook': request.form.get('social_links[facebook]', ''),
                'linkedin': request.form.get('social_links[linkedin]', ''),
                'twitter': request.form.get('social_links[twitter]', '')
            }
            
            combined_location = ""
            if state and school and location:
                combined_location = f"{state} > {school} > {location}"
            elif state and school:
                combined_location = f"{state} > {school}"
            elif state and location:
                combined_location = f"{state} > {location}"
            elif state:
                combined_location = state
            
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
                'working_days': working_days_form,
                'working_times': working_times_form,
                'delivery_methods': delivery_methods,
                'social_links': social_links_form,
            }
            
            try:
                profile_picture_file = request.files.get('profile_picture')
                if profile_picture_file and profile_picture_file.filename and allowed_file(profile_picture_file.filename):
                    blob_path = f"users/{user_uid}/profile.jpg"
                    blob = bucket.blob(blob_path)
                    blob.upload_from_file(profile_picture_file, content_type=profile_picture_file.content_type)
                    update_data['profile_picture'] = blob_path
                
                cover_photo_file = request.files.get('cover_photo')
                if cover_photo_file and cover_photo_file.filename and allowed_file(cover_photo_file.filename):
                    blob_path_cover = f"users/{user_uid}/cover.jpg"
                    blob = bucket.blob(blob_path_cover)
                    blob.upload_from_file(cover_photo_file, content_type=cover_photo_file.content_type)
                    update_data['cover_photo'] = blob_path_cover

                user_doc_ref.update(update_data)
                flash('Profile updated successfully!', 'success')
                return redirect(url_for('personal_details'))
            except Exception as e:
                logging.error(f"Error updating user profile for UID {user_uid}: {e}", exc_info=True)
                flash(f'An error occurred while updating your profile: {e}', 'error')
                return redirect(url_for('personal_details'))

        # GET request handling
        profile_pic_url = ""
        cover_photo_url = ""
        
        try:
            profile_blob = bucket.blob(f"users/{user_uid}/profile.jpg")
            if profile_blob.exists():
                profile_pic_url = profile_blob.generate_signed_url(timedelta(minutes=15), method='GET')
        except Exception as e:
            logging.error(f"Error generating profile pic URL for {user_uid}: {e}")
            
        try:
            cover_blob = bucket.blob(f"users/{user_uid}/cover.jpg")
            if cover_blob.exists():
                cover_photo_url = cover_blob.generate_signed_url(timedelta(minutes=15), method='GET')
        except Exception as e:
            logging.error(f"Error generating cover photo URL for {user_uid}: {e}")

        user_data['profile_picture_url'] = profile_pic_url
        user_data['cover_photo_url'] = cover_photo_url
        
        NIGERIAN_STATES = list(NIGERIAN_SCHOOLS.keys())
        
        return render_template(
            'personal_details.html',
            user=user_data,
            NIGERIAN_STATES=NIGERIAN_STATES,
            NIGERIAN_SCHOOLS=NIGERIAN_SCHOOLS
        )

    except Exception as e:
        logging.error(f"An unexpected error occurred in personal details route: {e}", exc_info=True)
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
            blob = bucket.blob(blob_path)
            
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









def get_geo_info(ip_address):
    """Fetches geolocation data from a web-based API like ip-api.com."""
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}')
        response.raise_for_status() # Raises an HTTPError for bad responses
        data = response.json()
        if data['status'] == 'success':
            return {
                'city': data.get('city'),
                'state': data.get('regionName'),
                'country': data.get('country')
            }
        # Fallback for unsuccessful lookups
        return {'city': None, 'state': None, 'country': None}
    except requests.exceptions.RequestException as e:
        logger.error(f"Error fetching geo-IP data for IP {ip_address}: {e}")
        return {'city': None, 'state': None, 'country': None}






@app.route('/')
def home():
    """
    Renders the homepage, fetching and sorting adverts based on a new
    location-aware, user-preference-driven, and visibility-prioritized system.
    """
    try:
        # Get user IP and fetch location data using the new API method
        user_ip = request.environ.get('REMOTE_ADDR', '127.0.0.1')
        user_geo_info = get_geo_info(user_ip)
        user_city = user_geo_info.get('city')
        user_ip_state = user_geo_info.get('state')
        
        locations_data = {
            'NIGERIAN_STATES': NIGERIAN_STATES,
            'NIGERIAN_SCHOOLS': NIGERIAN_SCHOOLS
        }

        # Fetch Categories
        categories_ref = db.collection('categories').stream()
        categories_data = []
        for doc in categories_ref:
            category = doc.to_dict()
            category['id'] = doc.id
            image_filename = category.get('image_filename')
            image_url = 'https://placehold.co/100x100/e0e0e0/777777?text=No+Image'
            
            if image_filename:
                blob_path = f"static/category/{image_filename}"
                blob = bucket.blob(blob_path)
                if blob.exists():
                    image_url = blob.generate_signed_url(timedelta(minutes=15), method='GET')
            
            category['image_url'] = image_url
            categories_data.append(category)

        # Adverts Logic
        user_id = session.get('user')
        user_preferences = {'preferred_categories': [], 'state': None, 'school': None}
        if user_id:
            user_doc = get_user_info(user_id)
            if user_doc:
                user_preferences['state'] = user_doc.get('state')
                user_preferences['school'] = user_doc.get('school')
                user_preferences['preferred_categories'] = user_doc.get('preferred_categories', [])
                
        # Define visibility hierarchy with a numerical ranking
        visibility_order = {
            'Admin': 0,
            'Featured': 1,
            'Premium': 2,
            'Standard': 3,
        }
        
        adverts_ref = db.collection('adverts').where('status', '==', 'published').stream()
        all_published_adverts = []
        now = datetime.now(timezone.utc)

        for advert_doc in adverts_ref:
            advert_data = advert_doc.to_dict()
            advert_data['id'] = advert_doc.id
            
            published_at = advert_data.get('published_at')
            duration_days = advert_data.get('advert_duration_days', 0)
            
            if published_at:
                if not isinstance(published_at, datetime):
                    published_at = published_at.to_datetime().astimezone(timezone.utc)
                
                expiration_date = published_at + timedelta(days=duration_days)
                
                if expiration_date > now:
                    # Poster info is still needed for roles, but you'll get location directly.
                    poster_user_ref = db.collection('users').document(advert_data['user_id'])
                    poster_user_doc = poster_user_ref.get()
                    if poster_user_doc.exists:
                        poster_user_data = poster_user_doc.to_dict()
                        advert_data['poster_role'] = poster_user_data.get('role', 'standard')
                    else:
                        advert_data['poster_role'] = 'standard'
                    
                    main_image_url = advert_data.get('main_image')
                    if main_image_url:
                        advert_data['display_image'] = main_image_url
                    else:
                        advert_data['display_image'] = 'https://placehold.co/400x250/E0E0E0/333333?text=No+Image'
                    
                    all_published_adverts.append(advert_data)

        # Separate admin/featured ads and general ads
        admin_ads_for_display = sorted([
            ad for ad in all_published_adverts if ad.get('poster_role') == 'admin' or ad.get('featured')
        ], key=lambda ad: visibility_order.get(ad.get('visibility_level', 'Standard'), 99))
        
        regular_adverts = [
            ad for ad in all_published_adverts if not (ad.get('poster_role') == 'admin' or ad.get('featured'))
        ]

        def sort_relevance_score(ad):
            score = 0
            # Prioritize by user's IP location
            advert_state = ad.get('state', '').lower()
            advert_school = ad.get('school', '').lower()
            if user_ip_state and user_ip_state.lower() == advert_state:
                score += 500
            
            # Prioritize by user's saved state/school from their profile
            if user_preferences['state'] and user_preferences['state'].lower() == advert_state:
                score += 300
            if user_preferences['school'] and user_preferences['school'].lower() == advert_school:
                score += 200

            # Prioritize by user's preferred categories
            if ad.get('category') in user_preferences['preferred_categories']:
                score += 100
            
            # Add time decay (newer posts get a higher score)
            published_at = ad.get('published_at', datetime.min)
            time_decay_factor = (now - published_at).total_seconds() / 3600 # Score reduces by 1 for each hour
            score -= time_decay_factor
            
            return score

        # Sort all regular adverts by relevance score
        sorted_by_relevance = sorted(regular_adverts, key=sort_relevance_score, reverse=True)
        
        # Merge the lists, giving admin/featured ads top priority
        final_adverts_list = admin_ads_for_display + sorted_by_relevance

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







SUBSCRIPTION_PLANS = {
    "starter": {"plan_name": "starter", "cost_naira": 500, "advert_duration_days": 7, "visibility_level": "Standard"},
    "basic": {"plan_name": "basic", "cost_naira": 1000, "advert_duration_days": 14, "visibility_level": "Standard"},
    "premium": {"plan_name": "premium", "cost_naira": 1500, "advert_duration_days": 30, "visibility_level": "Featured"},
    "small_business": {"plan_name": "small_business", "cost_naira": 3000, "advert_duration_days": 30, "visibility_level": "Featured"},
    "medium_business": {"plan_name": "medium_business", "cost_naira": 5000, "advert_duration_days": 60, "visibility_level": "Featured"},
    "large_business": {"plan_name": "large_business", "cost_naira": 8000, "advert_duration_days": 90, "visibility_level": "Premium"},
    "enterprise": {"plan_name": "enterprise", "cost_naira": 10000, "advert_duration_days": 180, "visibility_level": "Premium"},
        }





# One-time free advert plan
FREE_ADVERT_PLAN = {
    "plan_name": "free", "cost_naira": None, "advert_duration_days": 7, "max_adverts": 1, "visibility_level": "Standard"
}



# Referral plans
REFERRAL_PLANS = {
    5: {"plan_name": "referral 5", "cost_naira": None, "advert_duration_days": 30, "visibility_level": "Featured"},
    10: {"plan_name": "referral 10", "cost_naira": None, "advert_duration_days": 60, "visibility_level": "Featured"},
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



# The correct way to count documents in Firestore
def get_advert_count(user_id):
    try:
        # Use a server-side aggregation query for an accurate count
        aggregate_query = db.collection('adverts').where('user_id', '==', user_id).count()
        results = aggregate_query.get()
        return results[0][0].value
    except Exception as e:
        logger.error(f"Error getting advert count for user {user_id}: {e}")
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

def get_school_name(school_id):
    """Fetches the name of a school from its ID."""
    if not school_id:
        return 'N/A'
    
    school_ref = db.collection('schools').document(school_id)
    school_doc = school_ref.get()

    if school_doc.exists:
        return school_doc.to_dict().get('name', 'Unknown School')
    else:
        return 'Unknown School'

# Place this helper function in your app.py or helpers.py file
def get_school_by_state(state_name):
    """
    Returns a list of schools for a given state from the NIGERIAN_SCHOOLS dictionary.
    """
    return NIGERIAN_SCHOOLS.get(state_name, [])


# Add this function to your helpers.py file.
def is_advert_saved_by_user(user_id, advert_id):
    """
    Checks if a specific advert has been saved by a user.
    
    Args:
        user_id (str): The ID of the current user.
        advert_id (str): The ID of the advert to check.
    
    Returns:
        bool: True if the advert is saved by the user, False otherwise.
    """
    if not user_id or not advert_id:
        return False
        
    try:
        user_doc_ref = db.collection('users').document(user_id)
        saved_adverts_list = user_doc_ref.get().to_dict().get('saved_adverts', [])
        
        return advert_id in saved_adverts_list
        
    except Exception as e:
        logging.error(f"Error checking if advert {advert_id} is saved by user {user_id}: {e}", exc_info=True)
        return False




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


def upload_file_to_firebase(file, folder):
    """
    Uploads a file to Firebase Storage.
    Returns the public URL of the uploaded file on success, None otherwise.
    """
    if not file or not file.filename:
        return None

    filename = secure_filename(file.filename)
    extension = os.path.splitext(filename)[1]
    unique_filename = f"{uuid.uuid4().hex}{extension}" # Use .hex for a cleaner filename
    destination_path = f"{folder}/{unique_filename}"

    try:
        # Reset the file pointer to the beginning before uploading
        file.seek(0)
        
        blob = storage.bucket().blob(destination_path)
        blob.upload_from_file(file, content_type=file.content_type)
        blob.make_public()
        return blob.public_url
    except Exception as e:
        logging.error(f"Failed to upload file to Firebase Storage: {e}")
        return None





def handle_file_uploads(files, user_id, advert_data):
    """
    Handles file uploads for a new or existing advert.

    Args:
        files: The Werkzeug FileStorage dictionary from request.files.
        user_id: The ID of the current user.
        advert_data: The existing advert data (for reposting) or an empty dict.

    Returns:
        A tuple containing (main_image_url, additional_images_urls, video_url)
    """
    main_image_url = None
    additional_images_urls = []
    video_url = None

    # Handle Main Image Upload
    main_image_file = files.get('main_image')
    if main_image_file and main_image_file.filename != '':
        main_image_url = upload_file_to_firebase(main_image_file, f"adverts/{user_id}/images")
        if not main_image_url:
            raise Exception("Main image upload failed.")
    elif 'main_image' in advert_data:
        # If no new main image is uploaded, keep the existing one from advert_data
        main_image_url = advert_data.get('main_image')

    # Handle Additional Images Uploads
    additional_images_files = files.getlist('additional_images')
    if additional_images_files:
        for file in additional_images_files:
            if file and file.filename != '':
                url = upload_file_to_firebase(file, f"adverts/{user_id}/images")
                if url:
                    additional_images_urls.append(url)
    # If editing, you might want to merge with existing additional images
    # For a simple approach, we'll just use the newly uploaded ones.
    # To keep existing images, you'd need a more complex form that sends their URLs back.

    # Handle Video Upload
    video_file = files.get('video')
    if video_file and video_file.filename != '':
        video_url = upload_file_to_firebase(video_file, f"adverts/{user_id}/videos")
        if not video_url:
            raise Exception("Video upload failed.")
    elif 'video' in advert_data:
        # If no new video, keep the existing one
        video_url = advert_data.get('video')

    return main_image_url, additional_images_urls, video_url






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
    Checks if a specific advert has been saved by a user using a direct document lookup.
    """
    if not user_id or not advert_id:
        return False
    
    try:
        # Construct the document ID as we do in the unsave_advert route.
        doc_id = f"{user_id}_{advert_id}"
        
        # Get the document reference and check for its existence with a single operation.
        doc_ref = db.collection('saved_adverts').document(doc_id)
        return doc_ref.get().exists
        
    except Exception as e:
        logger.error(f"Error checking if advert {advert_id} is saved for user {user_id}: {e}", exc_info=True)
        return False




def get_subscription_plan(plan_type):
    return SUBSCRIPTION_PLANS.get(plan_type)



# Updated get_user_advert_options function to check user's referral count
def get_user_advert_options(user_id):
    options = []
    
    # Add paid subscription plans
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

    user_info = get_user_info(user_id)
    user_referral_count = user_info.get("referral_count", 0) # Assumes a new 'referral_count' field in user document
    
    # Check for referral-based options and add them if user is eligible
    for cost, plan_details in REFERRAL_PLANS.items():
        if user_referral_count >= cost:
            options.append({
                "type": f"referral_{cost}",
                "label": f"Referral Benefit: {plan_details['plan_name']} ({cost} referrals)",
                "plan_name": plan_details['plan_name'],
                "advert_duration_days": plan_details['advert_duration_days'],
                "visibility_level": plan_details['visibility_level'],
                "cost_description": f"{cost} Referrals"
            })

    # Add one-time free advert option last, if not yet used
    if not user_info.get("has_posted_free_ad", False):
        options.append({
            "type": "free_advert",
            "label": "Free Advert",
            "plan_name": FREE_ADVERT_PLAN["plan_name"],
            "advert_duration_days": FREE_ADVERT_PLAN["advert_duration_days"],
            "visibility_level": FREE_ADVERT_PLAN["visibility_level"],
            "cost_description": "One-time Free"
        })
            
    return options








def get_user_adverts_ids(user_id):
    """Helper function to get all advert IDs for a given user."""
    adverts_ref = db.collection('adverts').where('user_id', '==', user_id).stream()
    return [doc.id for doc in adverts_ref]


def get_media_type_from_extension(filename):
    """
    Determines the media type (image or video) from a filename's extension.
    It defaults to 'image' for any unrecognized file types.
    """
    if not isinstance(filename, str):
        # Fallback for non-string filenames
        return 'image'

    filename = filename.lower()
    
    # List of common video file extensions
    video_extensions = ['.mp4', '.mov', '.avi', '.mkv', '.webm', '.flv', '.wmv']

    ext = os.path.splitext(filename)[1]

    if ext in video_extensions:
        return 'video'
    else:
        # Treats all other file types, including images, as 'image'.
        return 'image'








def fetch_posts_for_display(category, search_query):
    """
    Fetches all searchable posts from Firestore for a given category.
    Includes the document ID in each post dictionary.
    """
    if db is None:
        return [], 0, "Database connection not established."

    try:
        posts_ref = db.collection('posts')
        posts_query = posts_ref.where('categories', 'array_contains', category).stream()
        
        all_posts = []
        for doc in posts_query:
            post_data = doc.to_dict()
            post_data['id'] = doc.id 
            all_posts.append(post_data)
        
        if search_query:
            search_query_lower = search_query.lower()
            filtered_posts = [
                post for post in all_posts
                if search_query_lower in post.get("title", "").lower() or
                   search_query_lower in post.get("content", "").lower()
            ]
        else:
            filtered_posts = all_posts
        
        filtered_posts.sort(key=lambda x: x.get('post_date', datetime.min), reverse=True)

        return filtered_posts, len(filtered_posts), None
    except Exception as e:
        logging.error(f"Error fetching posts: {e}", exc_info=True)
        return [], 0, str(e)

def fetch_single_post(post_id):
    """
    Fetches a single post from Firestore by its ID from the 'posts' collection.
    """
    if db is None:
        return None
    try:
        post_ref = db.collection("posts").document(post_id)
        doc = post_ref.get()
        if doc.exists:
            post_data = doc.to_dict()
            post_data['id'] = doc.id
            return post_data
    except Exception as e:
        app.logger.error(f"Error fetching post {post_id} from Firestore: {e}", exc_info=True)
    return None


def delete_media_from_firebase(media_url):
    """Deletes a file from Firebase Storage given its public URL."""
    try:
        # The URL contains a path, so we need to get the part after the bucket domain
        blob = bucket.blob(media_url.split(f"schomart-7a743.appspot.com/")[1])
        blob.delete()
        logging.info(f"Successfully deleted media at URL: {media_url}")
        return True
    except Exception as e:
        logging.error(f"Failed to delete media from Firebase Storage: {e}")
        return False






# Helper function to strictly determine media type as image or video
def get_media_type_from_extension(filename):
    """
    Strictly determines the media type (image or video) from a filename's extension.
    Returns None if the file is not an allowed image or video type.
    """
    if not isinstance(filename, str):
        return None

    filename = filename.lower()
    
    # List of allowed image and video file extensions
    allowed_image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
    allowed_video_extensions = ['.mp4', '.mov', '.avi', '.mkv', '.webm', '.flv', '.wmv']

    ext = os.path.splitext(filename)[1]

    if ext in allowed_image_extensions:
        return 'image'
    elif ext in allowed_video_extensions:
        return 'video'
    else:
        # Returns None for any file type that is not an image or video
        return None


def get_file_from_firebase(file_path):
    try:
        blob = bucket.blob(file_path)
        if not blob.exists():
            return None
        
        # Create a temporary file to store the downloaded content
        temp_dir = tempfile.gettempdir()
        temp_file_path = os.path.join(temp_dir, os.path.basename(file_path))
        blob.download_to_filename(temp_file_path)
        
        return temp_file_path
    except Exception as e:
        logging.error(f"Failed to get file from Firebase: {e}")
        return None

def get_all_materials(query=''):
    materials_ref = db.collection('study_materials')
    query_results = materials_ref.stream()
    
    materials_list = []
    for doc in query_results:
        material = doc.to_dict()
        material['id'] = doc.id
        # Simple server-side filtering for demonstration
        if not query or any(query.lower() in str(val).lower() for val in material.values()):
            materials_list.append(material)

    return materials_list

def get_material_by_id(material_id):
    material_doc = db.collection('study_materials').document(material_id).get()
    if material_doc.exists:
        material_data = material_doc.to_dict()
        material_data['id'] = material_doc.id
        return material_data
    return None




def delete_file_from_storage(file_url):
    """
    Deletes a file from Firebase Storage using its download URL.
    This function is reusable for images, videos, and any other file types.
    """
    try:
        # Extract the file path from the full download URL
        image_path = file_url.split('/o/')[1].split('?')[0]
        
        # Unquote the URL-encoded path to get the actual file path
        file_path = urllib.parse.unquote(image_path)
        
        # Get the blob and delete it
        blob = bucket.blob(file_path)
        blob.delete()
        print(f"File deleted successfully: {file_path}")
    except Exception as e:
        print(f"Error deleting file: {e}")






def delete_advert_and_data(advert_id):
    """
    Deletes an advert document from Firestore and all associated media files
    (main image, videos, and additional images) from Firebase Storage.
    """
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists:
        return False, "Advert not found."

    advert_data = advert_doc.to_dict()
    main_image_url = advert_data.get('image_url')
    video_url = advert_data.get('video_url')
    additional_images = advert_data.get('additional_images', [])

    # Delete the main image
    if main_image_url:
        delete_file_from_storage(main_image_url)

    # Delete the video
    if video_url:
        delete_file_from_storage(video_url)
    
    # Delete any additional images in the list
    for img_url in additional_images:
        delete_file_from_storage(img_url)

    # Finally, delete the Firestore document
    try:
        advert_ref.delete()
        return True, "Advert and associated data deleted successfully!"
    except Exception as e:
        return False, f"Error deleting advert from Firestore: {e}"





# Updated sell function with new validation and referral logic
@app.route('/sell', methods=['GET', 'POST'])
@app.route('/sell/<advert_id>', methods=['GET', 'POST'])
@login_required
def sell(advert_id=None):
    advert = None
    if advert_id:
        advert_doc_ref = db.collection("adverts").document(advert_id)
        advert_doc = advert_doc_ref.get()
        if advert_doc.exists:
            advert = advert_doc.to_dict()
    
    user_id = g.current_user.id
    user_data = get_user_info(user_id)
    available_options = get_user_advert_options(user_id)
    
    advert_data = {}
    form_data = {}

    if advert_id:
        if not advert or advert.get('user_id') != user_id:
            flash("Advert not found or you don't have permission to edit.", "error")
            return redirect(url_for('list_adverts'))
        
        advert_data = advert
        form_data = advert
        is_repost = True
    else:
        is_repost = False

    if request.method == 'POST':
        form_data = request.form.to_dict()
        files = request.files
        
        errors = []
        
        submitted_category = form_data.get('category')
        all_categories = get_all_categories()
        category_names = [cat.get('name') for cat in all_categories]
        if submitted_category and submitted_category not in category_names:
            errors.append("Please choose a valid Category from the suggested list.")
        
        submitted_state = form_data.get('state')
        if submitted_state and submitted_state not in NIGERIAN_STATES:
            errors.append("Please choose a valid State from the suggested list.")

        submitted_school = form_data.get('school')
        if submitted_state and submitted_school:
            schools_in_state = [school['name'] for school in NIGERIAN_SCHOOLS.get(submitted_state, [])]
            if submitted_school not in schools_in_state:
                errors.append("Please choose a valid School from the suggested list.")
                
        selected_option_key = form_data.get("posting_option")
        selected_option = None
        referral_cost_to_deduct = None

        if selected_option_key in SUBSCRIPTION_PLANS:
            selected_option = SUBSCRIPTION_PLANS.get(selected_option_key)
        elif selected_option_key == "free_advert":
            selected_option = FREE_ADVERT_PLAN
        elif selected_option_key and selected_option_key.startswith("referral_"):
            try:
                referral_cost_to_deduct = int(selected_option_key.split('_')[1])
                selected_option = REFERRAL_PLANS.get(referral_cost_to_deduct)
            except (ValueError, IndexError):
                pass
        
        if not selected_option:
            errors.append("Invalid advert plan selected or you are not eligible for this plan.")

        if errors:
            for error_msg in errors:
                flash(error_msg, 'error')
            
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
            
            category_name = form_data.get('category')
            category_id = get_category_id_from_name(category_name)

            # Get the new delivery option from the form
            delivery_option = form_data.get("delivery_option")
            
            advert_payload = {
                "user_id": user_id,
                "category_id": category_id,
                "title": form_data.get('title'),
                "description": form_data.get("description"),
                "price": float(form_data.get('price')),
                "negotiable": form_data.get("negotiable") == "Yes",
                "condition": form_data.get("condition"),
                "delivery_option": delivery_option,  # Add the new field here
                "state": form_data.get('state'),
                "school": form_data.get('school'),
                "specific_location": form_data.get("specific_location"),
                "main_image": main_image_url,
                "additional_images": additional_images_urls,
                "video": video_url,
                "plan_name": selected_option.get("plan_name"),
                "advert_duration_days": selected_option.get("advert_duration_days"),
                "visibility_level": selected_option.get("visibility_level"),
                "created_at": firestore.SERVER_TIMESTAMP,
                "referral_cost": referral_cost_to_deduct,  # Save the cost to the advert doc
            }
            
            is_subscription = selected_option.get('cost_naira') is not None
            
            if is_subscription:
                advert_payload["status"] = "pending_payment"
                new_advert_ref = db.collection("adverts").document()
                new_advert_ref.set(advert_payload)
                advert_id_for_payment = new_advert_ref.id
                
                flash("Your advert has been created. Please complete the payment.", "info")
                return redirect(url_for('payment', advert_id=advert_id_for_payment))
            else:
                advert_payload["status"] = "pending_review"
                
                if advert_id:
                    db.collection("adverts").document(advert_id).update(advert_payload)
                    flash("Your advert has been successfully updated and submitted for review.", "success")
                else:
                    new_advert_ref = db.collection("adverts").document()
                    new_advert_ref.set(advert_payload)
                    flash("Your advert has been submitted for review.", "success")
                    
                # New Logic: Deduct points for referral-based posts
                if selected_option_key.startswith("referral_"):
                    cost = int(selected_option_key.split('_')[1])
                    user_ref = db.collection("users").document(user_id)
                    user_ref.update({
                        "referral_count": firestore.Increment(-cost)
                    })
                # Old Logic: Flag one-time free advert as used
                elif selected_option_key == "free_advert":
                    db.collection("users").document(user_id).update({"has_posted_free_ad": True})

                
                return redirect(url_for('list_adverts'))
        
        except Exception as e:
            logger.error(f"Error during advert submission for user {user_id}: {e}", exc_info=True)
            flash("An unexpected error occurred. Please try again.", "error")
            return redirect(url_for('sell'))

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


# Updated /submit-advert/<advert_id> route
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

    # Get the plan_type from the advert
    plan_type = advert.get('plan_name')
    plan_details = None

    # Correctly check all three dictionaries for the selected plan
    if plan_type in SUBSCRIPTION_PLANS:
        plan_details = SUBSCRIPTION_PLANS.get(plan_type)
    elif plan_type == "free_advert":
        plan_details = FREE_ADVERT_PLAN
    elif plan_type.startswith("referral_"):
        try:
            cost = int(plan_type.split('_')[1])
            plan_details = REFERRAL_PLANS.get(cost)
        except (ValueError, IndexError):
            pass

    if not plan_details:
        flash("Invalid subscription plan details.", "error")
        return redirect(url_for('list_adverts'))

    duration_days = plan_details.get("advert_duration_days", 0)
    
    # It's better to calculate the expiry date at the time of admin publishing.
    # We will remove 'expires_at' and 'published_at' from here.
    # The admin review route will set these values once the advert is manually approved.

    db.collection("adverts").document(advert_id).update({
        # Only update the status to 'pending_review'
        "status": "pending_review",
    })
    
    flash("Your advert has been submitted for review. Thank you for your payment!", "success")
    return redirect(url_for('list_adverts'))











# Updated list_adverts function
@app.route('/adverts')
@login_required
def list_adverts():
    """
    Renders the list of a user's adverts, handling status updates and expiration,
    and sorting them for display.
    """
    user_id = g.current_user.id
    adverts_ref = db.collection('adverts').where('user_id', '==', user_id).stream()
    adverts = []
    
    # Get a list of advert IDs to process for deletion
    adverts_to_delete = []

    for doc in adverts_ref:
        advert_data = doc.to_dict()
        advert_data['id'] = doc.id
        
        status = advert_data.get('status', 'pending_review')
        
        # Check for expiration if the advert is published
        if status == 'published' and advert_data.get('published_at'):
            plan_name = advert_data.get('plan_name')
            plan_details = SUBSCRIPTION_PLANS.get(plan_name)
            
            if plan_details:
                duration_days = plan_details.get('advert_duration_days', 0)
                published_at = advert_data['published_at']
                
                # Convert to datetime object if it's a Firestore Timestamp
                if not isinstance(published_at, datetime):
                    published_at = published_at.to_datetime().astimezone(timezone.utc)
                
                # Use timedelta correctly with timezone-aware datetimes
                expiration_date = published_at + timedelta(days=duration_days)
                now = datetime.now(timezone.utc)
                
                if now > expiration_date:
                    # Update status to 'expired' in Firestore
                    doc.reference.update({'status': 'expired', 'expired_at': firestore.SERVER_TIMESTAMP})
                    status = 'expired'
        
        # Check if the advert is expired and passed the 2-day grace period
        if status == 'expired' and advert_data.get('expired_at'):
            expired_at = advert_data['expired_at']
            
            # Convert to datetime object if it's a Firestore Timestamp
            if not isinstance(expired_at, datetime):
                expired_at = expired_at.to_datetime().astimezone(timezone.utc)

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
        
        # NOTE: We remove the manual location combination. The template will now
        # access advert_data.get('state'), advert_data.get('school'), and
        # advert_data.get('specific_location') directly.
        
        # Format 'created_at' for display
        created_at = advert_data.get('created_at')
        if created_at and isinstance(created_at, datetime):
            advert_data['created_at'] = created_at.strftime('%Y-%m-%d %H:%M')
        elif created_at:
            advert_data['created_at'] = created_at.to_datetime().strftime('%Y-%m-%d %H:%M')
        else:
            advert_data['created_at'] = 'N/A'
            
        adverts.append(advert_data)
    
    # Process the batch deletion of expired adverts
    for advert_id in adverts_to_delete:
        delete_advert_and_data(advert_id)
    
    # Sort the adverts list for display
    def sort_key(advert):
        status_order = {
            'rejected': 0,
            'pending_payment': 1,
            'pending_review': 2,
            'published': 3,
            'expired': 4,
        }
        return status_order.get(advert.get('status'), 99)

    adverts.sort(key=sort_key)
    
    return render_template("list_adverts.html", adverts=adverts)






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




# The delete route
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
@login_required
@admin_required
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

        # This part of the code correctly handles the duration and expiry
        duration_days = advert.get("advert_duration_days")
        if duration_days and advert.get("created_at"):
            advert['calculated_expiry'] = datetime.now() + timedelta(days=duration_days)
        else:
            advert['calculated_expiry'] = None

        # -----------------------------------------------------------------
        # The key correction is here
        # Retrieve the main image using the consistent key 'main_image'
        main_image_url = advert.get('main_image')
        # -----------------------------------------------------------------
  
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
    Decrements the user's referral count only if the advert plan is 'referral_benefits'.
    """
    advert_id = request.form.get('advert_id')
    if not advert_id:
        flash("Advert ID not found.", 'error')
        return redirect(url_for('admin_advert_review'))

    advert_ref = db.collection("adverts").document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists:
        flash("Advert not found.", 'error')
        return redirect(url_for('admin_advert_review'))

    advert_data = advert_doc.to_dict()
    user_id = advert_data.get('user_id')
    
    # Get the plan_name from the advert data
    plan_name = advert_data.get('plan_name')

    if not user_id:
        flash("User ID not found for this advert.", 'error')
        return redirect(url_for('admin_advert_review'))

    user_ref = db.collection("users").document(user_id)
    user_doc = user_ref.get()

    if user_doc.exists:
        # Update the advert's status and publication date regardless of the plan
        advert_ref.update({
            'status': 'published',
            'published_at': firestore.SERVER_TIMESTAMP,
            'is_published': True
        })

        # Check if the advert was submitted using referral benefits
        if plan_name == 'referral_benefits':
            user_data = user_doc.to_dict()
            current_referral_count = user_data.get('referral_count', 0)

            # Check if the user has a positive referral count
            if current_referral_count > 0:
                # Atomically decrement the referral count
                user_ref.update({'referral_count': firestore.firestore.Increment(-1)})
                flash("Advert approved and published successfully. Referral count decremented.", 'success')
            else:
                # This case should ideally not happen if client-side validation is correct, but it's a good fallback
                flash("User does not have enough referral points. Advert published but referral count not decremented.", 'warning')
        else:
            # For paid or one-time free plans, just publish without decrementing the referral count
            flash("Advert approved and published successfully.", 'success')

    else:
        flash("User not found.", 'error')

    return redirect(url_for('admin_advert_review'))







@app.route('/admin/adverts/reject', methods=['POST'])
@login_required
@admin_required
def admin_advert_reject():
    """
    Handles the rejection of an advert, deletes its associated files (main image, videos,
    and additional images), and updates the advert's status.
    """
    advert_id = request.form.get('advert_id')
    rejection_reason = request.form.get('rejection_reason', 'No reason provided.')

    if not advert_id:
        return redirect(url_for('admin_advert_review'))

    advert_ref = db.collection("adverts").document(advert_id)
    advert_doc = advert_ref.get()

    if advert_doc.exists:
        advert_data = advert_doc.to_dict()
        main_image_url = advert_data.get('image_url')
        video_url = advert_data.get('video_url')
        additional_images = advert_data.get('additional_images', [])

        # Delete the main image
        if main_image_url:
            delete_file_from_storage(main_image_url)

        # Delete the video
        if video_url:
            delete_file_from_storage(video_url)
        
        # Delete any additional images in the list
        for img_url in additional_images:
            delete_file_from_storage(img_url)

        # Update the advert's status in Firestore
        advert_ref.update({
            'status': 'rejected',
            'rejection_reason': rejection_reason,
            'is_published': False
        })
        
    return redirect(url_for('admin_advert_review'))

















@app.route('/admin/action/mark_resolved/<report_id>', methods=['POST'])
@login_required
@admin_required
def mark_report_resolved(report_id):
    """Admin action to mark a report as resolved."""
    report_ref = db.collection('reports').document(report_id)
    report_doc = report_ref.get()

    if not report_doc.exists:
        return jsonify({"message": "Report not found."}), 404

    try:
        report_ref.update({
            'status': 'resolved',
            'resolved_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Report marked as resolved successfully!"}), 200
    except Exception as e:
        logging.error(f"Error marking report {report_id} as resolved: {e}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/admin/action/suspend_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def suspend_user_account(user_id):
    """Admin action to suspend a user's account."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({"message": "User not found."}), 404
        
    try:
        user_ref.update({
            'is_active': False,
            'account_status': 'suspended'
        })
        return jsonify({"message": "User account suspended successfully!"}), 200
    except Exception as e:
        logging.error(f"Error suspending user {user_id}: {e}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500

@app.route('/admin/action/take_down_advert/<advert_id>', methods=['POST'])
@login_required
@admin_required
def take_down_advert(advert_id):
    """Admin action to take down an advert."""
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists:
        return jsonify({"message": "Advert not found."}), 404

    try:
        advert_ref.update({
            'status': 'taken_down',
            'taken_down_at': firestore.SERVER_TIMESTAMP
        })
        return jsonify({"message": "Advert taken down successfully!"}), 200
    except Exception as e:
        logging.error(f"Error taking down advert {advert_id}: {e}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500




@app.route('/admin/action/dismiss_report/<advert_id>', methods=['POST'])
@login_required
@admin_required
def dismiss_report(advert_id):
    """Admin action to dismiss all reports for an advert."""
    advert_ref = db.collection('adverts').document(advert_id)
    advert_doc = advert_ref.get()

    if not advert_doc.exists:
        return jsonify({"message": "Advert not found."}), 404
        
    try:
        # Change the advert's status from 'reported' back to 'published'
        advert_ref.update({
            'status': 'published'
        })
        return jsonify({"message": "Advert reports dismissed successfully!"}), 200
    except Exception as e:
        logging.error(f"Error dismissing report for advert {advert_id}: {e}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500



@app.route('/admin/action/enable_user/<user_id>', methods=['POST'])
@login_required
@admin_required
def enable_user_account(user_id):
    """Admin action to enable a user's account."""
    user_ref = db.collection('users').document(user_id)
    user_doc = user_ref.get()

    if not user_doc.exists:
        return jsonify({"message": "User not found."}), 404
        
    try:
        user_ref.update({
            'is_active': True,
            'account_status': 'active'
        })
        return jsonify({"message": "User account enabled successfully!"}), 200
    except Exception as e:
        logging.error(f"Error enabling user {user_id}: {e}", exc_info=True)
        return jsonify({"message": f"An unexpected error occurred: {str(e)}"}), 500




@app.route('/admin/reported_adverts')
@login_required
@admin_required
def admin_reported_adverts():
    """
    Admin route to list and manage reported adverts by status.
    """
    reported_adverts = []
    try:
        # Query adverts where the status is 'reported'
        adverts_query = db.collection('adverts').where('status', '==', 'reported').stream()

        for advert_doc in adverts_query:
            advert_data = advert_doc.to_dict()
            advert_data['id'] = advert_doc.id

            # Fetch the reports sub-collection for this advert
            reports_query = db.collection('adverts').document(advert_doc.id).collection('reports').stream()
            advert_data['reports'] = [report.to_dict() for report in reports_query]
            
            # Use a variable for seller_id to avoid multiple calls
            seller_id = advert_data.get('seller_id')
            
            if seller_id:
                seller_doc = db.collection('users').document(seller_id).get()
                advert_data['seller_username'] = seller_doc.to_dict().get('username', 'N/A') if seller_doc.exists else 'N/A'
                advert_data['seller_email'] = seller_doc.to_dict().get('email', 'N/A') if seller_doc.exists else 'N/A'
            else:
                # Handle the case where seller_id is missing or empty
                advert_data['seller_username'] = 'Unknown'
                advert_data['seller_email'] = 'Unknown'

            # ... (rest of your data fetching code for category, plan, etc.)
            
            reported_adverts.append(advert_data)

    except Exception as e:
        logging.error(f"An unexpected error occurred in reported_adverts_admin route: {e}", exc_info=True)
        flash("An error occurred while fetching reported adverts.", "error")
        return redirect(url_for('admin_dashboard'))

    return render_template('admin_reported_adverts.html', reported_adverts=reported_adverts)









@app.route('/report_advert/<string:advert_id>', methods=['POST'])
@login_required
def report_advert(advert_id):
    """
    Handles a user reporting an advert by adding a report and updating the advert's status.
    """
    try:
        reporter_uid = g.current_user.id
        reason = request.form.get('reason', 'No reason provided')
        
        advert_ref = db.collection('adverts').document(advert_id)
        
        # Add the detailed report to a sub-collection
        report_data = {
            'reporter_id': reporter_uid,
            'reporter_email': g.current_user.email,
            'reason': reason,
            'reported_at': datetime.utcnow()
        }
        db.collection('adverts').document(advert_id).collection('reports').add(report_data)
        
        # Update the advert's status to 'reported'
        advert_ref.update({'status': 'reported'})
        
        flash("Report submitted.", 'success')
    except Exception as e:
        logging.error(f"Error submitting report for advert {advert_id}: {e}", exc_info=True)
        flash(f"An error occurred while submitting your report. Please try again.", "danger")
    
    return redirect(request.referrer)





@app.route('/submit_review', methods=['POST'])
@login_required
def submit_review():
    """
    Handles the submission of a new review for an advert.
    """
    try:
        # Get data from the form
        advert_id = request.form.get('advert_id')
        rating_str = request.form.get('rating')
        comment = request.form.get('comment')
        reviewee_id = request.form.get('reviewee_id')

        # This check is crucial to prevent the BuildError
        if not advert_id:
            flash('Advert ID is missing. Cannot submit review.', 'error')
            return redirect(url_for('some_default_page')) # Redirect to a safe page

        # Basic input validation
        if not all([rating_str, comment, reviewee_id]):
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









# --- Admin Function to Post New Airtime ---
@app.route('/admin/post_airtime', methods=['GET', 'POST'])
@login_required  # This decorator runs first, ensuring g.current_user exists.
@admin_required  # This decorator runs second, ensuring the user is an admin.
def admin_post_airtime():
    if request.method == 'POST':
        try:
            # Get form data
            network = request.form.get('network')
            amount_raw = request.form.get('amount')
            digits = request.form.get('digits')
            instructions = request.form.get('instructions')
            duration_value = request.form.get('duration_value', type=int)
            duration_unit = request.form.get('duration_unit')

            # --- Input Validation and Cleaning ---
            if not all([network, amount_raw, duration_value, duration_unit]):
                flash('All required fields (network, amount, duration) must be filled.', 'error')
                return redirect(url_for('admin_post_airtime'))

            amount = None
            try:
                # Clean non-digit characters and convert to integer
                cleaned_amount = re.sub(r'[^\d]', '', amount_raw)
                amount = int(cleaned_amount)
            except ValueError:
                flash('Invalid amount format. Please enter numbers only.', 'error')
                return redirect(url_for('admin_post_airtime'))

            cleaned_digits = re.sub(r'[^\d\s]', '', digits) if digits else None

            if not cleaned_digits and not 'airtime_image' in request.files:
                flash("You must provide either the airtime digits or an image.", "error")
                return redirect(url_for('admin_post_airtime'))

            # --- Calculate expiry time ---
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
                flash('Invalid duration unit provided.', 'error')
                return redirect(url_for('admin_post_airtime'))

            # Handle image upload to Firebase Storage
            image_url = None
            if 'airtime_image' in request.files:
                file = request.files['airtime_image']
                if file and allowed_file(file.filename):
                    try:
                        filename = secure_filename(file.filename)
                        unique_filename = f"{uuid.uuid4()}_{filename}"
                        blob = bucket.blob(f"airtime_images/{unique_filename}")
                        blob.upload_from_file(file, content_type=file.content_type)
                        blob.make_public()
                        image_url = blob.public_url
                        logger.info(f"Image uploaded to: {image_url}")
                    except Exception as e:
                        flash(f"Error uploading image: {e}", "error")
                        logger.error(f"Image upload failed: {e}")
                        return redirect(url_for('admin_post_airtime'))

            # --- Save to Firestore ---
            airtime_post_data = {
                'network': network,
                'amount': amount,
                'digits': cleaned_digits,
                'instructions': instructions,
                'image_url': image_url,
                'created_at': firestore.SERVER_TIMESTAMP,
                'expires_at': expiry_time,
                # Corrected line: Use the 'id' attribute of the User object
                'posted_by': g.current_user.id 
            }
            db.collection('airtime_posts').add(airtime_post_data)

            flash('Airtime post created successfully!', 'success')
            return redirect(url_for('admin_post_airtime'))

        except Exception as e:
            # Generic error handling for unexpected issues
            flash(f"An unexpected error occurred: {e}", "error")
            logging.error(f"Admin post airtime error: {e}", exc_info=True)
            return redirect(url_for('admin_post_airtime'))

    # Render the template for GET requests
    return render_template('admin_post_airtime.html')




# --- API Route to Fetch Active Airtime Posts ---
@app.route('/api/airtime-posts', methods=['GET'])
def get_airtime_posts():
    """
    Fetches the single most recent active airtime post.
    Filters by expiry time and sorts by creation time to get the newest post.
    """
    try:
        # Use datetime.utcnow() to get the current time
        now = datetime.utcnow()
        
        # Use a Firestore query to get the single most recent active post.
        # This is more efficient as it performs the ordering on the server side.
        posts_ref = db.collection('airtime_posts')\
            .where(filter=firestore.FieldFilter('expires_at', '>', now))\
            .order_by('created_at', direction=firestore.Query.DESCENDING)\
            
        
        docs = posts_ref.stream()
        posts_data = []

        for doc in docs:
            post = doc.to_dict()
            post['id'] = doc.id
            post['digits'] = str(post.get('digits')) if post.get('digits') is not None else ''

            # Corrected: Check for the type in a way that avoids using the Timestamp class
            # This checks if the object looks like a Timestamp object by checking for its methods
            if 'created_at' in post and hasattr(post['created_at'], 'isoformat'):
                post['created_at'] = post['created_at'].isoformat()
            if 'expires_at' in post and hasattr(post['expires_at'], 'isoformat'):
                post['expires_at'] = post['expires_at'].isoformat()
                
            posts_data.append(post)

        if posts_data:
            return jsonify(posts_data)
        else:
            return jsonify([])

    except Exception as e:
        logger.error(f"Error fetching airtime posts: {e}", exc_info=True)
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
                logger.error(f"Error deleting image from storage for post {post_id}: {e}", exc_info=True)
                # Log the error but continue to delete the document to maintain data consistency

        # Delete the Firestore document
        post_ref.delete()
        logger.info(f"Deleted Firestore document: {post_id}")
        return jsonify({'message': 'Airtime post deleted successfully'}), 200
    
    except Exception as e:
        logger.error(f"Error deleting post {post_id}: {e}", exc_info=True)
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
        now = datetime.utcnow()
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
                    logger.error(f"Error deleting image for post {post_id}: {e}", exc_info=True)
            
            # Delete the Firestore document
            db.collection('airtime_posts').document(post_id).delete()
            deleted_count += 1
       
        flash(f'Successfully cleaned up {deleted_count} expired airtime posts.', 'success')
        return redirect(url_for('admin_post_airtime'))

    except Exception as e:
        logger.error(f"Error during expired post cleanup: {e}", exc_info=True)
        flash(f'An error occurred during cleanup: {str(e)}', 'error')
        return redirect(url_for('admin_post_airtime'))





    
#@app.route('/admin_users_management')
#@login_required
#@admin_required
#def admin_users_management():
#    return render_template('admin_users_management.html')



@app.route('/referral-benefit')
def referral_benefit():
    return render_template('referral_benefit.html')





# You will need to add this new function to your helpers.py file as well.
# This function is the one that fetches and sorts similar adverts.
def get_similar_adverts(category_id, school, state, exclude_id, limit=8):
    """
    Fetches a list of similar adverts based on a weighted criteria,
    then sorts them by visibility level.
    """
    similar_list = []
    seen_ids = {exclude_id}
    
    visibility_priority = {
        'admin': 4,
        'featured': 3,
        'premium': 2,
        'standard': 1,
    }

    query1 = db.collection('adverts').where('category_id', '==', category_id).where('school', '==', school).where('status', '==', 'published').limit(limit)
    for doc in query1.stream():
        if doc.id not in seen_ids:
            advert = doc.to_dict()
            advert['id'] = doc.id
            similar_list.append(advert)
            seen_ids.add(doc.id)
            if len(similar_list) >= limit:
                break

    if len(similar_list) < limit:
        query2 = db.collection('adverts').where('category_id', '==', category_id).where('state', '==', state).where('status', '==', 'published').limit(limit)
        for doc in query2.stream():
            if doc.id not in seen_ids:
                advert = doc.to_dict()
                advert['id'] = doc.id
                similar_list.append(advert)
                seen_ids.add(doc.id)
                if len(similar_list) >= limit:
                    break

    def sort_by_priority(ad):
        user_id = ad.get('user_id')
        user_doc = db.collection('users').document(user_id).get()
        user_role = user_doc.to_dict().get('role', 'standard') if user_doc.exists else 'standard'
        
        visibility_level = 'standard'
        if user_role == 'admin':
            visibility_level = 'admin'
        elif user_role == 'featured':
            visibility_level = 'featured'
        elif user_role == 'premium':
            visibility_level = 'premium'
        
        published_at = ad.get('published_at', datetime.fromtimestamp(0, tz=UTC))
        return (visibility_priority.get(visibility_level, 0), published_at)
    
    similar_list.sort(key=sort_by_priority, reverse=True)
    
    for advert in similar_list:
        main_image_url = advert.get('main_image')
        if main_image_url:
            advert['display_image'] = main_image_url
        else:
            advert['display_image'] = 'https://placehold.co/400x250/E0E0E0/333333?text=No+Image'

    return similar_list[:limit]









# New Helper Functions to find names from your existing data format
def get_state_name_from_list(state_name):
    """Safely retrieves a state name from the NIGERIAN_STATES list."""
    if state_name in NIGERIAN_STATES:
        return state_name
    return 'Unknown State'


# Updated helper function to handle case and missing acronyms
def get_school_name_from_dict(school_id):
    """
    Finds the full school name from a school ID by searching the nested 
    NIGERIAN_SCHOOLS dictionary, handling case-insensitivity.
    """
    if not school_id:
        return 'Unknown School'
    
    # Iterate through the lists of schools for each state
    for state_schools in NIGERIAN_SCHOOLS.values():
        for school in state_schools:
            # Check for both 'acronym' and 'name' for a match, handling case-insensitivity
            acronym = school.get('acronym', '').lower()
            name = school.get('name', '').lower()
            
            # The lookup key from your advert document
            advert_key = school_id.lower()
            
            # Check for a match on acronym or name
            if acronym == advert_key or name == advert_key:
                return school.get('name')
                
    return 'Unknown School'







# Updated advert_detail function
@app.route('/advert/<string:advert_id>')
@login_required
def advert_detail(advert_id):
    """
    Handles displaying a single advert detail page, fetches similar adverts,
    and increments view count for unique, non-owner users.
    """
    current_user_id = g.current_user.id if hasattr(g, 'current_user') and g.current_user else None

    try:
        advert_ref = db.collection('adverts').document(advert_id)
        advert_doc = advert_ref.get()

        if not advert_doc.exists:
            abort(404)
        
        advert = advert_doc.to_dict()
        advert['id'] = advert_doc.id
        advert_owner_id = advert.get('user_id')

        is_owner = current_user_id == advert_owner_id
        if advert.get('status') != 'published' and not is_owner:
            abort(404)
        
        # New Logic for View Counting
        # ... (Your existing view counting logic here) ...
        # Based on our previous discussion, the backend should be handling this correctly now.

        # The rest of your code remains the same...
        seller_doc = db.collection('users').document(advert_owner_id).get()
        seller = seller_doc.to_dict() if seller_doc.exists else {}
        seller['id'] = seller_doc.id
        seller['profile_picture'] = get_profile_picture_url(advert_owner_id)

        # Corrected Logic: Calculate the seller's overall rating and review count
        seller_reviews_query = db.collection('reviews').where('reviewee_id', '==', advert_owner_id).stream()
        total_seller_rating = 0
        seller_review_count = 0
        for review_doc in seller_reviews_query:
            review_data = review_doc.to_dict()
            total_seller_rating += review_data.get('rating', 0)
            seller_review_count += 1
            
        seller['rating'] = total_seller_rating / seller_review_count if seller_review_count > 0 else 0.0
        seller['review_count'] = seller_review_count

        advert['category_name'] = get_category_name(advert.get('category_id'))
        advert_state = advert.get('state')
        advert_school = advert.get('school')
        
        advert['state_name'] = get_state_name_from_list(advert_state)
        advert['school_name'] = get_school_name_from_dict(advert_school)
        advert.setdefault('views_count', 0) # Ensure views_count is always present

        is_saved = False
        if current_user_id:
            is_saved = check_if_saved(current_user_id, advert_id)

        reviews_ref = db.collection('reviews').where('advert_id', '==', advert_id).order_by('created_at', direction=firestore.Query.DESCENDING).stream()
        reviews = []
        for review_doc in reviews_ref:
            review_data = review_doc.to_dict()
            reviewer_info = db.collection('users').document(review_data['user_id']).get()
            if reviewer_info.exists:
                reviewer_data = reviewer_info.to_dict()
                review_data['reviewer_username'] = reviewer_data.get('username', 'Anonymous')
                review_data['reviewer_profile_picture'] = get_profile_picture_url(review_data['user_id'])
            reviews.append(review_data)
        
        similar_adverts = get_similar_adverts(
            advert['category_id'], 
            advert['school'],
            advert['state'],
            advert_id,
            limit=8
        )

        return render_template(
            'advert_detail.html',
            advert=advert,
            seller=seller,
            reviews=reviews,
            is_saved=is_saved,
            current_user_id=current_user_id,
            is_owner=is_owner,
            similar_adverts=similar_adverts
        )

    except Exception as e:
        logging.error(f"Error fetching advert detail: {e}", exc_info=True)
        return abort(500)








































def get_advert_performance_data(user_id):
    """Fetches all performance data for a user's adverts."""
    advert_ids = get_user_adverts_ids(user_id)
    if not advert_ids:
        return {'views': [], 'saves': [], 'adverts': []}
        
    views_ref = db.collection('advert_views').where('advert_id', 'in', advert_ids).stream()
    views_data = [doc.to_dict() for doc in views_ref]

    saves_ref = db.collection('saved_adverts').where('advert_id', 'in', advert_ids).stream()
    saves_data = [doc.to_dict() for doc in saves_ref]
    
    adverts_ref = db.collection('adverts').where('user_id', '==', user_id).stream()
    adverts_data = {doc.id: doc.to_dict() for doc in adverts_ref}

    return {
        'views': views_data,
        'saves': saves_data,
        'adverts': adverts_data
    }

def aggregate_data_by_period(data_list, period):
    """Aggregates data based on the specified time period."""
    if not data_list:
        return []

    data_map = defaultdict(int)
    now = datetime.now()

    for item in data_list:
        # Use the correct timestamp field for aggregation
        timestamp = item.get('viewed_at') or item.get('saved_at')
        if not timestamp:
            continue

        dt_object = timestamp.cast(datetime)

        if period == 'hourly':
            # Aggregate by hour for the last 24 hours
            if dt_object > now - timedelta(hours=24):
                key = dt_object.strftime('%H:00')
                data_map[key] += 1
        elif period == 'daily':
            # Aggregate by day for the last 30 days
            if dt_object > now - timedelta(days=30):
                key = dt_object.strftime('%Y-%m-%d')
                data_map[key] += 1
        elif period == 'monthly':
            # Aggregate by month for the last 12 months
            if dt_object > now - timedelta(days=365):
                key = dt_object.strftime('%Y-%m')
                data_map[key] += 1
        elif period == 'yearly':
            # Aggregate by year
            key = dt_object.strftime('%Y')
            data_map[key] += 1
    
    # Sort data chronologically
    sorted_data = sorted(data_map.items())
    return sorted_data

@app.route('/progress_chart')
@login_required
def progress_chart_page():
    """Renders the progress chart page."""
    return render_template('progress_chart.html')

@app.route('/api/user_progress')
@login_required
def api_user_progress():
    """
    API endpoint to serve the user's progress data.
    Accepts a 'period' query parameter (e.g., 'hourly', 'daily').
    """
    user_id = g.current_user.id
    period = request.args.get('period', 'daily') # Default to daily

    # Get all performance data for the user
    performance_data = get_advert_performance_data(user_id)
    
    # Aggregate data based on the requested period
    views_data = aggregate_data_by_period(performance_data['views'], period)
    saves_data = aggregate_data_by_period(performance_data['saves'], period)
    
    return jsonify({
        'views': views_data,
        'saves': saves_data,
        'adverts_info': list(performance_data['adverts'].values())
    })





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

        # Consistent Profile Picture logic: Uses the unified helper function
        seller_info['profile_picture_url'] = get_profile_picture_url(seller_id)
        
        # Original Cover Photo logic: Fetches the filename and attaches the URL
        cover_photo_filename = seller_info.get('cover_photo')
        seller_info['cover_photo_url'] = get_cover_photo_url(cover_photo_filename)
        
        # Robust Rating Calculation
        reviews_query = db.collection('reviews').where('reviewee_id', '==', seller_id).stream()
        total_rating = 0
        review_count = 0
        for review_doc in reviews_query:
            review_data = review_doc.to_dict()
            total_rating += review_data.get('rating', 0)
            review_count += 1
        
        seller_info['rating'] = total_rating / review_count if review_count > 0 else 0.0
        seller_info['review_count'] = review_count

        seller_phone = seller_info.get('phone_number')
        if seller_phone:
            seller_info['whatsapp_link'] = f"https://wa.me/{seller_phone}"

        if seller_info.get('created_at') and hasattr(seller_info['created_at'], 'to_datetime'):
            seller_info['created_at'] = seller_info['created_at'].strftime('%Y-%m-%d %H:%M')

        if current_user_id:
            followers_query = db.collection('followers').where('follower_id', '==', current_user_id).where('followed_id', '==', seller_id).limit(1)
            is_following = len(list(followers_query.stream())) > 0

        adverts_ref = db.collection('adverts').where('user_id', '==', seller_id).where('status', '==', 'published').order_by('created_at', direction=firestore.Query.DESCENDING)
        
        seller_adverts = []
        for advert_doc in adverts_ref.stream():
            advert = advert_doc.to_dict()
            advert['id'] = advert_doc.id
            
            main_image_url = advert.get('main_image')
            if main_image_url:
                advert['display_image'] = main_image_url
            else:
                advert['display_image'] = url_for('static', filename='images/default_advert_image.png')

            if advert.get('created_at') and hasattr(advert['created_at'], 'to_datetime'):
                advert['created_at'] = advert['created_at'].strftime('%Y-%m-%d %H:%M')
            if advert.get('expires_at') and hasattr(advert['expires_at'], 'to_datetime'):
                advert['expires_at'] = advert['expires_at'].strftime('%Y-%m-%d %H:%M')

            advert_url = url_for('advert_detail', advert_id=advert['id'], _external=True)
            pre_filled_message = f"Hello, I am interested in this advert from your profile: {advert_url}"
            if seller_phone:
                advert['whatsapp_link_with_message'] = f"https://wa.me/{seller_phone}?text={quote(pre_filled_message)}"
            else:
                advert['whatsapp_link_with_message'] = None
            
            seller_adverts.append(advert)

        return render_template('seller_profile_view.html',
                               seller=seller_info,
                               adverts=seller_adverts,
                               is_following=is_following,
                               current_user_id=current_user_id)
    except Exception as e:
        logging.error(f"Unexpected error in seller_profile_view for user {seller_id}: {e}", exc_info=True)
        flash("An unexpected error occurred while loading the seller's profile. Please try again later.", "error")
        return redirect(url_for('home'))







@app.route('/saved_adverts')
@login_required
def saved_adverts_page():
    """
    Displays a list of adverts saved by the current user.
    """
    user_id = g.current_user.id
    saved_adverts_list = []

    try:
        # Step 1: Get the list of saved advert IDs for the current user
        saved_ref = db.collection('saved_adverts').where('user_id', '==', user_id).stream()
        saved_advert_ids = [doc.to_dict()['advert_id'] for doc in saved_ref]
        
        # Step 2: If there are saved IDs, fetch the full advert details
        if saved_advert_ids:
            for advert_id in saved_advert_ids:
                advert_doc = db.collection('adverts').document(advert_id).get()
                if advert_doc.exists:
                    advert_data = advert_doc.to_dict()
                    advert_data['id'] = advert_doc.id
                    # Ensure the correct image URL is used for display
                    if 'main_image' in advert_data:
                        advert_data['display_image'] = advert_data['main_image']
                    else:
                        advert_data['display_image'] = url_for('static', filename='images/default_advert_image.png')
                    saved_adverts_list.append(advert_data)

    except Exception as e:
        logger.error(f"Error fetching saved adverts for user {user_id}: {e}", exc_info=True)
        flash("An error occurred while loading your saved adverts.", "error")

    return render_template('saved_adverts.html', saved_adverts=saved_adverts_list)





# Updated unsave_advert route to correctly find and delete the document
@app.route('/api/unsave_advert', methods=['POST'])
@login_required
def unsave_advert():
    """Removes an advert from the user's saved list."""
    data = request.get_json()
    advert_id = data.get('advert_id')
    user_id = g.current_user.id

    if not advert_id:
        return jsonify({'success': False, 'message': 'Advert ID is required.'}), 400

    try:
        # Step 1: Find the document in the 'saved_adverts' collection
        # that matches both the user ID and the advert ID.
        query = db.collection('saved_adverts').where('user_id', '==', user_id).where('advert_id', '==', advert_id).limit(1).stream()
        
        # Convert the query results to a list to check if a document was found.
        docs_to_delete = list(query)
        
        if docs_to_delete:
            # Step 2: If a document is found, delete it using its actual ID.
            doc_to_delete = docs_to_delete[0]
            doc_to_delete.reference.delete()
            return jsonify({'success': True, 'message': 'Advert successfully removed from saved list.'}), 200
        else:
            # The document was not found, which is not an error, but indicates it's already unsaved.
            return jsonify({'success': False, 'message': 'Advert not found in saved list.'}), 404
            
    except Exception as e:
        logger.error(f"Error unsaving advert for user {user_id} and advert {advert_id}: {e}", exc_info=True)
        return jsonify({'success': False, 'message': 'An internal server error occurred.'}), 500


# Minor change for better clarity in the save_advert route.
@app.route('/api/save_advert', methods=['POST'])
@login_required
def save_advert():
    """Saves an advert to the user's saved list."""
    user_id = g.current_user.id
    data = request.get_json()
    advert_id = data.get('advert_id')

    if not advert_id:
        return jsonify({"success": False, "message": "Advert ID is required."}), 400

    try:
        # Check if the advert is already saved to prevent duplicates
        saved_advert_query = db.collection('saved_adverts').where('user_id', '==', user_id).where('advert_id', '==', advert_id).limit(1).stream()
        
        if any(saved_advert_query): # Use any() with a generator for efficiency
            return jsonify({"success": True, "message": "Advert is already saved."}), 200

        db.collection('saved_adverts').add({
            'user_id': user_id,
            'advert_id': advert_id,
            'saved_at': firestore.SERVER_TIMESTAMP
        })

        return jsonify({"success": True, "message": "Advert saved successfully."}), 200

    except Exception as e:
        logger.error(f"Error saving advert for user {user_id}: {e}", exc_info=True)
        return jsonify({"success": False, "message": "An error occurred."}), 500



@app.route('/subscribe', methods=['GET', 'POST'])
def subscribe():
     
    return render_template('subscribe.html')







@app.route('/search')
@login_required
def search():
    """Renders the search page with filters but no initial advert display."""
    search_query = request.args.get('search_query', '')
    category = request.args.get('category', '')
    state = request.args.get('state', '')
    school = request.args.get('school', '')
    location = request.args.get('location', '')
    price_min = request.args.get('price_min')
    price_max = request.args.get('price_max')
    condition = request.args.get('condition', '')
    negotiation = request.args.get('negotiation', '')
    delivery = request.args.get('delivery', '') # ADDED

    locations_data = {
        'NIGERIAN_STATES': NIGERIAN_STATES,
        'NIGERIAN_SCHOOLS': NIGERIAN_SCHOOLS
    }

    categories_ref = db.collection('categories').stream()
    categories_data = {doc.id: doc.to_dict() for doc in categories_ref}

    schools_in_state = []
    # Fetch schools only if a state has been selected
    if state:
        schools_in_state = get_school_by_state(state)

    return render_template(
        'search.html',
        locations=locations_data,
        categories=categories_data,
        states=NIGERIAN_STATES,
        search_query=search_query,
        selected_category=category,
        selected_state=state,
        selected_school=school,
        selected_location=location,
        price_min=price_min,
        price_max=price_max,
        selected_condition=condition,
        selected_negotiation=negotiation,
        selected_delivery=delivery, # ADDED
        schools_in_state=schools_in_state
    )

@app.route('/api/search_adverts')
def api_search_adverts():
    """API endpoint to fetch adverts based on search filters and pagination."""
    search_query = request.args.get('search_query', '')
    category = request.args.get('category', '')
    state = request.args.get('state', '')
    school = request.args.get('school', '')
    location = request.args.get('location', '')
    price_min = request.args.get('price_min')
    price_max = request.args.get('price_max')
    condition = request.args.get('condition', '')
    negotiation = request.args.get('negotiation', '')
    delivery = request.args.get('delivery', '') # ADDED
    page = int(request.args.get('page', 1))

    adverts = fetch_and_filter_adverts(
        search_query=search_query,
        category=category,
        state=state,
        school=school,
        location=location,
        price_min=price_min,
        price_max=price_max,
        condition=condition,
        negotiation=negotiation,
        delivery=delivery, # ADDED
        page=page
    )
    return jsonify(adverts)



# main.py
def fetch_and_filter_adverts(search_query, category, state, school, location, price_min, price_max, condition, negotiation, delivery, page, per_page=20):
    """
    Centralized function to query and filter adverts based on search parameters.
    """
    try:
        query_ref = db.collection('adverts').where('status', '==', 'published')

        # Apply Firestore filters for exact matches
        if category:
            query_ref = query_ref.where('category', '==', category)
        if state:
            query_ref = query_ref.where('state', '==', state)
        if school:
            query_ref = query_ref.where('school', '==', school)
        if condition:
            query_ref = query_ref.where('condition', '==', condition)
        if negotiation:
            query_ref = query_ref.where('negotiable', '==', negotiation == 'yes')
        
        # CORRECTED: Filter by the new delivery option strings
        if delivery:
            query_ref = query_ref.where('delivery_option', '==', delivery)
        
        # NOTE: Firestore does not support range queries on multiple fields.
        # This price filtering will continue to be done in Python.

        adverts = []
        now = datetime.now(timezone.utc)
        
        all_results_query = query_ref.order_by('published_at', direction='DESCENDING').stream()

        # Perform filtering and data processing in Python
        filtered_adverts = []
        for doc in all_results_query:
            advert_data = doc.to_dict()
            advert_data['id'] = doc.id
            
            # Apply price filter
            if price_min and advert_data.get('price', 0) < int(price_min):
                continue
            if price_max and advert_data.get('price', 0) > int(price_max):
                continue
            
            # Server-side keyword search and new precise location filtering
            combined_search_string = (
                f"{advert_data.get('title', '').lower()} "
                f"{advert_data.get('description', '').lower()} "
                f"{advert_data.get('location', '').lower()}"
            )
            
            if search_query:
                if search_query.lower() not in combined_search_string:
                    continue
            
            # Apply precise location filter
            if location and location.lower() not in advert_data.get('location', '').lower():
                continue

            # Expiration check
            published_at = advert_data.get('published_at')
            duration_days = advert_data.get('advert_duration_days', 0)
            if published_at:
                if not isinstance(published_at, datetime):
                    published_at = published_at.to_datetime().astimezone(timezone.utc)
                expiration_date = published_at + timedelta(days=duration_days)
                if expiration_date <= now:
                    continue

            # Fetch poster info and prepare data for display
            poster_user_doc = db.collection('users').document(advert_data['user_id']).get()
            if poster_user_doc.exists:
                poster_user_data = poster_user_doc.to_dict()
                advert_data['poster_username'] = poster_user_data.get('username')
                advert_data['poster_role'] = poster_user_data.get('role', 'standard')
            else:
                advert_data['poster_username'] = 'Unknown'
                advert_data['poster_role'] = 'standard'
            
            main_image_url = advert_data.get('main_image')
            if main_image_url:
                advert_data['display_image'] = main_image_url
            else:
                advert_data['display_image'] = 'https://placehold.co/400x250/E0E0E0/333333?text=No+Image'
            
            filtered_adverts.append(advert_data)

        # Implement simple pagination
        start_index = (page - 1) * per_page
        end_index = start_index + per_page
        paginated_adverts = filtered_adverts[start_index:end_index]
        
        return paginated_adverts

    except Exception as e:
        logging.error(f"Error fetching filtered adverts: {e}", exc_info=True)
        return []




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






# The fully updated route
@app.route("/admin/create_post", methods=["GET", "POST"])
@login_required
@admin_required
def create_post():
    """Handles the creation of new posts for the School News page."""
    user = g.current_user
    user_is_admin = getattr(user, 'is_admin', False)

    post_data = request.form.to_dict() if request.method == "POST" else {}
    if request.method == "POST":
        title = request.form.get("title")
        content = request.form.get("content")
        author_username = getattr(user, 'username', 'Unknown')
        submitted_external_link_url = request.form.get("link_url", "").strip()
        
        display_on = ["School News"] 
        
        if not title or not title.strip():
            flash("Please enter a title for your post.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        media_items_to_save = []
        try:
            media_files = request.files.getlist("media_files")
            for media_file in media_files:
                # The file handling now strictly checks for allowed types
                if media_file and media_file.filename != '':
                    filename_to_classify = str(media_file.filename or '')
                    media_type = get_media_type_from_extension(filename_to_classify)
                    
                    if media_type:
                        uploaded_url = upload_file_to_firebase(media_file, "posts")
                        if uploaded_url:
                            media_items_to_save.append({
                                "media_type": media_type, 
                                "media_path_or_url": uploaded_url,
                            })
                    else:
                        flash(f"File '{media_file.filename}' is not an allowed image or video format and was skipped.", "warning")
                        
        except Exception as e:
            flash(f"An error occurred during file upload: {e}", "error")
            logging.error(f"File upload error: {e}", exc_info=True)
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 500

        if submitted_external_link_url and not (submitted_external_link_url.startswith("http://") or submitted_external_link_url.startswith("https://")):
            flash("External link must start with http:// or https://", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400
            
        if not content.strip() and not media_items_to_save and not submitted_external_link_url:
            flash("Post must have content, uploaded media, or an external link.", "error")
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 400

        try:
            posts_ref = db.collection("posts")
            post_doc = {
                "title": title,
                "content": content,
                "categories": display_on,
                "author": author_username,
                "author_id": user.id,
                "post_date": datetime.now(),
                "external_link_url": submitted_external_link_url,
                "media_items": media_items_to_save,
            }

            posts_ref.add(post_doc)
            flash("Post created successfully!", "success")
            return redirect(url_for("school_news"))

        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
            logging.error(f"Error creating post: {e}", exc_info=True)
            return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin), 500

    return render_template("create_post.html", post_data=post_data, user_is_admin=user_is_admin)















@app.route("/school_news")
@login_required
def school_news():
    """
    Renders the school news page, which now fetches and displays all posts
    on a single page.
    """
    is_admin = getattr(g.current_user, 'is_admin', False)
    search_query = request.args.get("q")
    
    posts, total_posts, error = fetch_posts_for_display("School News", search_query)
    
    if error:
        flash(f"Error loading posts: {error}", "error")
        posts = []

    return render_template("school_news.html", posts=posts, is_admin=is_admin, search_query=search_query)


@app.route("/admin/delete_post/<string:post_id>", methods=["POST"])
@login_required
@admin_required
def delete_post(post_id):
    """
    Handles the deletion of a post, including its media files from Firebase Storage.
    """
    try:
        post_ref = db.collection("posts").document(post_id)
        post_doc = post_ref.get()

        if not post_doc.exists:
            flash("Post not found.", "error")
            return redirect(url_for("school_news"))

        post_data = post_doc.to_dict()

        # Delete all associated media files from Firebase Storage
        if 'media_items' in post_data and isinstance(post_data['media_items'], list):
            for media_item in post_data['media_items']:
                media_url = media_item.get('media_path_or_url')
                if media_url:
                    delete_media_from_firebase(media_url)

        # Delete the post document from Firestore
        post_ref.delete()
        flash("Post deleted successfully!", "success")
    except Exception as e:
        flash(f"An error occurred while deleting the post: {e}", "error")
        logging.error(f"Error deleting post {post_id}: {e}", exc_info=True)
        
    return redirect(url_for("school_news"))


@app.route("/posts/<post_id>")
@login_required
def view_post(post_id):
    """Fetches and displays a single post by its ID."""
    try:
        post_ref = db.collection("posts").document(post_id)
        post_doc = post_ref.get()

        if not post_doc.exists:
            flash("Sorry, that post was not found.", "error")
            return redirect(url_for('school_news'))

        post_data = post_doc.to_dict()
        post_data['id'] = post_doc.id

        return render_template("view_post.html", post=post_data)

    except Exception as e:
        logging.error(f"Error viewing post {post_id}: {e}", exc_info=True)
        flash("An error occurred while trying to view the post.", "error")
        return redirect(url_for("home"))





# FAQ page
@app.route('/faq')
def faq():
    # Implement FAQ
     return render_template('faq.html')








@app.route('/admin')
@login_required
@admin_required

def admin():
    return render_template('admin.html')

@app.route('/admin/post_material', methods=['POST'])
@login_required
@admin_required

def post_material():
    title = request.form.get('title')
    category = request.form.get('category')
    content = request.form.get('content')
    state = request.form.get('state')
    school = request.form.get('school')
    file = request.files.get('file')

    if not all([title, category, content, state, school, file]):
        return jsonify({'success': False, 'error': 'Missing required fields'}), 400

    try:
        # Generate a unique filename to prevent overwrites
        file_extension = os.path.splitext(file.filename)[1]
        timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
        unique_filename = f"{timestamp}_{title.replace(' ', '_')}{file_extension}"
        file_path = f"study_materials/{unique_filename}"
        
        download_url = upload_file_to_firebase(file, file_path)
        
        new_material_ref = db.collection('study_materials').document()
        new_material_ref.set({
            'title': title,
            'category': category,
            'content': content,
            'state': state,
            'school': school,
            'file_url': download_url,
            'file_path': file_path,
            'created_at': firestore.SERVER_TIMESTAMP
        })
        flash('Material posted successfully!', 'success')
        return jsonify({'success': True, 'message': 'Material posted successfully!'})
    except Exception as e:
        flash(f'An error occurred: {str(e)}', 'error')
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/materials')
@login_required
def get_materials_page():
    return render_template('get_materials.html')


# Updated to pass admin status using the `g` object
@app.route('/api/materials')
@login_required
def api_get_materials():
    query = request.args.get('query', '')
    materials = get_all_materials(query)
    
    # Check if 'current_user' is in g and if they are an admin.
    # This correctly uses your existing decorators' logic.
    is_admin_status = getattr(g.current_user, 'is_admin', False) if 'current_user' in g else False
    
    return jsonify({
        'materials': materials,
        'is_admin': is_admin_status
    })





@app.route('/download_material/<material_id>')
@login_required
def download_material(material_id):
    material = get_material_by_id(material_id)
    if not material:
        return "Material not found.", 404

    file_path = material.get('file_path')
    if not file_path:
        return "File path not found in database.", 404

    try:
        # Assuming get_file_from_firebase returns the local path to the downloaded file
        temp_file_path = get_file_from_firebase(file_path)
        
        if temp_file_path is None:
            return "File not found in storage.", 404

        # Get the original filename from the file_path for a better download name
        filename = os.path.basename(file_path)

        # Use after_this_request to clean up the temporary file
        @after_this_request
        def remove_file(response):
            try:
                os.remove(temp_file_path)
            except Exception as e:
                app.logger.error(f"Error removing temporary file: {e}")
            return response

        # Return the file as an attachment
        return send_file(temp_file_path, as_attachment=True, download_name=filename)

    except Exception as e:
        app.logger.error(f"An error occurred during file download: {str(e)}", exc_info=True)
        return f"An error occurred: {str(e)}", 500








# The new route for deleting materials
# We now use the admin_required decorator for this route. Your existing decorator handles the logic.
@app.route('/delete_material/<material_id>', methods=['POST'])
@login_required
@admin_required
def delete_material(material_id):
    try:
        material_ref = db.collection('study_materials').document(material_id)
        material_doc = material_ref.get()

        if not material_doc.exists:
            flash("Material not found.", "error")
            return redirect(url_for('get_materials_page'))

        material_data = material_doc.to_dict()
        file_path = material_data.get('file_path')

        if file_path:
            try:
                blob = bucket.blob(file_path)
                blob.delete()
                logging.info(f"Successfully deleted file from storage: {file_path}")
            except Exception as e:
                logging.error(f"Failed to delete file from storage: {e}")
        
        material_ref.delete()
        
        flash("Material has been successfully deleted.", "success")

    except Exception as e:
        logging.error(f"Error deleting material {material_id}: {e}", exc_info=True)
        flash("An error occurred while deleting the material. Please try again.", "error")

    return redirect(url_for('get_materials_page'))

# ... (Your existing @app.route('/admin') and @app.route('/admin/post_material') routes here) ...





# Updated CGPA Calculator Routes
@app.route('/cgpa_calculator')
@login_required
def cgpa_calculator_page():
    """Renders the CGPA calculation page."""
    # The session data will now be handled by JavaScript on the frontend
    return render_template('cgpa_calculator.html')

@app.route('/api/calculate_cgpa', methods=['POST'])
@login_required
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
            logging.warning(f"Invalid grade encountered: {grade}")

    if total_credit_units == 0:
        cgpa = 0.0
    else:
        cgpa = total_grade_points / total_credit_units

    cgpa_class = 'No Class'
    if 4.50 <= cgpa <= 5.00:
        cgpa_class = 'First Class'
    elif 3.50 <= cgpa <= 4.49:
        cgpa_class = 'Second Class Upper'
    elif 2.40 <= cgpa <= 3.49:
        cgpa_class = 'Second Class Lower'
    elif 1.50 <= cgpa <= 2.39:
        cgpa_class = 'Third Class'
    else:
        cgpa_class = 'Pass/Fail'
    
    # Return the results to the frontend
    return jsonify({
        'success': True,
        'cgpa': round(cgpa, 2),
        'total_grade_points': round(total_grade_points, 2),
        'total_credit_units': total_credit_units,
        'class_of_degree': cgpa_class
    })

# The rest of your main.py file remains unchanged.






@app.route('/leaderboard')
def leaderboard():
    """
    Fetches user data from Firestore to display a leaderboard,
    including dynamic profile pictures.
    """
    leaderboard_users = []

    try:
        # Fetch the top 50 users from Firestore, ordered by referral count.
        users_ref = db.collection('users').order_by('referral_count', direction=firestore.Query.DESCENDING).limit(50).stream()

        for doc in users_ref:
            user_data = doc.to_dict()
            profile_pic_url = get_profile_picture_url(doc.id)

            leaderboard_users.append({
                'id': doc.id,
                'username': user_data.get('username', 'N/A'),
                'profile_picture': profile_pic_url,
                'referral_count': user_data.get('referral_count', 0)
            })

    except Exception as e:
        logging.error(f"Error fetching leaderboard data: {e}", exc_info=True)
        flash('An error occurred while fetching the leaderboard.', 'error')

    return render_template('leaderboard.html', leaderboard=leaderboard_users)
































# The `school_gist` and `school_news` routes remain the same since they only render templates.
#@app.route('/school_gist')
#def school_gist():
   # current_user_id = get_current_user_id()
 #   current_user_role = get_user_role(current_user_id)
 #   return render_template('school_gist.html', current_user_id=current_user_id, current_user_role=current_user_role)















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
        
        

@app.route('/settings')
def settings():
    return render_template('settings.html')


    
@app.route('/disable-chats')
def disable_chats():
    return render_template('disable_chats.html')

@app.route('/disable-feedback')
def disable_feedback():
    return render_template('disable_feedback.html')



# Support page
@app.route('/support')
def support():
    # Implement support
     return render_template('support.html')
















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



def send_notification(user_id, message, notification_type="info"):
    """
    A placeholder function to simulate sending a user notification.
    """
    logging.info(f"NOTIFICATION to user {user_id}: {message}")




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

























































































































































































































































































































































































































