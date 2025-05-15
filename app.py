#!/usr/bin/env python3
"""
Face Recognition Photo Sharing System

This application allows event administrators to upload photos and generate QR codes,
and lets attendees view and download photos they appear in through facial recognition.
"""

import os
import json
import uuid
import shutil
import base64
import numpy as np
from datetime import datetime
from io import BytesIO
from PIL import Image
import face_recognition
import qrcode
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, send_file, Response, make_response
from mongo_adapter import MongoAdapter

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev_secret_key')  # Set a proper secret key in production

# MongoDB Setup
# Replace with your actual credentials
MONGO_URI = "mongodb+srv://shubhambhayaje:mc%40-M%403YCfiU%23R5@cluster0.k5srgdn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
mongo = MongoAdapter(MONGO_URI)

# Base directory for our "database"
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
EVENTS_DIR = os.path.join(DATA_DIR, 'events')
ADMINS_FILE = os.path.join(DATA_DIR, 'admins.json')  # Changed from ADMIN_FILE to ADMINS_FILE
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

# Create necessary directories if they don't exist
for directory in [DATA_DIR, EVENTS_DIR]:
    os.makedirs(directory, exist_ok=True)

# Initialize admin accounts if they don't exist - Using MongoDB
def init_admins():
    # Keeping file-based version for backward compatibility
    if not os.path.exists(ADMINS_FILE):
        admins_data = {
            'admin': {
                'password': generate_password_hash('admin123'),  # Default password, change this!
                'name': 'Administrator',
                'email': 'admin@example.com',
                'role': 'admin',  # Set the role to 'admin'
                'created_at': datetime.now().isoformat()
            }
        }
        with open(ADMINS_FILE, 'w') as f:
            json.dump(admins_data, f)
        print("Created default admin account: admin / admin123")

# Initialize the admin accounts - both file-based and MongoDB
init_admins()
mongo.init_admins()  # MongoDB version

# Helper functions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def get_event_path(event_id):
    return os.path.join(EVENTS_DIR, event_id)

def get_event_photos_path(event_id):
    return os.path.join(get_event_path(event_id), 'photos')

def get_event_faces_path(event_id):
    return os.path.join(get_event_path(event_id), 'faces')

def get_event_metadata_path(event_id):
    return os.path.join(get_event_path(event_id), 'event.json')

def get_event_faces_data_path(event_id):
    return os.path.join(get_event_path(event_id), 'faces_data.json')

def load_admins():
    """Load all admin accounts from MongoDB with file fallback."""
    # Get admins from MongoDB
    mongo_admins = mongo.load_admins()
    if mongo_admins:
        return mongo_admins
    
    # Fallback to file-based if MongoDB has no data
    if os.path.exists(ADMINS_FILE):
        with open(ADMINS_FILE, 'r') as f:
            return json.load(f)
    return {}

def save_admins(admins):
    """Save admin accounts to MongoDB and file for backward compatibility."""
    # Save to MongoDB
    mongo.save_admins(admins)
    
    # Helper function to make objects JSON serializable
    def make_json_serializable(obj):
        if isinstance(obj, dict):
            return {k: make_json_serializable(v) for k, v in obj.items()}
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            return [make_json_serializable(item) for item in obj]
        elif hasattr(obj, 'isoformat'):  # For datetime objects
            return obj.isoformat()
        elif hasattr(obj, '__str__'):  # For ObjectId and other objects
            return str(obj)
        else:
            return obj
    
    # Convert data to be JSON serializable
    serializable_admins = make_json_serializable(admins)
    
    # Also save to file for backward compatibility
    with open(ADMINS_FILE, 'w') as f:
        json.dump(serializable_admins, f)

def load_events(username=None):
    """
    Load events from MongoDB with file system fallback.
    If username is provided, only load events created by that user.
    Everyone can only see their own events, including admins.
    """
    current_user = session.get('admin_username')
    
    # If no username provided, use current user
    if username is None:
        username = current_user
    
    # Only show own events for everyone including admins
    if username != current_user:
        return []
    
    # Try to load from MongoDB first
    try:
        mongo_events = mongo.load_events(username)
        if mongo_events:
            # Add id field for compatibility
            for event in mongo_events:
                if '_id' in event and 'id' not in event:
                    event['id'] = event['_id']
            return mongo_events
    except Exception as e:
        print(f"Error loading events from MongoDB: {e}")
    
    # Fallback to file system
    events = []
    if os.path.exists(EVENTS_DIR):
        for event_id in os.listdir(EVENTS_DIR):
            event_path = get_event_path(event_id)
            metadata_path = get_event_metadata_path(event_id)
            if os.path.isdir(event_path) and os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    event_data = json.load(f)
                    
                    # Filter by creator - only show events created by the current user
                    if event_data.get('created_by') != username:
                        continue
                        
                    # Count photos
                    photos_path = get_event_photos_path(event_id)
                    photo_count = len(os.listdir(photos_path)) if os.path.exists(photos_path) else 0
                    event_data['photo_count'] = photo_count
                    event_data['id'] = event_id
                    events.append(event_data)
    
    return sorted(events, key=lambda x: x.get('date', ''), reverse=True)

def create_event(name, date, description=""):
    """Create a new event in MongoDB with file system backup."""
    # Create the event in MongoDB
    try:
        creator_username = session.get('admin_username')
        event_id = mongo.create_event(name, date, description, creator_username)
    except Exception as e:
        print(f"Error creating event in MongoDB: {e}")
        # Fallback to file system if MongoDB fails
        event_id = str(uuid.uuid4())
    
    # Also create directories and files for backward compatibility
    event_path = get_event_path(event_id)
    photos_path = get_event_photos_path(event_id)
    faces_path = get_event_faces_path(event_id)
    
    # Create directories
    os.makedirs(event_path, exist_ok=True)
    os.makedirs(photos_path, exist_ok=True)
    os.makedirs(faces_path, exist_ok=True)
    
    # Create event metadata
    event_data = {
        'name': name,
        'date': date,
        'description': description,
        'created_at': datetime.now().isoformat(),
        'created_by': session.get('admin_username'),
        'photo_count': 0
    }
    
    # Save metadata
    with open(get_event_metadata_path(event_id), 'w') as f:
        json.dump(event_data, f)
    
    # Create empty faces data file
    with open(get_event_faces_data_path(event_id), 'w') as f:
        json.dump({}, f)
    
    return event_id

def delete_event(event_id):
    """Delete an event and all its data from MongoDB and file system."""
    # Delete from MongoDB
    mongo_success = mongo.delete_event(event_id)
    
    # Also delete from file system for backward compatibility
    file_success = False
    event_path = get_event_path(event_id)
    if os.path.exists(event_path):
        try:
            shutil.rmtree(event_path)
            file_success = True
        except Exception as e:
            print(f"Error deleting event from file system: {e}")
    
    # Return true if either deletion succeeded
    return mongo_success or file_success

def generate_qr_code(event_id, base_url="http://localhost:5000"):
    """Generate a QR code for an event."""
    # Ensure base_url is not None and has a value
    if base_url is None or base_url == "":
        base_url = "http://localhost:5000"
    
    # Remove any trailing slashes to avoid double slashes
    base_url = base_url.rstrip('/')
    
    event_url = f"{base_url}/event/{event_id}"
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(event_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    # Convert to base64 for embedding in HTML
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"

def process_photo(event_id, photo_path):
    """Process a photo to extract and save faces."""
    # Load image and find face locations
    image = face_recognition.load_image_file(photo_path)
    face_locations = face_recognition.face_locations(image)
    
    if not face_locations:
        return []  # No faces found
    
    # Get face encodings
    face_encodings = face_recognition.face_encodings(image, face_locations)
    
    # Get filename without extension
    base_filename = os.path.basename(photo_path)
    
    # Load existing faces data
    faces_data_path = get_event_faces_data_path(event_id)
    faces_data = {}
    if os.path.exists(faces_data_path):
        with open(faces_data_path, 'r') as f:
            faces_data = json.load(f)
    
    # Process each face
    face_ids = []
    for i, (face_encoding, face_location) in enumerate(zip(face_encodings, face_locations)):
        # Create a unique ID for this face
        face_id = f"{base_filename}_{i}"
        face_ids.append(face_id)
        
        # Extract face image
        top, right, bottom, left = face_location
        face_image = image[top:bottom, left:right]
        pil_image = Image.fromarray(face_image)
        
        # Save face image
        face_path = os.path.join(get_event_faces_path(event_id), f"{face_id}.jpg")
        pil_image.save(face_path)
        
        # Store face encoding and metadata
        faces_data[face_id] = {
            'encoding': face_encoding.tolist(),  # Convert numpy array to list for JSON serialization
            'photo': base_filename,
            'location': face_location
        }
    
    # Save faces data
    with open(faces_data_path, 'w') as f:
        json.dump(faces_data, f)
    
    return face_ids

def match_face(event_id, face_image_stream):
    """Match a face against all faces in an event."""
    # Load the uploaded face image
    face_image_stream.seek(0)
    uploaded_image = face_recognition.load_image_file(face_image_stream)
    
    # Detect faces in the uploaded image
    face_locations = face_recognition.face_locations(uploaded_image)
    if not face_locations:
        return []  # No faces found in the uploaded image
    
    # Get face encodings (use the first face if multiple are detected)
    face_encodings = face_recognition.face_encodings(uploaded_image, [face_locations[0]])
    if not face_encodings:
        return []  # Failed to get face encoding
    
    uploaded_face_encoding = face_encodings[0]
    
    # Load faces data for the event
    faces_data_path = get_event_faces_data_path(event_id)
    if not os.path.exists(faces_data_path):
        return []
    
    with open(faces_data_path, 'r') as f:
        faces_data = json.load(f)
    
    # Match against all faces
    matched_photos = set()
    for face_id, face_data in faces_data.items():
        # Convert list back to numpy array
        stored_encoding = np.array(face_data['encoding'])
        
        # Compare faces with a tolerance (lower is stricter)
        if face_recognition.compare_faces([stored_encoding], uploaded_face_encoding, tolerance=0.6)[0]:
            matched_photos.add(face_data['photo'])
    
    return list(matched_photos)

# Flask routes

@app.route('/')
def index():
    """Home page."""
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page."""
    is_admin = session.get('admin_logged_in') and session.get('admin_role') == 'admin'
    
    # Regular users without admin privileges can't access the registration page if already logged in
    if session.get('admin_logged_in') and not is_admin:
        return redirect(url_for('admin_dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        
        # Basic validation
        admins = load_admins()
        
        if username in admins:
            flash('Username already exists', 'error')
            return redirect(url_for('register'))
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return redirect(url_for('register'))
        
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))
        
        # Create new user account
        is_admin_creating = session.get('admin_logged_in') and session.get('admin_role') == 'admin'
        
        # Determine role - admins can create other admins if they choose to
        role = 'user'
        if is_admin_creating and request.form.get('role') == 'admin':
            role = 'admin'
        # Make the first user an admin if no accounts exist
        elif not admins:
            role = 'admin'
            
        admins[username] = {
            'password': generate_password_hash(password),
            'name': name,
            'email': email,
            'role': role,
            'created_at': datetime.now().isoformat()
        }
        
        save_admins(admins)
        
        flash('Account created successfully. Please log in.', 'success')
        return redirect(url_for('admin_login_page'))
    
    return render_template('register.html')

@app.route('/admin')
def admin_login_page():
    """User login page."""
    if session.get('admin_logged_in'):
        return redirect(url_for('admin_dashboard'))
    return render_template('admin_login.html')

@app.route('/admin/login', methods=['POST'])
def admin_login():
    """Process admin login."""
    username = request.form.get('username')
    password = request.form.get('password')
    
    admins = load_admins()
    
    if username in admins and check_password_hash(admins[username]['password'], password):
        session['admin_logged_in'] = True
        session['admin_username'] = username
        session['admin_name'] = admins[username].get('name', username)
        session['admin_role'] = admins[username].get('role', 'user')  # Store the role in session
        flash('Logged in successfully', 'success')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('Invalid credentials', 'error')
        return redirect(url_for('admin_login_page'))

@app.route('/admin/logout')
def admin_logout():
    """Admin logout."""
    session.pop('admin_logged_in', None)
    session.pop('admin_username', None)
    session.pop('admin_name', None)
    flash('Logged out successfully', 'success')
    return redirect(url_for('admin_login_page'))

@app.route('/admin/account', methods=['GET', 'POST'])
def admin_account():
    """Admin account management."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    admins = load_admins()
    username = session.get('admin_username')
    
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        name = request.form.get('name', '')
        email = request.form.get('email', '')
        
        # Verify current password
        if not check_password_hash(admins[username]['password'], current_password):
            flash('Current password is incorrect', 'error')
            return redirect(url_for('admin_account'))
        
        # Update password if new password provided
        if new_password:
            if new_password != confirm_password:
                flash('New passwords do not match', 'error')
                return redirect(url_for('admin_account'))
            
            if len(new_password) < 8:
                flash('Password must be at least 8 characters', 'error')
                return redirect(url_for('admin_account'))
            
            admins[username]['password'] = generate_password_hash(new_password)
        
        # Update profile info
        admins[username]['name'] = name
        admins[username]['email'] = email
        
        # Save changes
        save_admins(admins)
        
        # Update session
        session['admin_name'] = name
        
        flash('Account updated successfully', 'success')
        return redirect(url_for('admin_account'))
    
    return render_template('admin_account.html', 
                         admin=admins.get(username, {}),
                         username=username)

@app.route('/admin/dashboard')
def admin_dashboard():
    """Dashboard page for all users."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Get username
    username = session.get('admin_username')
    
    # Load events - everyone only sees their own events
    events = load_events(username)
    
    return render_template('admin_dashboard.html', events=events)

@app.route('/admin/manage-accounts')
def manage_accounts():
    """Admin accounts management page."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Check if the current user is a super admin
    admins = load_admins()
    username = session.get('admin_username')
    
    if username not in admins or admins[username].get('role') != 'admin':
        flash('You do not have permission to access this page', 'error')
        return redirect(url_for('admin_dashboard'))
    
    return render_template('manage_accounts.html', admins=admins, current_user=username)

@app.route('/admin/delete-account/<username>', methods=['POST'])
def delete_account(username):
    """Delete an admin account."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Check if the current user is a super admin
    admins = load_admins()
    current_username = session.get('admin_username')
    
    if current_username not in admins or admins[current_username].get('role') != 'admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Cannot delete your own account
    if username == current_username:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('manage_accounts'))
    
    # Delete the account
    if username in admins:
        del admins[username]
        save_admins(admins)
        flash(f'Account {username} deleted successfully', 'success')
    else:
        flash('Account not found', 'error')
    
    return redirect(url_for('manage_accounts'))

@app.route('/admin/event/new', methods=['GET', 'POST'])
def new_event():
    """Create a new event."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        date = request.form.get('date')
        description = request.form.get('description', '')
        
        if name and date:
            event_id = create_event(name, date, description)
            flash('Event created successfully', 'success')
            return redirect(url_for('view_event', event_id=event_id))
        else:
            flash('Name and date are required', 'error')
    
    return render_template('new_event.html')

@app.route('/admin/event/<event_id>')
def view_event(event_id):
    """View event details from MongoDB or file system."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Try to get event from MongoDB first
    event_data = None
    try:
        event_data = mongo.get_event(event_id)
    except Exception as e:
        print(f"Error retrieving event from MongoDB: {e}")
    
    # If MongoDB failed, try file system
    if not event_data:
        metadata_path = get_event_metadata_path(event_id)
        if not os.path.exists(metadata_path):
            flash('Event not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Load event data from file
        with open(metadata_path, 'r') as f:
            event_data = json.load(f)
    
    # If still no event data, return error
    if not event_data:
        flash('Event not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Only allow the creator to view the event
    current_username = session.get('admin_username')
    
    if event_data.get('created_by') != current_username:
        flash('You do not have permission to view this event', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Get photos - try MongoDB first
    photos = []
    try:
        mongo_photos = mongo.get_photos_for_event(event_id)
        print(f"MongoDB photos raw: {mongo_photos}")
        if mongo_photos:
            # Check what's in the photos before processing
            for photo in mongo_photos:
                print(f"Photo fields: {photo.keys()}")
                if 'filename' in photo:
                    photos.append(photo['filename'])
                else:
                    # Try alternative field names
                    if 'metadata' in photo and 'filename' in photo['metadata']:
                        photos.append(photo['metadata']['filename'])
                    else:
                        print(f"Warning: Photo missing filename field: {photo}")
            print(f"Final photo list: {photos}")
    except Exception as e:
        print(f"Error retrieving photos from MongoDB: {e}")
    
    # If MongoDB failed or has no photos, try file system
    if not photos:
        photos_path = get_event_photos_path(event_id)
        if os.path.exists(photos_path):
            photos = os.listdir(photos_path)
    
    # Generate QR code
    try:
        base_url = request.url_root
        qr_code = generate_qr_code(event_id, base_url)
    except Exception as e:
        # Fallback to default base URL if there's any error
        app.logger.error(f"Error generating QR code: {str(e)}")
        qr_code = generate_qr_code(event_id)
    
    return render_template('view_event.html', event=event_data, event_id=event_id, photos=photos, qr_code=qr_code)

@app.route('/admin/event/<event_id>/upload', methods=['POST'])
def upload_photos(event_id):
    """Upload photos to an event."""
    print(f"Starting upload for event: {event_id}")
    if not session.get('admin_logged_in'):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Not logged in'}), 401
        return redirect(url_for('admin_login_page'))
    
    # Check if user has permission to upload to this event
    metadata_path = get_event_metadata_path(event_id)
    if not os.path.exists(metadata_path):
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Event not found'}), 404
        flash('Event not found', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Verify ownership
    with open(metadata_path, 'r') as f:
        event_data = json.load(f)
    
    current_username = session.get('admin_username')
    print(f"Current username: {current_username}, Event creator: {event_data.get('created_by')}")
    
    if event_data.get('created_by') != current_username:
        print("ERROR: Permission denied - user does not own this event")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'Permission denied'}), 403
        flash('You do not have permission to upload photos to this event', 'error')
        return redirect(url_for('admin_dashboard'))
    
    print(f"=================== UPLOAD DEBUG ===================")
    print(f"Request form: {request.form}")
    print(f"Request files: {request.files}")
    print(f"Request files keys: {list(request.files.keys())}")
    
    if 'photos' not in request.files:
        print("ERROR: 'photos' not in request.files")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'No files uploaded'}), 400
        flash('No file part', 'error')
        return redirect(url_for('view_event', event_id=event_id))
    
    files = request.files.getlist('photos')
    print(f"Files list length: {len(files)}")
    if not files:
        print("ERROR: No files found in request")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'No selected file'}), 400
        flash('No selected file', 'error')
        return redirect(url_for('view_event', event_id=event_id))
        
    if files[0].filename == '':
        print("ERROR: First file has empty filename")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify({'success': False, 'message': 'No selected file'}), 400
        flash('No selected file', 'error')
        return redirect(url_for('view_event', event_id=event_id))
    
    # Prepare for both MongoDB and file storage
    photos_path = get_event_photos_path(event_id)
    processed_count = 0
    uploaded_filenames = []
    
    print(f"Processing {len(files)} files for upload")
    
    for i, file in enumerate(files):
        print(f"File {i+1}: {file.filename if file else 'None'}")
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            print(f"Processing file: {filename}")
            
            # Store in MongoDB
            try:
                # Read file content
                file_content = file.read()
                file.seek(0)  # Reset the file pointer for further processing
                
                print(f"Read file content, size: {len(file_content)} bytes")
                
                # Save to MongoDB GridFS
                print(f"Calling save_photo with event_id: {event_id}, filename: {filename}")
                photo_id = mongo.save_photo(event_id, file_content, filename)
                print(f"Saved photo to MongoDB with ID: {photo_id}, filename: {filename}")
                
                if not photo_id:
                    print("ERROR: save_photo returned None - photo was not saved to MongoDB")
                
                # Process faces with face_recognition
                print("Loading image for face recognition")
                image = face_recognition.load_image_file(file)
                file.seek(0)  # Reset again for file.save()
                
                # Find faces
                print("Finding faces in image")
                face_locations = face_recognition.face_locations(image)
                print(f"Found {len(face_locations)} faces in image")
                
                if face_locations:
                    face_encodings = face_recognition.face_encodings(image, face_locations)
                    
                    # Save faces to MongoDB
                    for i, (face_location, face_encoding) in enumerate(zip(face_locations, face_encodings)):
                        face_id = str(uuid.uuid4())
                        
                        # Extract face image
                        top, right, bottom, left = face_location
                        face_image = image[top:bottom, left:right]
                        pil_image = Image.fromarray(face_image)
                        
                        # Save to MongoDB
                        mongo.save_face(event_id, photo_id, face_id, pil_image, face_encoding, face_location)
                    
                    processed_count += 1
            except Exception as e:
                print(f"MongoDB storage error: {e}")
                import traceback
                traceback.print_exc()
            
            # Also save to file system for backward compatibility
            file_path = os.path.join(photos_path, filename)
            file.save(file_path)
            uploaded_filenames.append(filename)
            
            # Process for file system as well
            face_ids = process_photo(event_id, file_path)
            if face_ids and processed_count == 0:  # Only increment if not already counted from MongoDB
                processed_count += 1
    
    # Set flash messages for non-AJAX responses
    if processed_count > 0:
        flash(f'Successfully uploaded and processed {processed_count} photos', 'success')
    else:
        flash('Photos uploaded but no faces were detected', 'warning')
    
    print(f"Upload complete: {len(uploaded_filenames)} files uploaded, {processed_count} processed with faces")
    print(f"=================== UPLOAD COMPLETE ===================")
    
    # Check if the request was AJAX or standard form
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'message': f'Successfully uploaded {len(uploaded_filenames)} photos.',
            'processed_count': processed_count,
            'total_uploaded': len(uploaded_filenames)
        })
    else:
        # Standard form post - redirect to the event page
        print(f"Redirecting to event page: {event_id}")
        flash(f'Successfully uploaded {len(uploaded_filenames)} photos.', 'success')
        return redirect(url_for('view_event', event_id=event_id))

@app.route('/admin/event/<event_id>/delete', methods=['POST'])
def delete_event_route(event_id):
    """Delete an event from MongoDB and file system."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Try to get event from MongoDB first
    event_data = None
    try:
        event_data = mongo.get_event(event_id)
    except Exception as e:
        print(f"Error retrieving event from MongoDB: {e}")
    
    # If MongoDB failed, try file system
    if not event_data:
        metadata_path = get_event_metadata_path(event_id)
        if not os.path.exists(metadata_path):
            flash('Event not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Load event data from file
        with open(metadata_path, 'r') as f:
            event_data = json.load(f)
    
    # Verify ownership
    current_username = session.get('admin_username')
    
    if event_data.get('created_by') != current_username:
        flash('You do not have permission to delete this event', 'error')
        return redirect(url_for('admin_dashboard'))
    
    if delete_event(event_id):
        flash('Event deleted successfully', 'success')
    else:
        flash('Failed to delete event', 'error')
    
    return redirect(url_for('admin_dashboard'))

@app.route('/event/<event_id>')
def public_event_page(event_id):
    """Public event page for attendees using MongoDB or file system."""
    # Try to get event from MongoDB first
    event_data = None
    try:
        event_data = mongo.get_event(event_id)
    except Exception as e:
        print(f"Error retrieving event from MongoDB: {e}")
    
    # If MongoDB failed, try file system
    if not event_data:
        metadata_path = get_event_metadata_path(event_id)
        if not os.path.exists(metadata_path):
            flash('Event not found', 'error')
            return redirect(url_for('index'))
        
        # Load event data from file
        with open(metadata_path, 'r') as f:
            event_data = json.load(f)
    
    return render_template('public_event.html', event=event_data, event_id=event_id)

@app.route('/event/<event_id>/match', methods=['POST'])
def match_face_route(event_id):
    """Match a face and return matching photos using MongoDB and file system."""
    if 'face' not in request.files:
        return jsonify({'error': 'No face image provided'}), 400
    
    face_file = request.files['face']
    if face_file.filename == '':
        return jsonify({'error': 'No face image selected'}), 400
    
    # Try MongoDB first for face matching
    try:
        # Read image from the stream
        face_file.seek(0)
        image_bytes = face_file.read()
        face_file.seek(0)  # Reset for potential file-based matching
        
        # Load the image
        image = face_recognition.load_image_file(BytesIO(image_bytes))
        
        # Find faces in the uploaded image
        face_locations = face_recognition.face_locations(image)
        if face_locations:
            # Use the first face found
            face_encodings = face_recognition.face_encodings(image, [face_locations[0]])
            if face_encodings:
                face_encoding = face_encodings[0]
                
                # Get all face data for this event
                event_faces = mongo.get_faces_for_event(event_id)
                
                # Match against stored faces
                if event_faces:
                    # Collect all face encodings to compare
                    known_face_encodings = []
                    known_face_data = []
                    
                    for face_data in event_faces:
                        # Convert stored encoding back to numpy array
                        encoding_bytes = face_data["encoding"]
                        encoding_shape = face_data["encoding_shape"]
                        
                        encoding_np = np.frombuffer(encoding_bytes, dtype=np.float64)
                        encoding_np = encoding_np.reshape(encoding_shape)
                        
                        known_face_encodings.append(encoding_np)
                        known_face_data.append(face_data)
                    
                    # Find matches
                    matches = face_recognition.compare_faces(known_face_encodings, face_encoding, tolerance=0.6)
                    
                    # Get matching photos
                    matching_photos = set()
                    for match, face_data in zip(matches, known_face_data):
                        if match:
                            # Get the photo filename
                            matching_photos.add(face_data["photo_filename"])
                    
                    if matching_photos:
                        return jsonify({'message': f'Found {len(matching_photos)} matching photos', 'photos': list(matching_photos)}), 200
    except Exception as e:
        print(f"MongoDB face matching error: {e}")
    
    # Fallback to file-based matching
    matched_photos = match_face(event_id, face_file)
    
    if not matched_photos:
        return jsonify({'message': 'No matches found', 'photos': []}), 200
    
    # Return the list of matching photos
    return jsonify({'message': f'Found {len(matched_photos)} matching photos', 'photos': matched_photos}), 200

@app.route('/event/<event_id>/photo/<filename>')
def get_event_photo(event_id, filename):
    """Serve an event photo from MongoDB or file system."""
    # If user is logged in, check if they have permission to view this photo
    if session.get('admin_logged_in'):
        # Try MongoDB first
        try:
            event_data = mongo.get_event(event_id)
            if not event_data:
                # Fallback to file system
                metadata_path = get_event_metadata_path(event_id)
                if os.path.exists(metadata_path):
                    with open(metadata_path, 'r') as f:
                        event_data = json.load(f)
            
            current_username = session.get('admin_username')
            
            # Only the creator can access
            if event_data and event_data.get('created_by') != current_username:
                return jsonify({'error': 'Access denied'}), 403
        except Exception as e:
            print(f"Error checking permissions: {e}")
            # Fallback to file check
            metadata_path = get_event_metadata_path(event_id)
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    event_data = json.load(f)
                    
                current_username = session.get('admin_username')
                
                # Only the creator can access
                if event_data.get('created_by') != current_username:
                    return jsonify({'error': 'Access denied'}), 403
    
    # Try to get from MongoDB first
    try:
        # Find the photo in GridFS by filename and event_id
        photo_file = mongo.db.fs.files.find_one({
            "filename": secure_filename(filename),
            "metadata.event_id": event_id
        })
        
        if photo_file:
            # Get the file from GridFS
            grid_out = mongo.fs.get(photo_file["_id"])
            return send_file(
                BytesIO(grid_out.read()),
                mimetype='image/jpeg'
            )
    except Exception as e:
        print(f"Error retrieving from MongoDB: {e}")
        # Continue to file fallback
    
    # Fallback to file system
    photo_path = os.path.join(get_event_photos_path(event_id), secure_filename(filename))
    if not os.path.exists(photo_path):
        return jsonify({'error': 'Photo not found'}), 404
    
    return send_file(photo_path)

@app.route('/event/<event_id>/download/<filename>')
def download_photo(event_id, filename):
    """Download a photo."""
    # If user is logged in, check if they have permission to download this photo
    if session.get('admin_logged_in'):
        metadata_path = get_event_metadata_path(event_id)
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                event_data = json.load(f)
                
            current_username = session.get('admin_username')
            
            # Only the creator can access
            if event_data.get('created_by') != current_username:
                return jsonify({'error': 'Access denied'}), 403
    
    photo_path = os.path.join(get_event_photos_path(event_id), secure_filename(filename))
    if not os.path.exists(photo_path):
        return jsonify({'error': 'Photo not found'}), 404
    
    return send_file(photo_path, as_attachment=True)

@app.route('/admin/event/<event_id>/photo/<filename>/delete', methods=['POST'])
def delete_photo(event_id, filename):
    """Delete a specific photo from MongoDB and file system."""
    if not session.get('admin_logged_in'):
        return redirect(url_for('admin_login_page'))
    
    # Try to get event from MongoDB first
    event_data = None
    try:
        event_data = mongo.get_event(event_id)
    except Exception as e:
        print(f"Error retrieving event from MongoDB: {e}")
    
    # If MongoDB failed, try file system
    if not event_data:
        metadata_path = get_event_metadata_path(event_id)
        if not os.path.exists(metadata_path):
            flash('Event not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Load event data from file
        with open(metadata_path, 'r') as f:
            event_data = json.load(f)
    
    # Verify ownership
    current_username = session.get('admin_username')
    
    if event_data.get('created_by') != current_username:
        flash('You do not have permission to delete photos from this event', 'error')
        return redirect(url_for('admin_dashboard'))
    
    # Secure the filename to prevent directory traversal
    secure_filename_str = secure_filename(filename)
    
    # Delete from MongoDB first
    mongo_deleted = False
    try:
        # Find the photo in MongoDB by filename and event_id
        photo_file = mongo.db.fs.files.find_one({
            "filename": secure_filename_str,
            "metadata.event_id": event_id
        })
        
        if photo_file:
            # Delete the photo and its faces from MongoDB
            photo_id = photo_file["_id"]
            if mongo.delete_photo(photo_id):
                mongo_deleted = True
                print(f"Successfully deleted {filename} from MongoDB")
    except Exception as e:
        print(f"Error deleting photo from MongoDB: {e}")
    
    # Now try to delete from file system
    file_deleted = False
    photo_path = os.path.join(get_event_photos_path(event_id), secure_filename_str)
    
    if os.path.exists(photo_path):
        try:
            # Remove the file
            os.remove(photo_path)
            file_deleted = True
            
            # Also remove related face data
            faces_data_path = get_event_faces_data_path(event_id)
            if os.path.exists(faces_data_path):
                with open(faces_data_path, 'r') as f:
                    faces_data = json.load(f)
                
                # Remove all entries for this photo
                modified_faces_data = {}
                for face_id, face_data in faces_data.items():
                    if face_data.get('photo') != secure_filename_str:
                        modified_faces_data[face_id] = face_data
                
                # Save updated faces data
                with open(faces_data_path, 'w') as f:
                    json.dump(modified_faces_data, f)
                
                # Remove face images from this photo
                faces_path = get_event_faces_path(event_id)
                if os.path.exists(faces_path):
                    for face_file in os.listdir(faces_path):
                        if face_file.startswith(f"{secure_filename_str}_"):
                            face_file_path = os.path.join(faces_path, face_file)
                            try:
                                os.remove(face_file_path)
                            except Exception as e:
                                print(f"Error removing face file: {str(e)}")
        except Exception as e:
            print(f"Error deleting photo from file system: {e}")
    
    # Set appropriate message based on whether anything was deleted
    if mongo_deleted or file_deleted:
        flash('Photo deleted successfully', 'success')
    else:
        flash('Photo not found', 'error')
    
    # Clear browser cache for this image
    response = make_response(redirect(url_for('view_event', event_id=event_id)))
    response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# HTML Templates as strings (for single-file deployment)
TEMPLATES = {
    'manage_accounts.html': '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Manage Accounts | Event Snap</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #5D4FE8;
            --primary-light: #EAE8FD;
            --primary-dark: #4A40CC;
            --secondary-color: #4AC2F2;
            --accent-color: #FF5A87;
            --dark-color: #11142D;
            --light-color: #F8F9FA;
            --text-color: #4B5563;
            --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
            --border-radius: 15px;
        }
        
        body { 
            padding: 0;
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            color: var(--text-color);
            background-color: #F5F7FE;
            min-height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            background-color: white;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            width: 250px;
            box-shadow: var(--card-shadow);
            z-index: 1000;
            transition: all 0.3s ease;
            overflow-y: auto;
        }
        
        .sidebar-header {
            padding: 25px 20px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .brand-logo {
            font-weight: 800;
            font-size: 1.4rem;
            color: var(--primary-color);
            text-decoration: none;
            display: flex;
            align-items: center;
        }
        
        .brand-logo i {
            margin-right: 10px;
            font-size: 1.5rem;
        }
        
        .nav-menu {
            padding: 15px 0;
        }
        
        .menu-item {
            padding: 10px 20px;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            cursor: pointer;
            text-decoration: none;
            color: var(--text-color);
            border-radius: 0 30px 30px 0;
            transition: all 0.3s ease;
        }
        
        .menu-item:hover, .menu-item.active {
            background-color: var(--primary-light);
            color: var(--primary-color);
        }
        
        .menu-item.active {
            border-left: 4px solid var(--primary-color);
            font-weight: 600;
        }
        
        .menu-item i {
            margin-right: 10px;
            font-size: 1.2rem;
        }
        
        /* Main Content */
        .main-content {
            margin-left: 250px;
            padding: 30px;
            transition: all 0.3s ease;
        }
        
        .card {
            border: none;
            border-radius: var(--border-radius);
            box-shadow: var(--card-shadow);
            overflow: hidden;
            margin-bottom: 30px;
            background-color: white;
        }
        
        .card-header {
            background-color: white;
            padding: 25px 30px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .card-header h3 {
            font-weight: 700;
            margin: 0;
            color: var(--dark-color);
            font-size: 1.3rem;
        }
        
        .card-body {
            padding: 30px;
        }
        
        .btn {
            padding: 12px 20px;
            font-weight: 600;
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
        }
        
        .btn-danger {
            background-color: var(--accent-color);
            border-color: var(--accent-color);
            box-shadow: 0 5px 15px rgba(255, 90, 135, 0.3);
        }
        
        .btn-danger:hover {
            background-color: #FF3B71;
            border-color: #FF3B71;
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(255, 90, 135, 0.4);
        }
        
        .alert {
            border-radius: 12px;
            border: none;
            padding: 15px 20px;
            font-weight: 500;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .alert-success {
            background-color: rgba(16, 185, 129, 0.15);
            color: #10B981;
        }
        
        .alert-danger {
            background-color: rgba(255, 90, 135, 0.15);
            color: var(--accent-color);
        }
        
        .alert-info {
            background-color: rgba(74, 194, 242, 0.15);
            color: var(--secondary-color);
        }
        
        .user-avatar {
            display: inline-block;
            width: 40px;
            height: 40px;
            border-radius: 10px;
            background-color: var(--primary-light);
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1rem;
        }
        
        .navbar-mobile {
            display: none;
            background-color: white;
            padding: 15px 20px;
            box-shadow: var(--card-shadow);
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
        }
        
        .menu-toggle {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--dark-color);
            cursor: pointer;
        }
        
        .user-badge {
            display: inline-block;
            padding: 3px 10px;
            border-radius: 20px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-left: 10px;
        }
        
        .admin-badge {
            background-color: var(--primary-light);
            color: var(--primary-color);
        }
        
        .user-badge {
            background-color: rgba(74, 194, 242, 0.15);
            color: var(--secondary-color);
        }
        
        @media (max-width: 991px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
                padding: 90px 20px 30px;
            }
            
            .navbar-mobile {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .close-sidebar {
                display: block;
                position: absolute;
                top: 20px;
                right: 20px;
                font-size: 1.5rem;
                cursor: pointer;
                color: var(--dark-color);
                background: none;
                border: none;
            }
        }
    </style>
</head>
<body>
    <!-- Mobile Navbar -->
    <nav class="navbar-mobile">
        <button class="menu-toggle" id="menuToggle">
            <i class="bi bi-list"></i>
        </button>
        <a href="/" class="brand-logo">
            <i class="bi bi-camera"></i>Event Snap
        </a>
        <div class="user-avatar">
            {{ session.get('admin_username', 'A')[0].upper() }}
        </div>
    </nav>
    
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <button class="close-sidebar" id="closeSidebar">
            <i class="bi bi-x-lg"></i>
        </button>
        <div class="sidebar-header">
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
        </div>
        <div class="nav-menu">
            <a href="/admin/dashboard" class="menu-item">
                <i class="bi bi-speedometer2"></i>Dashboard
            </a>
            <a href="/admin/event/new" class="menu-item">
                <i class="bi bi-plus-circle"></i>New Event
            </a>
            {% if session.get('admin_role') == 'admin' %}
            <a href="/admin/manage-accounts" class="menu-item active">
                <i class="bi bi-people"></i>Manage Users
            </a>
            {% endif %}
            <a href="/admin/account" class="menu-item">
                <i class="bi bi-person"></i>Account Settings
            </a>
            <a href="/admin/logout" class="menu-item">
                <i class="bi bi-box-arrow-right"></i>Logout
            </a>
        </div>
    </div>
    
    <!-- Main Content -->
    <div class="main-content">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                        <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                        {{ message }}
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="content-header">
            <h1 class="content-title">Manage User Accounts</h1>
            <a href="/register" class="btn btn-primary">
                <i class="bi bi-person-plus me-2"></i>Create New Account
            </a>
        </div>
        
        <div class="card">
            <div class="card-header">
                <h3>User Accounts</h3>
                <span>{{ admins|length }} accounts total</span>
            </div>
            <div class="table-responsive">
                <table class="table align-middle">
                    <thead>
                        <tr>
                            <th>User</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Joined</th>
                            <th class="text-end">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for username, user in admins.items() %}
                        <tr>
                            <td>
                                <div class="d-flex align-items-center">
                                    <div class="user-avatar me-3" style="background-color: {{ '#5D4FE8' if user.get('role') == 'admin' else '#4AC2F2' }};">
                                        {{ user.get('name', username)[0].upper() if user.get('name') else username[0].upper() }}
                                    </div>
                                    <div>
                                        <div class="fw-bold">{{ user.get('name', username) }}</div>
                                        <small class="text-muted">{{ username }}</small>
                                    </div>
                                </div>
                            </td>
                            <td>{{ user.get('email', 'No email') }}</td>
                            <td>
                                <span class="user-badge {{ 'admin-badge' if user.get('role') == 'admin' else 'user-badge' }}">
                                    {{ user.get('role', 'user').capitalize() }}
                                </span>
                            </td>
                            <td>
                                <small class="text-muted">{{ user.get('created_at', 'Unknown') }}</small>
                            </td>
                            <td class="text-end">
                                {% if username != current_user %}
                                <form action="/admin/delete-account/{{ username }}" method="POST" style="display: inline-block;" onsubmit="return confirm('Are you sure you want to delete this account?');">
                                    <button type="submit" class="btn btn-sm btn-danger">
                                        <i class="bi bi-trash me-1"></i>Delete
                                    </button>
                                </form>
                                {% else %}
                                <span class="text-muted">(Current user)</span>
                                {% endif %}
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const menuToggle = document.getElementById('menuToggle');
            const closeSidebar = document.getElementById('closeSidebar');
            const sidebar = document.getElementById('sidebar');
            
            if (menuToggle) {
                menuToggle.addEventListener('click', function() {
                    sidebar.classList.add('active');
                });
            }
            
            if (closeSidebar) {
                closeSidebar.addEventListener('click', function() {
                    sidebar.classList.remove('active');
                });
            }
        });
    </script>
</body>
</html>
    ''',
    'register.html': '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register Account | Event Snap</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #5D4FE8;
            --primary-light: #EAE8FD;
            --primary-dark: #4A40CC;
            --secondary-color: #4AC2F2;
            --accent-color: #FF5A87;
            --dark-color: #11142D;
            --light-color: #F8F9FA;
            --text-color: #4B5563;
            --gradient-bg: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
            --border-radius: 15px;
        }
        
        body { 
            background: var(--gradient-bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            padding: 20px;
        }
        
        .register-container {
            width: 100%;
            max-width: 550px;
        }
        
        .register-card {
            border-radius: 20px;
            overflow: hidden;
            box-shadow: var(--card-shadow);
            background-color: white;
        }
        
        .register-header {
            text-align: center;
            padding: 40px 20px 20px;
        }
        
        .brand-logo {
            font-weight: 800;
            font-size: 1.6rem;
            color: var(--primary-color);
            text-decoration: none;
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
        }
        
        .brand-logo i {
            margin-right: 10px;
            font-size: 1.8rem;
        }
        
        .register-header h2 {
            color: var(--dark-color);
            font-weight: 700;
            font-size: 2rem;
            margin-bottom: 10px;
        }
        
        .register-header p {
            color: var(--text-color);
            margin-bottom: 0;
        }
        
        .register-body {
            padding: 20px 40px 40px;
        }
        
        .form-control {
            border-radius: 12px;
            padding: 12px 15px;
            border: 2px solid #E5E7EB;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 4px rgba(93, 79, 232, 0.15);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--dark-color);
            margin-bottom: 8px;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
            padding: 12px 20px;
            font-weight: 600;
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
        }
        
        .alert {
            border-radius: 12px;
            border: none;
            padding: 15px 20px;
            font-weight: 500;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .alert-danger {
            background-color: rgba(255, 90, 135, 0.15);
            color: var(--accent-color);
        }
        
        .alert-success {
            background-color: rgba(16, 185, 129, 0.15);
            color: #10B981;
        }
        
        .link-primary {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .link-primary:hover {
            color: var(--primary-dark);
        }
    </style>
</head>
<body>
    <div class="register-container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} d-flex align-items-center mb-4">
                        <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                        <div>{{ message }}</div>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="register-card">
            <div class="register-header">
                <a href="/" class="brand-logo">
                    <i class="bi bi-camera"></i>Event Snap
                </a>
                <h2>Create Account</h2>
                <p>Join Event Snap to manage your events and photos</p>
            </div>
            <div class="register-body">
                <form method="post" action="/register">
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="username" class="form-label">Username *</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="name" class="form-label">Full Name</label>
                            <input type="text" class="form-control" id="name" name="name">
                        </div>
                    </div>
                    
                    <div class="mb-3">
                        <label for="email" class="form-label">Email Address</label>
                        <input type="email" class="form-control" id="email" name="email">
                    </div>
                    
                    <div class="row">
                        <div class="col-md-6 mb-3">
                            <label for="password" class="form-label">Password *</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        <div class="col-md-6 mb-3">
                            <label for="confirm_password" class="form-label">Confirm Password *</label>
                            <input type="password" class="form-control" id="confirm_password" name="confirm_password" required>
                        </div>
                    </div>
                    
                    <p class="text-muted small mb-4">Passwords must be at least 8 characters long.</p>
                    
                    {% if session.get('admin_logged_in') and session.get('admin_role') == 'admin' %}
                    <div class="mb-3">
                        <label class="form-label">Account Type</label>
                        <div>
                            <div class="form-check form-check-inline">
                                <input class="form-check-input" type="radio" name="role" id="roleUser" value="user" checked>
                                <label class="form-check-label" for="roleUser">Regular User</label>
                            </div>
                            <div class="form-check form-check-inline">
                                <input class="form-check-input" type="radio" name="role" id="roleAdmin" value="admin">
                                <label class="form-check-label" for="roleAdmin">Administrator</label>
                            </div>
                        </div>
                        <div class="form-text">Administrators can manage all users and have full system access.</div>
                    </div>
                    {% endif %}
                    
                    <div class="d-grid mb-4">
                        <button type="submit" class="btn btn-primary">
                            Register Account
                        </button>
                    </div>
                    
                    <div class="text-center">
                        <p>Already have an account? <a href="/admin" class="link-primary">Sign in</a></p>
                    </div>
                </form>
            </div>
        </div>
    </div>
</body>
</html>
    ''',
    
    'manage_accounts.html': '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Manage Accounts | Event Snap</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root {
                --primary-color: #5D4FE8;
                --primary-light: #EAE8FD;
                --primary-dark: #4A40CC;
                --secondary-color: #4AC2F2;
                --accent-color: #FF5A87;
                --dark-color: #11142D;
                --light-color: #F8F9FA;
                --text-color: #4B5563;
                --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
                --border-radius: 15px;
            }
            
            body { 
                padding: 0;
                font-family: 'Poppins', 'Segoe UI', sans-serif;
                color: var(--text-color);
                background-color: #F5F7FE;
                min-height: 100vh;
            }
            
            /* Sidebar */
            .sidebar {
                background-color: white;
                position: fixed;
                top: 0;
                left: 0;
                bottom: 0;
                width: 250px;
                box-shadow: var(--card-shadow);
                z-index: 1000;
                transition: all 0.3s ease;
                overflow-y: auto;
            }
            
            .sidebar-header {
                padding: 25px 20px;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .brand-logo {
                font-weight: 800;
                font-size: 1.4rem;
                color: var(--primary-color);
                text-decoration: none;
                display: flex;
                align-items: center;
            }
            
            .brand-logo i {
                margin-right: 10px;
                font-size: 1.5rem;
            }
            
            .nav-menu {
                padding: 15px 0;
            }
            
            .menu-item {
                padding: 10px 20px;
                margin-bottom: 5px;
                display: flex;
                align-items: center;
                cursor: pointer;
                text-decoration: none;
                color: var(--text-color);
                border-radius: 0 30px 30px 0;
                transition: all 0.3s ease;
            }
            
            .menu-item:hover, .menu-item.active {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .menu-item.active {
                border-left: 4px solid var(--primary-color);
                font-weight: 600;
            }
            
            .menu-item i {
                margin-right: 10px;
                font-size: 1.2rem;
            }
            
            /* Main Content */
            .main-content {
                margin-left: 250px;
                padding: 30px;
                transition: all 0.3s ease;
            }
            
            .content-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }
            
            .content-title {
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.8rem;
            }
            
            .card {
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
                border: none;
                margin-bottom: 30px;
                overflow: hidden;
            }
            
            .card-header {
                padding: 20px 25px;
                background-color: white;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .card-header h3 {
                margin: 0;
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.3rem;
            }
            
            .card-body {
                padding: 25px;
            }
            
            .table {
                margin-bottom: 0;
            }
            
            .table th {
                border-top: none;
                border-bottom-width: 1px;
                font-weight: 700;
                text-transform: uppercase;
                font-size: 0.8rem;
                letter-spacing: 0.5px;
                color: var(--text-color);
                padding: 15px 25px;
                background-color: #F9FAFC;
            }
            
            .table td {
                padding: 15px 25px;
                vertical-align: middle;
                color: var(--dark-color);
                border-color: rgba(0,0,0,0.03);
            }
            
            .table tr:hover {
                background-color: #F5F7FE;
            }
            
            .role-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 600;
            }
            
            .role-admin {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .role-user {
                background-color: rgba(74, 194, 242, 0.15);
                color: var(--secondary-color);
            }
            
            .btn {
                padding: 8px 15px;
                font-weight: 600;
                border-radius: 10px;
                transition: all 0.3s ease;
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
            }
            
            .btn-danger {
                background-color: var(--accent-color);
                border-color: var(--accent-color);
                box-shadow: 0 5px 15px rgba(255, 90, 135, 0.3);
            }
            
            .btn-danger:hover {
                background-color: #E03E67;
                border-color: #E03E67;
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(255, 90, 135, 0.4);
            }
            
            .alert {
                border-radius: 12px;
                border: none;
                padding: 15px 20px;
                font-weight: 500;
                margin-bottom: 25px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            }
            
            .navbar-mobile {
                display: none;
                background-color: white;
                padding: 15px 20px;
                box-shadow: var(--card-shadow);
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 1000;
            }
            
            .menu-toggle {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: var(--dark-color);
                cursor: pointer;
            }
            
            .user-avatar {
                display: inline-block;
                width: 40px;
                height: 40px;
                border-radius: 10px;
                background-color: var(--primary-light);
                color: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1rem;
            }
            
            @media (max-width: 991px) {
                .sidebar {
                    transform: translateX(-100%);
                }
                
                .sidebar.active {
                    transform: translateX(0);
                }
                
                .main-content {
                    margin-left: 0;
                    padding: 90px 20px 30px;
                }
                
                .navbar-mobile {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .close-sidebar {
                    display: block;
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--dark-color);
                    background: none;
                    border: none;
                }
            }
        </style>
    </head>
    <body>
        <!-- Mobile Navbar -->
        <nav class="navbar-mobile">
            <button class="menu-toggle" id="menuToggle">
                <i class="bi bi-list"></i>
            </button>
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
            <div class="user-avatar">
                {{ session.get('admin_username', 'A')[0].upper() }}
            </div>
        </nav>
        
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
            <button class="close-sidebar" id="closeSidebar">
                <i class="bi bi-x-lg"></i>
            </button>
            <div class="sidebar-header">
                <a href="/" class="brand-logo">
                    <i class="bi bi-camera"></i>Event Snap
                </a>
            </div>
            <div class="nav-menu">
                <a href="/admin/dashboard" class="menu-item">
                    <i class="bi bi-speedometer2"></i>Dashboard
                </a>
                <a href="/admin/event/new" class="menu-item">
                    <i class="bi bi-plus-circle"></i>New Event
                </a>
                <a href="/admin/account" class="menu-item">
                    <i class="bi bi-person"></i>Account Settings
                </a>
                <a href="/admin/manage-accounts" class="menu-item active">
                    <i class="bi bi-people"></i>Manage Accounts
                </a>
                <a href="/admin/logout" class="menu-item">
                    <i class="bi bi-box-arrow-right"></i>Logout
                </a>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                            <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="content-header">
                <h1 class="content-title">Manage Accounts</h1>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>All Accounts</h3>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Name</th>
                                    <th>Email</th>
                                    <th>Role</th>
                                    <th>Date Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for username, user in admins.items() %}
                                    <tr>
                                        <td>{{ username }}</td>
                                        <td>{{ user.get('name', '') }}</td>
                                        <td>{{ user.get('email', '') }}</td>
                                        <td>
                                            <span class="role-badge role-{{ user.get('role', 'user') }}">
                                                {{ user.get('role', 'user').capitalize() }}
                                            </span>
                                        </td>
                                        <td>{{ user.get('created_at', '') }}</td>
                                        <td>
                                            {% if username != session.get('admin_username') %}
                                                <form method="post" action="/admin/delete-account/{{ username }}" class="d-inline">
                                                    <button type="submit" class="btn btn-sm btn-danger" onclick="return confirm('Are you sure you want to delete this account?')">
                                                        <i class="bi bi-trash me-1"></i>Delete
                                                    </button>
                                                </form>
                                            {% endif %}
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const menuToggle = document.getElementById('menuToggle');
                const closeSidebar = document.getElementById('closeSidebar');
                const sidebar = document.getElementById('sidebar');
                
                if (menuToggle) {
                    menuToggle.addEventListener('click', function() {
                        sidebar.classList.add('active');
                    });
                }
                
                if (closeSidebar) {
                    closeSidebar.addEventListener('click', function() {
                        sidebar.classList.remove('active');
                    });
                }
            });
        </script>
    </body>
    </html>
    ''',
    'index.html': '''
   <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Event Snap - Find Your Photos</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #5D4FE8;
            --secondary-color: #4AC2F2;
            --accent-color: #FF5A87;
            --dark-color: #11142D;
            --light-color: #F8F9FA;
            --gradient-bg: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
        }
        
        body { 
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            color: var(--dark-color);
            background-color: #fafbff;
        }
        
        .navbar {
            box-shadow: 0 4px 20px rgba(0,0,0,0.05);
            background-color: white !important;
            padding: 18px 0;
            position: sticky;
            top: 0;
            z-index: 1000;
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--primary-color) !important;
            letter-spacing: -0.5px;
        }
        
        .navbar .nav-link {
            font-weight: 600;
            padding: 8px 16px !important;
            color: var(--dark-color);
            transition: all 0.3s ease;
        }
        
        .navbar .nav-link:hover {
            color: var(--primary-color);
        }
        
        .navbar .btn-primary {
            padding: 8px 20px;
            font-weight: 600;
            border-radius: 10px;
        }
        
        .hero { 
            background: var(--gradient-bg);
            padding: 100px 0 120px;
            margin-bottom: 80px;
            color: white;
            border-radius: 0 0 25px 25px;
            position: relative;
            overflow: hidden;
        }
        
        .hero::before {
            content: "";
            position: absolute;
            width: 300px;
            height: 300px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            top: -100px;
            right: -100px;
        }
        
        .hero::after {
            content: "";
            position: absolute;
            width: 200px;
            height: 200px;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
            bottom: -80px;
            left: -80px;
        }
        
        .hero h1 {
            font-weight: 800;
            margin-bottom: 24px;
            font-size: 3.5rem;
            line-height: 1.2;
            text-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        
        .hero p.lead {
            font-size: 1.25rem;
            max-width: 700px;
            margin: 0 auto 30px;
            opacity: 0.9;
        }
        
        .btn {
            padding: 12px 25px;
            font-weight: 600;
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.4);
        }
        
        .btn-primary:hover {
            background-color: #4a40cc;
            border-color: #4a40cc;
            transform: translateY(-3px);
            box-shadow: 0 8px 20px rgba(93, 79, 232, 0.5);
        }
        
        .btn-light {
            background-color: white;
            color: var(--dark-color);
            font-weight: 600;
            box-shadow: 0 5px 15px rgba(0,0,0,0.1);
        }
        
        .btn-light:hover {
            background-color: #f8f9fa;
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(0,0,0,0.15);
        }
        
        .btn-outline-light:hover {
            background-color: rgba(255,255,255,0.1);
        }
        
        .card {
            border: none;
            border-radius: 20px;
            box-shadow: var(--card-shadow);
            transition: transform 0.4s ease, box-shadow 0.4s ease;
            margin-bottom: 30px;
            overflow: hidden;
        }
        
        .card:hover {
            transform: translateY(-10px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.12);
        }
        
        .card-header {
            background-color: white;
            border-bottom: 1px solid rgba(0,0,0,0.05);
            padding: 25px 30px;
            font-weight: 700;
            font-size: 1.3rem;
            color: var(--dark-color);
        }
        
        .card-body {
            padding: 30px;
        }
        
        .form-control {
            border-radius: 12px;
            padding: 12px 20px;
            border: 2px solid #e9ecef;
            font-size: 1rem;
        }
        
        .form-control:focus {
            box-shadow: 0 0 0 4px rgba(93, 79, 232, 0.15);
            border-color: var(--primary-color);
        }
        
        .feature-icon {
            font-size: 3rem;
            margin-bottom: 20px;
            color: var(--primary-color);
            background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .feature-card {
            text-align: center;
            padding: 40px 30px;
            height: 100%;
            border-radius: 20px;
            transition: all 0.4s ease;
        }
        
        .feature-card:hover {
            background-color: white;
            box-shadow: 0 15px 35px rgba(0,0,0,0.08);
        }
        
        .feature-card h3 {
            margin: 20px 0 15px;
            font-weight: 700;
            color: var(--dark-color);
        }
        
        .feature-card p {
            color: #6B7280;
            line-height: 1.6;
        }
        
        .how-it-works {
            background-color: white;
            padding: 80px 0;
            border-radius: 30px;
            margin: 40px 0 80px;
            box-shadow: var(--card-shadow);
        }
        
        .step-card {
            padding: 40px 30px;
            text-align: center;
            background-color: #f8f9fa;
            border-radius: 20px;
            height: 100%;
            position: relative;
            transition: all 0.3s ease;
        }
        
        .step-card:hover {
            background-color: var(--primary-color);
            transform: translateY(-10px);
        }
        
        .step-card:hover .step-number,
        .step-card:hover h4,
        .step-card:hover p {
            color: white;
        }
        
        .step-number {
            font-size: 4rem;
            font-weight: 800;
            color: var(--primary-color);
            margin-bottom: 20px;
            line-height: 1;
            transition: all 0.3s ease;
        }
        
        .step-card h4 {
            font-weight: 700;
            margin-bottom: 15px;
            transition: all 0.3s ease;
        }
        
        .testimonial-card {
            padding: 30px;
            background-color: white;
            border-radius: 20px;
            height: 100%;
            border-top: 5px solid var(--primary-color);
        }
        
        .testimonial-stars {
            margin-bottom: 20px;
            color: #FFC107;
        }
        
        .testimonial-text {
            margin-bottom: 25px;
            font-style: italic;
            line-height: 1.7;
            color: #4B5563;
        }
        
        .testimonial-author {
            display: flex;
            align-items: center;
        }
        
        .author-avatar {
            width: 50px;
            height: 50px;
            border-radius: 50%;
            margin-right: 15px;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: 700;
        }
        
        .author-info h6 {
            margin-bottom: 3px;
            font-weight: 700;
        }
        
        .organizer-section {
            background-color: white;
            padding: 80px 0;
            border-radius: 30px;
            margin: 80px 0;
            box-shadow: var(--card-shadow);
        }
        
        .check-item {
            margin-bottom: 20px;
            display: flex;
            align-items: flex-start;
        }
        
        .check-icon {
            color: #10B981;
            font-size: 1.5rem;
            margin-right: 15px;
            flex-shrink: 0;
        }
        
        .check-text {
            font-size: 1.1rem;
            color: #4B5563;
        }
        
        .section-title {
            text-align: center;
            margin-bottom: 50px;
        }
        
        .section-title h2 {
            font-weight: 800;
            color: var(--dark-color);
            margin-bottom: 15px;
            font-size: 2.5rem;
        }
        
        .section-title p {
            color: #6B7280;
            font-size: 1.1rem;
            max-width: 600px;
            margin: 0 auto;
        }
        
        footer {
            background-color: var(--dark-color);
            padding: 80px 0 30px;
            color: rgba(255,255,255,0.8);
            margin-top: 100px;
            border-radius: 30px 30px 0 0;
        }
        
        footer h5 {
            color: white;
            font-weight: 700;
            margin-bottom: 25px;
            font-size: 1.3rem;
        }
        
        footer ul {
            padding: 0;
        }
        
        footer ul li {
            margin-bottom: 15px;
        }
        
        footer a {
            color: rgba(255,255,255,0.7);
            text-decoration: none;
            transition: all 0.3s ease;
        }
        
        footer a:hover {
            color: white;
            text-decoration: none;
        }
        
        .social-icons a {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background-color: rgba(255,255,255,0.1);
            color: white;
            margin-right: 10px;
            transition: all 0.3s ease;
        }
        
        .social-icons a:hover {
            background-color: var(--primary-color);
            transform: translateY(-3px);
        }
        
        .footer-bottom {
            margin-top: 50px;
            padding-top: 30px;
            border-top: 1px solid rgba(255,255,255,0.1);
            text-align: center;
            color: rgba(255,255,255,0.5);
        }
        
        .newsletter-form {
            display: flex;
        }
        
        .newsletter-form .form-control {
            border-radius: 12px 0 0 12px;
            border-right: none;
        }
        
        .newsletter-form .btn {
            border-radius: 0 12px 12px 0;
        }
        
        @media (max-width: 991px) {
            .hero h1 {
                font-size: 2.5rem;
            }
            
            .navbar-collapse {
                background: white;
                padding: 20px;
                border-radius: 15px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                margin-top: 15px;
            }
        }
        
        @media (max-width: 768px) {
            .hero {
                padding: 80px 0 100px;
            }
            
            .hero h1 {
                font-size: 2.2rem;
            }
            
            .section-title h2 {
                font-size: 2rem;
            }
            
            .testimonial-card, .feature-card, .step-card {
                margin-bottom: 30px;
            }
        }
        
        /* Animation for elements */
        .fade-up {
            opacity: 0;
            transform: translateY(20px);
            transition: opacity 0.6s ease, transform 0.6s ease;
        }
        
        .fade-up.active {
            opacity: 1;
            transform: translateY(0);
        }
        
        /* Animated background */
        @keyframes gradient {
            0% { background-position: 0% 50%; }
            50% { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
        }
    </style>
</head>
<body>
    <!-- Navigation -->
    <nav class="navbar navbar-expand-lg navbar-light">
        <div class="container">
            <a class="navbar-brand" href="/">
                <i class="bi bi-camera me-2"></i>Event Snap
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav ms-auto">
                    <li class="nav-item">
                        <a class="nav-link" href="#how-it-works">How It Works</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#features">Features</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="#testimonials">Testimonials</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link btn btn-success text-white ms-lg-2" href="/register">Sign Up</a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link btn btn-primary text-white ms-lg-2" href="/admin">Log In</a>
                    </li>
                </ul>
            </div>
        </div>
    </nav>
    
    <!-- Hero Section -->
    <section class="hero">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-8 mx-auto text-center">
                    <h1>Find Your Moments in Every Shot</h1>
                    <p class="lead">Use facial recognition to instantly discover all the photos you appear in from any event. Create an account or just take a selfie!</p>
                    <div class="mt-5">
                        <a href="/register" class="btn btn-light me-3">Create Account</a>
                        <a href="#how-it-works" class="btn btn-outline-light">Learn How It Works</a>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <!-- Features Section -->
    <section id="features" class="container mb-5">
        <div class="section-title">
            <h2>Why Choose Event Snap?</h2>
            <p>Simple, secure, and smart photo sharing for all your events</p>
        </div>
        
        <div class="row">
            <div class="col-md-4 mb-4">
                <div class="card feature-card h-100">
                    <div class="card-body">
                        <i class="bi bi-person-check feature-icon"></i>
                        <h3>Smart Recognition</h3>
                        <p>Our advanced AI accurately matches your selfie with event photos so you only see pictures you're in.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card feature-card h-100">
                    <div class="card-body">
                        <i class="bi bi-shield-check feature-icon"></i>
                        <h3>Privacy Focused</h3>
                        <p>Your selfie is only used for matching and never stored. We respect your privacy at every step.</p>
                    </div>
                </div>
            </div>
            <div class="col-md-4 mb-4">
                <div class="card feature-card h-100">
                    <div class="card-body">
                        <i class="bi bi-qr-code feature-icon"></i>
                        <h3>Instant Access</h3>
                        <p>Just scan the event QR code, take a selfie, and instantly access all your photos. No account needed.</p>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <!-- How It Works Section -->
    <section id="how-it-works" class="how-it-works">
        <div class="container">
            <div class="section-title">
                <h2>How It Works</h2>
                <p>Find your photos in three simple steps</p>
            </div>
            
            <div class="row g-4">
                <div class="col-md-4">
                    <div class="step-card">
                        <div class="step-number">1</div>
                        <h4>Scan QR Code</h4>
                        <p>Scan the event's unique QR code provided by the organizer</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="step-card">
                        <div class="step-number">2</div>
                        <h4>Take a Selfie</h4>
                        <p>Take a quick selfie to identify yourself in event photos</p>
                    </div>
                </div>
                <div class="col-md-4">
                    <div class="step-card">
                        <div class="step-number">3</div>
                        <h4>Get Your Photos</h4>
                        <p>Instantly view and download all photos featuring you</p>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <!-- For Organizers Section -->
    <section class="organizer-section">
        <div class="container">
            <div class="row align-items-center">
                <div class="col-lg-6 mb-5 mb-lg-0">
                    <h2 class="mb-4">For Event Organizers</h2>
                    <p class="lead mb-4">Make your events memorable with our simple photo sharing solution</p>
                    
                    <div class="check-item">
                        <span class="check-icon">
                            <i class="bi bi-check-circle-fill"></i>
                        </span>
                        <span class="check-text">Upload and manage all your event photos in one secure place</span>
                    </div>
                    
                    <div class="check-item">
                        <span class="check-icon">
                            <i class="bi bi-check-circle-fill"></i>
                        </span>
                        <span class="check-text">Generate unique QR codes for each event to share with attendees</span>
                    </div>
                    
                    <div class="check-item">
                        <span class="check-icon">
                            <i class="bi bi-check-circle-fill"></i>
                        </span>
                        <span class="check-text">Attendees can easily find photos they're in through facial recognition</span>
                    </div>
                    
                    <div class="check-item">
                        <span class="check-icon">
                            <i class="bi bi-check-circle-fill"></i>
                        </span>
                        <span class="check-text">Perfect for weddings, conferences, parties, corporate events and more</span>
                    </div>
                    
                    <div class="mt-5">
                        <a href="/register" class="btn btn-success me-3">Sign Up Free</a>
                        <a href="/admin" class="btn btn-primary">Log In</a>
                    </div>
                </div>
                <div class="col-lg-6">
                    <img src="https://images.unsplash.com/photo-1511795409834-ef04bbd61622?ixlib=rb-4.0.3&ixid=M3wxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8fA%3D%3D&auto=format&fit=crop&w=1169&q=80" alt="Event Organizer Dashboard" class="img-fluid rounded-3 shadow">
                </div>
            </div>
        </div>
    </section>
    
    <!-- Testimonials -->
    <section id="testimonials" class="container mb-5">
        <div class="section-title">
            <h2>What Our Users Say</h2>
            <p>Trusted by event organizers and attendees</p>
        </div>
        
        <div class="row g-4">
            <div class="col-md-4">
                <div class="testimonial-card">
                    <div class="testimonial-stars">
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                    </div>
                    <p class="testimonial-text">"We used Event Snap for our wedding and it was amazing! Our guests loved being able to find their photos so easily without creating accounts."</p>
                    <div class="testimonial-author">
                        <div class="author-avatar" style="background-color: #5D4FE8;">JM</div>
                        <div class="author-info">
                            <h6>Jessica Miller</h6>
                            <small class="text-muted">Wedding Organizer</small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="testimonial-card">
                    <div class="testimonial-stars">
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                    </div>
                    <p class="testimonial-text">"As a corporate event planner, this service has saved me countless hours managing and distributing photos to attendees."</p>
                    <div class="testimonial-author">
                        <div class="author-avatar" style="background-color: #10B981;">RC</div>
                        <div class="author-info">
                            <h6>Robert Chen</h6>
                            <small class="text-muted">Event Planner</small>
                        </div>
                    </div>
                </div>
            </div>
            <div class="col-md-4">
                <div class="testimonial-card">
                    <div class="testimonial-stars">
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                        <i class="bi bi-star-fill"></i>
                    </div>
                    <p class="testimonial-text">"I attended a conference and was able to find all my photos instantly. The facial recognition is amazingly accurate!"</p>
                    <div class="testimonial-author">
                        <div class="author-avatar" style="background-color: #4AC2F2;">AP</div>
                        <div class="author-info">
                            <h6>Alicia Patel</h6>
                            <small class="text-muted">Conference Attendee</small>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </section>
    
    <!-- Footer -->
    <footer>
        <div class="container">
            <div class="row">
                <div class="col-lg-4 mb-5 mb-lg-0">
                    <h5>Event Snap</h5>
                    <p>Making memories accessible through innovative facial recognition technology.</p>
                    <div class="social-icons mt-4">
                        <a href="#"><i class="bi bi-facebook"></i></a>
                        <a href="#"><i class="bi bi-instagram"></i></a>
                        <a href="#"><i class="bi bi-twitter"></i></a>
                        <a href="#"><i class="bi bi-linkedin"></i></a>
                    </div>
                </div>
                <div class="col-lg-2 col-md-3 col-6 mb-4 mb-md-0">
                    <h5>Site</h5>
                    <ul class="list-unstyled">
                        <li><a href="/">Home</a></li>
                        <li><a href="#how-it-works">How It Works</a></li>
                        <li><a href="#features">Features</a></li>
                        <li><a href="#testimonials">Testimonials</a></li>
                    </ul>
                </div>
                <div class="col-lg-2 col-md-3 col-6 mb-4 mb-md-0">
                    <h5>Support</h5>
                    <ul class="list-unstyled">
                        <li><a href="#">Help Center</a></li>
                        <li><a href="#">Privacy Policy</a></li>
                        <li><a href="#">Terms of Service</a></li>
                        <li><a href="#">Contact Us</a></li>
                    </ul>
                </div>
                <div class="col-lg-4 mt-4 mt-lg-0">
                    <h5>Stay Updated</h5>
                    <p>Subscribe to our newsletter for tips and updates.</p>
                    <form class="newsletter-form mt-4">
                        <div class="input-group">
                            <input type="email" class="form-control" placeholder="Your email address">
                            <button class="btn btn-primary" type="submit">Subscribe</button>
                        </div>
                    </form>
                </div>
            </div>
            <div class="footer-bottom">
                <p>&copy; 2025 Event Snap. All rights reserved.</p>
            </div>
        </div>
    </footer>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Fade up animation
        document.addEventListener('DOMContentLoaded', function() {
            const fadeElements = document.querySelectorAll('.fade-up');
            
            function checkFade() {
                fadeElements.forEach(element => {
                    const elementTop = element.getBoundingClientRect().top;
                    const windowHeight = window.innerHeight;
                    
                    if (elementTop < windowHeight - 100) {
                        element.classList.add('active');
                    }
                });
            }
            
            window.addEventListener('scroll', checkFade);
            checkFade(); // Check on page load
        });
    </script>
</body>
</html>
    ''',
    
    'admin_login.html': '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Admin Login | Event Snap</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    <style>
        :root {
            --primary-color: #5D4FE8;
            --primary-dark: #4A40CC;
            --secondary-color: #4AC2F2;
            --accent-color: #FF5A87;
            --dark-color: #11142D;
            --light-color: #F8F9FA;
            --text-color: #4B5563;
            --gradient-bg: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
            --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
        }
        
        body {
            background: var(--gradient-bg);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            padding: 20px;
        }
        
        .login-container {
            width: 100%;
            max-width: 1100px;
        }
        
        .login-card {
            border-radius: 20px;
            overflow: hidden;
            box-shadow: var(--card-shadow);
            background-color: white;
        }
        
        .navbar-brand {
            font-weight: 700;
            font-size: 1.5rem;
            color: var(--primary-color) !important;
            letter-spacing: -0.5px;
        }
        
        .login-header {
            text-align: center;
            padding: 40px 20px 20px;
        }
        
        .login-header h2 {
            color: var(--primary-color);
            font-weight: 800;
            font-size: 2.2rem;
            margin-bottom: 15px;
        }
        
        .login-header p {
            color: var(--text-color);
            font-size: 1.1rem;
            max-width: 400px;
            margin: 0 auto;
        }

        .login-body {
            padding: 30px 40px 40px;
        }
        
        .login-image {
            background: var(--gradient-bg);
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            padding: 40px;
            position: relative;
            overflow: hidden;
            height: 100%;
        }
        
        .login-image::before,
        .login-image::after {
            content: "";
            position: absolute;
            border-radius: 50%;
            background: rgba(255,255,255,0.1);
        }
        
        .login-image::before {
            width: 300px;
            height: 300px;
            top: -100px;
            right: -100px;
        }
        
        .login-image::after {
            width: 200px;
            height: 200px;
            bottom: -50px;
            left: -50px;
        }
        
        .login-image h3 {
            font-weight: 700;
            margin-bottom: 25px;
            font-size: 1.8rem;
            position: relative;
            z-index: 1;
        }
        
        .login-image-content {
            position: relative;
            z-index: 1;
            text-align: center;
        }
        
        .form-floating {
            margin-bottom: 20px;
        }
        
        .form-control {
            border-radius: 12px;
            padding: 15px 20px;
            height: 55px;
            border: 2px solid #e9ecef;
            font-size: 1rem;
        }
        
        .form-floating label {
            padding: 1rem 1.25rem;
            color: #858796;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 0.25rem rgba(93, 79, 232, 0.15);
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            padding: 12px 20px;
            font-weight: 600;
            border-radius: 12px;
            height: 55px;
            font-size: 1.1rem;
            transition: all 0.3s ease;
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.4);
        }
        
        .form-check-input:checked {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
        }
        
        .alert {
            border-radius: 12px;
            margin-bottom: 20px;
            padding: 15px;
            font-weight: 500;
            border: none;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .alert-danger {
            background-color: #FFE5E5;
            color: #D30000;
        }
        
        .alert-success {
            background-color: #E5FFF2;
            color: #00A86B;
        }
        
        .form-icon {
            position: relative;
        }
        
        .form-icon i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #858796;
            z-index: 2;
            font-size: 1.2rem;
        }
        
        .form-icon input {
            padding-left: 45px;  
        }
        
        .toggle-password {
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            cursor: pointer;
            color: #858796;
            z-index: 2;
            font-size: 1.2rem;
        }
        
        .link-primary {
            color: var(--primary-color);
            text-decoration: none;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .link-primary:hover {
            color: var(--primary-dark);
        }
        
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 15px;
            color: white;
        }
        
        .feature-row {
            margin-top: 40px;
        }
        
        .feature-item {
            text-align: center;
            padding: 10px;
        }
        
        .feature-item p {
            margin-top: 5px;
            margin-bottom: 0;
            font-size: 0.9rem;
            opacity: 0.9;
        }
        
        @media (max-width: 991px) {
            .login-image {
                display: none;
            }
        }
    </style>
</head>
<body>
    <div class="login-container">
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} d-flex align-items-center mb-4">
                        <i class="fas fa-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                        <div>{{ message }}</div>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="row g-0 login-card">
            <div class="col-lg-6">
                <div class="login-header">
                    <a href="/" class="navbar-brand d-flex align-items-center justify-content-center mb-4">
                        <i class="fas fa-camera-retro me-2"></i>Event Snap
                    </a>
                    <h2>Welcome Back</h2>
                    <p>Sign in to your admin account to manage events and photos</p>
                </div>
                <div class="login-body">
                    <form method="post" action="/admin/login">
                        <div class="form-icon mb-4">
                            <i class="fas fa-user"></i>
                            <input type="text" class="form-control" id="username" name="username" placeholder="Username" required>
                        </div>
                        <div class="form-icon mb-4">
                            <i class="fas fa-lock"></i>
                            <input type="password" class="form-control" id="password" name="password" placeholder="Password" required>
                            <i class="toggle-password fas fa-eye"></i>
                        </div>
                        <div class="row mb-4">
                            <div class="col">
                                <div class="form-check">
                                    <input class="form-check-input" type="checkbox" id="remember" name="remember">
                                    <label class="form-check-label" for="remember">Remember me</label>
                                </div>
                            </div>
                            <div class="col text-end">
                                <a href="#" class="link-primary">Forgot password?</a>
                            </div>
                        </div>
                        <div class="d-grid mb-4">
                            <button type="submit" class="btn btn-primary">
                                Sign In
                            </button>
                        </div>
                                            <div class="text-center">
                        <p class="text-muted">Need an account? <a href="/register" class="link-primary">Create account</a> | <a href="#" class="link-primary">Contact support</a></p>
                    </div>
                    </form>
                </div>
            </div>
            <div class="col-lg-6 login-image">
                <div class="login-image-content">
                    <h3>Event Photo Management</h3>
                    <p>Access the admin dashboard to upload, organize, and share event photos with your attendees.</p>
                    
                    <div class="row feature-row">
                        <div class="col-4 feature-item">
                            <i class="fas fa-upload feature-icon"></i>
                            <p>Upload Photos</p>
                        </div>
                        <div class="col-4 feature-item">
                            <i class="fas fa-qrcode feature-icon"></i>
                            <p>Generate QR Codes</p>
                        </div>
                        <div class="col-4 feature-item">
                            <i class="fas fa-face-smile feature-icon"></i>
                            <p>Facial Recognition</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const togglePassword = document.querySelector('.toggle-password');
            const passwordInput = document.querySelector('#password');
            
            togglePassword.addEventListener('click', function() {
                const type = passwordInput.getAttribute('type') === 'password' ? 'text' : 'password';
                passwordInput.setAttribute('type', type);
                this.classList.toggle('fa-eye');
                this.classList.toggle('fa-eye-slash');
            });
        });
    </script>
</body>
</html>
    ''',
    
    'admin_account.html': '''
    <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Account Settings | Event Snap</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
    <style>
        :root {
            --primary-color: #5D4FE8;
            --primary-light: #EAE8FD;
            --primary-dark: #4A40CC;
            --secondary-color: #4AC2F2;
            --accent-color: #FF5A87;
            --dark-color: #11142D;
            --light-color: #F8F9FA;
            --text-color: #4B5563;
            --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
            --border-radius: 15px;
        }
        
        body { 
            padding: 0;
            font-family: 'Poppins', 'Segoe UI', sans-serif;
            color: var(--text-color);
            background-color: #F5F7FE;
            min-height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            background-color: white;
            position: fixed;
            top: 0;
            left: 0;
            bottom: 0;
            width: 250px;
            box-shadow: var(--card-shadow);
            z-index: 1000;
            transition: all 0.3s ease;
            overflow-y: auto;
        }
        
        .sidebar-header {
            padding: 25px 20px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .brand-logo {
            font-weight: 800;
            font-size: 1.4rem;
            color: var(--primary-color);
            text-decoration: none;
            display: flex;
            align-items: center;
        }
        
        .brand-logo i {
            margin-right: 10px;
            font-size: 1.5rem;
        }
        
        .nav-menu {
            padding: 15px 0;
        }
        
        .menu-item {
            padding: 10px 20px;
            margin-bottom: 5px;
            display: flex;
            align-items: center;
            cursor: pointer;
            text-decoration: none;
            color: var(--text-color);
            border-radius: 0 30px 30px 0;
            transition: all 0.3s ease;
        }
        
        .menu-item:hover, .menu-item.active {
            background-color: var(--primary-light);
            color: var(--primary-color);
        }
        
        .menu-item.active {
            border-left: 4px solid var(--primary-color);
            font-weight: 600;
        }
        
        .menu-item i {
            margin-right: 10px;
            font-size: 1.2rem;
        }
        
        /* Main Content */
        .main-content {
            margin-left: 250px;
            padding: 30px;
            transition: all 0.3s ease;
        }
        
        .card {
            border: none;
            border-radius: var(--border-radius);
            box-shadow: var(--card-shadow);
            overflow: hidden;
            margin-bottom: 30px;
            background-color: white;
        }
        
        .card-header {
            background-color: white;
            padding: 25px 30px;
            border-bottom: 1px solid rgba(0,0,0,0.05);
        }
        
        .card-header h3 {
            font-weight: 700;
            margin: 0;
            color: var(--dark-color);
            font-size: 1.3rem;
        }
        
        .card-body {
            padding: 30px;
        }
        
        .form-control {
            border-radius: 12px;
            padding: 12px 15px;
            border: 2px solid #E5E7EB;
            font-size: 1rem;
            transition: all 0.3s ease;
        }
        
        .form-control:focus {
            border-color: var(--primary-color);
            box-shadow: 0 0 0 4px rgba(93, 79, 232, 0.15);
        }
        
        .form-label {
            font-weight: 600;
            color: var(--dark-color);
            margin-bottom: 8px;
        }
        
        .form-text {
            color: var(--text-color);
            font-size: 0.9rem;
        }
        
        .btn {
            padding: 12px 20px;
            font-weight: 600;
            border-radius: 12px;
            transition: all 0.3s ease;
        }
        
        .btn-primary {
            background-color: var(--primary-color);
            border-color: var(--primary-color);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
        }
        
        .btn-primary:hover {
            background-color: var(--primary-dark);
            border-color: var(--primary-dark);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
        }
        
        .alert {
            border-radius: 12px;
            border: none;
            padding: 15px 20px;
            font-weight: 500;
            margin-bottom: 25px;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
        }
        
        .section-title {
            color: var(--primary-color);
            font-weight: 700;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid rgba(0,0,0,0.05);
        }
        
        hr {
            margin: 30px 0;
            opacity: 0.1;
        }
        
        .input-group-text {
            background-color: white;
            border: 2px solid #E5E7EB;
            border-left: none;
            border-top-right-radius: 12px;
            border-bottom-right-radius: 12px;
        }
        
        .avatar-section {
            text-align: center;
            margin-bottom: 20px;
        }
        
        .avatar-img {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            border: 3px solid var(--primary-color);
            padding: 3px;
            background-color: white;
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.2);
            margin: 0 auto;
        }
        
        .password-toggle {
            cursor: pointer;
            position: absolute;
            right: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-color);
            z-index: 10;
        }
        
        .password-field {
            position: relative;
        }
        
        .input-icon {
            position: relative;
        }
        
        .input-icon i {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-color);
            z-index: 10;
        }
        
        .input-icon input {
            padding-left: 45px;
        }
        
        .user-avatar {
            display: inline-block;
            width: 40px;
            height: 40px;
            border-radius: 10px;
            background-color: var(--primary-light);
            color: var(--primary-color);
            display: flex;
            align-items: center;
            justify-content: center;
            font-weight: 700;
            font-size: 1rem;
        }
        
        .avatar-upload {
            position: relative;
            margin-top: 10px;
        }
        
        .avatar-upload label {
            display: inline-block;
            background-color: var(--primary-color);
            color: white;
            padding: 8px 15px;
            border-radius: 30px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: all 0.3s ease;
        }
        
        .avatar-upload label:hover {
            background-color: var(--primary-dark);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
        }
        
        .avatar-upload input {
            display: none;
        }
        
        .tab-pane {
            padding-top: 20px;
        }
        
        .nav-tabs {
            border-bottom: none;
        }
        
        .nav-tabs .nav-link {
            border: none;
            border-radius: 12px 12px 0 0;
            padding: 12px 20px;
            font-weight: 600;
            color: var(--text-color);
        }
        
        .nav-tabs .nav-link.active {
            background-color: white;
            color: var(--primary-color) !important;
            border-bottom: 3px solid var(--primary-color);
        }
        
        .navbar-mobile {
            display: none;
            background-color: white;
            padding: 15px 20px;
            box-shadow: var(--card-shadow);
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            z-index: 1000;
        }
        
        .menu-toggle {
            background: none;
            border: none;
            font-size: 1.5rem;
            color: var(--dark-color);
            cursor: pointer;
        }
        
        @media (max-width: 991px) {
            .sidebar {
                transform: translateX(-100%);
            }
            
            .sidebar.active {
                transform: translateX(0);
            }
            
            .main-content {
                margin-left: 0;
                padding: 90px 20px 30px;
            }
            
            .navbar-mobile {
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            
            .close-sidebar {
                display: block;
                position: absolute;
                top: 20px;
                right: 20px;
                font-size: 1.5rem;
                cursor: pointer;
                color: var(--dark-color);
                background: none;
                border: none;
            }
        }
    </style>
</head>
<body>
    <!-- Mobile Navbar -->
    <nav class="navbar-mobile">
        <button class="menu-toggle" id="menuToggle">
            <i class="bi bi-list"></i>
        </button>
        <a href="/" class="brand-logo">
            <i class="bi bi-camera"></i>Event Snap
        </a>
        <div class="user-avatar">
            {{ session.get('admin_username', 'A')[0].upper() }}
        </div>
    </nav>
    
    <!-- Sidebar -->
    <div class="sidebar" id="sidebar">
        <button class="close-sidebar" id="closeSidebar">
            <i class="bi bi-x-lg"></i>
        </button>
        <div class="sidebar-header">
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
        </div>
        <div class="nav-menu">
            <a href="/admin/dashboard" class="menu-item">
                <i class="bi bi-speedometer2"></i>Dashboard
            </a>
            <a href="/admin/event/new" class="menu-item">
                <i class="bi bi-plus-circle"></i>New Event
            </a>
            <a href="/admin/account" class="menu-item active">
                <i class="bi bi-person"></i>Account Settings
            </a>
            <a href="/admin/logout" class="menu-item">
                <i class="bi bi-box-arrow-right"></i>Logout
            </a>
        </div>
    </div>
    
    <div class="main-content">
        
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="alert alert-{{ 'danger' if category == 'error' else category }} d-flex align-items-center">
                        <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                        <div>{{ message }}</div>
                    </div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="row">
            <div class="col-lg-4 mb-4">
                <div class="card">
                    <div class="card-header">
                        <h3><i class="bi bi-person me-2"></i>Profile</h3>
                    </div>
                    <div class="card-body">
                        <div class="avatar-section">
                            <div class="avatar-img d-flex align-items-center justify-content-center" style="background-color: var(--primary-light); color: var(--primary-color); font-size: 3rem; font-weight: 700;">
                                {{ admin.get('name', username)[0].upper() if admin.get('name', username) else username[0].upper() }}
                            </div>
                            <div class="avatar-upload">
                                <label for="avatar-input" class="btn btn-sm btn-primary mt-3">
                                    <i class="bi bi-camera me-1"></i>Change Photo
                                </label>
                                <p class="text-muted small mt-2">Coming soon</p>
                                <input type="file" id="avatar-input" accept="image/*" disabled>
                            </div>
                        </div>
                        <div class="text-center mb-4">
                            <h4>{{ admin.get('name', 'Admin User') }}</h4>
                            <p class="text-muted">{{ username }}</p>
                        </div>
                        <div class="d-grid">
                            <a href="/admin/dashboard" class="btn btn-primary">
                                <i class="bi bi-speedometer2 me-2"></i>Go to Dashboard
                            </a>
                        </div>
                    </div>
                </div>
                
                <div class="card">
                    <div class="card-header">
                        <h3><i class="bi bi-info-circle me-2"></i>Account Info</h3>
                    </div>
                    <div class="card-body">
                        <ul class="list-group list-group-flush">
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-person-badge me-2"></i>Role</span>
                                <span class="badge bg-primary rounded-pill">Administrator</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-calendar me-2"></i>Joined</span>
                                <span>Jan 15, 2023</span>
                            </li>
                            <li class="list-group-item d-flex justify-content-between align-items-center">
                                <span><i class="bi bi-images me-2"></i>Total Events</span>
                                <span>24</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </div>
            
            <div class="col-lg-8">
                <div class="card">
                    <div class="card-header">
                        <h2><i class="fas fa-cog me-2"></i>Account Settings</h2>
                    </div>
                    <div class="card-body">
                        <ul class="nav nav-tabs" id="accountTabs" role="tablist">
                            <li class="nav-item" role="presentation">
                                <button class="nav-link active" id="profile-tab" data-bs-toggle="tab" data-bs-target="#profile" type="button" role="tab">
                                    <i class="fas fa-user-edit me-2"></i>Profile
                                </button>
                            </li>
                            <li class="nav-item" role="presentation">
                                <button class="nav-link" id="security-tab" data-bs-toggle="tab" data-bs-target="#security" type="button" role="tab">
                                    <i class="fas fa-shield-alt me-2"></i>Security
                                </button>
                            </li>
                        </ul>
                        
                        <div class="tab-content" id="accountTabsContent">
                            <div class="tab-pane fade show active" id="profile" role="tabpanel">
                                <form method="post" action="/admin/account">
                                    <div class="mb-4">
                                        <label class="form-label">Username</label>
                                        <div class="input-icon">
                                            <i class="fas fa-user"></i>
                                            <input type="text" class="form-control" value="{{ username }}" readonly>
                                        </div>
                                        <div class="form-text">Username cannot be changed</div>
                                    </div>
                                    <div class="mb-4">
                                        <label for="name" class="form-label">Full Name</label>
                                        <div class="input-icon">
                                            <i class="fas fa-id-card"></i>
                                            <input type="text" class="form-control" id="name" name="name" value="{{ admin.get('name', '') }}" placeholder="Enter your full name">
                                        </div>
                                    </div>
                                    <div class="mb-4">
                                        <label for="email" class="form-label">Email Address</label>
                                        <div class="input-icon">
                                            <i class="fas fa-envelope"></i>
                                            <input type="email" class="form-control" id="email" name="email" value="{{ admin.get('email', '') }}" placeholder="Enter your email">
                                        </div>
                                    </div>
                                    <div class="mb-4">
                                        <label for="phone" class="form-label">Phone Number</label>
                                        <div class="input-icon">
                                            <i class="fas fa-phone"></i>
                                            <input type="tel" class="form-control" id="phone" name="phone" value="{{ admin.get('phone', '') }}" placeholder="Enter your phone number">
                                        </div>
                                    </div>
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="bi bi-save me-2"></i>Save Profile Changes
                                        </button>
                                    </div>
                                </form>
                            </div>
                            
                            <div class="tab-pane fade" id="security" role="tabpanel">
                                <form method="post" action="/admin/account/password">
                                    <div class="mb-4">
                                        <label for="current_password" class="form-label">Current Password</label>
                                        <div class="password-field">
                                            <div class="input-icon">
                                                <i class="bi bi-lock"></i>
                                                <input type="password" class="form-control" id="current_password" name="current_password" placeholder="Enter your current password">
                                            </div>
                                            <i class="bi bi-eye password-toggle"></i>
                                        </div>
                                    </div>
                                    <div class="mb-4">
                                        <label for="new_password" class="form-label">New Password</label>
                                        <div class="password-field">
                                            <div class="input-icon">
                                                <i class="bi bi-key"></i>
                                                <input type="password" class="form-control" id="new_password" name="new_password" placeholder="Enter your new password">
                                            </div>
                                            <i class="bi bi-eye password-toggle"></i>
                                        </div>
                                        <div class="form-text">Leave blank to keep current password</div>
                                    </div>
                                    <div class="mb-4">
                                        <label for="confirm_password" class="form-label">Confirm New Password</label>
                                        <div class="password-field">
                                            <div class="input-icon">
                                                <i class="bi bi-check-circle"></i>
                                                <input type="password" class="form-control" id="confirm_password" name="confirm_password" placeholder="Confirm your new password">
                                            </div>
                                            <i class="bi bi-eye password-toggle"></i>
                                        </div>
                                    </div>
                                    
                                    <div class="alert alert-info d-flex align-items-center mt-4">
                                        <i class="bi bi-info-circle me-2"></i>
                                        <div>
                                            For a strong password, use at least 8 characters with a mix of letters, numbers, and symbols.
                                        </div>
                                    </div>
                                    
                                    <div class="d-grid">
                                        <button type="submit" class="btn btn-primary">
                                            <i class="bi bi-lock me-2"></i>Change Password
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        document.addEventListener('DOMContentLoaded', function() {
            // Password toggle functionality
            document.querySelectorAll('.password-toggle').forEach(toggle => {
                toggle.addEventListener('click', function() {
                    const input = this.previousElementSibling.querySelector('input');
                    const type = input.getAttribute('type') === 'password' ? 'text' : 'password';
                    input.setAttribute('type', type);
                    this.classList.toggle('bi-eye');
                    this.classList.toggle('bi-eye-slash');
                });
            });
            
            // Mobile sidebar functionality
            const menuToggle = document.getElementById('menuToggle');
            const closeSidebar = document.getElementById('closeSidebar');
            const sidebar = document.getElementById('sidebar');
            
            if (menuToggle) {
                menuToggle.addEventListener('click', function() {
                    sidebar.classList.add('active');
                });
            }
            
            if (closeSidebar) {
                closeSidebar.addEventListener('click', function() {
                    sidebar.classList.remove('active');
                });
            }
        });
    </script>
</body>
</html>
    ''',
    
    'admin_dashboard.html': '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{% if session.get('admin_role') == 'admin' %}Admin{% else %}User{% endif %} Dashboard | Event Snap</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root {
                --primary-color: #5D4FE8;
                --primary-light: #EAE8FD;
                --primary-dark: #4A40CC;
                --secondary-color: #4AC2F2;
                --accent-color: #FF5A87;
                --dark-color: #11142D;
                --light-color: #F8F9FA;
                --text-color: #4B5563;
                --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
                --border-radius: 15px;
            }
            
            body { 
                padding: 0;
                font-family: 'Poppins', 'Segoe UI', sans-serif;
                color: var(--text-color);
                background-color: #F5F7FE;
                min-height: 100vh;
            }
            
            /* Sidebar */
            .sidebar {
                background-color: white;
                position: fixed;
                top: 0;
                left: 0;
                bottom: 0;
                width: 250px;
                box-shadow: var(--card-shadow);
                z-index: 1000;
                transition: all 0.3s ease;
                overflow-y: auto;
            }
            
            .sidebar-header {
                padding: 25px 20px;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .brand-logo {
                font-weight: 800;
                font-size: 1.4rem;
                color: var(--primary-color);
                text-decoration: none;
                display: flex;
                align-items: center;
            }
            
            .brand-logo i {
                margin-right: 10px;
                font-size: 1.5rem;
            }
            
            .nav-menu {
                padding: 15px 0;
            }
            
            .menu-item {
                padding: 10px 20px;
                margin-bottom: 5px;
                display: flex;
                align-items: center;
                cursor: pointer;
                text-decoration: none;
                color: var(--text-color);
                border-radius: 0 30px 30px 0;
                transition: all 0.3s ease;
            }
            
            .menu-item:hover, .menu-item.active {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .menu-item.active {
                border-left: 4px solid var(--primary-color);
                font-weight: 600;
            }
            
            .menu-item i {
                margin-right: 10px;
                font-size: 1.2rem;
            }
            
            /* Main Content */
            .main-content {
                margin-left: 250px;
                padding: 30px;
                transition: all 0.3s ease;
            }
            
            .content-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }
            
            .content-title {
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.8rem;
            }
            
            /* Cards */
            .stat-card {
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
                padding: 25px;
                margin-bottom: 30px;
                transition: all 0.3s ease;
            }
            
            .stat-card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 35px rgba(0,0,0,0.12);
            }
            
            .stat-icon {
                width: 60px;
                height: 60px;
                display: flex;
                align-items: center;
                justify-content: center;
                border-radius: 15px;
                margin-bottom: 15px;
                font-size: 1.8rem;
            }
            
            .stat-value {
                font-size: 2rem;
                font-weight: 700;
                color: var(--dark-color);
                margin-bottom: 5px;
            }
            
            .stat-label {
                color: var(--text-color);
                font-size: 1rem;
            }
            
            .purple-bg {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .blue-bg {
                background-color: rgba(74, 194, 242, 0.15);
                color: var(--secondary-color);
            }
            
            .pink-bg {
                background-color: rgba(255, 90, 135, 0.15);
                color: var(--accent-color);
            }
            
            .green-bg {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10B981;
            }
            
            /* Tables */
            .table-card {
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
                overflow: hidden;
                transition: all 0.3s ease;
            }
            
            .table-card-header {
                padding: 20px 25px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .table-card-title {
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.2rem;
                margin: 0;
            }
            
            .table {
                margin-bottom: 0;
            }
            
            .table th {
                border-top: none;
                border-bottom-width: 1px;
                font-weight: 700;
                text-transform: uppercase;
                font-size: 0.8rem;
                letter-spacing: 0.5px;
                color: var(--text-color);
                padding: 15px 25px;
                background-color: #F9FAFC;
            }
            
            .table td {
                padding: 15px 25px;
                vertical-align: middle;
                color: var(--dark-color);
                border-color: rgba(0,0,0,0.03);
            }
            
            .table tr:hover {
                background-color: #F5F7FE;
            }
            
            .action-button {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                padding: 8px 15px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 0.9rem;
                text-decoration: none;
                transition: all 0.3s ease;
            }
            
            .action-button i {
                margin-right: 5px;
            }
            
            .view-btn {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .view-btn:hover {
                background-color: var(--primary-color);
                color: white;
            }
            
            .date-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 600;
                background-color: #EAE8FD;
                color: var(--primary-color);
            }
            
            .photos-badge {
                display: inline-block;
                padding: 5px 10px;
                border-radius: 8px;
                font-size: 0.85rem;
                font-weight: 600;
                background-color: rgba(16, 185, 129, 0.15);
                color: #10B981;
            }
            
            .empty-state {
                padding: 40px;
                text-align: center;
            }
            
            .empty-state-icon {
                font-size: 4rem;
                color: var(--primary-color);
                margin-bottom: 20px;
                opacity: 0.7;
            }
            
            .empty-text {
                font-size: 1.2rem;
                margin-bottom: 20px;
                color: var(--text-color);
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                border-radius: 10px;
                font-weight: 600;
                padding: 10px 20px;
                transition: all 0.3s ease;
                box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
            }
            
            .btn-primary:hover {
                background-color: var(--primary-dark);
                border-color: var(--primary-dark);
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
            }
            
            .alert {
                border-radius: 12px;
                border: none;
                padding: 15px 20px;
                font-weight: 500;
                margin-bottom: 25px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            }
            
            .alert-success {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10B981;
            }
            
            .alert-danger {
                background-color: rgba(255, 90, 135, 0.15);
                color: var(--accent-color);
            }
            
            .alert-info {
                background-color: rgba(74, 194, 242, 0.15);
                color: var(--secondary-color);
            }
            
            .welcome-card {
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
                border-radius: var(--border-radius);
                color: white;
                padding: 25px;
                margin-bottom: 30px;
                position: relative;
                overflow: hidden;
            }
            
            .welcome-card::before {
                content: "";
                position: absolute;
                width: 300px;
                height: 300px;
                border-radius: 50%;
                background: rgba(255,255,255,0.1);
                top: -100px;
                right: -100px;
            }
            
            .welcome-content {
                position: relative;
                z-index: 1;
            }
            
            .welcome-title {
                font-weight: 700;
                font-size: 1.5rem;
                margin-bottom: 10px;
            }
            
            .welcome-text {
                opacity: 0.9;
                margin-bottom: 0;
            }
            
            .user-avatar {
                display: inline-block;
                width: 40px;
                height: 40px;
                border-radius: 10px;
                background-color: var(--primary-light);
                color: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1rem;
            }
            
            .navbar-mobile {
                display: none;
                background-color: white;
                padding: 15px 20px;
                box-shadow: var(--card-shadow);
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 1000;
            }
            
            .menu-toggle {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: var(--dark-color);
                cursor: pointer;
            }
            
            @media (max-width: 991px) {
                .sidebar {
                    transform: translateX(-100%);
                }
                
                .sidebar.active {
                    transform: translateX(0);
                }
                
                .main-content {
                    margin-left: 0;
                    padding: 90px 20px 30px;
                }
                
                .navbar-mobile {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .close-sidebar {
                    display: block;
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--dark-color);
                    background: none;
                    border: none;
                }
            }
        </style>
    </head>
    <body>
        <!-- Mobile Navbar -->
        <nav class="navbar-mobile">
            <button class="menu-toggle" id="menuToggle">
                <i class="bi bi-list"></i>
            </button>
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
            <div class="user-avatar">
                {{ session.get('admin_username', 'A')[0].upper() }}
            </div>
        </nav>
        
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
            <button class="close-sidebar" id="closeSidebar">
                <i class="bi bi-x-lg"></i>
            </button>
            <div class="sidebar-header">
                <a href="/" class="brand-logo">
                    <i class="bi bi-camera"></i>Event Snap
                </a>
            </div>
            <div class="nav-menu">
                <a href="/admin/dashboard" class="menu-item active">
                    <i class="bi bi-speedometer2"></i>Dashboard
                </a>
                <a href="/admin/event/new" class="menu-item">
                    <i class="bi bi-plus-circle"></i>New Event
                </a>
                {% if session.get('admin_role') == 'admin' %}
                <a href="/admin/manage-accounts" class="menu-item">
                    <i class="bi bi-people"></i>Manage Users
                </a>
                {% endif %}
                <a href="/admin/account" class="menu-item">
                    <i class="bi bi-person"></i>Account Settings
                </a>
                <a href="/admin/logout" class="menu-item">
                    <i class="bi bi-box-arrow-right"></i>Logout
                </a>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                            <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="welcome-card">
                <div class="welcome-content">
                    <div class="welcome-title">Welcome, {{ session.get('admin_name', 'Admin') }}!</div>
                    <p class="welcome-text">
                        {% if session.get('admin_role') == 'admin' %}
                        Manage users, events and photos from this administrator dashboard
                        {% else %}
                        Manage your events and photos from this dashboard
                        {% endif %}
                    </p>
                </div>
            </div>
            
            <div class="row">
                <div class="col-lg-3 col-md-6">
                    <div class="stat-card">
                        <div class="stat-icon purple-bg">
                            <i class="bi bi-calendar-event"></i>
                        </div>
                        <div class="stat-value">{{ events|length }}</div>
                        <div class="stat-label">Total Events</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-card">
                        <div class="stat-icon blue-bg">
                            <i class="bi bi-images"></i>
                        </div>
                        <div class="stat-value">{% set total_photos = 0 %}{% for event in events %}{% if event.photo_count %}{% set total_photos = total_photos + event.photo_count %}{% endif %}{% endfor %}{{ total_photos }}</div>
                        <div class="stat-label">Total Photos</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-card">
                        <div class="stat-icon pink-bg">
                            <i class="bi bi-people"></i>
                        </div>
                        <div class="stat-value">-</div>
                        <div class="stat-label">Face Matches</div>
                    </div>
                </div>
                <div class="col-lg-3 col-md-6">
                    <div class="stat-card">
                        <div class="stat-icon green-bg">
                            <i class="bi bi-qr-code"></i>
                        </div>
                        <div class="stat-value">{{ events|length }}</div>
                        <div class="stat-label">Active QR Codes</div>
                    </div>
                </div>
            </div>
            
            <div class="content-header">
                <h1 class="content-title">
                    {% if session.get('admin_role') == 'admin' %}
                    All Events
                    {% else %}
                    Your Events
                    {% endif %}
                </h1>
                <a href="/admin/event/new" class="btn btn-primary">
                    <i class="bi bi-plus-lg me-2"></i>Create New Event
                </a>
            </div>
            
            {% if events %}
                <div class="table-card">
                    <div class="table-card-header">
                        <h2 class="table-card-title">{% if session.get('admin_role') == 'admin' %}All Events{% else %}Your Events{% endif %}</h2>
                    </div>
                    <div class="table-responsive">
                        <table class="table">
                            <thead>
                                <tr>
                                    <th>Event Name</th>
                                    <th>Date</th>
                                    <th>Photos</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for event in events %}
                                    <tr>
                                        <td>
                                            <div class="fw-bold">{{ event.name }}</div>
                                        </td>
                                        <td>
                                            <span class="date-badge">{{ event.date }}</span>
                                        </td>
                                        <td>
                                            <span class="photos-badge">{{ event.photo_count }} photos</span>
                                        </td>
                                        <td>{{ event.created_at|default('', true) }}</td>
                                        <td>
                                            <a href="/admin/event/{{ event.id }}" class="action-button view-btn">
                                                <i class="bi bi-eye"></i> View
                                            </a>
                                        </td>
                                    </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            {% else %}
                <div class="table-card">
                    <div class="empty-state">
                        <div class="empty-state-icon">
                            <i class="bi bi-calendar-plus"></i>
                        </div>
                        <div class="empty-text">No events found</div>
                        <p class="text-muted mb-4">Create your first event to get started</p>
                        <a href="/admin/event/new" class="btn btn-primary">
                            <i class="bi bi-plus-lg me-2"></i>Create New Event
                        </a>
                    </div>
                </div>
            {% endif %}
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const menuToggle = document.getElementById('menuToggle');
                const closeSidebar = document.getElementById('closeSidebar');
                const sidebar = document.getElementById('sidebar');
                
                if (menuToggle) {
                    menuToggle.addEventListener('click', function() {
                        sidebar.classList.add('active');
                    });
                }
                
                if (closeSidebar) {
                    closeSidebar.addEventListener('click', function() {
                        sidebar.classList.remove('active');
                    });
                }
            });
        </script>
    </body>
    </html>
    ''',
    
    'new_event.html': '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Create New Event | Event Snap</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root {
                --primary-color: #5D4FE8;
                --primary-light: #EAE8FD;
                --primary-dark: #4A40CC;
                --secondary-color: #4AC2F2;
                --accent-color: #FF5A87;
                --dark-color: #11142D;
                --light-color: #F8F9FA;
                --text-color: #4B5563;
                --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
                --border-radius: 15px;
            }
            
            body { 
                padding: 0;
                font-family: 'Poppins', 'Segoe UI', sans-serif;
                color: var(--text-color);
                background-color: #F5F7FE;
                min-height: 100vh;
            }
            
            /* Sidebar */
            .sidebar {
                background-color: white;
                position: fixed;
                top: 0;
                left: 0;
                bottom: 0;
                width: 250px;
                box-shadow: var(--card-shadow);
                z-index: 1000;
                transition: all 0.3s ease;
                overflow-y: auto;
            }
            
            .sidebar-header {
                padding: 25px 20px;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .brand-logo {
                font-weight: 800;
                font-size: 1.4rem;
                color: var(--primary-color);
                text-decoration: none;
                display: flex;
                align-items: center;
            }
            
            .brand-logo i {
                margin-right: 10px;
                font-size: 1.5rem;
            }
            
            .nav-menu {
                padding: 15px 0;
            }
            
            .menu-item {
                padding: 10px 20px;
                margin-bottom: 5px;
                display: flex;
                align-items: center;
                cursor: pointer;
                text-decoration: none;
                color: var(--text-color);
                border-radius: 0 30px 30px 0;
                transition: all 0.3s ease;
            }
            
            .menu-item:hover, .menu-item.active {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .menu-item.active {
                border-left: 4px solid var(--primary-color);
                font-weight: 600;
            }
            
            .menu-item i {
                margin-right: 10px;
                font-size: 1.2rem;
            }
            
            /* Main Content */
            .main-content {
                margin-left: 250px;
                padding: 30px;
                transition: all 0.3s ease;
            }
            
            .content-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }
            
            .content-title {
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.8rem;
            }
            
            /* Form Styles */
            .form-card {
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
                overflow: hidden;
                transition: all 0.3s ease;
            }
            
            .form-card-header {
                padding: 25px 30px;
                border-bottom: 1px solid rgba(0,0,0,0.05);
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
                color: white;
                position: relative;
                overflow: hidden;
            }
            
            .form-card-header::before {
                content: "";
                position: absolute;
                width: 150px;
                height: 150px;
                border-radius: 50%;
                background: rgba(255,255,255,0.1);
                top: -40px;
                right: -40px;
            }
            
            .form-card-title {
                font-weight: 700;
                font-size: 1.5rem;
                margin: 0;
                position: relative;
                z-index: 1;
            }
            
            .form-card-subtitle {
                opacity: 0.9;
                margin-top: 5px;
                margin-bottom: 0;
                position: relative;
                z-index: 1;
            }
            
            .form-card-body {
                padding: 30px;
            }
            
            .form-control {
                border-radius: 12px;
                padding: 12px 15px;
                border: 2px solid #E5E7EB;
                font-size: 1rem;
                transition: all 0.3s ease;
            }
            
            .form-control:focus {
                border-color: var(--primary-color);
                box-shadow: 0 0 0 4px rgba(93, 79, 232, 0.15);
            }
            
            .form-label {
                font-weight: 600;
                color: var(--dark-color);
                margin-bottom: 8px;
            }
            
            .form-text {
                color: var(--text-color);
                font-size: 0.9rem;
            }
            
            .btn {
                padding: 12px 20px;
                font-weight: 600;
                border-radius: 12px;
                transition: all 0.3s ease;
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
            }
            
            .btn-primary:hover {
                background-color: var(--primary-dark);
                border-color: var(--primary-dark);
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
            }
            
            .btn-secondary {
                background-color: #E5E7EB;
                border-color: #E5E7EB;
                color: var(--dark-color);
            }
            
            .btn-secondary:hover {
                background-color: #D1D5DB;
                border-color: #D1D5DB;
                color: var(--dark-color);
                transform: translateY(-3px);
            }
            
            .alert {
                border-radius: 12px;
                border: none;
                padding: 15px 20px;
                font-weight: 500;
                margin-bottom: 25px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            }
            
            .alert-success {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10B981;
            }
            
            .alert-danger {
                background-color: rgba(255, 90, 135, 0.15);
                color: var(--accent-color);
            }
            
            .alert-info {
                background-color: rgba(74, 194, 242, 0.15);
                color: var(--secondary-color);
            }
            
            .user-avatar {
                display: inline-block;
                width: 40px;
                height: 40px;
                border-radius: 10px;
                background-color: var(--primary-light);
                color: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1rem;
            }
            
            .navbar-mobile {
                display: none;
                background-color: white;
                padding: 15px 20px;
                box-shadow: var(--card-shadow);
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 1000;
            }
            
            .menu-toggle {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: var(--dark-color);
                cursor: pointer;
            }
            
            @media (max-width: 991px) {
                .sidebar {
                    transform: translateX(-100%);
                }
                
                .sidebar.active {
                    transform: translateX(0);
                }
                
                .main-content {
                    margin-left: 0;
                    padding: 90px 20px 30px;
                }
                
                .navbar-mobile {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .close-sidebar {
                    display: block;
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--dark-color);
                    background: none;
                    border: none;
                }
            }
        </style>
    </head>
    <body>
        <!-- Mobile Navbar -->
        <nav class="navbar-mobile">
            <button class="menu-toggle" id="menuToggle">
                <i class="bi bi-list"></i>
            </button>
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
            <div class="user-avatar">
                {{ session.get('admin_username', 'A')[0].upper() }}
            </div>
        </nav>
        
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
            <button class="close-sidebar" id="closeSidebar">
                <i class="bi bi-x-lg"></i>
            </button>
            <div class="sidebar-header">
                <a href="/" class="brand-logo">
                    <i class="bi bi-camera"></i>Event Snap
                </a>
            </div>
            <div class="nav-menu">
                <a href="/admin/dashboard" class="menu-item">
                    <i class="bi bi-speedometer2"></i>Dashboard
                </a>
                <a href="/admin/event/new" class="menu-item active">
                    <i class="bi bi-plus-circle"></i>New Event
                </a>
                <a href="/admin/account" class="menu-item">
                    <i class="bi bi-person"></i>Account Settings
                </a>
                <a href="/admin/logout" class="menu-item">
                    <i class="bi bi-box-arrow-right"></i>Logout
                </a>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                            <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="content-header">
                <h1 class="content-title">Create New Event</h1>
                <a href="/admin/dashboard" class="btn btn-secondary">
                    <i class="bi bi-arrow-left me-1"></i> Back to Dashboard
                </a>
            </div>
            
            <div class="row">
                <div class="col-lg-8 mx-auto">
                    <div class="form-card">
                        <div class="form-card-header">
                            <h2 class="form-card-title">Event Details</h2>
                            <p class="form-card-subtitle">Create a new event to start uploading and sharing photos</p>
                        </div>
                        <div class="form-card-body">
                            <form method="post" action="/admin/event/new">
                                <div class="mb-4">
                                    <label for="name" class="form-label">Event Name</label>
                                    <input type="text" class="form-control" id="name" name="name" placeholder="Enter event name" required>
                                    <div class="form-text">This will be displayed to attendees when they scan the QR code</div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="date" class="form-label">Event Date</label>
                                    <input type="date" class="form-control" id="date" name="date" required>
                                    <div class="form-text">The date when the event takes place</div>
                                </div>
                                
                                <div class="mb-4">
                                    <label for="description" class="form-label">Description (Optional)</label>
                                    <textarea class="form-control" id="description" name="description" rows="4" placeholder="Enter a short description of the event"></textarea>
                                    <div class="form-text">Provide additional details about your event</div>
                                </div>
                                
                                <div class="d-flex justify-content-end mt-5">
                                    <a href="/admin/dashboard" class="btn btn-secondary me-2">Cancel</a>
                                    <button type="submit" class="btn btn-primary">
                                        <i class="bi bi-calendar-plus me-1"></i> Create Event
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const menuToggle = document.getElementById('menuToggle');
                const closeSidebar = document.getElementById('closeSidebar');
                const sidebar = document.getElementById('sidebar');
                
                if (menuToggle) {
                    menuToggle.addEventListener('click', function() {
                        sidebar.classList.add('active');
                    });
                }
                
                if (closeSidebar) {
                    closeSidebar.addEventListener('click', function() {
                        sidebar.classList.remove('active');
                    });
                }
                
                // Set default date to today
                const dateInput = document.getElementById('date');
                if (dateInput) {
                    const today = new Date();
                    const year = today.getFullYear();
                    const month = String(today.getMonth() + 1).padStart(2, '0');
                    const day = String(today.getDate()).padStart(2, '0');
                    dateInput.value = `${year}-${month}-${day}`;
                }
            });
        </script>
    </body>
    </html>
    ''',
    
    'view_event.html': '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ event.name }} | Event Snap</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.0/font/bootstrap-icons.css">
        <style>
            :root {
                --primary-color: #5D4FE8;
                --primary-light: #EAE8FD;
                --primary-dark: #4A40CC;
                --secondary-color: #4AC2F2;
                --accent-color: #FF5A87;
                --dark-color: #11142D;
                --light-color: #F8F9FA;
                --text-color: #4B5563;
                --card-shadow: 0 10px 30px rgba(0,0,0,0.08);
                --border-radius: 15px;
            }
            
            body { 
                padding: 0;
                font-family: 'Poppins', 'Segoe UI', sans-serif;
                color: var(--text-color);
                background-color: #F5F7FE;
                min-height: 100vh;
            }
            
            /* Sidebar */
            .sidebar {
                background-color: white;
                position: fixed;
                top: 0;
                left: 0;
                bottom: 0;
                width: 250px;
                box-shadow: var(--card-shadow);
                z-index: 1000;
                transition: all 0.3s ease;
                overflow-y: auto;
            }
            
            .sidebar-header {
                padding: 25px 20px;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .brand-logo {
                font-weight: 800;
                font-size: 1.4rem;
                color: var(--primary-color);
                text-decoration: none;
                display: flex;
                align-items: center;
            }
            
            .brand-logo i {
                margin-right: 10px;
                font-size: 1.5rem;
            }
            
            .nav-menu {
                padding: 15px 0;
            }
            
            .menu-item {
                padding: 10px 20px;
                margin-bottom: 5px;
                display: flex;
                align-items: center;
                cursor: pointer;
                text-decoration: none;
                color: var(--text-color);
                border-radius: 0 30px 30px 0;
                transition: all 0.3s ease;
            }
            
            .menu-item:hover, .menu-item.active {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .menu-item.active {
                border-left: 4px solid var(--primary-color);
                font-weight: 600;
            }
            
            .menu-item i {
                margin-right: 10px;
                font-size: 1.2rem;
            }
            
            /* Main Content */
            .main-content {
                margin-left: 250px;
                padding: 30px;
                transition: all 0.3s ease;
            }
            
            .content-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 30px;
            }
            
            .content-title {
                font-weight: 700;
                color: var(--dark-color);
                font-size: 1.8rem;
            }
            
            /* Cards */
            .card {
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
                border: none;
                margin-bottom: 30px;
                overflow: hidden;
                transition: all 0.3s ease;
            }
            
            .card-header {
                padding: 25px 30px;
                background-color: white;
                border-bottom: 1px solid rgba(0,0,0,0.05);
            }
            
            .card-header h3 {
                font-weight: 700;
                margin: 0;
                color: var(--dark-color);
                font-size: 1.3rem;
            }
            
            .card-body {
                padding: 30px;
            }
            
            /* Photo Grid */
            .photo-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: 20px;
                margin-top: 20px;
            }
            
            .photo-item {
                position: relative;
                border-radius: 12px;
                overflow: hidden;
                aspect-ratio: 1/1;
                background-color: #f8f9fa;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                transition: all 0.3s ease;
            }
            
            .photo-item:hover {
                transform: translateY(-5px);
                box-shadow: 0 10px 25px rgba(0,0,0,0.15);
            }
            
            .photo-item img {
                width: 100%;
                height: 100%;
                object-fit: cover;
            }
            
            .photo-actions {
                position: absolute;
                bottom: 0;
                left: 0;
                right: 0;
                background: rgba(0,0,0,0.6);
                padding: 10px;
                display: flex;
                justify-content: flex-end;
                opacity: 0;
                transition: all 0.3s ease;
            }
            
            .photo-item:hover .photo-actions {
                opacity: 1;
            }
            
            .photo-action-btn {
                width: 36px;
                height: 36px;
                border-radius: 50%;
                display: flex;
                align-items: center;
                justify-content: center;
                background-color: white;
                color: var(--dark-color);
                border: none;
                margin-left: 8px;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .photo-action-btn:hover {
                background-color: var(--primary-color);
                color: white;
            }
            
            /* QR Code */
            .qr-code-container {
                text-align: center;
                padding: 30px;
                background-color: white;
                border-radius: var(--border-radius);
                box-shadow: var(--card-shadow);
            }
            
            .qr-code-container img {
                max-width: 200px;
                border-radius: 12px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.1);
                margin-bottom: 20px;
            }
            
            /* Form Styles */
            .form-control {
                border-radius: 12px;
                padding: 12px 15px;
                border: 2px solid #E5E7EB;
                font-size: 1rem;
                transition: all 0.3s ease;
            }
            
            .form-control:focus {
                border-color: var(--primary-color);
                box-shadow: 0 0 0 4px rgba(93, 79, 232, 0.15);
            }
            
            .input-group .form-control {
                border-right: none;
                border-top-right-radius: 0;
                border-bottom-right-radius: 0;
            }
            
            .input-group-text {
                border-top-right-radius: 12px;
                border-bottom-right-radius: 12px;
                border: 2px solid #E5E7EB;
                border-left: none;
                background-color: white;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .input-group-text:hover {
                background-color: var(--primary-light);
                color: var(--primary-color);
            }
            
            .btn {
                padding: 12px 20px;
                font-weight: 600;
                border-radius: 12px;
                transition: all 0.3s ease;
            }
            
            .btn-primary {
                background-color: var(--primary-color);
                border-color: var(--primary-color);
                box-shadow: 0 5px 15px rgba(93, 79, 232, 0.3);
            }
            
            .btn-primary:hover {
                background-color: var(--primary-dark);
                border-color: var(--primary-dark);
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(93, 79, 232, 0.4);
            }
            
            .btn-danger {
                background-color: var(--accent-color);
                border-color: var(--accent-color);
                box-shadow: 0 5px 15px rgba(255, 90, 135, 0.3);
            }
            
            .btn-danger:hover {
                background-color: #E03E67;
                border-color: #E03E67;
                transform: translateY(-3px);
                box-shadow: 0 8px 25px rgba(255, 90, 135, 0.4);
            }
            
            .alert {
                border-radius: 12px;
                border: none;
                padding: 15px 20px;
                font-weight: 500;
                margin-bottom: 25px;
                box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            }
            
            .alert-success {
                background-color: rgba(16, 185, 129, 0.15);
                color: #10B981;
            }
            
            .alert-danger {
                background-color: rgba(255, 90, 135, 0.15);
                color: var(--accent-color);
            }
            
            .alert-info {
                background-color: rgba(74, 194, 242, 0.15);
                color: var(--secondary-color);
            }
            
            /* Upload Area */
            .upload-area {
                border: 2px dashed #E5E7EB;
                border-radius: var(--border-radius);
                padding: 30px;
                text-align: center;
                transition: all 0.3s ease;
                cursor: pointer;
                margin-bottom: 20px;
            }
            
            .upload-area:hover, .upload-area.dragover {
                border-color: var(--primary-color);
                background-color: var(--primary-light);
            }
            
            .upload-icon {
                font-size: 3rem;
                color: var(--primary-color);
                margin-bottom: 15px;
            }
            
            .upload-text {
                margin-bottom: 5px;
                font-weight: 600;
                color: var(--dark-color);
            }
            
            .upload-hint {
                font-size: 0.9rem;
                color: var(--text-color);
                margin-bottom: 20px;
            }
            
            .file-input {
                display: none;
            }
            
            /* Event Info */
            .event-info {
                background: linear-gradient(135deg, var(--primary-color) 0%, var(--secondary-color) 100%);
                color: white;
                border-radius: var(--border-radius);
                padding: 30px;
                position: relative;
                overflow: hidden;
                margin-bottom: 30px;
            }
            
            .event-info::before {
                content: "";
                position: absolute;
                width: 300px;
                height: 300px;
                border-radius: 50%;
                background: rgba(255,255,255,0.1);
                top: -100px;
                right: -100px;
            }
            
            .event-info-content {
                position: relative;
                z-index: 1;
            }
            
            .event-title {
                font-weight: 800;
                font-size: 2rem;
                margin-bottom: 10px;
            }
            
            .event-date {
                font-size: 1.1rem;
                opacity: 0.9;
                margin-bottom: 15px;
                display: flex;
                align-items: center;
            }
            
            .event-date i {
                margin-right: 8px;
            }
            
            .event-description {
                margin-bottom: 20px;
                max-width: 600px;
                opacity: 0.9;
            }
            
            /* Empty State */
            .empty-state {
                padding: 50px 30px;
                text-align: center;
            }
            
            .empty-state-icon {
                font-size: 4rem;
                color: var(--primary-color);
                margin-bottom: 20px;
                opacity: 0.7;
            }
            
            .empty-text {
                font-size: 1.2rem;
                margin-bottom: 20px;
                color: var(--dark-color);
            }
            
            /* Modal */
            .modal-content {
                border: none;
                border-radius: var(--border-radius);
                overflow: hidden;
            }
            
            .modal-header {
                background-color: var(--primary-light);
                color: var(--primary-color);
                border-bottom: none;
                padding: 20px 25px;
            }
            
            .modal-title {
                font-weight: 700;
            }
            
            .modal-body {
                padding: 25px;
            }
            
            .modal-footer {
                border-top: none;
                padding: 20px 25px;
            }
            
            .user-avatar {
                display: inline-block;
                width: 40px;
                height: 40px;
                border-radius: 10px;
                background-color: var(--primary-light);
                color: var(--primary-color);
                display: flex;
                align-items: center;
                justify-content: center;
                font-weight: 700;
                font-size: 1rem;
            }
            
            .navbar-mobile {
                display: none;
                background-color: white;
                padding: 15px 20px;
                box-shadow: var(--card-shadow);
                position: fixed;
                top: 0;
                left: 0;
                right: 0;
                z-index: 1000;
            }
            
            .menu-toggle {
                background: none;
                border: none;
                font-size: 1.5rem;
                color: var(--dark-color);
                cursor: pointer;
            }
            
            @media (max-width: 991px) {
                .sidebar {
                    transform: translateX(-100%);
                }
                
                .sidebar.active {
                    transform: translateX(0);
                }
                
                .main-content {
                    margin-left: 0;
                    padding: 90px 20px 30px;
                }
                
                .navbar-mobile {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }
                
                .close-sidebar {
                    display: block;
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    font-size: 1.5rem;
                    cursor: pointer;
                    color: var(--dark-color);
                    background: none;
                    border: none;
                }
                
                .event-title {
                    font-size: 1.6rem;
                }
                
                .content-header {
                    flex-direction: column;
                    align-items: flex-start;
                }
                
                .content-header .btn {
                    margin-top: 15px;
                }
            }
        </style>
    </head>
    <body>
        <!-- Mobile Navbar -->
        <nav class="navbar-mobile">
            <button class="menu-toggle" id="menuToggle">
                <i class="bi bi-list"></i>
            </button>
            <a href="/" class="brand-logo">
                <i class="bi bi-camera"></i>Event Snap
            </a>
            <div class="user-avatar">
                {{ session.get('admin_username', 'A')[0].upper() }}
            </div>
        </nav>
        
        <!-- Sidebar -->
        <div class="sidebar" id="sidebar">
            <button class="close-sidebar" id="closeSidebar">
                <i class="bi bi-x-lg"></i>
            </button>
            <div class="sidebar-header">
                <a href="/" class="brand-logo">
                    <i class="bi bi-camera"></i>Event Snap
                </a>
            </div>
            <div class="nav-menu">
                <a href="/admin/dashboard" class="menu-item">
                    <i class="bi bi-speedometer2"></i>Dashboard
                </a>
                <a href="/admin/event/new" class="menu-item">
                    <i class="bi bi-plus-circle"></i>New Event
                </a>
                <a href="/admin/account" class="menu-item">
                    <i class="bi bi-person"></i>Account Settings
                </a>
                <a href="/admin/logout" class="menu-item">
                    <i class="bi bi-box-arrow-right"></i>Logout
                </a>
            </div>
        </div>
        
        <!-- Main Content -->
        <div class="main-content">
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="alert alert-{{ 'danger' if category == 'error' else category }}">
                            <i class="bi bi-{{ 'exclamation-circle' if category == 'error' else 'info-circle' }} me-2"></i>
                            {{ message }}
                        </div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="event-info">
                <div class="event-info-content">
                    <h1 class="event-title">{{ event.name }}</h1>
                    <div class="event-date">
                        <i class="bi bi-calendar3"></i> {{ event.date }}
                    </div>
                    {% if event.description %}
                        <p class="event-description">{{ event.description }}</p>
                    {% endif %}
                    <button type="button" class="btn btn-danger" data-bs-toggle="modal" data-bs-target="#deleteEventModal">
                        <i class="bi bi-trash me-1"></i> Delete Event
                    </button>
                </div>
            </div>
            
            <div class="row mb-4">
            
            <div class="card mb-4">
                <div class="card-header">
                    <h3>Share with Attendees</h3>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="qr-code-container">
                                <img src="{{ qr_code }}" alt="Event QR Code" class="img-fluid">
                                <p class="mt-2">Scan to access your photos</p>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="mb-3">
                                <label class="form-label">Event Link</label>
                                <div class="input-group">
                                    <input type="text" class="form-control" readonly value="{{ request.url_root }}event/{{ event_id }}" id="eventLink">
                                    <button class="btn btn-outline-secondary" type="button" onclick="copyEventLink()">Copy</button>
                                </div>
                            </div>
                            <p>Share this QR code or link with your event attendees. When they scan the QR code or visit the link, they'll be able to take a selfie and see all photos they appear in.</p>
                        </div>
                    </div>
                </div>
            </div>
            
            <div class="card mb-4">
                <div class="card-header d-flex justify-content-between align-items-center">
                    <h3>Upload Photos</h3>
                </div>
                <div class="card-body">
                    <form method="post" id="uploadForm" action="/admin/event/{{ event_id }}/upload" enctype="multipart/form-data">
                        <div class="mb-3">
                            <label for="photos" class="form-label">Select Photos</label>
                            <input class="form-control" type="file" id="photos" name="photos" multiple accept=".jpg,.jpeg,.png" required onchange="updateFileInfo()">
                            <div class="form-text" id="fileInfo">You can select multiple photos at once.</div>
                        </div>
                        <div class="progress mb-3" id="uploadProgress" style="display: none;">
                            <div class="progress-bar progress-bar-striped progress-bar-animated" id="uploadProgressBar" role="progressbar" aria-valuenow="0" aria-valuemin="0" aria-valuemax="100" style="width: 0%"></div>
                        </div>
                        <div id="uploadStatus" class="mb-3" style="display: none;">
                            <span class="text-primary">Uploading... <span id="uploadPercentage">0%</span></span>
                        </div>
                        <button type="submit" id="uploadBtn" class="btn btn-primary">Upload & Process</button>
                    </form>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <h3>Event Photos ({{ photos|length }})</h3>
                </div>
                <div class="card-body">
                    {% if photos %}
                        <div class="photo-grid">
                            {% for photo in photos %}
                                <div class="photo-item">
                                    <img src="/event/{{ event_id }}/photo/{{ photo }}" alt="Event photo">
                                    <div class="photo-actions">
                                        <a href="/event/{{ event_id }}/download/{{ photo }}" class="photo-action-btn" title="Download">
                                            <i class="bi bi-download"></i>
                                        </a>
                                        <button type="button" class="photo-action-btn" title="Delete" 
                                                onclick="confirmDeletePhoto('{{ photo }}')">
                                            <i class="bi bi-trash"></i>
                                        </button>
                                    </div>
                                </div>
                            {% endfor %}
                        </div>
                    {% else %}
                        <div class="alert alert-info">
                            No photos uploaded yet. Use the form above to upload photos.
                        </div>
                    {% endif %}
                </div>
            </div>
            
            <!-- Delete Event Modal -->
            <div class="modal fade" id="deleteEventModal" tabindex="-1" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Confirm Deletion</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p>Are you sure you want to delete this event and all its photos? This action cannot be undone.</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <form method="post" action="/admin/event/{{ event_id }}/delete">
                                <button type="submit" class="btn btn-danger">Delete Event</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Delete Photo Modal -->
            <div class="modal fade" id="deletePhotoModal" tabindex="-1" aria-hidden="true">
                <div class="modal-dialog">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">Confirm Photo Deletion</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                            <p>Are you sure you want to delete this photo? This action cannot be undone.</p>
                        </div>
                        <div class="modal-footer">
                            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
                            <form method="post" id="deletePhotoForm" action="">
                                <button type="submit" class="btn btn-danger">Delete Photo</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            function copyEventLink() {
                var copyText = document.getElementById("eventLink");
                copyText.select();
                copyText.setSelectionRange(0, 99999);
                navigator.clipboard.writeText(copyText.value);
                
                // Optional: Show feedback
                alert("Link copied to clipboard!");
            }
            
            function confirmDeletePhoto(filename) {
                // Set the form action to the correct endpoint
                document.getElementById('deletePhotoForm').action = '/admin/event/{{ event_id }}/photo/' + filename + '/delete';
                
                // Show the modal
                var deletePhotoModal = new bootstrap.Modal(document.getElementById('deletePhotoModal'));
                deletePhotoModal.show();
            }
            
            function updateFileInfo() {
                const fileInput = document.getElementById('photos');
                const fileInfo = document.getElementById('fileInfo');
                
                if (fileInput.files.length > 0) {
                    let totalSize = 0;
                    for (let i = 0; i < fileInput.files.length; i++) {
                        totalSize += fileInput.files[i].size;
                    }
                    
                    // Convert size to readable format
                    let sizeStr = '';
                    if (totalSize < 1024 * 1024) {
                        sizeStr = (totalSize / 1024).toFixed(2) + ' KB';
                    } else {
                        sizeStr = (totalSize / (1024 * 1024)).toFixed(2) + ' MB';
                    }
                    
                    fileInfo.innerHTML = `Selected ${fileInput.files.length} ${fileInput.files.length === 1 ? 'file' : 'files'} (${sizeStr})`;
                } else {
                    fileInfo.innerHTML = 'You can select multiple photos at once.';
                }
            }
            
            // Handle file uploads with progress
            document.addEventListener('DOMContentLoaded', function() {
                const uploadForm = document.getElementById('uploadForm');
                const uploadBtn = document.getElementById('uploadBtn');
                const progressBar = document.getElementById('uploadProgressBar');
                const uploadProgress = document.getElementById('uploadProgress');
                const uploadStatus = document.getElementById('uploadStatus');
                const uploadPercentage = document.getElementById('uploadPercentage');
                
                uploadForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    // Get form data
                    const formData = new FormData(uploadForm);
                    
                    // Create XMLHttpRequest
                    const xhr = new XMLHttpRequest();
                    
                    // Setup progress event
                    xhr.upload.addEventListener('progress', function(e) {
                        if (e.lengthComputable) {
                            const percentComplete = Math.round((e.loaded / e.total) * 100);
                            progressBar.style.width = percentComplete + '%';
                            progressBar.setAttribute('aria-valuenow', percentComplete);
                            uploadPercentage.textContent = percentComplete + '%';
                        }
                    });
                    
                    // Setup load event
                    xhr.addEventListener('load', function() {
                        if (xhr.status === 200) {
                            // Redirect to the same page to see the uploaded photos
                            window.location.href = window.location.href;
                        } else {
                            uploadStatus.innerHTML = '<span class="text-danger">Upload failed. Please try again.</span>';
                            uploadBtn.disabled = false;
                        }
                    });
                    
                    // Setup error event
                    xhr.addEventListener('error', function() {
                        uploadStatus.innerHTML = '<span class="text-danger">Upload failed. Please check your connection.</span>';
                        uploadBtn.disabled = false;
                    });
                    
                    // Open and send the request
                    xhr.open('POST', uploadForm.action, true);
                    xhr.send(formData);
                    
                    // Show progress bar and status
                    uploadProgress.style.display = 'block';
                    uploadStatus.style.display = 'block';
                    uploadBtn.disabled = true;
                });
            });
        </script>
    </body>
    </html>
    ''',
    
    'public_event.html': '''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{{ event.name }} - Find Your Photos</title>
        <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
        <style>
            body { padding-top: 20px; }
            .camera-container {
                position: relative;
                width: 100%;
                max-width: 500px;
                margin: 0 auto;
                overflow: hidden;
                border-radius: 10px;
                background-color: #f8f9fa;
            }
            #video, #canvas {
                width: 100%;
                max-width: 500px;
                max-height: 500px;
                display: block;
                border-radius: 10px;
                margin: 0 auto;
            }
            .camera-overlay {
                position: absolute;
                top: 0;
                left: 0;
                width: 100%;
                height: 100%;
                display: flex;
                flex-direction: column;
                justify-content: flex-end;
                align-items: center;
                padding-bottom: 20px;
            }
            .photo-grid {
                display: grid;
                grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
                gap: 15px;
                margin-top: 20px;
            }
            .photo-item {
                position: relative;
                border-radius: 8px;
                overflow: hidden;
                aspect-ratio: 1/1;
                background-color: #f8f9fa;
            }
            .photo-item img {
                width: 100%;
                height: 100%;
                object-fit: cover;
            }
            .photo-item .download {
                position: absolute;
                bottom: 10px;
                right: 10px;
                background-color: rgba(0,0,0,0.6);
                color: white;
                border: none;
                border-radius: 5px;
                padding: 5px 10px;
                cursor: pointer;
            }
            .spinner-border {
                width: 3rem;
                height: 3rem;
            }
            .loading-container {
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 50px 0;
            }
            #cameraError {
                display: none;
                max-width: 500px;
                margin: 0 auto;
                padding: 20px;
                text-align: center;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="text-center mb-4">
                <h1>{{ event.name }}</h1>
                <p class="lead">Find photos of you from this event</p>
            </div>
            
            <div class="row">
                <div class="col-md-8 offset-md-2">
                    <div class="card mb-4" id="cameraCard">
                        <div class="card-header">
                            <h3>Take a Selfie to Find Your Photos</h3>
                        </div>
                        <div class="card-body">
                            <div id="cameraError" class="alert alert-warning">
                                <p><strong>Camera access is required</strong></p>
                                <p>Please allow camera access to find your photos. We use your selfie only to match you in event photos and don't store it.</p>
                            </div>
                            
                            <div class="camera-container">
                                <video id="video" autoplay playsinline></video>
                                <canvas id="canvas" style="display:none;"></canvas>
                                <div class="camera-overlay">
                                    <button class="btn btn-primary btn-lg" id="captureBtn">
                                        Take Selfie
                                    </button>
                                </div>
                            </div>
                            <p class="text-center mt-3">
                                <small class="text-muted">Position your face clearly in the frame and take a selfie. We'll find photos where you appear.</small>
                            </p>
                        </div>
                    </div>
                    
                    <div id="loadingContainer" class="loading-container" style="display:none;">
                        <div class="spinner-border text-primary mb-3" role="status">
                            <span class="visually-hidden">Loading...</span>
                        </div>
                        <h3>Finding your photos...</h3>
                        <p>This might take a moment</p>
                    </div>
                    
                    <div id="resultsCard" class="card" style="display:none;">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h3>Your Photos</h3>
                            <button class="btn btn-outline-primary" id="tryAgainBtn">Try Another Selfie</button>
                        </div>
                        <div class="card-body">
                            <div id="noResults" style="display:none;">
                                <div class="alert alert-info">
                                    <p>We couldn't find any photos with you in them.</p>
                                    <p>Try taking another selfie with better lighting and a clear view of your face.</p>
                                </div>
                            </div>
                            <div id="photoResults" style="display:none;">
                                <p id="resultsCount" class="mb-3"></p>
                                <div class="photo-grid" id="photoGrid"></div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
        <script>
            document.addEventListener('DOMContentLoaded', function() {
                const video = document.getElementById('video');
                const canvas = document.getElementById('canvas');
                const captureBtn = document.getElementById('captureBtn');
                const tryAgainBtn = document.getElementById('tryAgainBtn');
                const cameraCard = document.getElementById('cameraCard');
                const loadingContainer = document.getElementById('loadingContainer');
                const resultsCard = document.getElementById('resultsCard');
                const noResults = document.getElementById('noResults');
                const photoResults = document.getElementById('photoResults');
                const photoGrid = document.getElementById('photoGrid');
                const resultsCount = document.getElementById('resultsCount');
                const cameraError = document.getElementById('cameraError');
                const eventId = '{{ event_id }}';
                
                // Start camera
                function startCamera() {
                    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'user' }, audio: false })
                        .then(function(stream) {
                            video.srcObject = stream;
                            cameraError.style.display = 'none';
                        })
                        .catch(function(err) {
                            console.error("Error accessing camera: ", err);
                            cameraError.style.display = 'block';
                        });
                }
                
                // Stop camera
                function stopCamera() {
                    if (video.srcObject) {
                        video.srcObject.getTracks().forEach(track => track.stop());
                    }
                }
                
                // Initialize camera
                startCamera();
                
                // Capture button event
                captureBtn.addEventListener('click', function() {
                    // Draw video frame to canvas
                    canvas.width = video.videoWidth;
                    canvas.height = video.videoHeight;
                    canvas.getContext('2d').drawImage(video, 0, 0);
                    
                    // Convert canvas to blob
                    canvas.toBlob(function(blob) {
                        const formData = new FormData();
                        formData.append('face', blob, 'selfie.jpg');
                        
                        // Show loading
                        cameraCard.style.display = 'none';
                        loadingContainer.style.display = 'flex';
                        
                        // Stop camera to save resources
                        stopCamera();
                        
                        // Send to server
                        fetch(`/event/${eventId}/match`, {
                            method: 'POST',
                            body: formData
                        })
                        .then(response => response.json())
                        .then(data => {
                            // Hide loading
                            loadingContainer.style.display = 'none';
                            resultsCard.style.display = 'block';
                            
                            if (data.photos && data.photos.length > 0) {
                                // Show results
                                noResults.style.display = 'none';
                                photoResults.style.display = 'block';
                                
                                // Update count text
                                resultsCount.textContent = `We found ${data.photos.length} photo${data.photos.length > 1 ? 's' : ''} with you in them:`;
                                
                                // Clear previous results
                                photoGrid.innerHTML = '';
                                
                                // Add photos to grid
                                data.photos.forEach(photo => {
                                    const photoItem = document.createElement('div');
                                    photoItem.className = 'photo-item';
                                    
                                    const img = document.createElement('img');
                                    img.src = `/event/${eventId}/photo/${photo}`;
                                    img.alt = 'Event photo';
                                    
                                    const downloadBtn = document.createElement('a');
                                    downloadBtn.className = 'download';
                                    downloadBtn.href = `/event/${eventId}/download/${photo}`;
                                    downloadBtn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" fill="currentColor" class="bi bi-download" viewBox="0 0 16 16"><path d="M.5 9.9a.5.5 0 0 1 .5.5v2.5a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-2.5a.5.5 0 0 1 1 0v2.5a2 2 0 0 1-2 2H2a2 2 0 0 1-2-2v-2.5a.5.5 0 0 1 .5-.5z"/><path d="M7.646 11.854a.5.5 0 0 0 .708 0l3-3a.5.5 0 0 0-.708-.708L8.5 10.293V1.5a.5.5 0 0 0-1 0v8.793L5.354 8.146a.5.5 0 1 0-.708.708l3 3z"/></svg>';
                                    
                                    photoItem.appendChild(img);
                                    photoItem.appendChild(downloadBtn);
                                    photoGrid.appendChild(photoItem);
                                });
                            } else {
                                // Show no results message
                                noResults.style.display = 'block';
                                photoResults.style.display = 'none';
                            }
                        })
                        .catch(error => {
                            console.error('Error:', error);
                            loadingContainer.style.display = 'none';
                            resultsCard.style.display = 'block';
                            noResults.style.display = 'block';
                            photoResults.style.display = 'none';
                        });
                    }, 'image/jpeg');
                });
                
                // Try again button event
                tryAgainBtn.addEventListener('click', function() {
                    resultsCard.style.display = 'none';
                    cameraCard.style.display = 'block';
                    startCamera();
                });
            });
        </script>
    </body>
    </html>
    '''
}

# Render template function to use our template strings
def render_template(template_name, **context):
    from flask import render_template_string, session
    
    # Add the session to the template context
    if 'session' not in context:
        context['session'] = session
        
    if template_name in TEMPLATES:
        return render_template_string(TEMPLATES[template_name], **context)
    else:
        return f"Template {template_name} not found!"

# Override Flask's render_template with our version
app.jinja_env.globals.update(render_template=render_template)

# Run the app
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    env = os.environ.get('FLASK_ENV', 'development')
    print(f"Running in environment: {env} on port: {port}")

    if env == 'production':
        app.run(host='0.0.0.0', port=port, debug=False)
    else:
        app.run(host='0.0.0.0', port=port, debug=True)
