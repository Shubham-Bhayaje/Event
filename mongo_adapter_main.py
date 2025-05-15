"""
Script to modify the main app.py to use MongoDB
This shows the key changes needed in app.py
"""

# Add this import at the top of app.py
from mongo_adapter import MongoAdapter

# MongoDB Setup
# Replace <db_username> and <db_password> with actual credentials
MONGO_URI = "mongodb+srv://shubhambhayaje:mc%40-M%403YCfiU%23R5@cluster0.k5srgdn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"
mongo = MongoAdapter(MONGO_URI)

# Replace file-based functions with MongoDB functions:

# Instead of init_admins():
mongo.init_admins()

# Replace load_admins()
# From: admins = load_admins()
# To: admins = mongo.load_admins()

# Replace save_admins(admins)
# From: save_admins(admins)
# To: mongo.save_admins(admins)

# Replace load_events(username)
# From: events = load_events(username)
# To: events = mongo.load_events(username)

# Replace create_event(name, date, description)
# From: event_id = create_event(name, date, description)
# To: event_id = mongo.create_event(name, date, description, session.get("admin_username"))

# Replace delete_event(event_id)
# From: success = delete_event(event_id)
# To: success = mongo.delete_event(event_id)

# Replace get_event_metadata_path(event_id) checks
# From:
"""
metadata_path = get_event_metadata_path(event_id)
if not os.path.exists(metadata_path):
    flash('Event not found', 'error')
    return redirect(url_for('admin_dashboard'))

with open(metadata_path, 'r') as f:
    event_data = json.load(f)
"""
# To:
"""
event_data = mongo.get_event(event_id)
if not event_data:
    flash('Event not found', 'error')
    return redirect(url_for('admin_dashboard'))
"""

# Replace upload photo handling
# From:
"""
photos_path = get_event_photos_path(event_id)
processed_count = 0
uploaded_filenames = []

for file in files:
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(photos_path, filename)
        file.save(file_path)
        uploaded_filenames.append(filename)
        
        # Process the photo to extract faces
        face_ids = process_photo(event_id, file_path)
        if face_ids:
            processed_count += 1
"""
# To:
"""
processed_count = 0
uploaded_filenames = []

for file in files:
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        uploaded_filenames.append(filename)
        
        # Read the file content
        file_content = file.read()
        file.seek(0)  # Reset the file pointer for further processing
        
        # Save the file to MongoDB GridFS
        photo_id = mongo.save_photo(event_id, file_content, filename)
        
        # Process the photo to extract faces
        try:
            # Load the image
            image = face_recognition.load_image_file(file)
            
            # Find all face locations and encodings
            face_locations = face_recognition.face_locations(image)
            face_encodings = face_recognition.face_encodings(image, face_locations)
            
            if face_encodings:
                # Update photo metadata to indicate faces
                mongo.db.fs.files.update_one(
                    {"_id": photo_id},
                    {"$set": {
                        "metadata.has_faces": True,
                        "metadata.face_count": len(face_encodings)
                    }}
                )
                
                # Save each face
                for i, (face_location, face_encoding) in enumerate(zip(face_locations, face_encodings)):
                    face_id = str(uuid.uuid4())
                    
                    # Extract face image
                    top, right, bottom, left = face_location
                    face_image = image[top:bottom, left:right]
                    pil_image = Image.fromarray(face_image)
                    
                    # Save face
                    mongo.save_face(event_id, photo_id, face_id, pil_image, face_encoding, face_location)
                
                processed_count += 1
        except Exception as e:
            print(f"Error processing photo: {e}")
"""

# Update get_event_photo route to serve from MongoDB
# From:
"""
photo_path = os.path.join(get_event_photos_path(event_id), secure_filename(filename))
if not os.path.exists(photo_path):
    return jsonify({'error': 'Photo not found'}), 404

return send_file(photo_path)
"""
# To:
"""
# Find the photo in GridFS by filename and event_id
photo_file = mongo.db.fs.files.find_one({
    "filename": secure_filename(filename),
    "metadata.event_id": event_id
})

if not photo_file:
    return jsonify({'error': 'Photo not found'}), 404

# Get the file from GridFS
grid_out = mongo.fs.get(photo_file["_id"])
return send_file(
    BytesIO(grid_out.read()),
    download_name=filename,
    mimetype='image/jpeg'
)
"""

# Update match_face function
# From: matched_photos = match_face(event_id, face_file)
# To:
"""
try:
    # Read image from the stream
    face_file.seek(0)
    image_bytes = face_file.read()
    
    # Convert to numpy array
    image = face_recognition.load_image_file(BytesIO(image_bytes))
    
    # Find faces in the uploaded image
    face_locations = face_recognition.face_locations(image)
    if not face_locations:
        return jsonify({'message': 'No faces found in the image', 'photos': []}), 200
    
    # Use the first face found
    face_encoding = face_recognition.face_encodings(image, [face_locations[0]])[0]
    
    # Get all face data for this event
    event_faces = mongo.get_faces_for_event(event_id)
    
    # No faces to compare against
    if not event_faces:
        return jsonify({'message': 'No faces to compare against', 'photos': []}), 200
    
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
    
    return jsonify({'message': f'Found {len(matching_photos)} matching photos', 'photos': list(matching_photos)}), 200
    
except Exception as e:
    print(f"Error matching face: {e}")
    return jsonify({'error': 'Error processing face image'}), 500
"""

# Add these changes to your requirements.txt
"""
pymongo==4.3.3
dnspython==2.3.0
""" 