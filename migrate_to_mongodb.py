#!/usr/bin/env python3
"""
Migration script to move data from file system to MongoDB

This script will:
1. Connect to MongoDB
2. Read all events from the file system
3. Migrate events, photos, and face data to MongoDB
"""

import os
import json
import face_recognition
from PIL import Image
from io import BytesIO
import uuid
from mongo_adapter import MongoAdapter
from datetime import datetime

# Replace with your MongoDB URI
MONGO_URI = "mongodb+srv://shubhambhayaje:mc%40-M%403YCfiU%23R5@cluster0.k5srgdn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

# File paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
EVENTS_DIR = os.path.join(DATA_DIR, 'events')
ADMINS_FILE = os.path.join(DATA_DIR, 'admins.json')

# Initialize MongoDB connection
mongo = MongoAdapter(MONGO_URI)

def migrate_admins():
    """Migrate admin accounts from JSON file to MongoDB"""
    if os.path.exists(ADMINS_FILE):
        print(f"Migrating admins from {ADMINS_FILE}")
        with open(ADMINS_FILE, 'r') as f:
            admins = json.load(f)
        
        # Convert to MongoDB format and save
        for username, admin_data in admins.items():
            # Fix timestamps
            if isinstance(admin_data.get('created_at'), str):
                try:
                    admin_data['created_at'] = datetime.fromisoformat(admin_data['created_at'])
                except ValueError:
                    admin_data['created_at'] = datetime.now()
            
            # Add username to the document
            admin_data['username'] = username
            
            # Save to MongoDB
            mongo.admin_collection.update_one(
                {"username": username},
                {"$set": admin_data},
                upsert=True
            )
        
        print(f"Migrated {len(admins)} admin accounts")
    else:
        print("No admins file found, skipping admin migration")

def migrate_events():
    """Migrate events from file system to MongoDB"""
    if not os.path.exists(EVENTS_DIR):
        print("No events directory found, skipping events migration")
        return
    
    # Get all event directories
    event_dirs = [d for d in os.listdir(EVENTS_DIR) 
                 if os.path.isdir(os.path.join(EVENTS_DIR, d))]
    
    print(f"Found {len(event_dirs)} events to migrate")
    
    for event_id in event_dirs:
        event_dir = os.path.join(EVENTS_DIR, event_id)
        metadata_path = os.path.join(event_dir, 'event.json')
        
        if not os.path.exists(metadata_path):
            print(f"Skipping event {event_id}: No metadata file")
            continue
        
        # Load event metadata
        with open(metadata_path, 'r') as f:
            event_data = json.load(f)
        
        # Add _id field if not present
        event_data['_id'] = event_id
        
        # Fix timestamps
        for field in ['created_at', 'updated_at']:
            if isinstance(event_data.get(field), str):
                try:
                    event_data[field] = datetime.fromisoformat(event_data[field])
                except (ValueError, TypeError):
                    event_data[field] = datetime.now()
        
        # Add photo_count field
        photos_dir = os.path.join(event_dir, 'photos')
        if os.path.exists(photos_dir):
            photo_files = [f for f in os.listdir(photos_dir) 
                          if os.path.isfile(os.path.join(photos_dir, f))]
            event_data['photo_count'] = len(photo_files)
        else:
            event_data['photo_count'] = 0
        
        # Save event to MongoDB
        mongo.event_collection.update_one(
            {"_id": event_id},
            {"$set": event_data},
            upsert=True
        )
        
        print(f"Migrated event {event_id}: {event_data.get('name')}")
        
        # Migrate photos
        migrate_photos(event_id, event_dir)

def migrate_photos(event_id, event_dir):
    """Migrate photos for an event to MongoDB GridFS"""
    photos_dir = os.path.join(event_dir, 'photos')
    if not os.path.exists(photos_dir):
        print(f"No photos directory for event {event_id}, skipping photos")
        return
    
    # Get all photo files
    photo_files = [f for f in os.listdir(photos_dir) 
                  if os.path.isfile(os.path.join(photos_dir, f))]
    
    print(f"Migrating {len(photo_files)} photos for event {event_id}")
    
    faces_dir = os.path.join(event_dir, 'faces')
    faces_data_path = os.path.join(event_dir, 'faces_data.json')
    
    # Load faces data if it exists
    faces_data = {}
    if os.path.exists(faces_data_path):
        try:
            with open(faces_data_path, 'r') as f:
                faces_data = json.load(f)
        except Exception as e:
            print(f"Error loading faces data: {e}")
    
    for photo_file in photo_files:
        photo_path = os.path.join(photos_dir, photo_file)
        
        try:
            # Save photo to GridFS
            with open(photo_path, 'rb') as f:
                photo_content = f.read()
                
                # Check if photo has faces
                photo_faces = []
                for face_id, face_info in faces_data.items():
                    if face_info.get('photo') == photo_file:
                        photo_faces.append(face_id)
                
                # Add photo to GridFS
                photo_id = mongo.save_photo(
                    event_id, 
                    photo_content, 
                    photo_file,
                    has_faces=(len(photo_faces) > 0),
                    face_count=len(photo_faces)
                )
                
                print(f"  Migrated photo {photo_file}")
                
                # Process faces for this photo
                if photo_faces and os.path.exists(faces_dir):
                    for face_id in photo_faces:
                        face_path = os.path.join(faces_dir, f"{face_id}.jpg")
                        if os.path.exists(face_path):
                            # Get face data
                            face_info = faces_data.get(face_id, {})
                            
                            try:
                                # Load face image
                                face_img = Image.open(face_path)
                                
                                # Get face encoding from image
                                face_encoding = face_recognition.face_encodings(
                                    face_recognition.load_image_file(face_path)
                                )[0]
                                
                                # Get location data
                                location = face_info.get('location', (0, 0, 10, 10))
                                
                                # Save face to MongoDB
                                mongo.save_face(
                                    event_id,
                                    photo_id,
                                    face_id,
                                    face_img,
                                    face_encoding,
                                    location
                                )
                                
                                print(f"    Migrated face {face_id}")
                            except Exception as e:
                                print(f"    Error migrating face {face_id}: {e}")
        
        except Exception as e:
            print(f"  Error migrating photo {photo_file}: {e}")

if __name__ == "__main__":
    print("Starting migration from file system to MongoDB")
    
    # Migrate admins
    migrate_admins()
    
    # Migrate events and their photos/faces
    migrate_events()
    
    print("Migration completed") 