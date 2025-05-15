"""
MongoDB adapter for Face Recognition Photo Sharing System
"""

import uuid
import numpy as np
import gridfs
import base64
from datetime import datetime
from io import BytesIO
from bson.binary import Binary
from bson.objectid import ObjectId
import pymongo
from werkzeug.security import generate_password_hash

class MongoAdapter:
    """MongoDB adapter for the face recognition system"""
    
    def __init__(self, mongo_uri):
        """Initialize MongoDB connection"""
        self.client = pymongo.MongoClient(mongo_uri)
        self.db = self.client.event_photos_db
        self.fs = gridfs.GridFS(self.db)
        
        # Collections
        self.admin_collection = self.db.admins
        self.event_collection = self.db.events
        self.face_collection = self.db.faces
        self.face_data_collection = self.db.face_data
    
    def init_admins(self):
        """Initialize admin accounts if they don't exist"""
        if self.admin_collection.count_documents({"username": "admin"}) == 0:
            admin_data = {
                "username": "admin",
                "password": generate_password_hash('admin123'),
                "name": "Administrator",
                "email": "admin@example.com",
                "role": "admin",
                "created_at": datetime.now()
            }
            self.admin_collection.insert_one(admin_data)
            print("Created default admin account: admin / admin123")
    
    def get_event(self, event_id):
        """Get event data from MongoDB"""
        return self.event_collection.find_one({"_id": event_id})
    
    def get_admin(self, username):
        """Get admin data from MongoDB"""
        return self.admin_collection.find_one({"username": username})
    
    def save_event(self, event_data):
        """Save event data to MongoDB"""
        event_id = event_data.get("_id", str(uuid.uuid4()))
        event_data["_id"] = event_id
        self.event_collection.update_one(
            {"_id": event_id}, 
            {"$set": event_data}, 
            upsert=True
        )
        return event_id
    
    def load_admins(self):
        """Load all admins from MongoDB"""
        return {admin["username"]: admin for admin in self.admin_collection.find()}
    
    def save_admins(self, admins):
        """Save admins to MongoDB - for bulk operations"""
        for username, admin_data in admins.items():
            admin_data["username"] = username
            self.admin_collection.update_one(
                {"username": username},
                {"$set": admin_data},
                upsert=True
            )
    
    def load_events(self, username=None):
        """
        Load events from MongoDB, optionally filtered by creator username
        """
        query = {"created_by": username} if username else {}
        events = list(self.event_collection.find(query).sort("date", -1))
        return events
    
    def create_event(self, name, date, description="", creator_username=None):
        """Create a new event in MongoDB"""
        event_id = str(uuid.uuid4())
        event_data = {
            "_id": event_id,
            "name": name,
            "date": date,
            "description": description,
            "created_by": creator_username,
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "photo_count": 0
        }
        
        # Save to MongoDB
        self.event_collection.insert_one(event_data)
        
        return event_id
    
    def delete_event(self, event_id):
        """Delete an event from MongoDB and all associated data"""
        try:
            # Delete all photos in GridFS
            photo_files = self.db.fs.files.find({"metadata.event_id": event_id})
            for photo in photo_files:
                self.fs.delete(photo["_id"])
            
            # Delete all face records
            self.face_collection.delete_many({"event_id": event_id})
            
            # Delete face data
            self.face_data_collection.delete_many({"event_id": event_id})
            
            # Delete event
            self.event_collection.delete_one({"_id": event_id})
            
            return True
        except Exception as e:
            print(f"Error deleting event: {e}")
            return False
    
    def save_photo(self, event_id, photo_data, filename, has_faces=False, face_count=0):
        """Save a photo to GridFS"""
        try:
            print(f"save_photo called with event_id={event_id}, filename={filename}")
            print(f"MongoDB Connection Status: {self.client.admin.command('ping')}")
            
            photo_id = self.fs.put(
                photo_data, 
                filename=filename,
                metadata={
                    "event_id": event_id,
                    "has_faces": has_faces,
                    "face_count": face_count,
                    "uploaded_at": datetime.now()
                }
            )
            
            print(f"Photo saved to GridFS with ID: {photo_id}")
            
            # Verify the file was saved by retrieving it
            saved_file = self.db.fs.files.find_one({"_id": photo_id})
            if saved_file:
                print(f"Successfully verified saved file: {saved_file.get('filename')}")
                print(f"File metadata: {saved_file.get('metadata')}")
            else:
                print(f"WARNING: Could not verify saved file with ID {photo_id}")
            
            # Update photo count in event
            update_result = self.event_collection.update_one(
                {"_id": event_id},
                {"$inc": {"photo_count": 1}}
            )
            
            print(f"Updated event photo count: {update_result.modified_count} documents modified")
            
            return photo_id
        except Exception as e:
            print(f"Error in save_photo: {e}")
            import traceback
            traceback.print_exc()
            return None
    
    def get_photo(self, photo_id):
        """Get a photo from GridFS"""
        return self.fs.get(photo_id)
    
    def get_photos_for_event(self, event_id):
        """Get all photos for an event"""
        try:
            print(f"Looking for photos with event_id: {event_id}")
            
            # Check if MongoDB is accessible
            print(f"MongoDB Connection Status: {self.client.admin.command('ping')}")
            
            # Check if GridFS has any files at all
            total_files = self.db.fs.files.count_documents({})
            print(f"Total files in GridFS: {total_files}")
            
            # Try a simpler query first to check if any documents exist
            if total_files > 0:
                # Show a sample of what's in GridFS
                sample_files = list(self.db.fs.files.find().limit(3))
                for idx, file in enumerate(sample_files):
                    print(f"Sample file {idx+1}:")
                    print(f"  - ID: {file.get('_id')}")
                    print(f"  - Filename: {file.get('filename')}")
                    print(f"  - Metadata: {file.get('metadata')}")
            
            # First check if there are any photos for this event
            file_count = self.db.fs.files.count_documents({"metadata.event_id": event_id})
            print(f"Found {file_count} documents in GridFS for event {event_id}")
            
            # Fetch the files
            cursor = self.db.fs.files.find({"metadata.event_id": event_id})
            files = list(cursor)  # Convert cursor to list
            
            # Add a consistent filename field for each document
            for file in files:
                if 'filename' not in file and 'metadata' in file:
                    file['filename'] = file.get('filename', file['metadata'].get('filename', 'unknown'))
            
            print(f"Returning {len(files)} photos for event {event_id}")
            return files
        except Exception as e:
            print(f"Error in get_photos_for_event: {e}")
            import traceback
            traceback.print_exc()
            return []
    
    def save_face(self, event_id, photo_id, face_id, face_image, face_encoding, face_location):
        """Save a face to GridFS and face data to MongoDB"""
        # Save face to GridFS
        face_buffer = BytesIO()
        face_image.save(face_buffer, format="JPEG")
        face_buffer.seek(0)
        
        face_file_id = self.fs.put(
            face_buffer,
            filename=f"{face_id}.jpg",
            metadata={
                "event_id": event_id,
                "photo_id": photo_id,
                "face_id": face_id
            }
        )
        
        # Store face data in MongoDB
        face_data = {
            "_id": face_id,
            "event_id": event_id,
            "photo_id": photo_id,
            "face_file_id": face_file_id,
            "photo_filename": self.fs.get(photo_id).filename,
            "encoding": Binary(face_encoding.tobytes()),
            "encoding_shape": face_encoding.shape,
            "location": {
                "top": face_location[0],
                "right": face_location[1],
                "bottom": face_location[2],
                "left": face_location[3]
            },
            "created_at": datetime.now()
        }
        
        self.face_collection.insert_one(face_data)
        return face_id
    
    def get_faces_for_event(self, event_id):
        """Get all faces for an event"""
        return list(self.face_collection.find({"event_id": event_id}))
    
    def get_face_data(self, face_id):
        """Get face data by ID"""
        return self.face_collection.find_one({"_id": face_id})
    
    def delete_photo(self, photo_id):
        """Delete a photo and all associated faces"""
        try:
            # Find all faces for this photo
            faces = self.face_collection.find({"photo_id": photo_id})
            
            # Delete face files and records
            for face in faces:
                face_file_id = face.get("face_file_id")
                if face_file_id:
                    self.fs.delete(face_file_id)
                self.face_collection.delete_one({"_id": face["_id"]})
            
            # Delete the photo
            self.fs.delete(photo_id)
            
            # Decrement photo count in event
            photo_metadata = self.db.fs.files.find_one({"_id": photo_id})
            if photo_metadata and "metadata" in photo_metadata:
                event_id = photo_metadata["metadata"].get("event_id")
                if event_id:
                    self.event_collection.update_one(
                        {"_id": event_id},
                        {"$inc": {"photo_count": -1}}
                    )
            
            return True
        except Exception as e:
            print(f"Error deleting photo: {e}")
            return False 