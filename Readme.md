# Event Snap – Face Recognition Photo Sharing System

## Screenshots

> _Add your own screenshots in the `screenshots/` folder and update the image links below as needed._

### Admin Dashboard

![Admin Dashboard](https://github.com/Shubham-Bhayaje/Event/blob/main/UI/Screenshot%202025-05-15%20090923.png)

### Event Creation

![Create Event](screenshots/create_event.png)

### Photo Upload

![Photo Upload](screenshots/photo_upload.png)

### Attendee Face Match

![Face Match](screenshots/face_match.png)

---

Event Snap is a web application that allows event administrators to upload photos and generate QR codes for events. Attendees can view and download photos they appear in using facial recognition. The system supports both MongoDB and file system storage for events and user data.

## Features

- **Admin Dashboard:** Manage events, upload photos, and generate QR codes.
- **Facial Recognition:** Attendees can find all photos they appear in by uploading a selfie.
- **User Management:** Admins can create, edit, and delete user accounts.
- **Event Management:** Create, view, and delete events.
- **Photo Upload:** Upload multiple photos per event.
- **QR Code Generation:** Each event has a unique QR code for easy access.
- **MongoDB Integration:** All data is stored in MongoDB with file system fallback for compatibility.
- **Responsive UI:** Modern, mobile-friendly interface using Bootstrap.

## Project Structure

```
app.py
Dockerfile
gunicorn_config.py
migrate_to_mongodb.py
mongo_adapter_main.py
mongo_adapter.py
requirements.txt
wsgi.py
data/
  admins.json
  events/
    <event_id>/
      event.json
      faces_data.json
      faces/
      photos/
uploads/
```

## Getting Started

### Prerequisites

- Python 3.9+
- MongoDB Atlas account (or local MongoDB instance)
- [requirements.txt](requirements.txt) dependencies

### Installation

1. **Clone the repository:**

   ```sh
   git clone <your-repo-url>
   cd <repo-folder>
   ```

2. **Install dependencies:**

   ```sh
   pip install -r requirements.txt
   ```

3. **Set up environment variables (optional):**

   - `SECRET_KEY`: Flask secret key
   - `MONGO_URI`: MongoDB connection string (already set in `app.py` for demo)

4. **Run the application:**
   ```sh
   python app.py
   ```
   Or with Gunicorn (recommended for production):
   ```sh
   gunicorn --bind 0.0.0.0:5000 --workers 1 --timeout 300 --worker-class gevent wsgi:app
   ```

### Docker

To run with Docker:

```sh
docker build -t event-snap .
docker run -p 5000:5000 event-snap
```

## Usage

- Visit `http://localhost:5000` in your browser.
- Register an admin account or use the default (`admin` / `admin123`).
- Create events, upload photos, and share the event QR code with attendees.
- Attendees can scan the QR code, upload a selfie, and find their photos.

## Configuration

- MongoDB URI is set in [`app.py`](app.py) as `MONGO_URI`.
- File uploads and event data are stored in the `data/` directory for backup.

## File Overview

- [`app.py`](app.py): Main Flask application.
- [`mongo_adapter.py`](mongo_adapter.py): MongoDB integration logic.
- [`requirements.txt`](requirements.txt): Python dependencies.
- [`Dockerfile`](Dockerfile): Docker configuration.
- [`wsgi.py`](wsgi.py): WSGI entry point for Gunicorn.

## Security Notes

- **Change the default admin password** after first login.
- Set a strong `SECRET_KEY` in production.
- Restrict MongoDB credentials and access.

## License

MIT License

---

**Made with ❤️ for event organizers and attendees!**
