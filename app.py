import os
import io
import random
import smtplib
import threading
import time
import requests
from datetime import datetime
from urllib.parse import quote_plus

from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from flask_mail import Mail, Message
from pymongo import MongoClient
from bson.objectid import ObjectId
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash

from utils import load_model, transform_image, get_prediction

app = Flask(__name__)
CORS(app)

# ==== JWT / Mail Config ====
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kiranpadhy2004@gmail.com'
app.config['MAIL_PASSWORD'] = 'jzjfkpzkncmfkklp'  # App Password only
app.config['MAIL_DEFAULT_SENDER'] = 'kiranpadhy2004@gmail.com'

mail = Mail(app)

# ==== MongoDB ====
username = quote_plus("swarnaprabhadash31")
password = quote_plus("Swarna@3009")
uri = f"mongodb+srv://{username}:{password}@cluster0.ayaj7ca.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(uri)
db = client["brain_tumor_db"]

history_collection = db["prediction_history"]
admin_collection = db["admin_users"]
users_collection = db["registered_users"]
feedback_collection = db["feedback"]
contacts = db["contacts"]

# ==== Load Model ====
model = load_model("model/brain_tumor_resnet.pth")

# ==== Routes ====

@app.route('/')
def home():
    return "Brain Tumor Detection API"

@app.route('/predict', methods=['POST'])
def predict():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400

    try:
        email = request.form.get('email', 'unknown')
        image_bytes = io.BytesIO(file.read())
        image_tensor = transform_image(image_bytes)
        prediction = get_prediction(model, image_tensor)

        history_collection.insert_one({
            "email": email,
            "prediction": prediction,
            "timestamp": datetime.utcnow()
        })

        return jsonify({'prediction': prediction})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route("/history", methods=["GET"])
def get_prediction_history():
    try:
        predictions = list(history_collection.find({}, {"email": 1, "prediction": 1, "timestamp": 1}))
        for prediction in predictions:
            prediction['_id'] = str(prediction['_id'])
            prediction['timestamp'] = prediction.get('timestamp').isoformat() if prediction.get('timestamp') else None
        return jsonify({"success": True, "predictions": predictions}), 200
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route("/delete-history/<id>", methods=["DELETE"])
def delete_prediction_by_id(id):
    try:
        result = history_collection.delete_one({"_id": ObjectId(id)})
        if result.deleted_count == 1:
            return jsonify({"success": True, "message": "Prediction deleted"}), 200
        return jsonify({"success": False, "message": "Prediction not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/admin-login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    admin = admin_collection.find_one({"email": email})
    if not admin or admin['password'] != password:
        return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 401

    return jsonify({'success': True, 'message': 'Login successful', 'email': admin['email']})

@app.route('/admin-dashboard', methods=['GET'])
def admin_dashboard():
    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1}))
    return jsonify({"users": users})

@app.route('/user-register', methods=['POST'])
def registered_users():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    if users_collection.find_one({"email": email}):
        return jsonify({"success": False, "message": "Email already registered"}), 409

    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    otp = str(random.randint(100000, 999999))

    users_collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_pw,
        "otp": otp,
        "is_verified": False
    })

    try:
        msg = Message("Your OTP for Brain Tumor Detection App", recipients=[email])
        msg.body = f"Hi {name},\n\nYour OTP is: {otp}"
        mail.send(msg)
        return jsonify({"success": True, "email": email})
    except Exception:
        users_collection.delete_one({"email": email})
        return jsonify({"success": False, "message": "Failed to send OTP"}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email')
    otp_input = data.get('otp')

    user = users_collection.find_one({"email": email})
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404
    if user.get("is_verified"):
        return jsonify({"success": True, "message": "Already verified"}), 200
    if user.get("otp") != otp_input:
        return jsonify({"success": False, "message": "Invalid OTP"}), 401

    users_collection.update_one(
        {"email": email},
        {"$set": {"is_verified": True}, "$unset": {"otp": ""}}
    )
    return jsonify({"success": True, "message": "OTP verified successfully"})

@app.route("/user-login", methods=["POST"])
def login_user():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = users_collection.find_one({"email": email})
    if user:
        stored_password = user["password"]
        if isinstance(stored_password, str):
            stored_password = stored_password.encode("utf-8")

        if bcrypt.checkpw(password.encode("utf-8"), stored_password):
            return jsonify({"success": True, "email": email}), 200

    return jsonify({"success": False, "message": "Invalid credentials"}), 401

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.get_json()
    feedback_collection.insert_one({
        "fullName": data.get("fullName"),
        "email": data.get("email"),
        "feedbackTitle": data.get("feedbackTitle"),
        "category": data.get("category"),
        "rating": data.get("rating"),
        "detailedFeedback": data.get("detailedFeedback")
    })
    return jsonify({"message": "Feedback received successfully"}), 200

@app.route("/get-feedback", methods=["GET"])
def get_feedback():
    try:
        feedback_list = list(feedback_collection.find({}, {
            "fullName": 1, "email": 1, "feedbackTitle": 1,
            "category": 1, "rating": 1, "detailedFeedback": 1
        }))
        for feedback in feedback_list:
            feedback['_id'] = str(feedback['_id'])
        return jsonify({"success": True, "feedback": feedback_list}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error fetching feedback"}), 500

@app.route('/api/delete_feedback/<feedback_id>', methods=['DELETE'])
def delete_feedback(feedback_id):
    try:
        result = feedback_collection.delete_one({"_id": ObjectId(feedback_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Feedback deleted successfully"}), 200
        return jsonify({"message": "Feedback not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/contact', methods=['POST'])
def contact():
    data = request.get_json()
    contacts.insert_one({
        "fullName": data.get('fullName'),
        "email": data.get('email'),
        "subject": data.get('subject'),
        "message": data.get('message'),
        "timestamp": datetime.utcnow().isoformat()
    })
    return jsonify({'message': 'Message received'}), 200

@app.route("/admin/contacts", methods=["GET"])
def get_contacts():
    try:
        contact_list = list(contacts.find())
        for contact in contact_list:
            contact['_id'] = str(contact['_id'])
        return jsonify(contact_list), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/admin/contacts/<id>", methods=["DELETE"])
def delete_contact(id):
    try:
        result = contacts.delete_one({"_id": ObjectId(id)})
        if result.deleted_count:
            return jsonify({"message": "Deleted"}), 200
        return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/change-password', methods=['POST'])
def change_password():
    data = request.get_json()
    email = data.get('email')
    current_password = data.get('currentPassword')
    new_password = data.get('newPassword')
    is_admin = data.get('isAdmin', False)

    collection = admin_collection if is_admin else users_collection
    user = collection.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if is_admin:
        if user['password'] != current_password:
            return jsonify({'success': False, 'message': 'Incorrect current password'}), 401
        collection.update_one({'email': email}, {'$set': {'password': new_password}})
    else:
        if not check_password_hash(user['password'], current_password):
            return jsonify({'success': False, 'message': 'Incorrect current password'}), 401
        collection.update_one({'email': email}, {'$set': {'password': generate_password_hash(new_password)}})

    return jsonify({'success': True, 'message': 'Password changed successfully'}), 200

# ==== Keep Alive Logic ====
def keep_alive():
    url = os.environ.get("KEEP_ALIVE_URL")
    if not url:
        print("KEEP_ALIVE_URL not set. Skipping keep_alive.")
        return

    while True:
        try:
            requests.get(url)
            print(f"Pinged {url}")
        except Exception as e:
            print("Ping failed:", e)
        time.sleep(600)

# ==== App Startup ====
if __name__ == '__main__':
    if admin_collection.count_documents({"email": "swarnaprabhadash04@gmail.com"}) == 0:
        admin_collection.insert_one({
            "email": "swarnaprabhadash04@gmail.com",
            "password": "admin123"
        })

    if os.environ.get("KEEP_ALIVE_URL"):
        threading.Thread(target=keep_alive, daemon=True).start()

    port = int(os.environ.get("PORT", 5000))
    app.run(debug=True, host='0.0.0.0', port=port)
