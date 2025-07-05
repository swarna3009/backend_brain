from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from flask_mail import Mail, Message
from datetime import datetime
from utils import load_model, transform_image, get_prediction
import io
import bcrypt
from werkzeug.security import generate_password_hash, check_password_hash
from bson.objectid import ObjectId
from urllib.parse import quote_plus
import jwt
import smtplib 
from flask import Response
from bson import json_util
import random
import time,secrets

app = Flask(_name_)
CORS(app)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'pranshujena2511@gmail.com'         # Replace
app.config['MAIL_PASSWORD'] = 'gimxxcktgcchbdlf'      # Use App Password
app.config['MAIL_DEFAULT_SENDER'] = 'Team TumorDetect', 'pranshujena2511@gmail.com'   # Same as username

mail = Mail(app)# Change this in production

# MongoDB credentials
username = quote_plus("pranshujena2511")
password = quote_plus("Pranshu@91")
uri = f"mongodb+srv://{username}:{password}@cluster0.fk09csn.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0"

client = MongoClient(uri)
db = client["brain_tumor_db"]

# Collections
history_collection = db["prediction_history"]
admin_collection = db["admin_users"]
users_collection = db["registered_users"]
feedback_collection = db["feedback"]
contacts = db['contacts']
otp_db = {} 
pending_users = {} 

# Load model
model = load_model("model/brain_tumor_resnet.pth")


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
            prediction['email'] = prediction.get('email', 'unknown')
            timestamp = prediction.get('timestamp')
            prediction['timestamp'] = timestamp.isoformat() if timestamp else None
        return jsonify({"success": True, "predictions": predictions}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Error fetching history: {str(e)}"}), 500

@app.route("/delete-history/<id>", methods=["DELETE"])
def delete_prediction_by_id(id):
    try:
        result = history_collection.delete_one({"_id": ObjectId(id)})
        if result.deleted_count == 1:
            return jsonify({"success": True, "message": "Prediction deleted"}), 200
        else:
            return jsonify({"success": False, "message": "Prediction not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/admin-login', methods=['POST'])
def admin_login():
    data = request.get_json()
    email = data.get('email', '')
    password = data.get('password', '')

    admin = admin_collection.find_one({"email": email})
    if not admin or admin['password'] != password:
        return jsonify({'success': False, 'message': 'Invalid admin credentials'}), 401

    return jsonify({'success': True, 'message': 'Login successful', 'email': admin['email']})

@app.route('/admin-dashboard', methods=['GET'])
def admin_dashboard():
    users = list(users_collection.find({}, {"_id": 0, "name": 1, "email": 1}))
    return jsonify({"users": users})


import random
from flask import request, jsonify
from flask_mail import Message
import bcrypt
@app.route('/user-register', methods=['POST'])
def register_user():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

    existing_user = users_collection.find_one({'email': email})
    if existing_user:
        return jsonify({'success': False, 'message': 'Email is already registered'}), 409

    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)]) 
    expiry = int(time.time()) + 60
    otp_db[email] = { 'otp': otp, 'expiry': expiry }

    hashed_password = generate_password_hash(password)
    pending_users[email] = {
        'name': name,
        'email': email,
        'hashed_password': hashed_password
    }

    try:
        msg = Message('Your OTP for Brain Tumor Detection App', recipients=[email])
        msg.html = f"""
        <div style="font-family: Arial; background-color: #1a1a1a; color: #fff; padding: 20px;">
            <h3>Hi {name},</h3>
            <p>Thank you for registering.</p>
            <p><strong>Your OTP is:</strong> 
               <span style="color:#ffd700; font-size:20px;">{otp}</span></p>
            <p>Visit Our page </p>
            <a href="https://brain-frontend3.vercel.app/"
               style="background:#ffd700; color:#000; padding:10px 20px; text-decoration:none; border-radius:5px;">
               Go to Home</a>
        </div>
        """
        mail.send(msg)
        return jsonify({'success': True, 'message': 'OTP sent to email'})
    except Exception as e:
        print("Mail error:", e)
        return jsonify({'success': False, 'message': 'Failed to send OTP'}), 500

# STEP 2: Verify OTP and Save User
@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    email = data.get('email', '').strip().lower()
    otp = data.get('otp')

    if not email or not otp:
        return jsonify({'success': False, 'message': 'Email and OTP required'}), 400

    record = otp_db.get(email)
    if not record or record['otp'] != otp:
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 401

    if int(time.time()) > record['expiry']:
        return jsonify({'success': False, 'message': 'OTP expired'}), 403

    user_info = pending_users.get(email)
    if not user_info:
        return jsonify({'success': False, 'message': 'No pending user'}), 404

    if users_collection.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email is already registered'}), 409

    users_collection.insert_one({
        'name': user_info['name'],
        'email': email,
        'hashed_password': user_info['hashed_password']
    })

    del otp_db[email]
    del pending_users[email]

    return jsonify({'success': True, 'message': 'User registered successfully'})

# STEP 3: Login using bcrypt
@app.route('/user-login', methods=['POST'])
def user_login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    if not email or not password:
        return jsonify({'success': False, 'message': 'Email and password are required'}), 400

    user = users_collection.find_one({'email': email})
    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if not check_password_hash(user['hashed_password'], password):
        return jsonify({'success': False, 'message': 'Incorrect password'}), 401


    return jsonify({'success': True, 'email': email, 'message': 'Login successful'}), 200

@app.route('/feedback', methods=['POST'])
def feedback():
    data = request.get_json()

    if not data:
        return jsonify({"error": "No data received"}), 400

    feedback_entry = {
        "fullName": data.get("fullName"),
        "email": data.get("email"),
        "feedbackTitle": data.get("feedbackTitle"),
        "category": data.get("category"),
        "rating": data.get("rating"),
        "detailedFeedback": data.get("detailedFeedback")
    }

    # Insert into MongoDB
    feedback_collection.insert_one(feedback_entry)

    return jsonify({"message": "Feedback received successfully"}), 200

@app.route("/get-feedback", methods=["GET"])
def get_feedback():
    try:
        feedback_list = list(feedback_collection.find({}, {
            "fullName": 1,
            "email": 1,
            "feedbackTitle": 1,
            "category": 1,
            "rating": 1,
            "detailedFeedback": 1
        }))
        for feedback in feedback_list:
            feedback['_id'] = str(feedback['_id'])
        return jsonify({"success": True, "feedback": feedback_list}), 200
    except Exception as e:
        print("Error:", e)
        return jsonify({"success": False, "message": "Error fetching feedback"}), 500


@app.route('/api/delete_feedback/<feedback_id>', methods=['DELETE'])
def delete_feedback(feedback_id):
    try:
        result = feedback_collection.delete_one({"_id": ObjectId(feedback_id)})
        if result.deleted_count == 1:
            return jsonify({"message": "Feedback deleted successfully"}), 200
        else:
            return jsonify({"message": "Feedback not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/contact', methods=['POST'])
def contact():
    data = request.get_json()
    full_name = data.get('fullName')
    email = data.get('email')
    subject = data.get('subject')
    message = data.get('message')

    if not full_name or not email or not message:
        return jsonify({'error': 'Missing required fields'}), 400

    contact_entry = {
        'fullName': full_name,
        'email': email,
        'subject': subject,
        'message': message,
        'timestamp': datetime.utcnow().isoformat()
    }

    contacts.insert_one(contact_entry)
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
        else:
            return jsonify({"error": "Not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/change-password', methods=['POST'])
def change_password():
    data = request.get_json()
    email = data.get('email', '').strip()
    current_password = data.get('currentPassword', '').strip()
    new_password = data.get('newPassword', '').strip()
    is_admin = data.get('isAdmin', False)

    if not all([email, current_password, new_password]):
        return jsonify({'success': False, 'message': 'All fields are required'}), 400

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
        hashed_new_password = generate_password_hash(new_password)
        collection.update_one({'email': email}, {'$set': {'password': hashed_new_password}})

    return jsonify({'success': True, 'message': 'Password changed successfully'}), 200

if _name_ == '_main_':
    if admin_collection.count_documents({"email": "pranshujena2511@gmail.com"}) == 0:
        admin_collection.insert_one({
            "email": "pranshujena2511@gmail.com",
            "password": "admin123"
        })
    app.run(debug=True)
