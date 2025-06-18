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
from flask import Response
from bson import json_util

app = Flask(__name__)
CORS(app)

# Secret key for JWT encoding/decoding
app.config['SECRET_KEY'] = 'your_secret_key_here'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'kiranpadhy2004@gmail.com'         # Replace
app.config['MAIL_PASSWORD'] = 'jzjfkpzkncmfkklp'      # Use App Password
app.config['MAIL_DEFAULT_SENDER'] = 'kiranpadhy2004@gmail.com'   # Same as username

mail = Mail(app)# Change this in production

# MongoDB credentials
username = quote_plus("swarnaprabhadash31")
password = quote_plus("Swarna@3009")
uri = f"mongodb+srv://{username}:{password}@cluster0.ayaj7ca.mongodb.net/?retryWrites=true&w=majority"

client = MongoClient(uri)
db = client["brain_tumor_db"]

# Collections
history_collection = db["prediction_history"]
admin_collection = db["admin_users"]
users_collection = db["registered_users"]
feedback_collection = db["feedback"]
contacts = db['contacts']

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

@app.route('/user-register', methods=['POST'])
def registered_users():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    # ✅ Check if user already exists
    if users_collection.find_one({"email": email}):
        return jsonify({"success": False, "message": "Email already registered. Please log in."}), 409
    hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


    # ✅ Register user
    users_collection.insert_one({
        "name": name,
        "email": email,
        "password": hashed_pw  # Note: Hash passwords in production!
    })

    # ✅ Send Welcome Email
    try:
        msg = Message("Welcome to Brain Tumor Detection App", recipients=[email])
        msg.body = f"""
Hi {name},

Thank you for registering on our Brain Tumor Detection website.
Congratulations! You have been successfully registered into our application.

Your login credentials are as follows:

Email: {email}
Password: {password}

Please log in to your account using these credentials.

We're excited to have you on board. Feel free to explore the features and try out our detection system!

Best regards,  
Brain Tumor Detection Team
"""
        mail.send(msg)
        return jsonify({"success": True, "email": email})
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to send email: {str(e)}"}), 500

    # Flask example

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

@app.route('/send-feedback', methods=['POST'])
def send_feedback():
    data = request.get_json()
    feedback_text = data.get('feedback')
    email = data.get('email', 'anonymous')

    if not feedback_text:
        return jsonify({"success": False, "message": "Feedback is required"}), 400

    feedback_entry = {
        "email": email,
        "feedback": feedback_text,
        "timestamp": datetime.utcnow()
    }

    feedback_collection.insert_one(feedback_entry)
    return jsonify({"success": True, "message": "Feedback sent successfully"})

@app.route("/get-feedback", methods=["GET"])
def get_feedback():
    try:
        feedback_list = list(feedback_collection.find({}, { "email": 1, "feedback": 1, "timestamp": 1}))
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
        else:
            return jsonify({"message": "Feedback not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/contact', methods=['POST'])
def contact():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    message = data.get('message')

    if not name or not email or not message:
        return jsonify({'error': 'Missing fields'}), 400

    contact_entry = {
        'name': name,
        'email': email,
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

if __name__ == '__main__':
    if admin_collection.count_documents({"email": "admin@example.com"}) == 0:
        admin_collection.insert_one({
            "email": "swarnaprabhadash04@gmail.com",
            "password": "admin123"
        })
    app.run(debug=True)
