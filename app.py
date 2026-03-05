from flask import Flask, request, jsonify
from flask_cors import CORS
from pymongo import MongoClient
from flask_mail import Mail, Message
from datetime import datetime
from utils import load_model, transform_image, get_prediction
from bson import ObjectId
from urllib.parse import quote_plus
from werkzeug.security import generate_password_hash, check_password_hash
import io, time, secrets, random, traceback, os, re

app = Flask(__name__)
CORS(app)

# ================= SECRET =================
app.config['SECRET_KEY'] = os.environ.get("SECRET_KEY", "supersecretkey")

# ================= MAIL CONFIG =================
app.config['MAIL_SERVER'] = 'smtp.sendgrid.net'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'apikey'
app.config['MAIL_PASSWORD'] = os.environ.get("SENDGRID_API_KEY")
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get("MAIL_USERNAME")

mail = Mail(app)

# ================= MONGODB =================
username = quote_plus("pranshujena2511")
password = quote_plus("Pranshu@91")

uri = f"mongodb+srv://{username}:{password}@cluster0.fk09csn.mongodb.net/?retryWrites=true&w=majority"

client = MongoClient(uri)
db = client["brain_tumor_db"]

history_collection = db["prediction_history"]
admin_collection = db["admin_users"]
users_collection = db["registered_users"]
feedback_collection = db["feedback"]
contacts = db["contacts"]
admin_otp_collection = db["admin_otps"]

otp_db = {}
pending_users = {}

SUPER_ADMIN_EMAIL = os.environ.get("SUPER_ADMIN_EMAIL", "pranshujena2511@gmail.com")

model = None

# ================= HEALTH CHECK =================
@app.route("/")
def home():
    return "Brain Tumor Detection API Running"

@app.route("/ping")
def ping():
    return jsonify({"status": "ok"})


# ================= PREDICTION =================
@app.route('/predict', methods=['POST'])
def predict():
    global model

    try:
        if model is None:
            print("Loading ML model...")
            model = load_model("model/brain_tumor_resnet.pth")

        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
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
        traceback.print_exc()
        return jsonify({'error': str(e)}), 500


# ================= USER REGISTER =================
@app.route('/user-register', methods=['POST'])
def register_user():

    if not request.is_json:
        return jsonify({'success': False, 'message': 'JSON required'}), 415

    data = request.get_json()

    name = data.get('name')
    email = data.get('email', '').strip().lower()
    password = data.get('password')

    if not name or not email or not password:
        return jsonify({'success': False, 'message': 'All fields required'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'success': False, 'message': 'Email already registered'}), 409

    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    expiry = int(time.time()) + 60

    otp_db[email] = {'otp': otp, 'expiry': expiry}

    pending_users[email] = {
        'name': name,
        'email': email,
        'password': generate_password_hash(password)
    }

    try:

        msg = Message(
            "Your OTP for Brain Tumor Detection",
            recipients=[email]
        )

        msg.html = f"""
        <h3>Hello {name}</h3>
        <p>Your OTP is:</p>
        <h2>{otp}</h2>
        <p>This OTP expires in 60 seconds.</p>
        """

        mail.send(msg)

        return jsonify({
            "success": True,
            "message": "OTP sent to email"
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Email service error"
        }), 500


# ================= VERIFY OTP =================
@app.route('/verify-otp', methods=['POST'])
def verify_otp():

    data = request.get_json()

    email = data.get('email', '').strip().lower()
    otp = data.get('otp')

    record = otp_db.get(email)

    if not record:
        return jsonify({'success': False, 'message': 'OTP not found'}), 404

    if record['otp'] != otp:
        return jsonify({'success': False, 'message': 'Invalid OTP'}), 401

    if time.time() > record['expiry']:
        return jsonify({'success': False, 'message': 'OTP expired'}), 403

    user = pending_users.get(email)

    users_collection.insert_one({
        "name": user['name'],
        "email": email,
        "password": user['password'],
        "created_at": datetime.utcnow()
    })

    del otp_db[email]
    del pending_users[email]

    return jsonify({
        "success": True,
        "message": "Registration successful"
    })


# ================= SEND OTP FOR PREDICTION =================
@app.route('/send-otp', methods=['POST'])
def send_otp():

    data = request.get_json()
    email = data.get('email', '').strip().lower()

    user = users_collection.find_one({'email': email})

    if not user:
        return jsonify({'success': False, 'message': 'Email not registered'}), 404

    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])

    expiry = int(time.time()) + 300

    otp_db[email] = {
        "otp": otp,
        "expiry": expiry
    }

    try:

        msg = Message("Tumor Analysis OTP", recipients=[email])
        msg.body = f"Your verification OTP is: {otp}"

        mail.send(msg)

        return jsonify({
            "success": True,
            "message": "OTP sent"
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({
            "success": False,
            "message": "Failed to send OTP"
        }), 500


# ================= LOGIN =================
@app.route('/user-login', methods=['POST'])
def user_login():

    data = request.get_json()

    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})

    if not user:
        return jsonify({'success': False, 'message': 'User not found'}), 404

    if not check_password_hash(user['password'], password):
        return jsonify({'success': False, 'message': 'Incorrect password'}), 401

    return jsonify({
        "success": True,
        "email": email,
        "message": "Login successful"
    })


# ================= FEEDBACK =================
@app.route('/feedback', methods=['POST'])
def feedback():

    data = request.get_json()

    feedback_collection.insert_one(data)

    return jsonify({"message": "Feedback received"})


# ================= CONTACT =================
@app.route('/contact', methods=['POST'])
def contact():

    data = request.get_json()

    data['timestamp'] = datetime.utcnow()

    contacts.insert_one(data)

    return jsonify({'message': 'Message received'})


# ================= DELETE HISTORY =================
@app.route("/delete-history/<id>", methods=["DELETE"])
def delete_prediction_by_id(id):

    try:

        result = history_collection.delete_one({"_id": ObjectId(id)})

        if result.deleted_count:
            return jsonify({"success": True})

        return jsonify({"success": False}), 404

    except Exception as e:

        return jsonify({"success": False, "error": str(e)})


# ================= RUN SERVER =================
if __name__ == "__main__":

    if admin_collection.count_documents({"email": SUPER_ADMIN_EMAIL}) == 0:
        admin_collection.insert_one({
            "name": "Super Admin",
            "email": SUPER_ADMIN_EMAIL,
            "password": "admin123",
            "status": "approved"
        })

    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
