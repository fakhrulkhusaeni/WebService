from flask import Flask, render_template, redirect, url_for, request, flash, jsonify, Response
from flask_login import LoginManager, login_user, logout_user, login_required, UserMixin, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
import os
from werkzeug.utils import secure_filename
from bson.objectid import ObjectId
from flask_mail import Mail, Message
import random
import string
import secrets


from ultralytics import YOLO
from ultralytics.solutions import object_counter
import cv2
from pymongo import MongoClient
import datetime
import calendar
from shapely.geometry import Point


app = Flask(__name__)

# Enable CORS
CORS(app)

# Configuration
app.config['SECRET_KEY'] = '9OLWxND4o83j4K4iuopO'
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_PATH'] = 16 * 1024 * 1024  # 16 MB

# Konfigurasi Flask-Mail
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'fakhrulkhusaeni@gmail.com'
app.config['MAIL_PASSWORD'] = 'ocjakxqttwwgjvyg'

mail = Mail(app)

# Konfigurasi MongoDB
app.config['MONGO_URI'] = 'mongodb://localhost:27017/mylogin'

# Database setup
client = MongoClient(app.config['MONGO_URI'])
db = client.get_database()
users_collection = db['users']

login_manager = LoginManager()
login_manager.init_app(app)

# JWT manager setup
jwt = JWTManager(app)

# User model
class User(UserMixin):
    def __init__(self, user_data):
        self.id = str(user_data['_id'])
        self.email = user_data['email']
        self.password = user_data['password']
        self.name = user_data['name']
        self.profile_picture = user_data.get('profile_picture')

# User loader
@login_manager.user_loader
def load_user(user_id):
    user_data = users_collection.find_one({'_id': ObjectId(user_id)})
    if user_data:
        return User(user_data)
    return None

@app.route('/')
def index():
    return "Hello World!"

# Fungsi untuk menghasilkan token reset
def generate_reset_token(length=6):
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

# Endpoint untuk request forgot password
@app.route('/forgot_password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')

    user_data = users_collection.find_one({'email': email})
    if not user_data:
        return jsonify({'message': 'Email tidak ditemukan.'}), 400

    reset_token = generate_reset_token()
    users_collection.update_one(
        {'_id': user_data['_id']},
        {'$set': {'reset_token': reset_token}}
    )

    msg = Message('Reset Password',
                  sender='noreply@gmail.com',  # Ganti dengan email pengirim
                  recipients=[email])
    msg.body = f'Kode token password Anda adalah {reset_token}'
    mail.send(msg)

    return jsonify({'message': 'Token reset password telah dikirim ke email Anda.'}), 200

# Endpoint untuk reset password
@app.route('/reset_password', methods=['PUT'])
def reset_password():
    data = request.get_json()
    reset_token = data.get('reset_token')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')

    if len(new_password) < 8:
        return jsonify({'error': 'Password baru harus memiliki 8 karakter'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Password baru tidak cocok.'}), 400

    user_data = users_collection.find_one({'reset_token': reset_token})
    if not user_data:
        return jsonify({'error': 'Token reset tidak valid.'}), 400

    users_collection.update_one(
        {'_id': user_data['_id']},
        {'$set': {'password': generate_password_hash(new_password, method='pbkdf2:sha256'), 'reset_token': None}}
    )

    return jsonify({'message': 'Password berhasil direset.'}), 200



# Endpoint for user registration with email verification
@app.route('/signup', methods=['POST'])
def signup():
    data = request.get_json()
    email = data.get('email')
    name = data.get('name')
    password = data.get('password')

    if len(password) < 8:
        return jsonify({'message': 'Password harus memiliki 8 karakter'}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Alamat email sudah ada'}), 400

    verification_token = secrets.token_urlsafe(32)
    new_user = {
        'email': email,
        'name': name,
        'password': generate_password_hash(password, method='pbkdf2:sha256'),
        'verification_token': verification_token,
        'is_verified': False
    }

    users_collection.insert_one(new_user)

    msg = Message('Verify Your Email',
                  sender='noreply@gmail.com',
                  recipients=[email])
    verification_link = f'http://192.168.43.13:5000/verify_email/{verification_token}'
    msg.body = f'Please click the link to verify your email: {verification_link}'
    mail.send(msg)

    return jsonify({'message': 'User berhasil dibuat. Periksa email Anda untuk verifikasi.'}), 200

# Endpoint to handle email verification
@app.route('/verify_email/<token>', methods=['GET'])
def verify_email(token):
    user_data = users_collection.find_one({'verification_token': token})
    if not user_data:
        return jsonify({'message': 'Token verifikasi tidak valid.'}), 400

    users_collection.update_one(
        {'_id': user_data['_id']},
        {'$set': {'is_verified': True, 'verification_token': None}}
    )

    return jsonify({'message': 'Email berhasil diverifikasi.'}), 200

# Modified login endpoint to check email verification status
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user_data = users_collection.find_one({'email': email})
    
    if not user_data or not check_password_hash(user_data['password'], password): 
        message = 'Silakan periksa detail login Anda dan coba lagi.'
        return jsonify({'message': message}), 400

    if not user_data['is_verified']:
        return jsonify({'message': 'Email belum diverifikasi.'}), 400

    user = User(user_data)
    login_user(user)
    access_token = create_access_token(identity=user.id)
    return jsonify({'message': 'Login berhasil', 'access_token': access_token}), 200


@app.route('/edit_profile', methods=['PUT'])
@jwt_required()
def edit_profile():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    
    current_user_id = get_jwt_identity()
    users_collection.update_one(
        {'_id': ObjectId(current_user_id)},
        {'$set': {'name': name, 'email': email}}
    )

    return jsonify({'message': 'Profil berhasil diperbarui.'}), 200

@app.route('/change_password', methods=['PUT'])
@jwt_required()
def change_password():
    data = request.get_json()
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    confirm_password = data.get('confirm_password')
    
    current_user_id = get_jwt_identity()
    user_data = users_collection.find_one({'_id': ObjectId(current_user_id)})

    if not check_password_hash(user_data['password'], current_password):
        return jsonify({'error': 'Password saat ini salah.'}), 400

    if len(new_password) < 8:
        return jsonify({'error': 'Password baru harus memiliki 8 karakter'}), 400

    if new_password != confirm_password:
        return jsonify({'error': 'Password baru tidak cocok.'}), 400

    users_collection.update_one(
        {'_id': ObjectId(current_user_id)},
        {'$set': {'password': generate_password_hash(new_password, method='pbkdf2:sha256')}}
    )

    return jsonify({'message': 'Password berhasil diubah.'}), 200

@app.route('/upload_profile', methods=['POST'])
@jwt_required()
def upload_profile():
    if 'profile_picture' not in request.files:
        return jsonify({'error': 'Tidak ada file yang diunggah'}), 400
    
    current_user_id = get_jwt_identity()
    file = request.files['profile_picture']
    if file.filename == '':
        return jsonify({'error': 'Tidak ada file yang dipilih'}), 400

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)

        users_collection.update_one(
            {'_id': ObjectId(current_user_id)},
            {'$set': {'profile_picture': filename}}
        )

        return jsonify({'message': 'Foto profil berhasil diperbarui.'}), 200

    return jsonify({'error': 'Jenis file tidak valid.'}), 400

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user_id = get_jwt_identity()
    user_data = users_collection.find_one({'_id': ObjectId(current_user_id)})
    profile_picture_url = f"http://192.168.43.13:5000/static/uploads/{user_data.get('profile_picture', '')}"
    return jsonify(
        name=user_data['name'],
        email=user_data['email'],
        profile_picture=profile_picture_url
    ), 200



def count_object(selected_location):
    # Setup MongoDB
    client = MongoClient('mongodb://localhost:27017/')
    db = client['helmet']
    collection = db['detections']

    # Inisialisasi model YOLO dan ObjectCounter
    model = YOLO("model/best1.pt")
    region_of_interest = [(0, 400), (1070, 400), (1070, 380), (0, 380)]
    counter = object_counter.ObjectCounter()
    counter.set_args(view_img=True, reg_pts=region_of_interest, classes_names=model.names, draw_tracks=True)

    cap = cv2.VideoCapture("model/Video.mp4")
    assert cap.isOpened()
    tracked_ids = set()
    while True:
        success, im0 = cap.read()
        if not success:
            break
        tracks = model.track(im0, persist=True, show=False)
        im0 = counter.start_counting(im0, tracks)
        
        # Proses track dan simpan ke MongoDB jika melintasi ROI
        if tracks[0].boxes.id is not None:
            boxes = tracks[0].boxes.xyxy.cpu()
            clss = tracks[0].boxes.cls.cpu().tolist()
            track_ids = tracks[0].boxes.id.int().cpu().tolist()

            for box, track_id, cls in zip(boxes, track_ids, clss):
                if track_id not in tracked_ids:
                    prev_position = counter.track_history[track_id][-2] if len(counter.track_history[track_id]) > 1 else None
                    current_position = (float((box[0] + box[2]) / 2), float((box[1] + box[3]) / 2))
                    
                    if len(region_of_interest) >= 3:
                        is_inside = counter.counting_region.contains(Point(current_position))
                        if prev_position and is_inside:
                            tracked_ids.add(track_id)
                            now = datetime.datetime.now()
                            day_name = calendar.day_name[now.weekday()]
                            date = now.strftime('%Y-%m-%d')
                            time = now.strftime('%H:%M')
                            detection = {
                                "class": counter.names[cls],
                                "date": date,
                                "time": time,
                                "day": day_name,
                                "location": selected_location
                            }
                            collection.insert_one(detection)

        ret, buffer = cv2.imencode('.jpg', im0)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')

    cap.release()
    client.close()

    

@app.route('/realtime')
def realtime():
    return render_template('video.html')

@app.route('/video_feed')
def video_feed():
    selected_location = request.args.get('kecamatan')
    return Response(count_object(selected_location), mimetype='multipart/x-mixed-replace; boundary=frame')



if __name__ == '__main__':
    app.run(debug=True, host="192.168.43.13")
