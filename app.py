from flask import Flask, request, render_template, send_from_directory, abort, Response, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from functools import wraps
import os
import time
from dotenv import load_dotenv

load_dotenv()  # 환경 변수 로드

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # 비밀 키 설정

# 데이터베이스 설정
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL')  # PostgreSQL URI 가져오기
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16 MB
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# 폴더가 존재하지 않으면 생성
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 인증 정보 설정
USERNAME = os.getenv('UPLOAD_USERNAME')
PASSWORD = os.getenv('UPLOAD_PASSWORD')
MAX_ATTEMPTS = 3
BLOCK_TIME = 24 * 60 * 60  # 24시간 (초 단위)

# 실패한 로그인 시도 저장
login_attempts = {}

def check_auth(username, password):
    """유저네임과 패스워드가 올바른지 확인"""
    return username == USERNAME and password == PASSWORD

def authenticate():
    """로그인 창을 표시"""
    return Response(
        'Could not verify your login.\n'
        'Please enter the correct username and password.', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )

def is_ip_blocked(ip):
    """IP가 차단되었는지 확인"""
    if ip in login_attempts:
        attempts, last_attempt_time = login_attempts[ip]
        if attempts >= MAX_ATTEMPTS and time.time() - last_attempt_time < BLOCK_TIME:
            return True
    return False

def register_failed_attempt(ip):
    """로그인 실패 시도 등록"""
    if ip in login_attempts:
        attempts, last_attempt_time = login_attempts[ip]
        if time.time() - last_attempt_time < BLOCK_TIME:
            login_attempts[ip] = (attempts + 1, time.time())
        else:
            login_attempts[ip] = (1, time.time())
    else:
        login_attempts[ip] = (1, time.time())

def requires_auth(f):
    """인증 데코레이터"""
    @wraps(f)
    def decorated(*args, **kwargs):
        ip = request.remote_addr
        if is_ip_blocked(ip):
            return abort(403, 'Your IP is blocked for 24 hours due to multiple failed login attempts.')

        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            register_failed_attempt(ip)
            return authenticate()
        return f(*args, **kwargs)
    return decorated

def allowed_file(filename):
    """허용된 파일 형식 확인"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# DB 모델 정의 (예: PDF 파일 정보를 저장)
class PDFFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(120), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=time.strftime('%Y-%m-%d %H:%M:%S'))

    def __repr__(self):
        return f"PDFFile('{self.filename}', '{self.upload_date}')"

@app.route('/')
def index():
    files = PDFFile.query.all()  # 데이터베이스에서 모든 파일을 조회
    return render_template('index.html', files=files)

@app.route('/upload', methods=['POST'])
@requires_auth
def upload_file():
    if 'pdf_file' not in request.files:
        return 'No file part'
    file = request.files['pdf_file']
    if file.filename == '':
        return 'No selected file'
    if file and allowed_file(file.filename):
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(filepath)
        
        # 파일 정보를 데이터베이스에 저장
        new_file = PDFFile(filename=file.filename)
        db.session.add(new_file)
        db.session.commit()
        
        return 'File successfully uploaded'
    else:
        return 'File type not allowed'

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    db.create_all()  # 데이터베이스 테이블 생성
    app.run(port=5000)
