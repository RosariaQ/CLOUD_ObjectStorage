import sqlite3
import bcrypt
import jwt
import datetime
import os
import uuid
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory # send_from_directory 추가
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 설정 (Configurations) ---
app.config['SECRET_KEY'] = 'your_very_secret_key_please_change_it_for_production'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'mp4', 'mov', 'avi', 'pdf', 'zip', 'hwp', 'docx', 'xlsx', 'pptx'} # 다양한 확장자 추가
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 최대 업로드 파일 크기 (예: 100MB)

DATABASE = 'object_storage.db'

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# --- 데이터베이스 헬퍼 함수 ---
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

@app.cli.command('init-db')
def init_db_command():
    init_db()
    print('Initialized the database.')

# --- JWT 인증 데코레이터 ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({"message": "Bearer token malformed"}), 401
        if not token:
            return jsonify({"message": "Token is missing!"}), 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.current_user_id = data['user_id']
            g.current_username = data['username']
        except jwt.ExpiredSignatureError:
            return jsonify({"message": "Token has expired!"}), 401
        except jwt.InvalidTokenError:
            return jsonify({"message": "Token is invalid!"}), 401
        except Exception as e:
            return jsonify({"message": "Error processing token: " + str(e)}), 500
        return f(*args, **kwargs)
    return decorated

# --- 기본 라우트 ---
@app.route('/')
def hello_world():
    return jsonify({"message": "Welcome to the Simple Object Storage API!"}), 200

# --- 인증 API (이전과 동일) ---
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400
    username = data['username']
    password = data['password']
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return jsonify({"message": "Username already exists"}), 409
    except sqlite3.Error as e:
        return jsonify({"message": "Database error: " + str(e)}), 500
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password_bytes.decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password_str))
        db.commit()
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": "Database error: " + str(e)}), 500
    return jsonify({"message": "User registered successfully"}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400
    username = data['username']
    password = data['password']
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error: " + str(e)}), 500
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401
    stored_password_hash_bytes = user['password_hash'].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash_bytes):
        token_payload = {
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1) # 토큰 만료 시간 1시간
        }
        try:
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({"message": "Login successful", "token": token}), 200
        except Exception as e:
            return jsonify({"message": "Error generating token: " + str(e)}), 500
    else:
        return jsonify({"message": "Invalid credentials"}), 401

# --- 파일 업로드 API (이전과 동일) ---
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No file selected for uploading"}), 400
    if file and allowed_file(file.filename):
        original_filename = secure_filename(file.filename)
        file_extension = original_filename.rsplit('.', 1)[1].lower() if '.' in original_filename else ''
        unique_internal_filename = f"{uuid.uuid4()}.{file_extension}" if file_extension else str(uuid.uuid4())
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_internal_filename)
        try:
            file.save(filepath)
            filesize = os.path.getsize(filepath)
            download_link_id = str(uuid.uuid4())
            db = get_db()
            cursor = db.cursor()
            cursor.execute("""
                INSERT INTO files (user_id, filename, filepath, filesize, download_link_id, permission)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (g.current_user_id, original_filename, filepath, filesize, download_link_id, 'private'))
            db.commit()
            file_id = cursor.lastrowid
            return jsonify({
                "message": "File uploaded successfully",
                "file_id": file_id,
                "filename": original_filename,
                "filesize": filesize,
                "download_link_id": download_link_id,
                "uploaded_by": g.current_username
            }), 201
        except Exception as e:
            if os.path.exists(filepath): # 오류 발생 시 저장된 파일 삭제 시도
                try:
                    os.remove(filepath)
                except OSError as oe: # 파일 삭제 중 오류 발생 가능성 처리
                    print(f"Error deleting file {filepath} after upload failure: {oe}")
            return jsonify({"message": "Failed to upload file: " + str(e)}), 500
    else:
        return jsonify({"message": "File type not allowed"}), 400

# --- 내가 업로드한 파일 목록 조회 API (GET /files) ---
@app.route('/files', methods=['GET'])
@token_required # JWT 인증 필요
def list_my_files():
    """
    현재 로그인한 사용자가 업로드한 파일 목록을 반환합니다.
    """
    db = get_db()
    cursor = db.cursor()
    try:
        # files 테이블에서 user_id가 현재 로그인한 사용자의 ID와 일치하는 모든 파일 정보를 조회합니다.
        # 필요한 컬럼만 선택하여 반환할 수 있습니다. (예: filepath는 제외)
        cursor.execute("""
            SELECT id, filename, filesize, upload_time, permission, download_link_id
            FROM files
            WHERE user_id = ?
            ORDER BY upload_time DESC
        """, (g.current_user_id,))
        files_data = cursor.fetchall() # 모든 결과를 가져옵니다.
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching files: " + str(e)}), 500

    # sqlite3.Row 객체 리스트를 JSON으로 직렬화 가능한 딕셔너리 리스트로 변환합니다.
    my_files = [dict(row) for row in files_data]

    return jsonify({"files": my_files, "count": len(my_files)}), 200

# --- 특정 파일 메타데이터 조회 API (GET /files/<file_id>) ---
@app.route('/files/<int:file_id>', methods=['GET'])
@token_required # JWT 인증 필요
def get_file_metadata(file_id):
    """
    특정 파일 ID에 해당하는 파일의 상세 메타데이터를 반환합니다.
    파일 소유자만 접근 가능하도록 제한합니다. (향후 'public' 권한 파일은 다르게 처리 가능)
    """
    db = get_db()
    cursor = db.cursor()
    try:
        # user_id도 함께 조회하여 소유권 확인
        cursor.execute("""
            SELECT f.id, f.filename, f.filesize, f.upload_time, f.permission, f.download_link_id, u.username as owner_username
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ?
        """, (file_id,))
        file_data = cursor.fetchone() # 하나의 결과 또는 None을 가져옵니다.
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file metadata: " + str(e)}), 500

    if not file_data:
        return jsonify({"message": "File not found"}), 404 # Not Found

    # 파일 소유권 확인 (현재는 소유자만 메타데이터 조회 가능)
    # file_data는 sqlite3.Row 객체이므로, user_id를 직접 가져오려면 files 테이블을 조회할 때 user_id를 포함해야 합니다.
    # 또는, 위 쿼리에서 f.user_id를 SELECT에 추가하고 여기서 g.current_user_id와 비교할 수 있습니다.
    # 여기서는 JOIN을 통해 owner_username을 가져왔으므로, g.current_username과 비교하거나,
    # files 테이블에서 user_id를 가져와 g.current_user_id와 비교합니다.
    # 더 명확하게 하기 위해 files 테이블에서 user_id를 가져와 비교하는 것으로 수정합니다.
    
    cursor.execute("SELECT user_id FROM files WHERE id = ?", (file_id,))
    owner_check = cursor.fetchone()

    if not owner_check or owner_check['user_id'] != g.current_user_id:
        # 만약 'public' 파일도 접근 허용하려면, 여기서 file_data['permission'] == 'public' 조건 추가
        return jsonify({"message": "Access denied or file not found"}), 403 # Forbidden (또는 404로 통일)


    return jsonify(dict(file_data)), 200


# 애플리케이션 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
