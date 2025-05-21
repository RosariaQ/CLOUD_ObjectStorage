import sqlite3
import bcrypt
import jwt
import datetime
import os
import uuid
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory # send_from_directory 임포트
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 설정 (Configurations) ---
app.config['SECRET_KEY'] = 'your_very_secret_key_please_change_it_for_production'
UPLOAD_FOLDER = 'uploads'
# 다양한 확장자 허용 (필요에 따라 조정)
ALLOWED_EXTENSIONS = {
    'txt', 'log', 'md', 'json', 'xml', 'csv', # 텍스트 기반
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'hwp', # 문서
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico', # 이미지
    'mp4', 'mov', 'avi', 'wmv', 'mkv', 'webm', # 비디오
    'mp3', 'wav', 'ogg', 'flac', # 오디오
    'zip', 'tar', 'gz', '7z' # 압축 파일
}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024  # 최대 업로드 파일 크기 (예: 256MB)

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
        return jsonify({"message": "Database error checking username: " + str(e)}), 500
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password_bytes.decode('utf-8')
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password_str))
        db.commit()
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": "Database error registering user: " + str(e)}), 500
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
        return jsonify({"message": "Database error fetching user: " + str(e)}), 500
    if not user:
        return jsonify({"message": "Invalid credentials"}), 401
    stored_password_hash_bytes = user['password_hash'].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash_bytes):
        token_payload = {
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24) # 토큰 만료 시간 24시간으로 연장
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
        # 실제 저장되는 파일명은 고유하게, 원래 파일명은 DB에 저장
        unique_internal_filename = f"{uuid.uuid4().hex}.{file_extension}" if file_extension else uuid.uuid4().hex
        filepath_on_server = os.path.join(app.config['UPLOAD_FOLDER'], unique_internal_filename)
        try:
            file.save(filepath_on_server)
            filesize = os.path.getsize(filepath_on_server)
            download_link_id = str(uuid.uuid4()) # 다운로드용 고유 ID
            db = get_db()
            cursor = db.cursor()
            # filepath는 서버 내부 경로이므로, unique_internal_filename을 저장하는 것이 더 적절할 수 있음
            # 여기서는 전체 경로를 저장
            cursor.execute("""
                INSERT INTO files (user_id, filename, filepath, filesize, download_link_id, permission)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (g.current_user_id, original_filename, filepath_on_server, filesize, download_link_id, 'private'))
            db.commit()
            file_id = cursor.lastrowid
            return jsonify({
                "message": "File uploaded successfully",
                "file_id": file_id,
                "filename": original_filename,
                "filesize_bytes": filesize,
                "download_link_id": download_link_id, # 이 링크로 다운로드 API 접근
                "uploaded_by": g.current_username
            }), 201
        except Exception as e:
            if os.path.exists(filepath_on_server):
                try:
                    os.remove(filepath_on_server)
                except OSError as oe:
                    print(f"Error deleting file {filepath_on_server} after upload failure: {oe}")
            return jsonify({"message": "Failed to upload file: " + str(e)}), 500
    else:
        return jsonify({"message": "File type not allowed"}), 400

# --- 파일 목록 및 메타데이터 조회 API (이전과 동일) ---
@app.route('/files', methods=['GET'])
@token_required
def list_my_files():
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            SELECT id, filename, filesize, upload_time, permission, download_link_id
            FROM files
            WHERE user_id = ?
            ORDER BY upload_time DESC
        """, (g.current_user_id,))
        files_data = cursor.fetchall()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching files: " + str(e)}), 500
    my_files = [dict(row) for row in files_data]
    return jsonify({"files": my_files, "count": len(my_files)}), 200

@app.route('/files/<int:file_id>', methods=['GET'])
@token_required
def get_file_metadata(file_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            SELECT f.id, f.filename, f.filesize, f.upload_time, f.permission, f.download_link_id, u.username as owner_username
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ?
        """, (file_id,))
        file_data_row = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file metadata: " + str(e)}), 500

    if not file_data_row:
        return jsonify({"message": "File not found"}), 404

    file_info = dict(file_data_row) # sqlite3.Row를 딕셔너리로 변환

    # 소유권 확인 또는 공개 파일인지 확인
    # files 테이블에서 user_id를 직접 가져와서 비교하는 것이 더 명확
    cursor.execute("SELECT user_id FROM files WHERE id = ?", (file_id,))
    owner_check = cursor.fetchone()

    # 현재는 소유자만 메타데이터 조회 가능하도록 함. 공개 파일도 허용하려면 조건 추가
    if not owner_check or (owner_check['user_id'] != g.current_user_id and file_info['permission'] != 'public'):
         return jsonify({"message": "Access denied or file not found"}), 403
    
    return jsonify(file_info), 200


# --- 파일 접근 권한 설정 API (PUT /files/<file_id>/permission) ---
@app.route('/files/<int:file_id>/permission', methods=['PUT'])
@token_required # JWT 인증 필요
def set_file_permission(file_id):
    data = request.get_json()
    new_permission = data.get('permission') # 'public', 'private', 'password'
    file_password = data.get('password') # 'password' 권한 설정 시 필요

    if not new_permission or new_permission not in ['public', 'private', 'password']:
        return jsonify({"message": "Invalid permission value. Must be 'public', 'private', or 'password'."}), 400

    if new_permission == 'password' and not file_password:
        return jsonify({"message": "Password is required for 'password' permission."}), 400

    db = get_db()
    cursor = db.cursor()

    # 파일 존재 및 소유권 확인
    try:
        cursor.execute("SELECT user_id, permission, access_password_hash FROM files WHERE id = ?", (file_id,))
        file_record = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file: " + str(e)}), 500

    if not file_record:
        return jsonify({"message": "File not found"}), 404

    if file_record['user_id'] != g.current_user_id:
        return jsonify({"message": "Access denied. You are not the owner of this file."}), 403

    new_access_password_hash = file_record['access_password_hash'] # 기본값은 기존 해시값

    if new_permission == 'password':
        hashed_pw_bytes = bcrypt.hashpw(file_password.encode('utf-8'), bcrypt.gensalt())
        new_access_password_hash = hashed_pw_bytes.decode('utf-8')
    elif file_record['permission'] == 'password' and new_permission != 'password': # 비밀번호 권한에서 다른 권한으로 변경 시
        new_access_password_hash = None # 기존 비밀번호 해시 제거

    try:
        cursor.execute("""
            UPDATE files
            SET permission = ?, access_password_hash = ?
            WHERE id = ?
        """, (new_permission, new_access_password_hash, file_id))
        db.commit()
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": "Database error updating permission: " + str(e)}), 500

    return jsonify({"message": f"File permission updated to '{new_permission}' successfully."}), 200


# --- 파일 다운로드 API (GET /download/<link_id>) ---
@app.route('/download/<string:link_id>', methods=['GET'])
def download_file_with_link(link_id):
    db = get_db()
    cursor = db.cursor()

    try:
        # download_link_id로 파일 정보 조회
        cursor.execute("""
            SELECT id, filename, filepath, permission, access_password_hash, user_id
            FROM files
            WHERE download_link_id = ?
        """, (link_id,))
        file_record = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file by link: " + str(e)}), 500

    if not file_record:
        return jsonify({"message": "Invalid download link or file not found."}), 404

    # 파일 정보
    original_filename = file_record['filename']
    server_filepath = file_record['filepath'] # 서버 내 실제 파일 경로
    file_permission = file_record['permission']
    stored_password_hash_str = file_record['access_password_hash']
    
    # 파일이 실제로 서버에 존재하는지 확인
    if not os.path.exists(server_filepath):
        return jsonify({"message": "File not found on server. It might have been deleted."}), 404


    # 1. 공개 파일 ('public') 처리
    if file_permission == 'public':
        try:
            # send_from_directory는 디렉토리와 파일명을 인자로 받음
            # server_filepath에서 디렉토리와 파일명 분리 필요
            directory = os.path.dirname(server_filepath)
            filename_on_server = os.path.basename(server_filepath)
            return send_from_directory(directory, filename_on_server, as_attachment=True, download_name=original_filename)
        except Exception as e:
            return jsonify({"message": "Error sending file: " + str(e)}), 500

    # 2. 비밀번호로 보호된 파일 ('password') 처리
    elif file_permission == 'password':
        # 비밀번호는 요청 헤더나 쿼리 파라미터로 받을 수 있음. 여기서는 쿼리 파라미터 'password' 사용
        provided_password = request.args.get('password')
        if not provided_password:
            # 또는 'Authorization: Basic base64(username:password)' 형태도 고려 가능
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Basic '):
                try:
                    # 'Basic ' 제거 후 base64 디코딩, username:password 형태에서 password 추출
                    # 실제 username은 사용하지 않으므로, _:password 형태로 받을 수 있음
                    decoded_str = base64.b64decode(auth_header.split(" ")[1]).decode('utf-8')
                    # username:password 또는 password만 오는 경우 처리
                    if ':' in decoded_str:
                        provided_password = decoded_str.split(':', 1)[1]
                    else:
                        provided_password = decoded_str
                except Exception:
                    return jsonify({"message": "Malformed Basic Auth header for password."}), 400
            
            if not provided_password:
                 return jsonify({"message": "Password required for this file. Provide as query parameter 'password' or Basic Auth."}), 401


        if stored_password_hash_str and bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash_str.encode('utf-8')):
            try:
                directory = os.path.dirname(server_filepath)
                filename_on_server = os.path.basename(server_filepath)
                return send_from_directory(directory, filename_on_server, as_attachment=True, download_name=original_filename)
            except Exception as e:
                return jsonify({"message": "Error sending file: " + str(e)}), 500
        else:
            return jsonify({"message": "Incorrect password."}), 401 # Unauthorized

    # 3. 비공개 파일 ('private') 처리
    # 'private' 파일은 이 /download/<link_id> 엔드포인트로는 직접 다운로드 불가.
    # 소유자만 자신의 파일 목록에서 다른 방식으로 다운로드 받거나,
    # 또는 이 엔드포인트에 JWT 인증을 추가하고 소유자일 경우에만 허용해야 함.
    # 과제 요구사항: "접근 가능한 경우만 다운로드 허용"
    # 현재는 'private' 파일은 이 링크로 다운로드할 수 없도록 처리.
    elif file_permission == 'private':
        # 소유자인지 확인 (JWT 토큰 필요)
        # 이 엔드포인트는 기본적으로 토큰 없이 접근 가능하도록 설계되어 있으므로,
        # private 파일 다운로드를 위해서는 별도의 인증된 엔드포인트가 필요하거나,
        # 이 엔드포인트에서 선택적으로 토큰을 확인해야 함.
        # 여기서는 간단히 private 파일은 이 링크로 접근 불가로 처리.
        # 소유자는 /files/<id>/download (새 엔드포인트) 등으로 접근하게 할 수 있음.
        # 또는, 이 download_link_id가 소유자에게만 노출된다고 가정하고,
        # 소유자가 이 링크로 접근 시 user_id를 어떻게든 확인해야 함. (복잡)
        # 가장 간단한 방법은, 'private' 파일은 이 공개 링크로는 다운로드할 수 없게 하는 것.
        # 사용자가 로그인 후 자신의 파일 목록에서 다운로드 받는 API를 따로 만드는 것이 좋음.
        # 여기서는 일단 접근 거부.
        return jsonify({"message": "This file is private and cannot be downloaded via this link without owner authentication."}), 403


    else: # 정의되지 않은 권한
        return jsonify({"message": "File has an unknown permission type."}), 500
        
# 애플리케이션 실행
if __name__ == '__main__':
    import base64 # download_file_with_link 함수 내 Basic Auth 처리를 위해 추가
    app.run(host='0.0.0.0', port=5050, debug=True)
