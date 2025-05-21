import sqlite3
import bcrypt
import jwt
import datetime
import os
import uuid
import base64 # 이전 단계에서 다운로드 시 Basic Auth 처리를 위해 추가됨
from functools import wraps
from flask import Flask, request, jsonify, g, send_from_directory
from werkzeug.utils import secure_filename

app = Flask(__name__)

# --- 설정 (Configurations) ---
app.config['SECRET_KEY'] = 'your_very_secret_key_please_change_it_for_production'
UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {
    'txt', 'log', 'md', 'json', 'xml', 'csv',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx', 'hwp',
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'svg', 'ico',
    'mp4', 'mov', 'avi', 'wmv', 'mkv', 'webm',
    'mp3', 'wav', 'ogg', 'flac',
    'zip', 'tar', 'gz', '7z'
}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 256 * 1024 * 1024

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
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
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
        unique_internal_filename = f"{uuid.uuid4().hex}.{file_extension}" if file_extension else uuid.uuid4().hex
        filepath_on_server = os.path.join(app.config['UPLOAD_FOLDER'], unique_internal_filename)
        try:
            file.save(filepath_on_server)
            filesize = os.path.getsize(filepath_on_server)
            download_link_id = str(uuid.uuid4())
            db = get_db()
            cursor = db.cursor()
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
                "download_link_id": download_link_id,
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
            SELECT f.id, f.filename, f.filesize, f.upload_time, f.permission, f.download_link_id, f.user_id, u.username as owner_username
            FROM files f
            JOIN users u ON f.user_id = u.id
            WHERE f.id = ?
        """, (file_id,)) # user_id도 SELECT에 추가
        file_data_row = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file metadata: " + str(e)}), 500

    if not file_data_row:
        return jsonify({"message": "File not found"}), 404

    file_info = dict(file_data_row)

    if file_info['user_id'] != g.current_user_id and file_info['permission'] != 'public':
         return jsonify({"message": "Access denied or file not found"}), 403
    
    # user_id는 응답에서 제외할 수 있음 (필요에 따라)
    # del file_info['user_id'] 
    return jsonify(file_info), 200

# --- 파일 접근 권한 설정 API (이전과 동일) ---
@app.route('/files/<int:file_id>/permission', methods=['PUT'])
@token_required
def set_file_permission(file_id):
    data = request.get_json()
    new_permission = data.get('permission')
    file_password = data.get('password')

    if not new_permission or new_permission not in ['public', 'private', 'password']:
        return jsonify({"message": "Invalid permission value. Must be 'public', 'private', or 'password'."}), 400
    if new_permission == 'password' and not file_password:
        return jsonify({"message": "Password is required for 'password' permission."}), 400

    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("SELECT user_id, permission, access_password_hash FROM files WHERE id = ?", (file_id,))
        file_record = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file: " + str(e)}), 500
    if not file_record:
        return jsonify({"message": "File not found"}), 404
    if file_record['user_id'] != g.current_user_id:
        return jsonify({"message": "Access denied. You are not the owner of this file."}), 403

    new_access_password_hash = file_record['access_password_hash']
    if new_permission == 'password':
        hashed_pw_bytes = bcrypt.hashpw(file_password.encode('utf-8'), bcrypt.gensalt())
        new_access_password_hash = hashed_pw_bytes.decode('utf-8')
    elif file_record['permission'] == 'password' and new_permission != 'password':
        new_access_password_hash = None
    try:
        cursor.execute("""
            UPDATE files SET permission = ?, access_password_hash = ? WHERE id = ?
        """, (new_permission, new_access_password_hash, file_id))
        db.commit()
    except sqlite3.Error as e:
        db.rollback()
        return jsonify({"message": "Database error updating permission: " + str(e)}), 500
    return jsonify({"message": f"File permission updated to '{new_permission}' successfully."}), 200

# --- 파일 다운로드 API (이전과 동일) ---
@app.route('/download/<string:link_id>', methods=['GET'])
def download_file_with_link(link_id):
    db = get_db()
    cursor = db.cursor()
    try:
        cursor.execute("""
            SELECT id, filename, filepath, permission, access_password_hash, user_id
            FROM files WHERE download_link_id = ?
        """, (link_id,))
        file_record = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file by link: " + str(e)}), 500
    if not file_record:
        return jsonify({"message": "Invalid download link or file not found."}), 404

    original_filename = file_record['filename']
    server_filepath = file_record['filepath']
    file_permission = file_record['permission']
    stored_password_hash_str = file_record['access_password_hash']
    
    if not os.path.exists(server_filepath):
        # DB에는 기록이 있지만 실제 파일이 없는 경우, DB 기록도 삭제하는 로직 추가 가능 (선택적)
        # cursor.execute("DELETE FROM files WHERE download_link_id = ?", (link_id,))
        # db.commit()
        return jsonify({"message": "File not found on server. It might have been deleted."}), 404

    if file_permission == 'public':
        try:
            directory = os.path.dirname(server_filepath)
            filename_on_server = os.path.basename(server_filepath)
            return send_from_directory(directory, filename_on_server, as_attachment=True, download_name=original_filename)
        except Exception as e:
            return jsonify({"message": "Error sending file: " + str(e)}), 500
    elif file_permission == 'password':
        provided_password = request.args.get('password')
        if not provided_password:
            auth_header = request.headers.get('Authorization')
            if auth_header and auth_header.startswith('Basic '):
                try:
                    decoded_str = base64.b64decode(auth_header.split(" ")[1]).decode('utf-8')
                    provided_password = decoded_str.split(':', 1)[1] if ':' in decoded_str else decoded_str
                except Exception:
                    return jsonify({"message": "Malformed Basic Auth header for password."}), 400
            if not provided_password:
                 return jsonify({"message": "Password required. Provide as query parameter 'password' or Basic Auth."}), 401
        if stored_password_hash_str and bcrypt.checkpw(provided_password.encode('utf-8'), stored_password_hash_str.encode('utf-8')):
            try:
                directory = os.path.dirname(server_filepath)
                filename_on_server = os.path.basename(server_filepath)
                return send_from_directory(directory, filename_on_server, as_attachment=True, download_name=original_filename)
            except Exception as e:
                return jsonify({"message": "Error sending file: " + str(e)}), 500
        else:
            return jsonify({"message": "Incorrect password."}), 401
    elif file_permission == 'private':
        return jsonify({"message": "This file is private and cannot be downloaded via this link without owner authentication."}), 403
    else:
        return jsonify({"message": "File has an unknown permission type."}), 500

# --- 업로드한 파일 삭제 API (DELETE /files/<file_id>) ---
@app.route('/files/<int:file_id>', methods=['DELETE'])
@token_required # JWT 인증 필요
def delete_file(file_id):
    """
    특정 파일 ID에 해당하는 파일을 삭제합니다.
    파일 소유자만 자신의 파일을 삭제할 수 있습니다.
    서버의 실제 파일과 데이터베이스의 메타데이터를 모두 삭제합니다.
    """
    db = get_db()
    cursor = db.cursor()

    # 파일 존재 및 소유권 확인, 그리고 파일 경로 가져오기
    try:
        cursor.execute("SELECT user_id, filepath FROM files WHERE id = ?", (file_id,))
        file_record = cursor.fetchone()
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching file for deletion: " + str(e)}), 500

    if not file_record:
        return jsonify({"message": "File not found"}), 404

    if file_record['user_id'] != g.current_user_id:
        return jsonify({"message": "Access denied. You are not the owner of this file."}), 403

    server_filepath_to_delete = file_record['filepath']

    try:
        # 1. 데이터베이스에서 파일 메타데이터 삭제
        cursor.execute("DELETE FROM files WHERE id = ?", (file_id,))
        # db.commit() # 실제 파일 삭제 성공 후 커밋하는 것이 더 안전할 수 있음

        # 2. 서버에서 실제 파일 삭제
        if os.path.exists(server_filepath_to_delete):
            os.remove(server_filepath_to_delete)
        else:
            # DB에는 있었지만 실제 파일이 없는 경우, 경고 로그를 남길 수 있음
            print(f"Warning: File {server_filepath_to_delete} not found on server but was in DB.")
            # 이 경우에도 DB 레코드는 삭제하는 것이 일반적임

        db.commit() # 모든 작업 성공 후 최종 커밋
        return jsonify({"message": "File deleted successfully"}), 200
    
    except sqlite3.Error as e_db:
        db.rollback()
        return jsonify({"message": "Database error during file deletion: " + str(e_db)}), 500
    except OSError as e_os:
        # 실제 파일 삭제 중 오류 발생 시 DB 롤백 (이미 커밋했다면 별도 처리 필요)
        # 위에서는 DB 삭제 후 파일 삭제 순서이므로, 파일 삭제 실패 시 DB는 이미 삭제되었을 수 있음.
        # 순서를 바꾸거나, 트랜잭션 관리를 더 정교하게 할 수 있음.
        # 여기서는 DB 삭제를 먼저 시도하고, 파일 삭제 실패 시에도 DB는 삭제된 상태로 둘 수 있음 (또는 롤백)
        db.rollback() # 파일 시스템 오류 시에도 DB 롤백
        return jsonify({"message": "Error deleting file from server: " + str(e_os)}), 500
    except Exception as e:
        db.rollback()
        return jsonify({"message": "An unexpected error occurred during file deletion: " + str(e)}), 500

# 애플리케이션 실행
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5050, debug=True)
