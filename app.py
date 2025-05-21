import sqlite3
import bcrypt # 비밀번호 해싱
import jwt    # JWT 생성 및 검증
import datetime # JWT 만료 시간 설정을 위해
from flask import Flask, request, jsonify, g # g를 여기서 import 합니다.

app = Flask(__name__)

# JWT 설정
# !!매우 중요!! 실제 배포 시에는 환경 변수 등을 통해 안전하게 관리되는 복잡하고 예측 불가능한 키로 변경하세요.
# 예: import os; app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'fallback_secret_key_if_not_set')
app.config['SECRET_KEY'] = 'your_very_secret_key_please_change_it_for_production'
DATABASE = 'object_storage.db' # SQLite 데이터베이스 파일명

# SQLite 데이터베이스 연결 함수
def get_db():
    """
    현재 애플리케이션 컨텍스트에 대한 데이터베이스 연결을 가져오거나 새로 생성합니다.
    """
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
        db.row_factory = sqlite3.Row # 결과를 딕셔너리 형태로 (컬럼명으로) 접근 가능하게 합니다.
    return db

# 애플리케이션 컨텍스트 종료 시 데이터베이스 연결 자동 닫기
@app.teardown_appcontext
def close_connection(exception):
    """
    애플리케이션 컨텍스트가 종료될 때 데이터베이스 연결을 닫습니다.
    """
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()

# 데이터베이스 테이블 초기화 함수
def init_db():
    """
    schema.sql 파일에 정의된 대로 데이터베이스 테이블을 생성(또는 재생성)합니다.
    """
    with app.app_context(): # init_db_command에서 호출될 때 app_context가 필요합니다.
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

# Flask CLI에 'init-db' 명령어 추가
@app.cli.command('init-db')
def init_db_command():
    """
    기존 데이터를 지우고 새 테이블을 생성합니다.
    터미널에서 'flask init-db' 명령으로 실행합니다.
    """
    init_db()
    print('Initialized the database.')

# --- 기본 라우트 (애플리케이션 동작 테스트용) ---
@app.route('/')
def hello_world():
    """
    애플리케이션의 루트 URL에 접근했을 때 간단한 환영 메시지를 반환합니다.
    """
    return jsonify({"message": "Welcome to the Simple Object Storage API!"}), 200

# --- 회원가입 API (POST /register) ---
@app.route('/register', methods=['POST'])
def register():
    """
    새로운 사용자를 시스템에 등록합니다.
    요청 본문에는 'username'과 'password'가 JSON 형태로 포함되어야 합니다.
    """
    data = request.get_json() # 요청 본문에서 JSON 데이터 파싱

    # 필수 입력 값 검증
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400 # Bad Request

    username = data['username']
    password = data['password']

    db = get_db()
    cursor = db.cursor()

    # 사용자 이름 중복 확인
    try:
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            return jsonify({"message": "Username already exists"}), 409 # Conflict
    except sqlite3.Error as e:
        return jsonify({"message": "Database error checking username: " + str(e)}), 500 # Internal Server Error


    # 비밀번호 해싱 (bcrypt 사용)
    # password.encode('utf-8')는 문자열을 바이트로 변환합니다. bcrypt는 바이트를 입력으로 받습니다.
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    hashed_password_str = hashed_password_bytes.decode('utf-8') # 데이터베이스 저장을 위해 다시 문자열로 변환

    # 새 사용자 정보 데이터베이스에 삽입
    try:
        cursor.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)",
                       (username, hashed_password_str))
        db.commit() # 변경 사항 커밋
    except sqlite3.Error as e:
        db.rollback() # 오류 발생 시 롤백
        return jsonify({"message": "Database error registering user: " + str(e)}), 500 # Internal Server Error

    return jsonify({"message": "User registered successfully"}), 201 # Created

# --- 로그인 API (POST /login) ---
@app.route('/login', methods=['POST'])
def login():
    """
    사용자 로그인을 처리하고 성공 시 JWT를 발급합니다.
    요청 본문에는 'username'과 'password'가 JSON 형태로 포함되어야 합니다.
    """
    data = request.get_json()

    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"message": "Username and password are required"}), 400

    username = data['username']
    password = data['password']

    db = get_db()
    cursor = db.cursor()

    # 사용자 정보 조회
    try:
        cursor.execute("SELECT id, username, password_hash FROM users WHERE username = ?", (username,))
        user = cursor.fetchone() # sqlite3.Row 객체 또는 None 반환
    except sqlite3.Error as e:
        return jsonify({"message": "Database error fetching user: " + str(e)}), 500

    if not user:
        return jsonify({"message": "User not found"}), 404 # NotFound (사용자 이름이 틀렸을 수도 있음)

    # 저장된 해시된 비밀번호와 입력된 비밀번호 비교
    # user['password_hash']는 DB에서 읽어온 문자열, 이를 다시 바이트로 변환하여 bcrypt.checkpw에 전달
    stored_password_hash_bytes = user['password_hash'].encode('utf-8')
    if bcrypt.checkpw(password.encode('utf-8'), stored_password_hash_bytes):
        # 비밀번호 일치 시 JWT 생성
        token_payload = {
            'user_id': user['id'],
            'username': user['username'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1) # 토큰 만료 시간 (예: 1시간)
            # 'iat': datetime.datetime.utcnow() # 토큰 발급 시간 (선택 사항)
        }
        try:
            # HS256 알고리즘으로 토큰 인코딩
            token = jwt.encode(token_payload, app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({"message": "Login successful", "token": token}), 200 # OK
        except Exception as e:
            return jsonify({"message": "Error generating token: " + str(e)}), 500
    else:
        return jsonify({"message": "Invalid credentials"}), 401 # Unauthorized (비밀번호가 틀렸을 경우)


# 애플리케이션 실행 (개발 서버)
if __name__ == '__main__':
    # debug=True는 개발 중에 유용하며, 코드 변경 시 서버가 자동으로 재시작되고,
    # 오류 발생 시 브라우저에 디버깅 정보를 표시합니다.
    # 실제 배포 환경에서는 debug=False로 설정해야 합니다.
    # host='0.0.0.0'은 외부에서도 접속 가능하게 합니다 (로컬 네트워크 등).
    app.run(host='0.0.0.0', port=5050, debug=True)
