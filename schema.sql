DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS files; -- 나중에 파일 정보를 저장할 테이블 (미리 추가)

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 파일 메타데이터를 저장할 테이블 (과제 요구사항 기반) [cite: 3]
CREATE TABLE files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    filename TEXT NOT NULL,
    filepath TEXT NOT NULL, -- 실제 파일 저장 경로
    filesize INTEGER NOT NULL,
    upload_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    permission TEXT DEFAULT 'private', -- 'public', 'private', 'password' [cite: 2]
    access_password_hash TEXT, -- 'password' 접근 권한 시 사용될 비밀번호 해시
    download_link_id TEXT UNIQUE NOT NULL, -- 파일 다운로드 고유 링크 ID [cite: 2]
    FOREIGN KEY (user_id) REFERENCES users (id)
);