USE sact_db;

-- Bảng sinh viên
CREATE TABLE students (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ho_ten VARCHAR(100) NOT NULL,
    msv VARCHAR(20) NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Bảng bài tập
CREATE TABLE assignments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ten_bai_tap VARCHAR(255) NOT NULL,
    han_nop DATETIME,
    mo_ta TEXT
);

-- Bảng bài nộp
CREATE TABLE submissions (
    id INT AUTO_INCREMENT PRIMARY KEY,
    student_id INT NOT NULL,
    assignment_id INT NOT NULL,
    ten_file VARCHAR(255) NOT NULL,
    tong_so_chunk INT NOT NULL,
    hash_toan_file VARCHAR(64),
    trang_thai ENUM('receiving', 'completed', 'failed') DEFAULT 'receiving',
    thoi_gian_nop TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (student_id) REFERENCES students(id),
    FOREIGN KEY (assignment_id) REFERENCES assignments(id)
);

-- Bảng log từng chunk
CREATE TABLE chunk_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    submission_id INT NOT NULL,
    chunk_index INT NOT NULL,
    hash_chunk VARCHAR(64),
    ket_qua ENUM('valid', 'invalid_hash', 'decrypt_failed', 'duplicate') NOT NULL,
    thoi_gian TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (submission_id) REFERENCES submissions(id)
);