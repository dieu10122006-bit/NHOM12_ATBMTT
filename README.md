# Secure Assignment Chunk Transfer (SACT)
# Link WEB cho Mọi Người TEST https://sact-nhom12-onrender-com.onrender.com/register
Hệ thống truyền file bài tập bảo mật qua giao thức TCP tự thiết kế, sử dụng mã hóa lai (hybrid encryption) RSA + AES, chữ ký số RSA-PSS, và ghi log toàn bộ quá trình vào MySQL.

## Mục tiêu

Đảm bảo 3 thuộc tính bảo mật cốt lõi khi sinh viên nộp bài tập qua mạng:

- **Bảo mật (Confidentiality):** Dữ liệu file được mã hóa bằng AES-256-GCM, khóa phiên AES được bảo vệ bằng RSA-OAEP — chỉ server sở hữu private key mới giải mã được.
- **Toàn vẹn (Integrity):** Mỗi chunk được băm bằng SHA-256; AES-GCM tự động phát hiện dữ liệu bị sửa đổi trên đường truyền.
- **Xác thực & chống chối bỏ (Authentication & Non-repudiation):** Manifest (metadata của lần nộp bài) được ký bằng RSA-PSS với private key của sinh viên — server xác minh chữ ký trước khi chấp nhận bất kỳ chunk nào.

## Kiến trúc
Client (sinh viên)                       Server (giảng viên/hệ thống)
───────────────────                      ────────────────────────────

Sinh khóa phiên AES-256 ngẫu nhiên
Mã hóa khóa phiên bằng RSA-OAEP
(public key của SERVER)        ───►   Giải mã khóa phiên bằng
RSA private key của server
Tạo manifest: MSV, tên file,
tổng số chunk, hash từng chunk,
hash toàn file
Ký manifest bằng RSA-PSS
(private key của CLIENT)       ───►   Tra public key sinh viên trong DB,
xác thực chữ ký bằng RSA-PSS
Chia file thành các chunk,
mã hóa từng chunk bằng
AES-GCM (dùng khóa phiên)      ───►   Giải mã từng chunk, kiểm tra
SHA-256, phát hiện chunk
trùng lặp/hỏng/thiếu
                                   Ráp file hoàn chỉnh, so hash
                                   toàn file, ghi log vào MySQL



## Công nghệ sử dụng

| Thành phần | Công nghệ |
|---|---|
| Ngôn ngữ | Python 3.14 |
| Mật mã | `cryptography` (RSA-2048, AES-256-GCM, SHA-256) |
| Giao tiếp mạng | Python `socket` (TCP), giao thức đóng khung tự thiết kế |
| Cơ sở dữ liệu | MySQL 8.0, thông qua `mysql-connector-python` |
| Cấu hình | `python-dotenv` (biến môi trường trong `.env`) |

## Cấu trúc thư mục
secure_chunk_transfer/
├── common/
│   ├── crypto_utils.py   # RSA-OAEP, RSA-PSS, AES-GCM, SHA-256
│   ├── protocol.py       # Đóng khung gói tin TCP, gửi/nhận JSON & binary
│   ├── db.py              # Các hàm thao tác MySQL
│   └── config.py          # Đọc cấu hình từ .env
├── db/
│   ├── schema.sql          # Định nghĩa 4 bảng: students, assignments, submissions, chunk_logs
│   └── seed.py             # Thêm dữ liệu mẫu (sinh viên, bài tập)
├── keys/                    # Cặp khóa RSA của server và client (.pem — không commit)
├── demo_files/              # File mẫu dùng để test (.txt, .zip, .pdf, .bin)
├── received/                # Nơi server ráp file sau khi nhận (không commit)
├── logs/                    # Log chạy server (không commit)
├── server.py                # Server: nhận, xác thực, giải mã, ráp file
├── client.py                # Client: chia chunk, mã hóa, ký, gửi
├── generate_keys.py          # Sinh cặp khóa RSA cho server & client
├── benchmark_performance.py  # Đo hiệu năng mã hóa/giải mã
├── test_attacks.py           # Kiểm thử 4 kịch bản tấn công giả lập
├── requirements.txt
└── .env                       # Cấu hình DB (không commit)

## Cài đặt & Chạy thử

### 1. Cài môi trường

```bash
python -m venv venv
venv\Scripts\Activate.ps1        # Windows
pip install -r requirements.txt
```

### 2. Cấu hình MySQL

Tạo database và user riêng (không dùng `root`):

```sql
CREATE DATABASE sact_db;
CREATE USER 'sact_user'@'localhost' IDENTIFIED BY '<mat_khau>';
GRANT ALL PRIVILEGES ON sact_db.* TO 'sact_user'@'localhost';
FLUSH PRIVILEGES;
```

Chạy `db/schema.sql` để tạo 4 bảng.

Tạo file `.env`:
DB_HOST=localhost
DB_PORT=3306
DB_USER=sact_user
DB_PASSWORD=<mat_khau>
DB_NAME=sact_db

### 3. Sinh khóa RSA và dữ liệu mẫu

```bash
python generate_keys.py
python db/seed.py
```

### 4. Chạy server và client

```bash
# Terminal 1
python server.py

# Terminal 2
python client.py demo_files/test.txt SV001 1
```

## Kiểm thử bảo mật

Chạy toàn bộ 4 kịch bản tấn công giả lập (sửa dữ liệu, giả mạo chữ ký, thiếu chunk, replay chunk):

```bash
python test_attacks.py
```

| Kịch bản | Mô tả | Kết quả kỳ vọng |
|---|---|---|
| A | Sửa 1 byte trong 1 chunk trước khi gửi | `failed` (phát hiện sai hash/giải mã lỗi) |
| B | Giả mạo chữ ký RSA-PSS của manifest | `rejected` (từ chối ngay từ bước xác thực) |
| C | Cố tình bỏ bớt 1 chunk khi gửi | `failed` (phát hiện thiếu chunk) |
| D | Gửi lại 1 chunk hai lần (replay) | `completed` (chunk trùng bị bỏ qua, không ảnh hưởng kết quả) |

## Đo hiệu năng

```bash
python benchmark_performance.py
```

So sánh thời gian mã hóa/giải mã AES-GCM và RSA-OAEP với file 1MB, 10MB, và ảnh hưởng của kích thước chunk (16KB/64KB/256KB).

## Tác giả

Bùi Diệu — Đại Nam University — Đề tài 6, học phần An toàn thông tin.