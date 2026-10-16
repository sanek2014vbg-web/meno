# MeNo Messenger
**Commercial Grade Messaging System with E2E Encryption**

MeNo is a high-performance, secure messaging application built with a modern asynchronous stack. It features End-to-End (E2E) encryption using X25519 and AES-GCM, ensuring that only the participants of a chat can read the messages.

## 🚀 Tech Stack
- **Backend:** FastAPI (Python 3.12+), PostgreSQL 16, Redis 7.
- **Frontend:** Flet (Flutter for Python).
- **Storage:** S3-Compatible Object Storage (AWS S3 / MinIO).
- **Security:** TOTP 2FA, JWT Access/Refresh tokens, Account Lockout.
- **Delivery:** SMS.RU API, FCM (Push Notifications), WebSockets.

## ✨ Key Features
- **Security:** E2E Encryption, PIN-protected chats, and secure session management.
- **Performance:** Cursor-based pagination, Redis caching, and GIN-indexed full-text search.
- **Reliability:** Structured logging via Loguru, error tracking via Sentry, and CI/CD pipeline.
- **Multimedia:** Support for voice messages, images, and files via CDN.

## 🛠 Installation & Setup

### 1. Environment Configuration
Create a `.env` file in the project root based on `.env.example`.

### 2. Infrastructure (Docker)
```bash
docker-compose up -d
```

### 3. Server Setup
```bash
cd server
pip install -r requirements.txt
uvicorn main:app --reload
```

### 4. Client Setup
```bash
cd client
pip install -r requirements.txt
python main.py
```

## 🛡 Security Architecture
- **E2E:** Keys are generated and stored on the client device. The server only stores public keys.
- **Auth:** Multi-stage verification (SMS $\rightarrow$ Password $\rightarrow$ TOTP).
- **Protection:** Rate limiting per IP/User and automatic account lockout after 5 failed attempts.

## 📜 License
Distributed under the MIT License. See `LICENSE` for more information.
