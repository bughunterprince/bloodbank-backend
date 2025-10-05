# Blood Bank Management Backend API

Flask-based REST API for Blood Bank Management System.

## Deploy on Render

1. **Create a New Web Service** on Render
2. **Connect this repository**
3. **Configuration**:
   - Build Command: `pip install -r requirements.txt`
   - Start Command: `python app.py`
   - Environment Variables:
     - `DB_ENGINE=sqlite`
     - `SECRET_KEY=your-random-secret-key`
     - `OTP_MODE=console`

## API Endpoints

- `GET /` - API information
- `GET /api/health` - Health check
- `POST /api/login` - Authentication
- `POST /api/logout` - Logout
- `GET /api/user` - Get current user
- `POST /api/submit-customer` - Customer appointment

## Local Development

```bash
pip install -r requirements.txt
python app.py
```

Server runs on http://127.0.0.1:5000

## Database

SQLite database with tables:
- users
- customer_appointments  
- blood_stock
- blood_requests

## Admin Login
- Email: admin@gmail.com
- Password: admin