# 🛡️ Tamper-Evident Logging System

A professional logging system with cryptographic hash verification, tamper detection, and real-time monitoring dashboard.

## ✨ Features

- ✅ **Hash Chaining**: SHA-256 cryptographic integrity verification
- ✅ **Tamper Detection**: Instantly identify any log modifications
- ✅ **IP Tracking**: Record source IP for complete audit trails
- ✅ **Alert System**: Real-time notifications for critical events
- ✅ **Admin Panel**: Secure monitoring and management dashboard
- ✅ **CSV Export**: Download complete audit records

## 📁 Project Structure

```
project/
├── app.py                 # Flask application
├── requirements.txt       # Python dependencies
├── logs.json             # Event log storage
├── alerts.json           # Alert tracking
├── README.md             # This file
│
└── templates/
    ├── index.html        # Home page with event logging
    ├── logs.html         # Event log viewer with integrity status
    ├── admin.html        # Admin login & dashboard (unified)
    └── error.html        # Error page (404, 500, etc)
```

## 🚀 Quick Start

### Installation

```bash
# Clone/navigate to project
cd project

# Create virtual environment
python -m venv .venv

# Activate virtual environment
# Windows:
.\.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Application

```bash
# Set the admin password (required)
export ADMIN_PASSWORD="your_secure_password_here"

# On Windows (PowerShell):
$env:ADMIN_PASSWORD="your_secure_password_here"

# Run the Flask application
python app.py
```

The application will be available at: **http://127.0.0.1:5000**

## 🔐 Configuration

### Environment Variables

- **ADMIN_PASSWORD** (required): Set a secure password for admin access
- **SECRET_KEY** (optional): Flask session signing key (auto-generated if not set)

```bash
# Example configuration
export ADMIN_PASSWORD="MySecurePassword123"
export SECRET_KEY="your_session_secret_key"
```

## 📖 Usage

### Pages

| Route | Purpose |
|-------|---------|
| `/` | Home - Log new events |
| `/logs` | View all logs with integrity status |
| `/admin` | Admin login & dashboard |
| `/export` | Download CSV audit trail |

### Default Admin Credentials

The admin password must be set via the **ADMIN_PASSWORD** environment variable before running the application.

```bash
# Example: Set a strong password before startup
export ADMIN_PASSWORD="YourSecurePassword123!"
python app.py
```

⚠️ **Important**: Never hardcode credentials in application files. Always use environment variables for production deployments.

## 🔐 Security Features

### Hash Chaining
Each log entry includes a hash of the previous log:
```
Log 0: hash_0
Log 1: hash_1 = SHA256(timestamp | event | desc | ip | severity | hash_0)
Log 2: hash_2 = SHA256(timestamp | event | desc | ip | severity | hash_1)
```

### Tamper Detection
If any log is modified, the entire chain breaks and tampering is detected immediately.

### Input Validation
- Max 50 chars for event
- Max 500 chars for description  
- Dangerous characters removed: `< > " '`

### Rate Limiting
- 5 login attempts allowed per 60 seconds
- Excess attempts logged as CRITICAL alerts

## 📊 Log Entry Format

```json
{
  "id": 1,
  "timestamp": "2026-04-15T10:30:45.123456",
  "event": "LOGIN",
  "description": "User authentication successful",
  "ip": "192.168.1.100",
  "severity": "INFO",
  "prev_hash": "0",
  "hash": "a1b2c3d4e5f6..."
}
```

## 🚨 Alert Format

```json
{
  "id": 1,
  "timestamp": "2026-04-15T10:30:45.123456",
  "event": "ALERT",
  "description": "Failed admin login attempt",
  "ip": "192.168.1.100",
  "status": "ACTIVE",
  "acknowledged": false
}
```

## 🎯 API Endpoints

### Logging
- `POST /add` - Add new event
- `GET /export` - Export logs as CSV
- `GET /api/logs/verified` - Check integrity status (JSON)

### Admin
- `GET/POST /admin` - Login and dashboard
- `GET /logout` - Logout
- `GET /api/alerts` - Get active alerts (protected)
- `PUT /api/acknowledge-alert/<id>` - Acknowledge alert (protected)

### Error Handling
- `GET /error` - Error pages (404, 500)

## 🔧 Configuration

Edit `app.py` for production:

```python
# Change admin password
ADMIN_PASSWORD = "YourSecurePassword"

# Set secret key from environment
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key")

# Disable debug mode
app.run(debug=False, host="127.0.0.1", port=5000)
```

## 📊 Admin Dashboard

**Features:**
- System integrity status
- Active alerts list
- Last 20 logs
- One-click alert acknowledgment
- CSV export button

**Protected by**: Password authentication + session management

## 🧪 Testing

### Add an Event
1. Go to home page
2. Enter event type and description
3. Click "Log Event"
4. View in `/logs` with integrity ✓

### Check Integrity
1. Visit `/logs`
2. See "All Logs Secure ✅" or tampering notice
3. Admin dashboard shows detailed status

### Test Admin Panel
1. Go to `/admin`
2. Enter default password: `SecureAdmin123!`
3. View dashboard with stats and alerts

## 📈 Event Types

| Event | Severity | Use Case |
|-------|----------|----------|
| `INFO` | INFO | Standard operations |
| `AUTH` | WARNING | Logins/authentications |
| `ALERT` | CRITICAL | Suspicious activities |

## ⚙️ Environment Setup

### Production Deployment

1. **Change Admin Password**
   ```python
   ADMIN_PASSWORD = "ComplexSecure123!@#"
   ```

2. **Set Secret Key**
   ```bash
   export SECRET_KEY="your-random-secret-key"
   ```

3. **Use WSGI Server**
   ```bash
   pip install gunicorn
   gunicorn -w 4 app:app
   ```

4. **Deploy with HTTPS**
   - Use reverse proxy (nginx/apache)
   - Enable SSL/TLS

5. **Enable Log Rotation**
   - Logs auto-rotate at 1MB size

## 🐛 Troubleshooting

| Issue | Solution |
|-------|----------|
| Port 5000 in use | Change port in `app.py` |
| Import errors | Run `pip install -r requirements.txt` |
| Can't login | Check password in `app.py` |
| Logs not showing | Ensure `logs.json` exists |

## 📝 Log File Management

### Backup Logs
```bash
# Export before archiving
curl http://127.0.0.1:5000/export -o logs_backup_$(date +%Y%m%d).csv
```

### Reset Logs (Development Only)
```bash
# Clear logs.json
echo "[]" > logs.json
echo "[]" > alerts.json
```

## 🔒 Security Checklist

- [ ] Change admin password
- [ ] Set `SECRET_KEY` environment variable
- [ ] Disable debug mode
- [ ] Use HTTPS in production
- [ ] Enable regular backups
- [ ] Monitor alerts
- [ ] Rotate logs periodically

## 📞 Support

For issues:
1. Check `/logs` for recent events
2. Review alerts in admin dashboard
3. Export logs for analysis
4. Verify hash chain integrity

## 📄 License

MIT License

---

**Version**: 2.0 (Clean & Minimal)  
**Status**: Production Ready ✅  
**Last Updated**: April 15, 2026

