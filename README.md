# JWT Authentication API

A secure, production-ready JWT-based authentication system built with FastAPI, SQLAlchemy, and Supabase PostgreSQL. This API provides comprehensive user management, role-based access control, and robust security features.

## 🚀 Features

- **User Authentication**: Secure registration and login with JWT tokens
- **Role-Based Access Control**: Admin and user roles with appropriate permissions
- **Password Security**: Bcrypt hashing with configurable rounds
- **Token Management**: JWT with configurable expiration and refresh capabilities
- **User Management**: Complete CRUD operations for user accounts (admin only)
- **Database Integration**: SQLAlchemy ORM with Supabase PostgreSQL
- **API Documentation**: Auto-generated OpenAPI/Swagger documentation
- **Security Headers**: CORS, trusted hosts, and security middleware
- **Error Handling**: Comprehensive error handling with detailed responses
- **Logging**: Structured logging for monitoring and debugging
- **Health Checks**: Application and database health monitoring

## 🛠️ Technology Stack

- **Framework**: FastAPI 0.104.1
- **Database**: Supabase PostgreSQL with SQLAlchemy 2.0.23
- **Authentication**: JWT with python-jose[cryptography] 3.3.0
- **Password Hashing**: bcrypt via passlib[bcrypt] 1.7.4
- **Server**: Uvicorn 0.24.0
- **Environment**: python-dotenv 1.0.0
- **Validation**: Pydantic 2.5.0

## 📋 Prerequisites

- Python 3.8 or higher
- Supabase account and project
- Git (for cloning the repository)

## 🔧 Installation

### 1. Clone the Repository

```bash
git clone <repository-url>
cd jwt-authentication-api
```

### 2. Create Virtual Environment

```bash
# Create virtual environment
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Environment Configuration

The project includes a pre-configured `.env` file with your Supabase credentials. Review and modify if needed:

```env
# Supabase Configuration
SUPABASE_URL=https://nrhxybugnskvgofdbjxf.supabase.co
SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
SUPABASE_SERVICE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...

# Database Configuration
DATABASE_URL=postgresql://postgres:[YOUR-PASSWORD]@db.nrhxybugnskvgofdbjxf.supabase.co:5432/postgres

# JWT Configuration
JWT_SECRET_KEY=your-super-secret-jwt-key-change-this-in-production
JWT_ALGORITHM=HS256
JWT_EXPIRATION_HOURS=24

# Application Settings
ENVIRONMENT=development
API_TITLE=JWT Authentication API
API_VERSION=1.0.0
DEBUG=true
```

**Important**: Update the `DATABASE_URL` with your actual Supabase database password.

### 5. Database Setup

Execute the SQL queries in `database_schema.sql` in your Supabase SQL editor:

1. Open your Supabase project dashboard
2. Go to the SQL Editor
3. Copy and paste the contents of `database_schema.sql`
4. Execute the queries to create the required tables and configurations

The schema includes:
- `users` table with UUID primary keys
- `user_role` enum (admin, user)
- Indexes for performance
- Row Level Security (RLS) policies
- Triggers for automatic timestamp updates

## 🚀 Running the Application

### Backend API Server

#### Development Mode

```bash
# Using the startup script (recommended)
python run.py

# Or directly with uvicorn
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

#### Production Mode

```bash
# Set environment to production
export ENVIRONMENT=production
export DEBUG=false

# Run with production settings
uvicorn app.main:app --host 0.0.0.0 --port 8000 --workers 4
```

The API will be available at:
- **API**: http://localhost:8000
- **Documentation**: http://localhost:8000/docs (development only)
- **ReDoc**: http://localhost:8000/redoc (development only)
- **Health Check**: http://localhost:8000/health

### Frontend (Streamlit)

#### Quick Start

```bash
# Start the frontend (Windows)
start_frontend.bat

# Or using Python directly
python run_frontend.py
```

#### Manual Setup

```bash
# Install frontend dependencies
pip install streamlit requests pandas

# Start Streamlit
streamlit run streamlit_app.py --server.port=8501
```

The frontend will be available at:
- **Frontend**: http://localhost:8501

#### Frontend Features

- **User Registration**: Create new user accounts
- **User Login**: Authenticate with username/email and password
- **Profile Management**: View and update user profile
- **Admin Dashboard**: User management and statistics (admin only)
- **Real-time API Integration**: Direct connection to FastAPI backend
- **Responsive UI**: Clean and intuitive interface

#### Running Both Services

1. **Start the API server first**:
   ```bash
   python run.py
   ```

2. **Start the frontend** (in a new terminal):
   ```bash
   python run_frontend.py
   ```

3. **Access the applications**:
   - Frontend: http://localhost:8501
   - API: http://localhost:8000
   - API Docs: http://localhost:8000/docs

## 📚 API Documentation

### Authentication Endpoints

#### POST `/api/v1/auth/register`
Register a new user account.

```json
{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "SecurePassword123!"
}
```

#### POST `/api/v1/auth/login`
Login with username/email and password.

```json
{
  "username": "john_doe",
  "password": "SecurePassword123!"
}
```

#### GET `/api/v1/auth/profile`
Get current user profile (requires authentication).

#### PUT `/api/v1/auth/change-password`
Change user password (requires authentication).

```json
{
  "current_password": "OldPassword123!",
  "new_password": "NewPassword123!"
}
```

#### POST `/api/v1/auth/refresh`
Refresh JWT token (requires valid token).

### User Management Endpoints (Admin Only)

#### GET `/api/v1/users/`
Get paginated list of all users with filtering options.

#### GET `/api/v1/users/{user_id}`
Get specific user by ID.

#### PUT `/api/v1/users/{user_id}`
Update user information.

#### PUT `/api/v1/users/{user_id}/role`
Update user role.

#### DELETE `/api/v1/users/{user_id}`
Delete user account.

#### GET `/api/v1/users/stats/summary`
Get user statistics and analytics.

### Authentication

All protected endpoints require a JWT token in the Authorization header:

```
Authorization: Bearer <your-jwt-token>
```

## 🔒 Security Features

### Password Security
- Minimum 8 characters
- Must contain uppercase, lowercase, number, and special character
- Bcrypt hashing with 12 rounds
- Password change requires current password verification

### JWT Security
- Configurable expiration time
- Secure secret key
- Token refresh capability
- Automatic token validation

### API Security
- CORS configuration
- Trusted host middleware (production)
- Request rate limiting ready
- Comprehensive input validation
- SQL injection prevention via ORM

### Database Security
- Row Level Security (RLS) policies
- UUID primary keys
- Prepared statements via SQLAlchemy
- Connection pooling

## 🏗️ Project Structure

```
jwt-authentication-api/
├── app/
│   ├── __init__.py
│   ├── main.py                 # FastAPI application entry point
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py          # Application configuration
│   │   ├── database.py        # Database connection and session management
│   │   └── security.py        # JWT and password utilities
│   ├── models/
│   │   ├── __init__.py
│   │   └── user.py            # SQLAlchemy User model
│   ├── schemas/
│   │   ├── __init__.py
│   │   └── user.py            # Pydantic models for API validation
│   ├── dependencies/
│   │   ├── __init__.py
│   │   └── auth.py            # Authentication dependencies
│   └── routers/
│       ├── __init__.py
│       ├── auth.py            # Authentication endpoints
│       └── users.py           # User management endpoints
├── .env                       # Environment variables
├── requirements.txt           # Python dependencies
├── database_schema.sql        # Database schema and setup
├── run.py                     # Application startup script
└── README.md                  # This file
```

## 🧪 Testing

### Manual Testing

1. **Health Check**:
   ```bash
   curl http://localhost:8000/health
   ```

2. **User Registration**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/register" \
        -H "Content-Type: application/json" \
        -d '{
          "username": "testuser",
          "email": "test@example.com",
          "password": "TestPassword123!"
        }'
   ```

3. **User Login**:
   ```bash
   curl -X POST "http://localhost:8000/api/v1/auth/login" \
        -H "Content-Type: application/json" \
        -d '{
          "username": "testuser",
          "password": "TestPassword123!"
        }'
   ```

4. **Access Protected Endpoint**:
   ```bash
   curl -X GET "http://localhost:8000/api/v1/auth/profile" \
        -H "Authorization: Bearer <your-jwt-token>"
   ```

### API Documentation Testing

Visit http://localhost:8000/docs to use the interactive Swagger UI for testing all endpoints.

## 🚀 Deployment

### Local Deployment

The application is configured for local deployment by default. Simply run:

```bash
python run.py
```

### Production Deployment

1. **Update Environment Variables**:
   ```env
   ENVIRONMENT=production
   DEBUG=false
   JWT_SECRET_KEY=<strong-production-secret>
   ```

2. **Use Production WSGI Server**:
   ```bash
   pip install gunicorn
   gunicorn app.main:app -w 4 -k uvicorn.workers.UvicornWorker
   ```

3. **Docker Deployment** (optional):
   ```dockerfile
   FROM python:3.11-slim
   WORKDIR /app
   COPY requirements.txt .
   RUN pip install -r requirements.txt
   COPY . .
   CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default | Required |
|----------|-------------|---------|----------|
| `SUPABASE_URL` | Supabase project URL | - | Yes |
| `SUPABASE_ANON_KEY` | Supabase anonymous key | - | Yes |
| `SUPABASE_SERVICE_KEY` | Supabase service role key | - | Yes |
| `DATABASE_URL` | PostgreSQL connection string | - | Yes |
| `JWT_SECRET_KEY` | JWT signing secret | - | Yes |
| `JWT_ALGORITHM` | JWT algorithm | HS256 | No |
| `JWT_EXPIRATION_HOURS` | Token expiration time | 24 | No |
| `ENVIRONMENT` | Application environment | development | No |
| `DEBUG` | Debug mode | true | No |
| `API_TITLE` | API title | JWT Authentication API | No |
| `API_VERSION` | API version | 1.0.0 | No |

### Security Configuration

- **Password Requirements**: Configurable in `app/core/security.py`
- **JWT Settings**: Configurable in `app/core/config.py`
- **CORS Settings**: Configurable in `app/main.py`
- **Rate Limiting**: Ready for implementation

## 📝 Logging

The application uses structured logging with the following levels:
- **INFO**: General application flow
- **WARNING**: Potential issues (failed login attempts, etc.)
- **ERROR**: Application errors
- **DEBUG**: Detailed debugging information (development only)

Logs are written to both console and `app.log` file.

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Failed**:
   - Check your Supabase credentials
   - Verify the database URL format
   - Ensure your IP is allowed in Supabase settings

2. **JWT Token Invalid**:
   - Check JWT_SECRET_KEY configuration
   - Verify token hasn't expired
   - Ensure proper Authorization header format

3. **Import Errors**:
   - Verify all dependencies are installed
   - Check Python version compatibility
   - Activate virtual environment

4. **Permission Denied**:
   - Check user roles and permissions
   - Verify JWT token is valid
   - Ensure proper endpoint access levels

### Debug Mode

Enable debug mode for detailed error information:

```env
DEBUG=true
ENVIRONMENT=development
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Check the troubleshooting section
- Review the API documentation at `/docs`
- Check application logs for error details
- Verify environment configuration

## 🔄 Version History

- **v1.0.0**: Initial release with core authentication features
  - User registration and login
  - JWT token authentication
  - Role-based access control
  - User management (admin)
  - Comprehensive security features
  - API documentation
  - Health monitoring

---

**Built with ❤️ using FastAPI, SQLAlchemy, and Supabase**