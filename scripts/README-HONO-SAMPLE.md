# Hono.js REST API with Authentication Sample

This is a comprehensive example of a REST API built with **Hono.js** and integrated with the framework-agnostic authentication library. It demonstrates a complete blog API with user authentication, authorization, and CRUD operations.

## 🚀 Features

- **User Authentication**: Registration, login, and JWT token-based authentication
- **Role-Based Access Control (RBAC)**: Admin and user roles with different permissions
- **Blog Post Management**: Full CRUD operations for blog posts
- **Ownership-Based Permissions**: Users can only modify their own posts
- **Security Features**: CORS, rate limiting, input validation, and error handling
- **Admin Panel**: Special endpoints for administrators
- **Comprehensive Testing**: Automated test suite for all endpoints

## 📁 Files

- `hono-sample.ts` - Main Hono.js application with all endpoints
- `test-api.ts` - Comprehensive test suite for the API
- `README-HONO-SAMPLE.md` - This documentation file

## 🛠️ Setup and Running

### Prerequisites

- Bun runtime installed
- The auth library properly set up in the project

### Running the API

```bash
# Start the Hono API server
bun ./scripts/hono-sample.ts
```

The server will start on `http://localhost:3001`

### Running Tests

```bash
# Run the comprehensive test suite
bun ./scripts/test-api.ts
```

## 📚 API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Welcome message and API documentation |
| GET | `/health` | Health check endpoint |
| GET | `/posts` | Get all posts (with optional `?published=true` filter) |
| GET | `/posts/:id` | Get a specific post by ID |

### Authentication Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|---------------|
| POST | `/auth/register` | Register a new user | ❌ |
| POST | `/auth/login` | Login user | ❌ |
| GET | `/auth/profile` | Get current user profile | ✅ |

### Blog Post Endpoints

| Method | Endpoint | Description | Auth Required | Permission |
|--------|----------|-------------|---------------|------------|
| POST | `/posts` | Create a new post | ✅ | User |
| PUT | `/posts/:id` | Update a post | ✅ | Owner/Admin |
| DELETE | `/posts/:id` | Delete a post | ✅ | Owner/Admin |
| PUT | `/posts/:id/publish` | Publish/unpublish a post | ✅ | Owner/Admin |

### Admin Endpoints

| Method | Endpoint | Description | Auth Required | Permission |
|--------|----------|-------------|---------------|------------|
| GET | `/admin/users` | Get all users | ✅ | Admin |
| GET | `/admin/posts` | Get all posts (including unpublished) | ✅ | Admin |

## 🔐 Authentication Flow

### 1. User Registration

```bash
curl -X POST http://localhost:3001/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123",
    "firstName": "John",
    "lastName": "Doe"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe"
  },
  "token": "jwt-token-here"
}
```

### 2. User Login

```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "password123"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "firstName": "John",
    "lastName": "Doe",
    "roles": ["user"]
  },
  "token": "jwt-token-here"
}
```

### 3. Using the Token

For protected endpoints, include the JWT token in the Authorization header:

```bash
curl -X GET http://localhost:3001/auth/profile \
  -H "Authorization: Bearer your-jwt-token-here"
```

## 📝 Blog Post Operations

### Create a Post

```bash
curl -X POST http://localhost:3001/posts \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "title": "My First Post",
    "content": "This is the content of my first blog post.",
    "published": false
  }'
```

### Get All Posts

```bash
# Get all posts
curl http://localhost:3001/posts

# Get only published posts
curl http://localhost:3001/posts?published=true
```

### Update a Post

```bash
curl -X PUT http://localhost:3001/posts/post-id \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{
    "title": "Updated Title",
    "content": "Updated content",
    "published": true
  }'
```

### Publish/Unpublish a Post

```bash
curl -X PUT http://localhost:3001/posts/post-id/publish \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer your-jwt-token" \
  -d '{"published": true}'
```

### Delete a Post

```bash
curl -X DELETE http://localhost:3001/posts/post-id \
  -H "Authorization: Bearer your-jwt-token"
```

## 🔒 Security Features

### JWT Authentication
- All protected routes require a valid JWT token
- Tokens are generated upon successful login/registration
- Tokens contain user information and roles

### Role-Based Access Control
- **User Role**: Can create, read, update, and delete their own posts
- **Admin Role**: Can perform all operations on any post and access admin endpoints

### Ownership Validation
- Users can only modify posts they created
- Admins can modify any post
- Ownership is validated on update and delete operations

### Input Validation
- Email and password validation on registration
- Required field validation on all endpoints
- Data sanitization and trimming

### Error Handling
- Comprehensive error responses with appropriate HTTP status codes
- Detailed error messages for debugging
- Graceful handling of authentication failures

## 🧪 Testing

The included test suite (`test-api.ts`) covers:

- ✅ Health check and welcome endpoints
- ✅ User registration and login
- ✅ Protected routes with JWT authentication
- ✅ Blog post CRUD operations
- ✅ Ownership-based permissions
- ✅ Security and error handling
- ✅ Admin endpoint access control
- ✅ Unauthorized access attempts
- ✅ Invalid token handling
- ✅ 404 error handling

### Test Output Example

```
🧪 Starting Blog API Tests...
==================================================

🏥 Testing Health Check...
🔗 GET /health
📊 Status: 200
📄 Response: {
  "status": "ok",
  "timestamp": "2024-01-01T12:00:00.000Z",
  "service": "Blog API with Authentication"
}

📝 Testing User Registration...
🔗 POST /auth/register
📊 Status: 201
📄 Response: {
  "success": true,
  "message": "User registered successfully",
  "user": { ... },
  "token": "jwt-token"
}

... (more test results)

==================================================
✅ All tests completed!
```

## 🏗️ Architecture

### Middleware Stack
1. **Logger**: Request logging
2. **Pretty JSON**: Formatted JSON responses
3. **CORS**: Cross-origin resource sharing
4. **Auth Middleware**: JWT token validation (on protected routes)

### Route Organization
- **Main App**: Health check and welcome
- **Auth Routes**: Registration, login, profile
- **Posts Routes**: Blog post CRUD operations
- **Admin Routes**: Administrative endpoints

### Data Storage
- **Users**: Stored in SQLite database via auth library
- **Posts**: In-memory storage (for demo purposes)
- **Authentication**: JWT tokens with user context

## 🔧 Configuration

### Environment Variables
- `JWT_SECRET`: Secret key for JWT token signing (defaults to demo key)
- `PORT`: Server port (defaults to 3001)

### Auth Library Configuration
```typescript
const auth = createHonoAuth({
  jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
  jwtExpiration: '24h'
})
```

## 🚀 Production Considerations

1. **Database**: Replace in-memory post storage with a real database
2. **Environment Variables**: Set proper JWT_SECRET in production
3. **HTTPS**: Use HTTPS in production
4. **Rate Limiting**: Implement proper rate limiting
5. **Logging**: Add comprehensive logging
6. **Monitoring**: Add health checks and monitoring
7. **Validation**: Add more robust input validation
8. **Caching**: Implement caching for better performance

## 📖 Related Documentation

- [Hono.js Documentation](https://hono.dev/)
- [Auth Library Documentation](../AUTH_LIBRARY_IMPLEMENTATION.md)
- [JWT.io](https://jwt.io/) - JWT token information
- [REST API Best Practices](https://restfulapi.net/)

## 🤝 Contributing

This is a sample implementation. Feel free to extend it with:
- More blog features (categories, tags, comments)
- File upload capabilities
- Email verification
- Password reset functionality
- Social media authentication
- Real-time features with WebSockets

---

**Happy coding! 🎉**