import { test, expect, describe } from 'bun:test';
import app from '../examples/hono';

describe('Public Routes', () => {
  test('GET / returns welcome message for guest', async () => {
    const res = await app.request('/auth');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe('Welcome, guest! Please log in.');
  });
});
describe('Registration', () => {
  test('allows basic user registration', async () => {
    const newUser = { first_name: 'Test', last_name: 'User', email: 'test@example.com', password: 'password123' };
    const res = await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.data.user).toBeDefined();
    expect(data.data.token).toBeDefined();
    expect(data.data.refreshToken).toBeDefined();
  });

  test('allows registration with role', async () => {
    const newUser = { first_name: 'Mod', last_name: 'User', email: 'mod@example.com', password: 'modpassword', role_name: 'moderator', permission_names: ['edit:content'] };
    const res = await app.request('/auth/register-with-role', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(newUser) });
    expect(res.status).toBe(201);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.message).toBe('User registered successfully');
  });

  test('prevents duplicate email registration', async () => {
    // First registration
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Test', last_name: 'User', email: 'duplicate@example.com', password: 'password123' }) });
    // Second attempt
    const res = await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Test2', last_name: 'User2', email: 'duplicate@example.com', password: 'password456' }) });
    expect(res.status).toBe(409);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({ type: 'USER_ALREADY_EXISTS', message: 'A user with this email already exists' });
  });
});
describe('Login', () => {
  test('allows successful login', async () => {
    // Register user first
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Test', last_name: 'User', email: 'login@example.com', password: 'password123' }) });
    const credentials = { email: 'login@example.com', password: 'password123' };
    const res = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.success).toBe(true);
    expect(data.data.token).toBeDefined();
    expect(data.data.user).toBeDefined();
    expect(data.data.refreshToken).toBeDefined();
  });

  test('rejects invalid credentials', async () => {
    // Register user
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Test', last_name: 'User', email: 'invalid@example.com', password: 'password123' }) });
    const credentials = { email: 'invalid@example.com', password: 'wrongpassword' };
    const res = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({ type: 'INVALID_CREDENTIALS', message: 'Invalid credentials' });
  });

  test('rejects login for inactive user', async () => {
    // Register inactive user
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Inactive', last_name: 'User', email: 'inactive@example.com', password: 'password123', is_active: false }) });
    const credentials = { email: 'inactive@example.com', password: 'password123' };
    const res = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(credentials) });
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.success).toBe(false);
    expect(data.error).toMatchObject({ type: 'ACCOUNT_INACTIVE', message: 'User account is deactivated' });
  });
});
describe('Protected Routes', () => {
  test('allows authenticated user to access profile', async () => {
    // Register and login
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Test', last_name: 'User', email: 'profile@example.com', password: 'password123' }) });
    const loginRes = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'profile@example.com', password: 'password123' }) });
    const { data: { token } } = await loginRes.json();
    const res = await app.request('/api/profile', { headers: { 'Authorization': `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe('This is your private profile data.');
    expect(data.user.email).toBe('profile@example.com');
  });

  test('rejects unauthorized profile access', async () => {
    const res = await app.request('/api/profile');
    expect(res.status).toBe(401);
    const data = await res.json();
    expect(data.error).toBe('Authorization header is missing');
  });

  test('allows moderator to access mod content', async () => {
    // Register moderator
    await app.request('/auth/register-with-role', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Mod', last_name: 'User', email: 'mod2@example.com', password: 'modpass', role_name: 'moderator', permission_names: ['edit:content'] }) });
    const loginRes = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'mod2@example.com', password: 'modpass' }) });
    const { data: { token } } = await loginRes.json();
    const res = await app.request('/api/mod/content', { headers: { 'Authorization': `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.message).toBe('Here is the content you can moderate.');
  });

  test('allows admin to access user list', async () => {
    // Register admin
    await app.request('/auth/register-with-role', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Admin', last_name: 'User', email: 'admin@example.com', password: 'adminpass', role_name: 'admin', permission_names: ['manage:users'] }) });
    const loginRes = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'admin@example.com', password: 'adminpass' }) });
    const { data: { token } } = await loginRes.json();
    const res = await app.request('/api/admin/users', { headers: { 'Authorization': `Bearer ${token}` } });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.users).toBeDefined();
  });

  test('rejects non-moderator from mod content', async () => {
    // Register regular user
    await app.request('/auth/register', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ first_name: 'Regular', last_name: 'User', email: 'regular@example.com', password: 'regpass' }) });
    const loginRes = await app.request('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email: 'regular@example.com', password: 'regpass' }) });
    const { data: { token } } = await loginRes.json();
    const res = await app.request('/api/mod/content', { headers: { 'Authorization': `Bearer ${token}` } });
    expect(res.status).toBe(403);
    const data = await res.json();
    expect(data.error).toBe('Access denied. Required role not found.');
  });
});
// Remove redundant it() blocks at the end