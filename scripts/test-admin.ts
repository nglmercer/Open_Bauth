#!/usr/bin/env bun

/**
 * Test script to verify admin endpoints work with admin credentials
 */

const BASE_URL = 'http://localhost:3001'

interface LoginResponse {
  success: boolean
  token?: string
  user?: any
  error?: string
}

interface ApiResponse {
  success: boolean
  users?: any[]
  posts?: any[]
  error?: string
  status?: number
  message?: string
  timestamp?: string
}

async function makeRequest(endpoint: string, options: RequestInit = {}): Promise<any> {
  const url = `${BASE_URL}${endpoint}`
  
  const headers = {
    'Content-Type': 'application/json',
    ...options.headers
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers
    })

    const data = await response.json()
    console.log(`\n🔗 ${options.method || 'GET'} ${endpoint}`)
    console.log(`📊 Status: ${response.status}`)
    console.log(`📄 Response:`, JSON.stringify(data, null, 2))
    
    return { ...data, status: response.status }
  } catch (error) {
    console.error(`❌ Error calling ${endpoint}:`, error)
    return { success: false, error: 'Network error' }
  }
}

async function testAdminEndpoints() {
  console.log('🧪 Testing Admin Endpoints with Admin Credentials')
  console.log('=' .repeat(60))
  
  // Step 1: Login as admin
  console.log('\n🔐 Logging in as admin...')
  const loginResponse: LoginResponse = await makeRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'admin@example.com',
      password: 'Admin123!@#'
    })
  })
  
  if (!loginResponse.success || !loginResponse.token) {
    console.error('❌ Admin login failed!')
    return
  }
  
  console.log('✅ Admin login successful!')
  const adminToken = loginResponse.token
  
  // Step 2: Test admin endpoints
  console.log('\n👑 Testing Admin Endpoints...')
  
  // Test /admin/users
  const usersResponse: ApiResponse = await makeRequest('/admin/users', {
    headers: {
      'Authorization': `Bearer ${adminToken}`
    }
  })
  
  if (usersResponse.success) {
    console.log('✅ /admin/users endpoint working correctly!')
    console.log(`📊 Found ${usersResponse.users?.length || 0} users`)
  } else {
    console.error('❌ /admin/users endpoint failed!')
  }
  
  // Test /admin/posts
  const postsResponse: ApiResponse = await makeRequest('/admin/posts', {
    headers: {
      'Authorization': `Bearer ${adminToken}`
    }
  })
  
  if (postsResponse.success) {
    console.log('✅ /admin/posts endpoint working correctly!')
    console.log(`📊 Found ${postsResponse.posts?.length || 0} posts`)
  } else {
    console.error('❌ /admin/posts endpoint failed!')
  }
  
  // Step 3: Test with regular user (should fail)
  console.log('\n🚫 Testing with regular user (should fail)...')
  const userLoginResponse: LoginResponse = await makeRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'user@example.com',
      password: 'User123!'
    })
  })
  
  if (userLoginResponse.success && userLoginResponse.token) {
    const userToken = userLoginResponse.token
    
    // Try to access admin endpoint with user token
    const unauthorizedResponse: ApiResponse = await makeRequest('/admin/users', {
      headers: {
        'Authorization': `Bearer ${userToken}`
      }
    })
    
    if (unauthorizedResponse.status === 403) {
      console.log('✅ Authorization working correctly - regular user denied access!')
    } else {
      console.error('❌ Authorization failed - regular user should not have access!')
    }
  }
  
  console.log('\n' + '=' .repeat(60))
  console.log('🎉 Admin endpoint testing completed!')
}

// Run the test
if (import.meta.main) {
  await testAdminEndpoints()
}

export { testAdminEndpoints }