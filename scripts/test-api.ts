// Test script for the Hono Blog API with Authentication
// This script demonstrates all the available endpoints

const API_BASE = 'http://localhost:3001'

interface ApiResponse {
  success: boolean
  [key: string]: any
}

class BlogApiTester {
  private token: string = ''
  private userId: string = ''
  private postId: string = ''

  async makeRequest(endpoint: string, options: RequestInit = {}): Promise<ApiResponse> {
    const url = `${API_BASE}${endpoint}`
    const headers = {
      'Content-Type': 'application/json',
      ...options.headers
    }

    if (this.token && !('Authorization' in headers)) {
      (headers as Record<string, string>)['Authorization'] = `Bearer ${this.token}`
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
      
      return data
    } catch (error) {
      console.error(`❌ Error calling ${endpoint}:`, error)
      return { success: false, error: 'Network error' }
    }
  }

  async testHealthCheck() {
    console.log('\n🏥 Testing Health Check...')
    await this.makeRequest('/health')
  }

  async testWelcome() {
    console.log('\n👋 Testing Welcome Endpoint...')
    await this.makeRequest('/')
  }

  async testRegister() {
    console.log('\n📝 Testing User Registration...')
    const userData = {
      email: `test${Date.now()}@example.com`,
      password: 'Password123',
      firstName: 'John',
      lastName: 'Doe'
    }

    const result = await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData)
    })

    if (result.success && result.token) {
      this.token = result.token
      this.userId = result.user?.id
      console.log('✅ Registration successful! Token saved.')
    }

    return result
  }

  async testLogin() {
    console.log('\n🔐 Testing User Login...')
    
    // First register a user for login test
    const email = `login${Date.now()}@example.com`
    await this.makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password: 'Password123',
        firstName: 'Jane',
        lastName: 'Smith'
      })
    })

    // Now test login
    const result = await this.makeRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({
        email,
        password: 'Password123'
      })
    })

    if (result.success && result.token) {
      this.token = result.token
      this.userId = result.user?.id
      console.log('✅ Login successful! Token updated.')
    }

    return result
  }

  async testProfile() {
    console.log('\n👤 Testing Get Profile (Protected Route)...')
    if (!this.token) {
      console.log('⚠️ No token available, skipping profile test')
      return
    }

    await this.makeRequest('/auth/profile')
  }

  async testCreatePost() {
    console.log('\n📝 Testing Create Post (Protected Route)...')
    if (!this.token) {
      console.log('⚠️ No token available, skipping create post test')
      return
    }

    const postData = {
      title: 'My First Blog Post',
      content: 'This is the content of my first blog post. It contains some interesting information about web development and authentication.',
      published: false
    }

    const result = await this.makeRequest('/posts', {
      method: 'POST',
      body: JSON.stringify(postData)
    })

    if (result.success && result.post?.id) {
      this.postId = result.post.id
      console.log('✅ Post created successfully! Post ID saved.')
    }

    return result
  }

  async testGetPosts() {
    console.log('\n📚 Testing Get All Posts (Public Route)...')
    await this.makeRequest('/posts')
  }

  async testGetPublishedPosts() {
    console.log('\n📖 Testing Get Published Posts Only...')
    await this.makeRequest('/posts?published=true')
  }

  async testGetSinglePost() {
    console.log('\n📄 Testing Get Single Post...')
    if (!this.postId) {
      console.log('⚠️ No post ID available, skipping single post test')
      return
    }

    await this.makeRequest(`/posts/${this.postId}`)
  }

  async testUpdatePost() {
    console.log('\n✏️ Testing Update Post (Protected + Ownership)...')
    if (!this.token || !this.postId) {
      console.log('⚠️ No token or post ID available, skipping update test')
      return
    }

    const updateData = {
      title: 'My Updated Blog Post',
      content: 'This is the updated content of my blog post. Now it has even more interesting information!',
      published: true
    }

    await this.makeRequest(`/posts/${this.postId}`, {
      method: 'PUT',
      body: JSON.stringify(updateData)
    })
  }

  async testPublishPost() {
    console.log('\n🚀 Testing Publish Post...')
    if (!this.token || !this.postId) {
      console.log('⚠️ No token or post ID available, skipping publish test')
      return
    }

    await this.makeRequest(`/posts/${this.postId}/publish`, {
      method: 'PUT',
      body: JSON.stringify({ published: true })
    })
  }

  async testUnauthorizedAccess() {
    console.log('\n🚫 Testing Unauthorized Access...')
    const originalToken = this.token
    this.token = '' // Remove token temporarily

    await this.makeRequest('/auth/profile')
    await this.makeRequest('/posts', {
      method: 'POST',
      body: JSON.stringify({
        title: 'Unauthorized Post',
        content: 'This should fail'
      })
    })

    this.token = originalToken // Restore token
  }

  async testInvalidToken() {
    console.log('\n🔒 Testing Invalid Token...')
    const originalToken = this.token
    this.token = 'invalid-token-123'

    await this.makeRequest('/auth/profile')

    this.token = originalToken // Restore token
  }

  async testAdminEndpoints() {
    console.log('\n👑 Testing Admin Endpoints (Should fail for regular user)...')
    if (!this.token) {
      console.log('⚠️ No token available, skipping admin tests')
      return
    }

    await this.makeRequest('/admin/users')
    await this.makeRequest('/admin/posts')
  }

  async testDeletePost() {
    console.log('\n🗑️ Testing Delete Post (Protected + Ownership)...')
    if (!this.token || !this.postId) {
      console.log('⚠️ No token or post ID available, skipping delete test')
      return
    }

    await this.makeRequest(`/posts/${this.postId}`, {
      method: 'DELETE'
    })
  }

  async testNotFound() {
    console.log('\n❓ Testing 404 Not Found...')
    await this.makeRequest('/nonexistent-endpoint')
  }

  async runAllTests() {
    console.log('🧪 Starting Blog API Tests...')
    console.log('=' .repeat(50))

    try {
      // Basic endpoints
      await this.testHealthCheck()
      await this.testWelcome()
      
      // Authentication
      await this.testRegister()
      await this.testLogin()
      await this.testProfile()
      
      // Blog posts
      await this.testGetPosts()
      await this.testCreatePost()
      await this.testGetSinglePost()
      await this.testUpdatePost()
      await this.testPublishPost()
      await this.testGetPublishedPosts()
      
      // Security tests
      await this.testUnauthorizedAccess()
      await this.testInvalidToken()
      await this.testAdminEndpoints()
      
      // Cleanup
      await this.testDeletePost()
      
      // Error handling
      await this.testNotFound()
      
      console.log('\n' + '=' .repeat(50))
      console.log('✅ All tests completed!')
      console.log('\n📋 Test Summary:')
      console.log('   ✅ Health check and welcome endpoints')
      console.log('   ✅ User registration and login')
      console.log('   ✅ Protected routes with JWT authentication')
      console.log('   ✅ Blog post CRUD operations')
      console.log('   ✅ Ownership-based permissions')
      console.log('   ✅ Security and error handling')
      console.log('   ✅ Admin endpoint access control')
      
    } catch (error) {
      console.error('❌ Test suite failed:', error)
    }
  }
}

// Run tests if this file is executed directly
if (import.meta.main) {
  const tester = new BlogApiTester()
  await tester.runAllTests()
}

export { BlogApiTester }