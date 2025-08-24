import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { prettyJSON } from 'hono/pretty-json'
import { 
  createHonoAuth,
  initializeAuth,
  AuthService,
  PermissionService,
  initJWTService,
  initAuthService,
  initPermissionService,
  type RegisterData,
  type LoginData,
  type User
} from '../src/index'

// Initialize the app
const app = new Hono()

// Auth middleware will be initialized after auth service is ready
let auth: any

// Global middleware
app.use('*', logger())
app.use('*', prettyJSON())
app.use('*', cors({
  origin: ['http://localhost:3000', 'http://localhost:5173'],
  allowMethods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}))

// Initialize auth library on startup
let authService: AuthService
let permissionService: PermissionService

// Mock blog posts database (in production, use a real database)
interface BlogPost {
  id: string
  title: string
  content: string
  authorId: string
  authorEmail: string
  createdAt: Date
  updatedAt: Date
  published: boolean
}

const blogPosts: BlogPost[] = []

// Health check endpoint
app.get('/health', (c) => {
  return c.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    service: 'Blog API with Authentication'
  })
})

// Public routes
app.get('/', (c) => {
  return c.json({
    message: 'Welcome to Blog API with Authentication',
    version: '1.0.0',
    endpoints: {
      auth: {
        register: 'POST /auth/register',
        login: 'POST /auth/login',
        profile: 'GET /auth/profile (requires auth)'
      },
      posts: {
        list: 'GET /posts',
        create: 'POST /posts (requires auth)',
        get: 'GET /posts/:id',
        update: 'PUT /posts/:id (requires auth + ownership)',
        delete: 'DELETE /posts/:id (requires auth + ownership)',
        publish: 'PUT /posts/:id/publish (requires auth + ownership)'
      }
    }
  })
})

// Authentication routes
const authRoutes = new Hono()

// Register endpoint
authRoutes.post('/register', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password, firstName, lastName } = body

    // Validate input
    if (!email || !password) {
      return c.json({ 
        success: false, 
        error: 'Email and password are required' 
      }, 400)
    }

    if (password.length < 6) {
      return c.json({ 
        success: false, 
        error: 'Password must be at least 6 characters long' 
      }, 400)
    }

    const registerData: RegisterData = {
      email: email.toLowerCase().trim(),
      password,
      firstName: firstName?.trim(),
      lastName: lastName?.trim()
    }

    const result = await authService.register(registerData)

    if (!result.success) {
      return c.json({ 
        success: false, 
        error: result.error?.message || 'Registration failed' 
      }, 400)
    }

    return c.json({
      success: true,
      message: 'User registered successfully',
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName
      },
      token: result.token
    }, 201)

  } catch (error: any) {
    console.error('Registration error:', error)
    return c.json({ 
      success: false, 
      error: 'Internal server error' 
    }, 500)
  }
})

// Login endpoint
authRoutes.post('/login', async (c) => {
  try {
    const body = await c.req.json()
    const { email, password } = body

    // Validate input
    if (!email || !password) {
      return c.json({ 
        success: false, 
        error: 'Email and password are required' 
      }, 400)
    }

    const loginData: LoginData = {
      email: email.toLowerCase().trim(),
      password
    }

    const result = await authService.login(loginData)

    if (!result.success) {
      return c.json({ 
        success: false, 
        error: result.error?.message || 'Login failed' 
      }, 401)
    }

    return c.json({
      success: true,
      message: 'Login successful',
      user: {
        id: result.user?.id,
        email: result.user?.email,
        firstName: result.user?.firstName,
        lastName: result.user?.lastName,
        roles: result.user?.roles?.map(r => r.name)
      },
      token: result.token
    })

  } catch (error: any) {
    console.error('Login error:', error)
    return c.json({ 
      success: false, 
      error: 'Internal server error' 
    }, 500)
  }
})

// Profile route will be added in setupProtectedRoutes

// Auth routes (public routes only)
app.route('/auth', authRoutes)

// Blog posts routes
const postsRoutes = new Hono()

// Get all posts (public)
postsRoutes.get('/', (c) => {
  const published = c.req.query('published')
  let filteredPosts = blogPosts

  if (published === 'true') {
    filteredPosts = blogPosts.filter(post => post.published)
  }

  return c.json({
    success: true,
    posts: filteredPosts.map(post => ({
      id: post.id,
      title: post.title,
      content: post.content,
      authorEmail: post.authorEmail,
      createdAt: post.createdAt,
      updatedAt: post.updatedAt,
      published: post.published
    })),
    total: filteredPosts.length
  })
})

// Get single post (public)
postsRoutes.get('/:id', (c) => {
  const id = c.req.param('id')
  const post = blogPosts.find(p => p.id === id)

  if (!post) {
    return c.json({ 
      success: false, 
      error: 'Post not found' 
    }, 404)
  }

  return c.json({
    success: true,
    post: {
      id: post.id,
      title: post.title,
      content: post.content,
      authorEmail: post.authorEmail,
      createdAt: post.createdAt,
      updatedAt: post.updatedAt,
      published: post.published
    }
  })
})

// Create post route will be added in setupProtectedRoutes

// Update post route will be added in setupProtectedRoutes

// Delete post route will be added in setupProtectedRoutes

// Publish post route will be added in setupProtectedRoutes

app.route('/posts', postsRoutes)

// Admin routes (requires admin role)
const adminRoutes = new Hono()

// Admin users route will be added in setupProtectedRoutes

// Admin posts route will be added in setupProtectedRoutes

// Routes will be added after auth initialization

// Error handling middleware
app.onError((err, c) => {
  console.error('Unhandled error:', err)
  return c.json({
    success: false,
    error: 'Internal server error',
    timestamp: new Date().toISOString()
  }, 500)
})

// 404 handler
app.notFound((c) => {
  return c.json({
    success: false,
    error: 'Endpoint not found',
    path: c.req.path,
    method: c.req.method
  }, 404)
})

// Setup protected routes after auth is initialized
function setupProtectedRoutes() {
  // Get user profile (protected route)
  authRoutes.get('/profile', auth.required(), async (c) => {
    try {
      const authContext = c.get('auth')
      const user = authContext?.user

      if (!user) {
        return c.json({ 
          success: false, 
          error: 'User not found' 
        }, 404)
      }

      return c.json({
        success: true,
        user: {
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles?.map(r => r.name),
          createdAt: user.created_at,
          lastLoginAt: user.lastLoginAt
        }
      })

    } catch (error: any) {
      console.error('Profile error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  app.route('/auth', authRoutes)

  // Create new post (protected)
  postsRoutes.post('/', auth.required(), async (c) => {
    try {
      const authContext = c.get('auth')
      const user = authContext?.user

      if (!user) {
        return c.json({ 
          success: false, 
          error: 'Authentication required' 
        }, 401)
      }

      const body = await c.req.json()
      const { title, content, published = false } = body

      if (!title || !content) {
        return c.json({ 
          success: false, 
          error: 'Title and content are required' 
        }, 400)
      }

      const newPost: BlogPost = {
        id: crypto.randomUUID(),
        title: title.trim(),
        content: content.trim(),
        authorId: user.id,
        authorEmail: user.email,
        createdAt: new Date(),
        updatedAt: new Date(),
        published: Boolean(published)
      }

      blogPosts.push(newPost)

      return c.json({
        success: true,
        message: 'Post created successfully',
        post: {
          id: newPost.id,
          title: newPost.title,
          content: newPost.content,
          authorEmail: newPost.authorEmail,
          createdAt: newPost.createdAt,
          published: newPost.published
        }
      }, 201)

    } catch (error: any) {
      console.error('Create post error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  // Update post (protected + ownership)
  postsRoutes.put('/:id', auth.required(), async (c) => {
    try {
      const authContext = c.get('auth')
      const user = authContext?.user

      if (!user) {
        return c.json({ 
          success: false, 
          error: 'Authentication required' 
        }, 401)
      }

      const postId = c.req.param('id')
      const postIndex = blogPosts.findIndex(p => p.id === postId)
      
      if (postIndex === -1) {
        return c.json({ 
          success: false, 
          error: 'Post not found' 
        }, 404)
      }

      const post = blogPosts[postIndex]
      
      // Check ownership (only author or admin can update)
      const isOwner = post.authorId === user.id
      const isAdmin = user.roles?.some(role => ['admin', 'administrator'].includes(role.name))

      if (!isOwner && !isAdmin) {
        return c.json({ 
          success: false, 
          error: 'You can only update your own posts' 
        }, 403)
      }

      const body = await c.req.json()
      const { title, content, published } = body

      // Update post
      if (title !== undefined) post.title = title.trim()
      if (content !== undefined) post.content = content.trim()
      if (published !== undefined) post.published = Boolean(published)
      post.updatedAt = new Date()

      blogPosts[postIndex] = post

      return c.json({
        success: true,
        message: 'Post updated successfully',
        post: {
          id: post.id,
          title: post.title,
          content: post.content,
          authorEmail: post.authorEmail,
          createdAt: post.createdAt,
          updatedAt: post.updatedAt,
          published: post.published
        }
      })

    } catch (error: any) {
      console.error('Update post error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  // Delete post (protected + ownership)
  postsRoutes.delete('/:id', auth.required(), async (c) => {
    try {
      const authContext = c.get('auth')
      const user = authContext?.user

      if (!user) {
        return c.json({ 
          success: false, 
          error: 'Authentication required' 
        }, 401)
      }

      const postId = c.req.param('id')
      const postIndex = blogPosts.findIndex(p => p.id === postId)
      
      if (postIndex === -1) {
        return c.json({ 
          success: false, 
          error: 'Post not found' 
        }, 404)
      }

      const post = blogPosts[postIndex]
      
      // Check ownership (only author or admin can delete)
      const isOwner = post.authorId === user.id
      const isAdmin = user.roles?.some(role => ['admin', 'administrator'].includes(role.name))

      if (!isOwner && !isAdmin) {
        return c.json({ 
          success: false, 
          error: 'You can only delete your own posts' 
        }, 403)
      }

      // Remove post
      blogPosts.splice(postIndex, 1)

      return c.json({
        success: true,
        message: 'Post deleted successfully'
      })

    } catch (error: any) {
      console.error('Delete post error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  // Publish/unpublish post (protected + ownership)
  postsRoutes.put('/:id/publish', auth.required(), async (c) => {
    try {
      const authContext = c.get('auth')
      const user = authContext?.user

      if (!user) {
        return c.json({ 
          success: false, 
          error: 'Authentication required' 
        }, 401)
      }

      const postId = c.req.param('id')
      const postIndex = blogPosts.findIndex(p => p.id === postId)
      
      if (postIndex === -1) {
        return c.json({ 
          success: false, 
          error: 'Post not found' 
        }, 404)
      }

      const post = blogPosts[postIndex]
      
      // Check ownership (only author or admin can publish)
      const isOwner = post.authorId === user.id
      const isAdmin = user.roles?.some(role => ['admin', 'administrator'].includes(role.name))

      if (!isOwner && !isAdmin) {
        return c.json({ 
          success: false, 
          error: 'You can only publish your own posts' 
        }, 403)
      }

      const body = await c.req.json()
      const { published } = body

      post.published = Boolean(published)
      post.updatedAt = new Date()
      blogPosts[postIndex] = post

      return c.json({
        success: true,
        message: `Post ${published ? 'published' : 'unpublished'} successfully`,
        post: {
          id: post.id,
          title: post.title,
          published: post.published,
          updatedAt: post.updatedAt
        }
      })

    } catch (error: any) {
      console.error('Publish post error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  app.route('/posts', postsRoutes)

  // Get all users (admin only)
  adminRoutes.get('/users', auth.required(), auth.admin(), async (c) => {
    try {
      const result = await authService.getUsers(1, 50, { includeRoles: true })
      
      return c.json({
        success: true,
        users: result.users.map(user => ({
          id: user.id,
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roles: user.roles?.map(r => r.name),
          isActive: user.is_active,
          createdAt: user.created_at,
          lastLoginAt: user.lastLoginAt
        })),
        total: result.total
      })

    } catch (error: any) {
      console.error('Get users error:', error)
      return c.json({ 
        success: false, 
        error: 'Internal server error' 
      }, 500)
    }
  })

  // Get all posts (admin only - includes unpublished)
  adminRoutes.get('/posts', auth.required(), auth.admin(), (c) => {
    return c.json({
      success: true,
      posts: blogPosts.map(post => ({
        id: post.id,
        title: post.title,
        content: post.content.substring(0, 100) + '...',
        authorId: post.authorId,
        authorEmail: post.authorEmail,
        createdAt: post.createdAt,
        updatedAt: post.updatedAt,
        published: post.published
      })),
      total: blogPosts.length
    })
  })

  app.route('/admin', adminRoutes)
}

// Initialize auth services
async function initializeApp() {
  try {
    console.log('🚀 Initializing Blog API with Authentication...')
    
    // Initialize JWT service first
    initJWTService(process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production')
    
    // Initialize auth library
    const authLibrary = await initializeAuth({
      jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
      jwtExpiration: '24h'
    })
    
    // Initialize the global AuthService singleton
    initAuthService()
    initPermissionService()
    authService = authLibrary.getAuthService()
    permissionService = authLibrary.getPermissionService()
    
    // Initialize auth middleware after auth service is ready
    auth = createHonoAuth({
      jwtSecret: process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production',
      jwtExpiration: '24h'
    })
    
    // Now add all protected routes
    setupProtectedRoutes()
    
    console.log('✅ Auth library initialized successfully')
    console.log('📚 Blog API ready with the following features:')
    console.log('   - User registration and authentication')
    console.log('   - JWT token-based authorization')
    console.log('   - Role-based access control (RBAC)')
    console.log('   - Blog post CRUD operations')
    console.log('   - Ownership-based permissions')
    console.log('   - Admin panel endpoints')
    console.log('')
    console.log('🔗 Available endpoints:')
    console.log('   POST /auth/register - Register new user')
    console.log('   POST /auth/login - Login user')
    console.log('   GET  /auth/profile - Get user profile (auth required)')
    console.log('   GET  /posts - Get all posts')
    console.log('   POST /posts - Create post (auth required)')
    console.log('   GET  /posts/:id - Get single post')
    console.log('   PUT  /posts/:id - Update post (auth + ownership required)')
    console.log('   DELETE /posts/:id - Delete post (auth + ownership required)')
    console.log('   PUT  /posts/:id/publish - Publish/unpublish post')
    console.log('   GET  /admin/users - Get all users (admin only)')
    console.log('   GET  /admin/posts - Get all posts (admin only)')
    console.log('')
    
  } catch (error) {
    console.error('❌ Failed to initialize app:', error)
  }
}

// Initialize on startup
initializeApp()

// Start the server
const port = process.env.PORT || 3001

Bun.serve({
  port,
  fetch: app.fetch,
})

console.log(`🚀 Blog API server running on http://localhost:${port}`)
console.log(`📖 API Documentation available at http://localhost:${port}/`)

export default app