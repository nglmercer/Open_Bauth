#!/usr/bin/env bun

/**
 * Script to manually create an admin user via API
 */

import { seedDatabase } from '../src/scripts/seed'
import { AuthService } from '../src/services/auth'
import { PermissionService } from '../src/services/permissions'
import { initDatabase } from '../src/db/connection'
import { initJWTService } from '../src/services/jwt'
import { defaultLogger as logger } from '../src/logger'
const BASE_URL = 'http://localhost:3001'

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
    logger.info(`\n🔗 ${options.method || 'GET'} ${endpoint}`)
    logger.info(`📊 Status: ${response.status}`)
    logger.info(`📄 Response:`, {data:JSON.stringify(data, null, 2)})
    
    return { ...data, status: response.status }
  } catch (error) {
    console.error(`❌ Error calling ${endpoint}:`, error)
    return { success: false, error: 'Network error' }
  }
}

async function createAdminUser() {
  logger.info('🔧 Creating Admin User via API')
  logger.info('=' .repeat(50))
  
  // Initialize JWT service first
  logger.info('🔧 Initializing JWT service...')
  initJWTService(process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production')
  
  // First, ensure database is seeded with roles
  logger.info('🌱 Seeding database with roles and permissions...')
  try {
    await seedDatabase()
    logger.info('✅ Database seeded successfully!')
  } catch (error) {
    logger.info('⚠️ Database already seeded or seeding failed:', {error})
  }
  
  // Try to login with seeded admin user first
  logger.info('🔐 Trying to login with seeded admin user...')
  let loginResponse = await makeRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'admin@example.com',
      password: 'Admin123!@#'
    })
  })
  
  // If seeded admin doesn't work, try to register a new admin user
  if (!loginResponse.success) {
    logger.info('🔧 Seeded admin login failed, trying to create new admin user...')
    const registerResponse = await makeRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({
        email: 'admin@test.com',
        password: 'Admin123!',
        firstName: 'Admin',
        lastName: 'User'
      })
    })
    
    if (registerResponse.success) {
      logger.info('✅ Admin user created successfully!')
      
      // Assign admin role to the user
      logger.info('👑 Assigning admin role...')
      try {
        initDatabase()
        const authService = new AuthService()
        const assignResult = await authService.assignRole(registerResponse.user.id, 'admin')
        if (assignResult) {
          logger.info('✅ Admin role assigned successfully!')
        } else {
          console.error('❌ Failed to assign admin role:', {data:assignResult})
        }
      } catch (error) {
        console.error('❌ Error assigning admin role:', error)
      }
      
      // Now try to login with new admin
      loginResponse = await makeRequest('/auth/login', {
        method: 'POST',
        body: JSON.stringify({
          email: 'admin@test.com',
          password: 'Admin123!'
        })
      })
    } else {
      console.error('❌ Admin user creation failed!')
      return
    }
  } else {
    logger.info('✅ Seeded admin login successful!')
  }
  
  // Continue with admin endpoint testing
   if (loginResponse.success && loginResponse.token) {
     logger.info('✅ Admin login successful!')
     const adminToken = loginResponse.token
     
     // Test admin endpoints
     logger.info('\n👑 Testing Admin Endpoints...')
     
     const usersResponse = await makeRequest('/admin/users', {
       headers: {
         'Authorization': `Bearer ${adminToken}`
       }
     })
     
     const postsResponse = await makeRequest('/admin/posts', {
       headers: {
         'Authorization': `Bearer ${adminToken}`
       }
     })
     
     if (usersResponse.status === 403) {
       logger.info('⚠️ Admin endpoints require admin role - user needs to be promoted to admin')
     } else if (usersResponse.status === 200) {
       logger.info('✅ Admin endpoints working!')
     }
   } else {
     console.error('❌ Admin login failed!')
   }
}

// Run the script
if (import.meta.main) {
  await createAdminUser()
}

export { createAdminUser }