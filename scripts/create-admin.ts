#!/usr/bin/env bun

/**
 * Script to manually create an admin user via API
 */

import { seedDatabase } from '../src/scripts/seed'
import { AuthService } from '../src/services/auth'
import { PermissionService } from '../src/services/permissions'
import { initDatabase } from '../src/db/connection'
import { initJWTService } from '../src/services/jwt'

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
    console.log(`\n🔗 ${options.method || 'GET'} ${endpoint}`)
    console.log(`📊 Status: ${response.status}`)
    console.log(`📄 Response:`, JSON.stringify(data, null, 2))
    
    return { ...data, status: response.status }
  } catch (error) {
    console.error(`❌ Error calling ${endpoint}:`, error)
    return { success: false, error: 'Network error' }
  }
}

async function createAdminUser() {
  console.log('🔧 Creating Admin User via API')
  console.log('=' .repeat(50))
  
  // Initialize JWT service first
  console.log('🔧 Initializing JWT service...')
  initJWTService(process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production')
  
  // First, ensure database is seeded with roles
  console.log('🌱 Seeding database with roles and permissions...')
  try {
    await seedDatabase()
    console.log('✅ Database seeded successfully!')
  } catch (error) {
    console.log('⚠️ Database already seeded or seeding failed:', error)
  }
  
  // Try to login with seeded admin user first
  console.log('🔐 Trying to login with seeded admin user...')
  let loginResponse = await makeRequest('/auth/login', {
    method: 'POST',
    body: JSON.stringify({
      email: 'admin@example.com',
      password: 'Admin123!@#'
    })
  })
  
  // If seeded admin doesn't work, try to register a new admin user
  if (!loginResponse.success) {
    console.log('🔧 Seeded admin login failed, trying to create new admin user...')
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
      console.log('✅ Admin user created successfully!')
      
      // Assign admin role to the user
      console.log('👑 Assigning admin role...')
      try {
        initDatabase()
        const authService = new AuthService()
        const assignResult = await authService.assignRole(registerResponse.user.id, 'admin')
        if (assignResult.success) {
          console.log('✅ Admin role assigned successfully!')
        } else {
          console.error('❌ Failed to assign admin role:', assignResult.error)
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
    console.log('✅ Seeded admin login successful!')
  }
  
  // Continue with admin endpoint testing
   if (loginResponse.success && loginResponse.token) {
     console.log('✅ Admin login successful!')
     const adminToken = loginResponse.token
     
     // Test admin endpoints
     console.log('\n👑 Testing Admin Endpoints...')
     
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
       console.log('⚠️ Admin endpoints require admin role - user needs to be promoted to admin')
     } else if (usersResponse.status === 200) {
       console.log('✅ Admin endpoints working!')
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