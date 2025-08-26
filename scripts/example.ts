/**
 * Complete Usage Example of DatabaseInitializer
 * Shows how to safely initialize and use the database with TypeScript
 */

import { Database } from "bun:sqlite";
import { 
  DatabaseInitializer, 
  type DatabaseConfig,
} from "../src/database/database-initializer";
import type { Logger,User,UserRole,Permission,Role } from "../src/";
// Custom logger example
const customLogger = {
  info: (msg: string, ...args: any[]) => console.log(`[DB-INFO] ${msg}`, ...args),
  warn: (msg: string, ...args: any[]) => console.warn(`[DB-WARN] ${msg}`, ...args),
  error: (msg: string, ...args: any[]) => console.error(`[DB-ERROR] ${msg}`, ...args)
};

async function main() {
  // Initialize database connection
  const database = new Database("./app.db"); // or ":memory:" for in-memory

  // Create database initializer with configuration
  const config: DatabaseConfig = {
    database,
    logger: customLogger,
    enableWAL: true,
    enableForeignKeys: true
  };

  const dbInitializer = new DatabaseInitializer(config);

  try {
    // 1. Initialize database (creates all tables and indexes)
    console.log("=== Initializing Database ===");
    const initResult = await dbInitializer.initialize();
    
    if (!initResult.success) {
      console.error("Failed to initialize database:", initResult.errors);
      return;
    }

    console.log(`Database initialized successfully!
      - Tables created: ${initResult.tablesCreated.join(', ')}
      - Indexes created: ${initResult.indexesCreated.join(', ')}
      - Duration: ${initResult.duration}ms`);

    // 2. Check database integrity
    console.log("\n=== Checking Database Integrity ===");
    const integrity = await dbInitializer.checkIntegrity();
    
    if (integrity.isValid) {
      console.log("Database integrity check passed!");
    } else {
      console.log(`Integrity issues found:
        - Missing tables: ${integrity.missingTables}
        - Missing indexes: ${integrity.missingIndexes}`);
    }

    // 3. Create type-safe controllers for each table
    console.log("\n=== Creating Type-Safe Controllers ===");
    const usersController = dbInitializer.createController<User>("users");
    const rolesController = dbInitializer.createController<Role>("roles");
    const permissionsController = dbInitializer.createController<Permission>("permissions");

    // 4. Perform CRUD operations with full type safety
    console.log("\n=== CRUD Operations Example ===");

    // Create a role
    const adminRoleResult = await rolesController.create({
      name: "admin",
      description: "Administrator role with full access",
      is_active: true
    });

    if (!adminRoleResult.success) {
      console.error("Failed to create role:", adminRoleResult.error);
      return;
    }

    console.log("Created admin role:", adminRoleResult.data);

    // Create permissions
    const permissions = [
      { name: "users.read", resource: "users", action: "read", description: "Read user data" },
      { name: "users.write", resource: "users", action: "write", description: "Modify user data" },
      { name: "users.delete", resource: "users", action: "delete", description: "Delete users" }
    ];

    const createdPermissions: Permission[] = [];
    for (const permission of permissions) {
      const result = await permissionsController.create(permission);
      if (result.success && result.data) {
        createdPermissions.push(result.data);
        console.log(`Created permission: ${result.data.name}`);
      }
    }

    // Create a user with full type checking
    const userResult = await usersController.create({
      email: "admin@example.com",
      password_hash: "hashed_password_here", // In real app, use proper hashing
      first_name: "Admin",
      last_name: "User",
      is_active: true
    });

    if (!userResult.success) {
      console.error("Failed to create user:", userResult.error);
      return;
    }

    console.log("Created user:", userResult.data);

    // 5. Advanced queries with type safety
    console.log("\n=== Advanced Query Examples ===");

    // Find active users
    const activeUsers = await usersController.search({ is_active: true });
    console.log(`Found ${activeUsers.data?.length || 0} active users`);

    // Find user by email
    const foundUser = await usersController.findFirst({ 
      email: "admin@example.com" 
    });

    if (foundUser.success && foundUser.data) {
      console.log(`Found user: ${foundUser.data.first_name} ${foundUser.data.last_name}`);
      
      // Update user with type checking
      const updateResult = await usersController.update(foundUser.data.id, {
        last_login_at: new Date().toISOString(),
        first_name: "Super Admin" // TypeScript ensures this field exists
      });

      if (updateResult.success) {
        console.log("Updated user login time and name");
      }
    }

    // 6. Complex queries using custom SQL
    const userStatsQuery = `
      SELECT 
        COUNT(*) as total_users,
        COUNT(CASE WHEN is_active = 1 THEN 1 END) as active_users,
        COUNT(CASE WHEN last_login_at IS NOT NULL THEN 1 END) as users_with_login
      FROM users
    `;

    const statsResult = await usersController.query(userStatsQuery);
    if (statsResult.success) {
      console.log("User statistics:", statsResult.data?.[0]);
    }

    // 7. Get database statistics
    console.log("\n=== Database Statistics ===");
    const stats = await dbInitializer.getStatistics();
    console.log("Table record counts:", stats);

    // 8. Test migration functionality
    console.log("\n=== Testing Migration ===");
    const migrationResult = await dbInitializer.migrate();
    console.log(`Migration result: ${migrationResult.success ? 'Success' : 'Failed'}`);

    // 9. Demonstrate error handling
    console.log("\n=== Error Handling Example ===");
    
    // Try to create user with duplicate email (should fail due to unique constraint)
    const duplicateUserResult = await usersController.create({
      email: "admin@example.com", // Duplicate email
      password_hash: "another_hash",
      first_name: "Duplicate",
      last_name: "User"
    });

    if (!duplicateUserResult.success) {
      console.log("Expected error for duplicate email:", duplicateUserResult.error);
    }

    // Try to find non-existent user
    const nonExistentUser = await usersController.findById("non-existent-id");
    if (!nonExistentUser.success) {
      console.log("Expected error for non-existent user:", nonExistentUser.error);
    }

  } catch (error) {
    console.error("An unexpected error occurred:", error);
  } finally {
    // Close database connection
    database.close();
  }
}

// Example of database repair/reset functionality
async function maintenanceExample() {
  const database = new Database(":memory:");
  const dbInitializer = new DatabaseInitializer({ database });

  console.log("=== Database Maintenance Example ===");

  // Initialize database
  await dbInitializer.initialize();

  // Simulate damage by dropping a table
  database.exec("DROP TABLE users");
  console.log("Simulated database corruption (dropped users table)");

  // Check integrity
  const integrity = await dbInitializer.checkIntegrity();
  console.log("Integrity after corruption:", {
    isValid: integrity.isValid,
    missingTables: integrity.missingTables
  });

  // Repair database
  const repairResult = await dbInitializer.repair();
  console.log("Repair result:", {
    success: repairResult.success,
    tablesCreated: repairResult.tablesCreated
  });

  // Verify repair
  const integrityAfterRepair = await dbInitializer.checkIntegrity();
  console.log("Integrity after repair:", integrityAfterRepair.isValid);

  database.close();
}

// Example with custom schema
async function customSchemaExample() {
  const database = new Database(":memory:");
  
  // Define custom schema
  const customSchemas = [
    {
      tableName: "products",
      columns: [
        { name: "id", type: "INTEGER" as const, primaryKey: true, autoIncrement: true },
        { name: "name", type: "TEXT" as const, notNull: true },
        { name: "price", type: "REAL" as const, notNull: true },
        { name: "in_stock", type: "BOOLEAN" as const, defaultValue: true }
      ],
      indexes: [
        { name: "idx_products_name", columns: ["name"] }
      ]
    }
  ];

  const dbInitializer = new DatabaseInitializer({ database });
  
  // Initialize with custom schema
  const result = await dbInitializer.initialize(customSchemas);
  console.log("Custom schema initialization:", result.success);

  // Use the custom table
  interface Product {
    id: number;
    name: string;
    price: number;
    in_stock: boolean;
  }

  const productsController = dbInitializer.createController<Product>("products");
  
  const productResult = await productsController.create({
    name: "Laptop",
    price: 999.99,
    in_stock: true
  });

  console.log("Created product:", productResult.data);
  
  database.close();
}

// Run examples
if (import.meta.main) {
  console.log("Running database examples...\n");
  
  main()
    .then(() => console.log("\n=== Main Example Complete ==="))
    .then(() => maintenanceExample())
    .then(() => console.log("\n=== Maintenance Example Complete ==="))
    .then(() => customSchemaExample())
    .then(() => console.log("\n=== Custom Schema Example Complete ==="))
    .catch(console.error);
}