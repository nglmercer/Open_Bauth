import { UserRepository } from '../repositories/user';
import { RoleRepository } from '../repositories/role';
import { withTransaction, withSavepoints, getTransactionManager } from '../database/transaction';
import type { User, CreateUserData, Role } from '../types/auth';
import type { DatabaseTransaction } from '../types/common';
import { AuthErrorFactory } from '../errors/auth';
import { AUTH_CONFIG } from '../config/constants';

/**
 * Transactional service that demonstrates complex operations using database transactions
 */
export class TransactionalService {
  private userRepository: UserRepository;
  private roleRepository: RoleRepository;

  constructor() {
    this.userRepository = new UserRepository();
    this.roleRepository = new RoleRepository();
  }

  /**
   * Create a user with roles in a single transaction
   */
  async createUserWithRoles(
    userData: Omit<User, 'created_at' | 'updated_at' | 'roles'>,
    roleNames: string[]
  ): Promise<User> {
    return withTransaction(async (transaction) => {
      try {
        // Create the user
        const user = await this.userRepository.create(userData, transaction);

        // Assign roles to the user
        for (const roleName of roleNames) {
          const role = await this.roleRepository.findByName(roleName, transaction);
          if (!role) {
            throw AuthErrorFactory.validation(`Role '${roleName}' not found`);
          }
          await this.roleRepository.assignToUser(user.id, role.id, transaction);
        }

        // Return the user with roles
        return await this.userRepository.findById(user.id, { includeRoles: true }, transaction) as User;
      } catch (error) {
        throw AuthErrorFactory.database(`Failed to create user with roles: ${error}`, 'createUserWithRoles');
      }
    });
  }

  /**
   * Transfer roles from one user to another
   */
  async transferRoles(fromUserId: string, toUserId: string): Promise<{ fromUser: User; toUser: User }> {
    return withTransaction(async (transaction) => {
      try {
        // Verify both users exist
        const fromUser = await this.userRepository.findById(fromUserId, { includeRoles: true }, transaction);
        if (!fromUser) {
          throw AuthErrorFactory.validation(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
        }

        const toUser = await this.userRepository.findById(toUserId, {}, transaction);
        if (!toUser) {
          throw AuthErrorFactory.validation(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
        }

        // Transfer each role
        for (const role of fromUser.roles) {
          // Remove role from source user
          await this.roleRepository.removeFromUser(fromUserId, role.id, transaction);
          
          // Check if target user already has this role
          const hasRole = await this.roleRepository.userHasRole(toUserId, role.id, transaction);
          if (!hasRole) {
            // Assign role to target user
            await this.roleRepository.assignToUser(toUserId, role.id, transaction);
          }
        }

        // Return updated users
        const updatedFromUser = await this.userRepository.findById(fromUserId, { includeRoles: true }, transaction) as User;
        const updatedToUser = await this.userRepository.findById(toUserId, { includeRoles: true }, transaction) as User;

        return {
          fromUser: updatedFromUser,
          toUser: updatedToUser
        };
      } catch (error) {
        throw AuthErrorFactory.database(`Failed to transfer roles: ${error}`, 'transferRoles');
      }
    });
  }

  /**
   * Bulk user operations with savepoints
   */
  async bulkUserOperations(operations: Array<{
    type: 'create' | 'update' | 'delete';
    data: any;
    rollbackOnError?: boolean;
  }>): Promise<Array<{ success: boolean; result?: any; error?: string }>> {
    const results: Array<{ success: boolean; result?: any; error?: string }> = [];

    const savePointOperations = operations.map((operation, index) => ({
      name: `bulk_op_${index}`,
      operation: async (transaction: DatabaseTransaction, savepoint: string) => {
        try {
          let result: any;

          switch (operation.type) {
            case 'create':
              result = await this.userRepository.create(operation.data, transaction);
              break;
            case 'update':
              result = await this.userRepository.update(operation.data.id, operation.data.updates, transaction);
              break;
            case 'delete':
              await this.userRepository.delete(operation.data.id, transaction);
              result = { deleted: true };
              break;
            default:
              throw new Error(`Unknown operation type: ${operation.type}`);
          }

          results.push({ success: true, result });
          return result;
        } catch (error) {
          const errorMessage = error instanceof Error ? error.message : String(error);
          results.push({ success: false, error: errorMessage });
          
          if (operation.rollbackOnError) {
            throw error; // This will trigger rollback to savepoint
          }
          
          return null; // Continue with next operation
        }
      }
    }));

    try {
      await withSavepoints(savePointOperations);
    } catch (error) {
      // Some operations failed and triggered rollbacks
      console.warn('Some bulk operations failed:', error);
    }

    return results;
  }

  /**
   * Create multiple users with different roles atomically
   */
  async createUsersWithRolesBatch(userDataList: Array<{
    userData: Omit<User, 'id' | 'created_at' | 'updated_at' | 'roles'>;
    roles: string[];
  }>): Promise<User[]> {
    return withTransaction(async (transaction) => {
      const createdUsers: User[] = [];

      try {
        for (const { userData, roles } of userDataList) {
          // Create user
          const user = await this.userRepository.create(userData, transaction);

          // Assign roles
          for (const roleName of roles) {
            const role = await this.roleRepository.findByName(roleName, transaction);
            if (!role) {
              // Create role if it doesn't exist
              const newRoleId = crypto.randomUUID();
              await this.roleRepository.create({
                id: newRoleId,
                name: roleName,
                isActive: true
              }, transaction);
              await this.roleRepository.assignToUser(user.id, newRoleId, transaction);
            } else {
              await this.roleRepository.assignToUser(user.id, role.id, transaction);
            }
          }

          // Get user with roles
          const userWithRoles = await this.userRepository.findById(user.id, { includeRoles: true }, transaction) as User;
          createdUsers.push(userWithRoles);
        }

        return createdUsers;
      } catch (error) {
        throw AuthErrorFactory.database(`Failed to create users batch: ${error}`, 'createUsersWithRolesBatch');
      }
    });
  }

  /**
   * Update user profile and roles atomically
   */
  async updateUserProfileAndRoles(
    userId: string,
    profileUpdates: Partial<Omit<User, 'id' | 'created_at' | 'roles'>>,
    newRoles: string[]
  ): Promise<User> {
    return withTransaction(async (transaction) => {
      try {
        // Verify user exists
        const existingUser = await this.userRepository.findById(userId, { includeRoles: true }, transaction);
        if (!existingUser) {
          throw AuthErrorFactory.validation(AUTH_CONFIG.ERROR_MESSAGES.USER_NOT_FOUND);
        }

        // Update user profile
        const updatedUser = await this.userRepository.update(userId, profileUpdates, transaction);

        // Remove all existing roles
        for (const role of existingUser.roles) {
          await this.roleRepository.removeFromUser(userId, role.id, transaction);
        }

        // Assign new roles
        for (const roleName of newRoles) {
          const role = await this.roleRepository.findByName(roleName, transaction);
          if (!role) {
            throw AuthErrorFactory.validation(`Role '${roleName}' not found`);
          }
          await this.roleRepository.assignToUser(userId, role.id, transaction);
        }

        // Return updated user with new roles
        return await this.userRepository.findById(userId, { includeRoles: true }, transaction) as User;
      } catch (error) {
        throw AuthErrorFactory.database(`Failed to update user profile and roles: ${error}`, 'updateUserProfileAndRoles');
      }
    });
  }

  /**
   * Cleanup inactive users and their roles
   */
  async cleanupInactiveUsers(inactiveDays: number = 90): Promise<{ deletedUsers: number; cleanedRoles: number }> {
    return withTransaction(async (transaction) => {
      try {
        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - inactiveDays);

        // Find inactive users (simplified query - in real implementation you'd check last_login_at)
        const db = transaction.getDatabase();
        const inactiveUsersQuery = db.query(`
          SELECT id FROM users 
          WHERE is_active = 0 
          AND updated_at < ?
        `);
        
        const inactiveUsers = inactiveUsersQuery.all(cutoffDate.toISOString()) as Array<{ id: string }>;
        
        let deletedUsers = 0;
        let cleanedRoles = 0;

        for (const user of inactiveUsers) {
          // Get user roles count before deletion
          const rolesQuery = db.query('SELECT COUNT(*) as count FROM user_roles WHERE user_id = ?');
          const roleCount = (rolesQuery.get(user.id) as { count: number }).count;
          
          // Delete user (this should cascade to user_roles if foreign keys are set up)
          await this.userRepository.delete(user.id, transaction);
          
          deletedUsers++;
          cleanedRoles += roleCount;
        }

        return { deletedUsers, cleanedRoles };
      } catch (error) {
        throw AuthErrorFactory.database(`Failed to cleanup inactive users: ${error}`, 'cleanupInactiveUsers');
      }
    });
  }

  /**
   * Get transaction statistics
   */
  getTransactionStats() {
    const manager = getTransactionManager();
    return manager.getStats();
  }

  /**
   * Emergency rollback all active transactions
   */
  async emergencyRollbackAll(): Promise<void> {
    const manager = getTransactionManager();
    await manager.rollbackAll();
  }
}

/**
 * Export a singleton instance
 */
export const transactionalService = new TransactionalService();