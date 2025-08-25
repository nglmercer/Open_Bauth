import { Database } from 'bun:sqlite';
import { getDatabase, isDatabaseInitialized } from '../db/connection';
import type { DatabaseTransaction } from '../types/common';
import { AuthErrorFactory } from '../errors/auth';

/**
 * SQLite transaction implementation
 */
export class SqliteTransaction implements DatabaseTransaction {
  private db: Database;
  private isTransactionActive: boolean = false;
  private transactionId: string;
  private savepoints: string[] = [];

  constructor(database?: Database) {
    this.db = database || getDatabase();
    this.transactionId = `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Verifica si la base de datos está disponible y reconecta si es necesario
   */
  private ensureDatabaseConnection(): void {
    try {
      // Test if current database is still accessible
      this.db.query("SELECT 1").get();
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        console.warn("⚠️ Database connection lost in transaction, attempting to reconnect...");
        // Get a fresh database connection
        this.db = getDatabase();
        // Reset transaction state since the connection was lost
        this.isTransactionActive = false;
        this.savepoints = [];
      } else {
        throw error;
      }
    }
  }

  /**
   * Begin the transaction
   */
  async begin(): Promise<void> {
    if (this.isTransactionActive) {
      throw AuthErrorFactory.database('Transaction is already active', 'begin');
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec('BEGIN TRANSACTION');
      this.isTransactionActive = true;
    } catch (error: any) {
      // If database connection failed, try to get a fresh connection
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        try {
          this.db = getDatabase();
          this.db.exec('BEGIN TRANSACTION');
          this.isTransactionActive = true;
        } catch (retryError) {
          throw AuthErrorFactory.database(`Failed to begin transaction after reconnection: ${retryError}`, 'begin');
        }
      } else {
        throw AuthErrorFactory.database(`Failed to begin transaction: ${error}`, 'begin');
      }
    }
  }

  /**
   * Commit the transaction
   */
  async commit(): Promise<void> {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction to commit', 'commit');
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec('COMMIT');
      this.isTransactionActive = false;
      this.savepoints = [];
    } catch (error: any) {
      // If database is closed, consider transaction lost
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        this.isTransactionActive = false;
        this.savepoints = [];
        throw AuthErrorFactory.database('Transaction lost due to database disconnection', 'commit');
      } else {
        throw AuthErrorFactory.database(`Failed to commit transaction: ${error}`, 'commit');
      }
    }
  }

  /**
   * Rollback the transaction
   */
  async rollback(): Promise<void> {
    if (!this.isTransactionActive) {
      // If not active, there's nothing to rollback
      return;
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec('ROLLBACK');
      this.isTransactionActive = false;
      this.savepoints = [];
    } catch (error: any) {
      // If database is closed, consider transaction already rolled back
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        this.isTransactionActive = false;
        this.savepoints = [];
        // Don't throw error for rollback when database is closed
        console.warn('Transaction rollback skipped due to closed database connection');
      } else {
        this.isTransactionActive = false;
        this.savepoints = [];
        throw AuthErrorFactory.database(`Failed to rollback transaction: ${error}`, 'rollback');
      }
    }
  }

  /**
   * Check if transaction is active
   */
  isActive(): boolean {
    if (!this.isTransactionActive) {
      return false;
    }

    // Verify database connection is still valid
    try {
      this.db.query("SELECT 1").get();
      return true;
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        this.isTransactionActive = false;
        this.savepoints = [];
        return false;
      }
      return true; // Other errors don't necessarily mean transaction is inactive
    }
  }

  /**
   * Create a savepoint
   */
  async savepoint(name?: string): Promise<string> {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction for savepoint', 'savepoint');
    }

    const savepointName = name || `sp_${Date.now()}_${Math.random().toString(36).substr(2, 6)}`;
    
    try {
      this.ensureDatabaseConnection();
      this.db.exec(`SAVEPOINT ${savepointName}`);
      this.savepoints.push(savepointName);
      return savepointName;
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        throw AuthErrorFactory.database('Cannot create savepoint: database connection lost', 'savepoint');
      }
      throw AuthErrorFactory.database(`Failed to create savepoint: ${error}`, 'savepoint');
    }
  }

  /**
   * Rollback to a savepoint
   */
  async rollbackToSavepoint(name: string): Promise<void> {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction for savepoint rollback', 'rollbackToSavepoint');
    }

    if (!this.savepoints.includes(name)) {
      throw AuthErrorFactory.database(`Savepoint '${name}' does not exist`, 'rollbackToSavepoint');
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec(`ROLLBACK TO SAVEPOINT ${name}`);
      // Remove savepoints created after this one
      const index = this.savepoints.indexOf(name);
      this.savepoints = this.savepoints.slice(0, index + 1);
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        throw AuthErrorFactory.database('Cannot rollback to savepoint: database connection lost', 'rollbackToSavepoint');
      }
      throw AuthErrorFactory.database(`Failed to rollback to savepoint: ${error}`, 'rollbackToSavepoint');
    }
  }

  /**
   * Release a savepoint
   */
  async releaseSavepoint(name: string): Promise<void> {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction for savepoint release', 'releaseSavepoint');
    }

    if (!this.savepoints.includes(name)) {
      throw AuthErrorFactory.database(`Savepoint '${name}' does not exist`, 'releaseSavepoint');
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec(`RELEASE SAVEPOINT ${name}`);
      // Remove this savepoint and all subsequent ones
      const index = this.savepoints.indexOf(name);
      this.savepoints = this.savepoints.slice(0, index);
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        throw AuthErrorFactory.database('Cannot release savepoint: database connection lost', 'releaseSavepoint');
      }
      throw AuthErrorFactory.database(`Failed to release savepoint: ${error}`, 'releaseSavepoint');
    }
  }

  /**
   * Execute a query within the transaction
   */
  query(sql: string, params?: any[]): any {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction for query execution', 'query');
    }

    try {
      this.ensureDatabaseConnection();
      const statement = this.db.query(sql);
      return params ? statement.all(...params) : statement.all();
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        throw AuthErrorFactory.database('Cannot execute query: database connection lost', 'query');
      }
      throw AuthErrorFactory.database(`Failed to execute query in transaction: ${error}`, 'query');
    }
  }

  /**
   * Execute a statement within the transaction
   */
  exec(sql: string): void {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction for statement execution', 'exec');
    }

    try {
      this.ensureDatabaseConnection();
      this.db.exec(sql);
    } catch (error: any) {
      if (error.message && (
        error.message.includes('closed database') ||
        error.message.includes('Database has closed') ||
        error.message.includes('database is closed')
      )) {
        throw AuthErrorFactory.database('Cannot execute statement: database connection lost', 'exec');
      }
      throw AuthErrorFactory.database(`Failed to execute statement in transaction: ${error}`, 'exec');
    }
  }

  /**
   * Get the transaction ID
   */
  getId(): string {
    return this.transactionId;
  }

  /**
   * Get the database instance
   */
  getDatabase(): Database {
    return this.db;
  }
}

/**
 * Transaction manager for handling database transactions
 */
export class TransactionManager {
  private db: Database;
  private activeTransactions = new Map<string, SqliteTransaction>();

  constructor(database?: Database) {
    this.db = database || getDatabase();
  }

  /**
   * Create a new transaction
   */
  async createTransaction(): Promise<SqliteTransaction> {
    // Ensure we have a valid database connection
    if (!isDatabaseInitialized()) {
      this.db = getDatabase();
    }

    const transaction = new SqliteTransaction(this.db);
    await transaction.begin();
    this.activeTransactions.set(transaction.getId(), transaction);
    return transaction;
  }

  /**
   * Execute a function within a transaction
   */
  async withTransaction<T>(
    callback: (transaction: SqliteTransaction) => Promise<T>
  ): Promise<T> {
    const transaction = await this.createTransaction();
    
    try {
      const result = await callback(transaction);
      await transaction.commit();
      this.activeTransactions.delete(transaction.getId());
      return result;
    } catch (error) {
      try {
        await transaction.rollback();
      } catch (rollbackError) {
        console.error('Failed to rollback transaction:', rollbackError);
      }
      this.activeTransactions.delete(transaction.getId());
      throw error;
    }
  }

  /**
   * Execute multiple operations in a transaction with savepoints
   */
  async withSavepoints<T>(
    operations: Array<{
      name?: string;
      operation: (transaction: SqliteTransaction, savepoint: string) => Promise<T>;
    }>
  ): Promise<T[]> {
    return this.withTransaction(async (transaction) => {
      const results: T[] = [];
      
      for (const { name, operation } of operations) {
        const savepoint = await transaction.savepoint(name);
        
        try {
          const result = await operation(transaction, savepoint);
          results.push(result);
          await transaction.releaseSavepoint(savepoint);
        } catch (error) {
          await transaction.rollbackToSavepoint(savepoint);
          throw error;
        }
      }
      
      return results;
    });
  }

  /**
   * Get active transaction by ID
   */
  getTransaction(id: string): SqliteTransaction | undefined {
    return this.activeTransactions.get(id);
  }

  /**
   * Get all active transactions
   */
  getActiveTransactions(): SqliteTransaction[] {
    return Array.from(this.activeTransactions.values());
  }

  /**
   * Rollback all active transactions (emergency cleanup)
   */
  async rollbackAll(): Promise<void> {
    const transactions = Array.from(this.activeTransactions.values());
    
    for (const transaction of transactions) {
      try {
        if (transaction.isActive()) {
          await transaction.rollback();
        }
      } catch (error) {
        console.error(`Failed to rollback transaction ${transaction.getId()}:`, error);
      }
    }
    
    this.activeTransactions.clear();
  }

  /**
   * Get transaction statistics
   */
  getStats(): {
    activeTransactions: number;
    transactionIds: string[];
  } {
    return {
      activeTransactions: this.activeTransactions.size,
      transactionIds: Array.from(this.activeTransactions.keys())
    };
  }
}

/**
 * Global transaction manager instance
 */
let transactionManager: TransactionManager | null = null;

/**
 * Initialize the transaction manager
 */
export function initTransactionManager(database?: Database): TransactionManager {
  transactionManager = new TransactionManager(database);
  return transactionManager;
}

/**
 * Get the global transaction manager
 */
export function getTransactionManager(): TransactionManager {
  if (!transactionManager || !isDatabaseInitialized()) {
    transactionManager = new TransactionManager();
  }
  return transactionManager;
}

/**
 * Reset the global transaction manager (useful when database is reinitialized)
 */
export function resetTransactionManager(): void {
  // Rollback any active transactions before resetting
  if (transactionManager) {
    transactionManager.rollbackAll().catch(error => {
      console.error('Error rolling back transactions during reset:', error);
    });
  }
  transactionManager = null;
}

/**
 * Utility function to execute code within a transaction
 */
export async function withTransaction<T>(
  callback: (transaction: SqliteTransaction) => Promise<T>
): Promise<T> {
  const manager = getTransactionManager();
  return manager.withTransaction(callback);
}

/**
 * Utility function to execute code with savepoints
 */
export async function withSavepoints<T>(
  operations: Array<{
    name?: string;
    operation: (transaction: SqliteTransaction, savepoint: string) => Promise<T>;
  }>
): Promise<T[]> {
  const manager = getTransactionManager();
  return manager.withSavepoints(operations);
}