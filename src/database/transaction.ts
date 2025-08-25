import { Database } from 'bun:sqlite';
import { getDatabase } from '../db/connection';
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
   * Begin the transaction
   */
  async begin(): Promise<void> {
    if (this.isTransactionActive) {
      throw AuthErrorFactory.database('Transaction is already active', 'begin');
    }

    try {
      this.db.exec('BEGIN TRANSACTION');
      this.isTransactionActive = true;
    } catch (error) {
      throw AuthErrorFactory.database(`Failed to begin transaction: ${error}`, 'begin');
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
      this.db.exec('COMMIT');
      this.isTransactionActive = false;
      this.savepoints = [];
    } catch (error) {
      throw AuthErrorFactory.database(`Failed to commit transaction: ${error}`, 'commit');
    }
  }

  /**
   * Rollback the transaction
   */
  async rollback(): Promise<void> {
    if (!this.isTransactionActive) {
      throw AuthErrorFactory.database('No active transaction to rollback', 'rollback');
    }

    try {
      this.db.exec('ROLLBACK');
      this.isTransactionActive = false;
      this.savepoints = [];
    } catch (error) {
      throw AuthErrorFactory.database(`Failed to rollback transaction: ${error}`, 'rollback');
    }
  }

  /**
   * Check if transaction is active
   */
  isActive(): boolean {
    return this.isTransactionActive;
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
      this.db.exec(`SAVEPOINT ${savepointName}`);
      this.savepoints.push(savepointName);
      return savepointName;
    } catch (error) {
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
      this.db.exec(`ROLLBACK TO SAVEPOINT ${name}`);
      // Remove savepoints created after this one
      const index = this.savepoints.indexOf(name);
      this.savepoints = this.savepoints.slice(0, index + 1);
    } catch (error) {
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
      this.db.exec(`RELEASE SAVEPOINT ${name}`);
      // Remove this savepoint and all subsequent ones
      const index = this.savepoints.indexOf(name);
      this.savepoints = this.savepoints.slice(0, index);
    } catch (error) {
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
      const statement = this.db.query(sql);
      return params ? statement.all(...params) : statement.all();
    } catch (error) {
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
      this.db.exec(sql);
    } catch (error) {
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
  if (!transactionManager) {
    transactionManager = new TransactionManager(database);
  }
  return transactionManager;
}

/**
 * Get the global transaction manager
 */
export function getTransactionManager(): TransactionManager {
  if (!transactionManager) {
    transactionManager = new TransactionManager();
  }
  return transactionManager;
}

/**
 * Reset the global transaction manager (useful when database is reinitialized)
 */
export function resetTransactionManager(): void {
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