// src/index.ts
export * from './middleware/auth';
export * from './logger';
export * from './services';
export * from './database';
export * from './types/auth';
/**
 * Library Information
 */
export const AUTH_LIBRARY_INFO = {
  name: 'Framework-Agnostic Authentication Library',
  version: '1.2.0',
  description: 'A comprehensive framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite',
  author: 'Auth Library Development Team',
  license: 'MIT',
  runtime: 'Bun',
  database: 'SQLite, PostgreSQL, MySQL, MariaDB, SQLite in-memory',
};

console.log(`📚 ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} loaded successfully`);
