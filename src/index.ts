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
  version: '1.1.2',
  description: 'A comprehensive framework-agnostic authentication and authorization library built with TypeScript, Bun, and SQLite',
  author: 'Auth Library Development Team',
  license: 'MIT',
  repository: 'https://github.com/auth-library/framework-agnostic-auth',
  frameworks: ['Hono', 'Express', 'WebSockets', 'Socket.IO', 'Fastify'],
  runtime: 'Bun',
  database: 'SQLite, PostgreSQL, MySQL, MariaDB, SQLite in-memory',
};

console.log(`📚 ${AUTH_LIBRARY_INFO.name} v${AUTH_LIBRARY_INFO.version} loaded successfully`);
