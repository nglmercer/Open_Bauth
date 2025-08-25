#!/usr/bin/env bun

import { initDatabase } from '../db/connection';
import { runMigrations } from '../db/newmigrations';

async function main() {
  try {
    console.log('🔄 Iniciando proceso de migración...');
    
    // Inicializar base de datos
    await initDatabase();
    console.log('✅ Base de datos inicializada');
    
    // Ejecutar migraciones
    await runMigrations();
    console.log('✅ Migraciones completadas exitosamente');
    
  } catch (error) {
    console.error('❌ Error durante la migración:', error);
  }
}

// Ejecutar si es llamado directamente
if (import.meta.main) {
  main();
}