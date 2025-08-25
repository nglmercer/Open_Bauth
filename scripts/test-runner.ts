#!/usr/bin/env bun
// scripts/test-runner.ts
// Script personalizado para ejecutar tests con diferentes configuraciones

import { spawn } from 'child_process';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';

// Configuración del runner de tests
interface TestConfig {
  name: string;
  description: string;
  command: string[];
  env?: Record<string, string>;
  timeout?: number;
}

// Configuraciones predefinidas de tests
const testConfigs: Record<string, TestConfig> = {
  unit: {
    name: 'Unit Tests',
    description: 'Ejecutar tests unitarios (servicios y middleware)',
    command: ['bun', 'test', 'tests/services', 'tests/middleware', '--coverage'],
    timeout: 30000
  },
  
  integration: {
    name: 'Integration Tests',
    description: 'Ejecutar tests de integración',
    command: ['bun', 'test', 'tests/integration', '--timeout', '60000'],
    timeout: 120000
  },
  
  adapters: {
    name: 'Adapter Tests',
    description: 'Ejecutar tests de adaptadores de frameworks',
    command: ['bun', 'test', 'tests/adapters'],
    timeout: 45000
  },
  services: {
    name: 'Service Tests',
    description: 'Ejecutar tests de servicios',
    command: ['bun', 'test', 'tests/services'],
    timeout: 60000
  },
  performance: {
    name: 'Performance Tests',
    description: 'Ejecutar tests de rendimiento',
    command: ['bun', 'test', '--test-name-pattern', 'Performance', '--timeout', '120000'],
    env: { PERFORMANCE_TEST: 'true' },
    timeout: 180000
  },
  
  watch: {
    name: 'Watch Mode',
    description: 'Ejecutar tests en modo watch',
    command: ['bun', 'test', '--watch'],
    timeout: 0 // Sin timeout para watch mode
  },
  
  coverage: {
    name: 'Coverage Report',
    description: 'Generar reporte de cobertura completo',
    command: ['bun', 'test', '--coverage', '--coverage-reporter', 'html', '--coverage-reporter', 'text', '--coverage-reporter', 'lcov'],
    timeout: 60000
  },
  
  ci: {
    name: 'CI/CD Tests',
    description: 'Ejecutar tests para CI/CD con reportes JUnit',
    command: ['bun', 'test', '--reporter', 'junit', '--reporter-outfile', 'test-results.xml', '--coverage'],
    timeout: 120000
  },
  
  debug: {
    name: 'Debug Mode',
    description: 'Ejecutar tests en modo debug (sin timeout)',
    command: ['bun', 'test', '--timeout', '0'],
    timeout: 0
  },
  
  specific: {
    name: 'Specific Test',
    description: 'Ejecutar un test específico',
    command: ['bun', 'test'], // Se completará dinámicamente
    timeout: 30000
  },
  
  bail: {
    name: 'Bail on First Failure',
    description: 'Detener tests en el primer fallo',
    command: ['bun', 'test', '--bail'],
    timeout: 60000
  },
  
  rerun: {
    name: 'Rerun Tests',
    description: 'Ejecutar cada test múltiples veces para detectar flakiness',
    command: ['bun', 'test', '--rerun-each', '3'],
    timeout: 180000
  },
  
  parallel: {
    name: 'Parallel Tests',
    description: 'Ejecutar tests en paralelo con máxima concurrencia',
    command: ['bun', 'test', '--concurrency', '4'],
    timeout: 45000
  }
};

// Colores para output
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m'
};

// Función para imprimir con colores
function colorLog(message: string, color: keyof typeof colors = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

// Función para mostrar ayuda
function showHelp() {
  colorLog('\n🧪 Test Runner para Bun Auth Library', 'bright');
  colorLog('\nUso: bun run scripts/test-runner.ts [comando] [opciones]\n', 'cyan');
  
  colorLog('Comandos disponibles:', 'yellow');
  Object.entries(testConfigs).forEach(([key, config]) => {
    colorLog(`  ${key.padEnd(12)} - ${config.description}`, 'green');
  });
  
  colorLog('\nEjemplos:', 'yellow');
  colorLog('  bun run scripts/test-runner.ts unit', 'cyan');
  colorLog('  bun run scripts/test-runner.ts coverage', 'cyan');
  colorLog('  bun run scripts/test-runner.ts specific tests/services/jwt.test.ts', 'cyan');
  colorLog('  bun run scripts/test-runner.ts watch', 'cyan');
  
  colorLog('\nOpciones adicionales:', 'yellow');
  colorLog('  --verbose    - Output detallado', 'green');
  colorLog('  --quiet      - Output mínimo', 'green');
  colorLog('  --help       - Mostrar esta ayuda', 'green');
}

// Función para ejecutar comando
function runCommand(config: TestConfig, args: string[] = [], options: { verbose?: boolean; quiet?: boolean } = {}): Promise<number> {
  return new Promise((resolve) => {
    const command = [...config.command, ...args];
    
    if (!options.quiet) {
      colorLog(`\n🚀 Ejecutando: ${config.name}`, 'bright');
      colorLog(`📝 Descripción: ${config.description}`, 'cyan');
      colorLog(`⚡ Comando: ${command.join(' ')}`, 'magenta');
      
      if (config.env) {
        colorLog(`🌍 Variables de entorno: ${Object.entries(config.env).map(([k, v]) => `${k}=${v}`).join(', ')}`, 'yellow');
      }
      
      colorLog('\n' + '='.repeat(60), 'blue');
    }
    
    const env = {
      ...process.env,
      ...config.env
    };
    
    const child = spawn(command[0], command.slice(1), {
      stdio: options.quiet ? 'pipe' : 'inherit',
      env,
      shell: true
    });
    
    // Timeout si está configurado
    let timeoutId: NodeJS.Timeout | null = null;
    if (config.timeout && config.timeout > 0) {
      timeoutId = setTimeout(() => {
        colorLog(`\n⏰ Timeout alcanzado (${config.timeout}ms), terminando proceso...`, 'red');
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
      }, config.timeout);
    }
    
    child.on('close', (code) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      if (!options.quiet) {
        colorLog('\n' + '='.repeat(60), 'blue');
        
        if (code === 0) {
          colorLog(`✅ ${config.name} completado exitosamente`, 'green');
        } else {
          colorLog(`❌ ${config.name} falló con código ${code}`, 'red');
        }
      }
      
      resolve(code || 0);
    });
    
    child.on('error', (error:any) => {
      if (timeoutId) {
        clearTimeout(timeoutId);
      }
      
      colorLog(`\n💥 Error ejecutando comando: ${error.message}`, 'red');
      resolve(1);
    });
  });
}

// Función para preparar entorno de test
function prepareTestEnvironment() {
  const dirs = [
    'tests/data',
    'coverage',
    'reports',
    'logs'
  ];
  
  dirs.forEach(dir => {
    if (!existsSync(dir)) {
      mkdirSync(dir, { recursive: true });
    }
  });
}

// Función principal
async function main() {
  const args = process.argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    showHelp();
    return;
  }
  
  const command = args[0];
  const options = {
    verbose: args.includes('--verbose'),
    quiet: args.includes('--quiet')
  };
  
  // Filtrar opciones de los argumentos
  const filteredArgs = args.slice(1).filter(arg => !arg.startsWith('--'));
  
  if (!testConfigs[command]) {
    colorLog(`❌ Comando desconocido: ${command}`, 'red');
    colorLog('\nComandos disponibles:', 'yellow');
    Object.keys(testConfigs).forEach(key => {
      colorLog(`  ${key}`, 'green');
    });
  }
  
  // Preparar entorno
  prepareTestEnvironment();
  
  // Configuración especial para comando 'specific'
  if (command === 'specific' && filteredArgs.length > 0) {
    testConfigs.specific.command = ['bun', 'test', ...filteredArgs];
  }
  
  // Ejecutar comando
  const startTime = Date.now();
  const exitCode = await runCommand(testConfigs[command], [], options);
  const duration = Date.now() - startTime;
  
  if (!options.quiet) {
    colorLog(`\n⏱️  Tiempo total: ${(duration / 1000).toFixed(2)}s`, 'cyan');
    
    if (exitCode === 0) {
      colorLog('\n🎉 ¡Todos los tests completados exitosamente!', 'green');
    } else {
      colorLog('\n💔 Algunos tests fallaron. Revisa los logs para más detalles.', 'red');
    }
  }
  
}

// Ejecutar función principal
if (import.meta.main) {
  main().catch((error:any) => {
    colorLog(`\n💥 Error fatal: ${error.message}`, 'red');
  });
}

// Exportar para uso como módulo
export { testConfigs, runCommand, prepareTestEnvironment };