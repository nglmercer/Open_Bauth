# Especificación técnica para extender las tablas iniciales (Plantilla)

Este documento define la forma estandarizada de añadir nuevas tablas al esquema base del proyecto, asegurando que siempre existan y se creen/migren de forma segura a través del inicializador de base de datos.

Archivos relevantes:
- Inicializador y registro de esquemas: src/database/database-initializer.ts
- Controlador genérico y utilidades de SQL: src/database/base-controller.ts
- Re-exports de base de datos: src/database/index.ts y src/index.ts

## Objetivo
- Incorporar nuevas tablas (p. ej., puntos, notificaciones, procesos) de manera segura y repetible.
- Garantizar su creación mediante DatabaseInitializer.initialize/migrate/repair.
- Mantener consistencia en nombres, tipos de datos, claves, relaciones e índices.
- Permitir extender el esquema desde fuera de la librería mediante una API mínima (externalSchemas, registerSchemas y SchemaRegistry), sin modificar el arreglo base DATABASE_SCHEMAS.

## Conceptos base
- TableSchema: describe la tabla (columnas, índices). Es consumido por BaseController.initializeDatabase para generar y ejecutar CREATE TABLE/INDEX IF NOT EXISTS.
- ColumnDefinition: define nombre, tipo, PK, UNIQUE, NOT NULL, DEFAULT, y referencias (FK).
- DEFAULT_SCHEMAS: alias exportado del conjunto interno por defecto (retrocompatibilidad). No lo modifiques; úsalo como base si necesitas componer.
- Esquemas efectivos: DatabaseInitializer combina por defecto DEFAULT_SCHEMAS + (externalSchemas opcionales) y los usa en initialize, checkIntegrity, reset y getStatistics salvo que se le pase un arreglo explícito.
- API de extensión:
  - externalSchemas (constructor): permite pasar un arreglo de TableSchema desde fuera para combinarlos con los de base.
  - registerSchemas(schemas): método para registrar dinámicamente nuevos esquemas tras la construcción; deduplica por tableName y sobrescribe el existente si hay duplicados.
  - SchemaRegistry: utilidad ligera para registrar, combinar (merge) y obtener esquemas modularmente, útil para paquetes/plugins externos.
- Manejo de tipos y defaults:
  - mapDataType adapta tipos para SQLite y otros motores.
  - formatDefaultValue asegura defaults correctos: valores booleanos → 1/0 en SQLite; funciones/keywords SQL sin comillas (p. ej. CURRENT_TIMESTAMP, o expresiones entre paréntesis); literales string con comillas simples.
- Integridad y migración:
  - DatabaseInitializer.checkIntegrity detecta tablas/índices faltantes.
  - DatabaseInitializer.initialize crea todo el conjunto de esquemas.
  - DatabaseInitializer.migrate/repair re-crea componentes faltantes.

## Flujo para extender el esquema
1) Define tu nueva tabla como TableSchema en tu propio paquete o en código de aplicación (fuera de la librería).
2) Regístrala usando una de estas opciones (sin tocar DATABASE_SCHEMAS):
   - Pasándola en el constructor vía externalSchemas.
   - Llamando a initializer.registerSchemas(schema | schema[]) tras construir el DatabaseInitializer.
   - Componiendo un SchemaRegistry, y pasando registry.getAll() al constructor o a registerSchemas.
3) Ejecuta initialize() o migrate()/repair() en el arranque para asegurar su existencia.
4) Consume la tabla a través de BaseController o con DatabaseInitializer.createController.

## Plantilla de TableSchema (copiar y adaptar)
```ts
// Archivo de referencia: src/database/database-initializer.ts
export const NUEVOS_ESQUEMAS: TableSchema[] = [
  {
    tableName: "<nombre_tabla>",
    columns: [
      // PK recomendada (UUID-like via randomblob hex en SQLite):
      { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },

      // Ejemplos:
      // { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
      // { name: "is_active", type: "BOOLEAN", defaultValue: true },
      // { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
      // { name: "amount", type: "INTEGER", notNull: true, defaultValue: 0 },
      // { name: "payload", type: "TEXT" },
    ],
    indexes: [
      // Definir índices por columnas de filtro frecuente:
      // { name: "idx_<tabla>_<col>", columns: ["<col>"] },
      // { name: "idx_<tabla>_<col1>_<col2>", columns: ["<col1>", "<col2>"], unique: true },
    ]
  }
];
```

Para activar tu tabla no necesitas modificar el código de la librería. Regístrala desde fuera usando externalSchemas en el constructor, el método registerSchemas() o un SchemaRegistry (ver secciones siguientes).

## Ejemplos listos para usar

1) Tabla de puntos (points)
```ts
{
  tableName: "points",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
    { name: "points", type: "INTEGER", notNull: true, defaultValue: 0 },
    { name: "reason", type: "TEXT" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  indexes: [
    { name: "idx_points_user_id", columns: ["user_id"] },
    { name: "idx_points_created_at", columns: ["created_at"] }
  ]
}
```

2) Tabla de notificaciones (notifications)
```ts
{
  tableName: "notifications",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "user_id", type: "TEXT", notNull: true, references: { table: "users", column: "id" } },
    { name: "title", type: "TEXT", notNull: true },
    { name: "body", type: "TEXT" },
    { name: "channel", type: "TEXT" }, // ej: email, push, sms
    { name: "status", type: "TEXT", defaultValue: "'pending'" }, // pending | sent | failed | read
    { name: "read_at", type: "DATETIME" },
    { name: "created_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" }
  ],
  indexes: [
    { name: "idx_notifications_user_id", columns: ["user_id"] },
    { name: "idx_notifications_status", columns: ["status"] },
    { name: "idx_notifications_read_at", columns: ["read_at"] }
  ]
}
```

3) Tabla de procesos (processes)
```ts
{
  tableName: "processes",
  columns: [
    { name: "id", type: "TEXT", primaryKey: true, defaultValue: "(lower(hex(randomblob(16))))" },
    { name: "name", type: "TEXT", notNull: true },
    { name: "status", type: "TEXT", defaultValue: "'pending'" }, // pending | running | success | error
    { name: "retries", type: "INTEGER", defaultValue: 0 },
    { name: "payload", type: "TEXT" }, // JSON serializado opcional
    { name: "last_error", type: "TEXT" },
    { name: "started_at", type: "DATETIME", defaultValue: "CURRENT_TIMESTAMP" },
    { name: "finished_at", type: "DATETIME" }
  ],
  indexes: [
    { name: "idx_processes_status", columns: ["status"] },
    { name: "idx_processes_started_at", columns: ["started_at"] }
  ]
}
```

Nota sobre defaults string: para literales TEXT usa comillas simples dentro del string TS (ej. defaultValue: "'pending'"), mientras que funciones/keywords SQL (CURRENT_TIMESTAMP) o expresiones con paréntesis se pasan sin comillas.

## API de extensión (sin tocar el core)
Tienes tres formas de añadir tus tablas desde fuera del paquete.

1) Constructor con externalSchemas
```ts
import { Database } from 'bun:sqlite';
import { DatabaseInitializer } from 'src/database/database-initializer';

const db = new Database(':memory:');
const external = [pointsSchema, notificationsSchema]; // definidos en tu app/paquete
const initializer = new DatabaseInitializer({ database: db, externalSchemas: external });
await initializer.initialize();
```

2) Registro dinámico tras construir (registerSchemas)
```ts
const initializer = new DatabaseInitializer({ database: db });
initializer.registerSchemas(pointsSchema);
initializer.registerSchemas([notificationsSchema, processesSchema]);
await initializer.initialize();
```

3) Composición modular con SchemaRegistry
```ts
import { SchemaRegistry } from 'src/database/database-initializer';

const registryA = new SchemaRegistry([pointsSchema]);
const registryB = new SchemaRegistry([notificationsSchema, processesSchema]);
const merged = SchemaRegistry.merge(registryA, registryB);

const initializer = new DatabaseInitializer({ database: db, externalSchemas: merged.getAll() });
await initializer.initialize();
```

Notas:
- Si registras una tabla con un tableName ya existente, la definición nueva sobrescribe la anterior (override explícito).
- initialize, checkIntegrity, reset y getStatistics toman por defecto los esquemas efectivos (DEFAULT_SCHEMAS + externos) a menos que pases un arreglo de esquemas explícito.
- DEFAULT_SCHEMAS está exportado por conveniencia, pero no necesitas modificarlo.

## Asegurar la existencia en el arranque
- initialize(): crea todas las tablas/índices si no existen.
- migrate(): ejecuta checkIntegrity() y crea lo faltante.
- repair(): similar a migrate(), fuerza reparación de componentes faltantes.

Integración típica en bootstrap de la app:
```ts
const initializer = new DatabaseInitializer({ database: db /* bun:sqlite */, logger });
await initializer.initialize(); // o await initializer.migrate();
```

## Acceso a datos (CRUD) con BaseController
Puedes obtener un controlador puntual para tu tabla (incluyendo tablas añadidas externamente):
```ts
const initializer = new DatabaseInitializer({ database: db, externalSchemas: [pointsSchema] });
await initializer.initialize();

const points = initializer.createController<{ id: string; user_id: string; points: number }>("points");
await points.create({ user_id: "...", points: 10, reason: "signup" });
const list = await points.findAll({ where: { user_id: "..." }, orderBy: "created_at", orderDirection: "DESC" });
```
También puedes instanciar BaseController directamente si ya creaste la tabla vía initialize/migrate:
```ts
const points = new BaseController("points", { database: db, isSQLite: true });
```

## Convenciones y buenas prácticas
- Nombres: snake_case para columnas. Índices: idx_<tabla>_<col1>[_<col2>].
- PK: TEXT con defaultValue: (lower(hex(randomblob(16)))) para compatibilidad y unicidad.
- Fechas: DATETIME con CURRENT_TIMESTAMP cuando aplique.
- Booleanos: type: BOOLEAN, defaultValue: true/false (el mapeo lo convertirá a 1/0 en SQLite).
- Relaciones: usar references { table, column } y crear índices por columnas FK.
- Índices: indexar columnas de filtros/joins frecuentes; usar unique cuando corresponda.
- Cadenas default: envolver literales en comillas simples ("'valor'"), no así funciones/keywords SQL.

## Checklist de incorporación
- [ ] Definí TableSchema con PK, columnas, FKs e índices adecuados.
- [ ] Registré el/los schema(s) usando externalSchemas, registerSchemas o un SchemaRegistry (sin tocar DATABASE_SCHEMAS).
- [ ] Probé initialize()/migrate() en entorno local y verifiqué integridad.
- [ ] Cubrí filtros comunes con índices apropiados.
- [ ] Validé defaults y tipos (especialmente TEXT vs INTEGER vs BOOLEAN vs DATETIME).

## Problemas comunes y solución
- Error por default mal citado: si el default es un literal TEXT, usar "'texto'"; si es una función/keyword (CURRENT_TIMESTAMP) o expresión entre paréntesis, no citar.
- Violación de UNIQUE/FK: revisar índices unique y referencias; asegúrate del orden de creación (initialize genera todo dentro de una transacción en SQLite).
- Tipos booleanos erróneos: declara BOOLEAN; el controlador manejará 1/0 en SQLite.

## Notas sobre compatibilidad de tipos
- SQLite: BOOLEAN → INTEGER (1/0); VARCHAR → TEXT; DATETIME/DATE → TEXT.
- Otros motores: el mapeo en BaseController ajusta a tipos nativos cuando corresponda.

## Validación con tests (Bun)
- Este repositorio incluye pruebas de integración para la API de extensión.
- Ejecuta: bun test tests/schema-extension.test.ts
- Casos cubiertos: uso de externalSchemas en constructor, uso de registerSchemas tras la construcción, y composición mediante SchemaRegistry; se validan operaciones CRUD en tablas extendidas.

---
Con esta plantilla y pasos, podrás extender el esquema base de manera consistente, segura y automatizada, garantizando que las nuevas tablas se creen y permanezcan íntegras en todos los entornos.