-- 删除触发器
DROP TRIGGER IF EXISTS update_users_updated_at ON users;
DROP TRIGGER IF EXISTS update_roles_updated_at ON roles;
DROP TRIGGER IF EXISTS update_sessions_updated_at ON sessions;
DROP TRIGGER IF EXISTS update_plugins_updated_at ON plugins;
DROP TRIGGER IF EXISTS update_usage_quotas_updated_at ON usage_quotas;
DROP TRIGGER IF EXISTS update_system_configs_updated_at ON system_configs;

-- 删除触发器函数
DROP FUNCTION IF EXISTS update_updated_at_column();

-- 删除索引
DROP INDEX IF EXISTS idx_users_email;
DROP INDEX IF EXISTS idx_users_username;
DROP INDEX IF EXISTS idx_users_status;
DROP INDEX IF EXISTS idx_users_created_at;

DROP INDEX IF EXISTS idx_sessions_user_id;
DROP INDEX IF EXISTS idx_sessions_status;
DROP INDEX IF EXISTS idx_sessions_created_at;
DROP INDEX IF EXISTS idx_sessions_updated_at;

DROP INDEX IF EXISTS idx_messages_session_id;
DROP INDEX IF EXISTS idx_messages_parent_id;
DROP INDEX IF EXISTS idx_messages_role;
DROP INDEX IF EXISTS idx_messages_created_at;
DROP INDEX IF EXISTS idx_messages_session_created;

DROP INDEX IF EXISTS idx_plugins_name;
DROP INDEX IF EXISTS idx_plugins_status;
DROP INDEX IF EXISTS idx_plugins_category;
DROP INDEX IF EXISTS idx_plugins_created_at;

DROP INDEX IF EXISTS idx_plugin_executions_plugin_id;
DROP INDEX IF EXISTS idx_plugin_executions_user_id;
DROP INDEX IF EXISTS idx_plugin_executions_session_id;
DROP INDEX IF EXISTS idx_plugin_executions_status;
DROP INDEX IF EXISTS idx_plugin_executions_created_at;

DROP INDEX IF EXISTS idx_api_keys_user_id;
DROP INDEX IF EXISTS idx_api_keys_key_hash;
DROP INDEX IF EXISTS idx_api_keys_is_active;

DROP INDEX IF EXISTS idx_usage_quotas_user_id;
DROP INDEX IF EXISTS idx_usage_quotas_quota_type;

-- 删除表
DROP TABLE IF EXISTS system_configs;
DROP TABLE IF EXISTS usage_quotas;
DROP TABLE IF EXISTS api_keys;
DROP TABLE IF EXISTS plugin_executions;
DROP TABLE IF EXISTS user_plugins;
DROP TABLE IF EXISTS plugins;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_roles;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS users;