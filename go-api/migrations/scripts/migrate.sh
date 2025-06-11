#!/bin/bash

# 切换到scripts目录
cd "$(dirname "$0")"

# 设置默认环境变量（如果没有设置的话）
export DB_HOST=${DB_HOST:-localhost}
export DB_PORT=${DB_PORT:-5432}
export DB_USER=${DB_USER:-postgres}
export DB_PASSWORD=${DB_PASSWORD:-password}
export DB_NAME=${DB_NAME:-ai_agent}
export DB_SSLMODE=${DB_SSLMODE:-disable}

# 获取命令参数
COMMAND=${1:-up}
STEPS=${2:-0}
VERSION=${3:-0}

echo "=== Database Migration Tool ==="
echo "Command: $COMMAND"
echo "Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "User: $DB_USER"
echo ""

# 根据命令执行对应操作
case $COMMAND in
    "up")
        if [ "$STEPS" -gt 0 ]; then
            echo "Running $STEPS migration(s) up..."
            go run migration.go -command=up -steps=$STEPS
        else
            echo "Running all pending migrations up..."
            go run migration.go -command=up
        fi
        ;;
    "down")
        if [ "$STEPS" -gt 0 ]; then
            echo "Rolling back $STEPS migration(s)..."
            go run migration.go -command=down -steps=$STEPS
        else
            echo "Rolling back all migrations..."
            go run migration.go -command=down
        fi
        ;;
    "version")
        echo "Checking migration version..."
        go run migration.go -command=version
        ;;
    "force")
        if [ "$VERSION" -eq 0 ]; then
            echo "Error: Version must be specified for force command"
            echo "Usage: $0 force <version>"
            exit 1
        fi
        echo "Forcing version to $VERSION..."
        go run migration.go -command=force -version=$VERSION
        ;;
    "drop")
        echo "Dropping all database objects..."
        go run migration.go -command=drop
        ;;
    "create")
        if [ -z "$2" ]; then
            echo "Error: Migration name must be specified"
            echo "Usage: $0 create <migration_name>"
            exit 1
        fi
        
        MIGRATION_NAME=$2
        TIMESTAMP=$(date +%Y%m%d%H%M%S)
        
        # 创建up迁移文件
        UP_FILE="../${TIMESTAMP}_${MIGRATION_NAME}.up.sql"
        DOWN_FILE="../${TIMESTAMP}_${MIGRATION_NAME}.down.sql"
        
        echo "-- Migration: $MIGRATION_NAME" > "$UP_FILE"
        echo "-- Created: $(date)" >> "$UP_FILE"
        echo "" >> "$UP_FILE"
        echo "-- Add your migration SQL here" >> "$UP_FILE"
        
        echo "-- Rollback migration: $MIGRATION_NAME" > "$DOWN_FILE"
        echo "-- Created: $(date)" >> "$DOWN_FILE"
        echo "" >> "$DOWN_FILE"
        echo "-- Add your rollback SQL here" >> "$DOWN_FILE"
        
        echo "Created migration files:"
        echo "  Up:   $UP_FILE"
        echo "  Down: $DOWN_FILE"
        ;;
    *)
        echo "Usage: $0 {up|down|version|force|drop|create} [args...]"
        echo ""
        echo "Commands:"
        echo "  up [steps]       - Apply pending migrations (optionally limit steps)"
        echo "  down [steps]     - Rollback migrations (optionally limit steps)"
        echo "  version          - Show current migration version"
        echo "  force <version>  - Force set migration version (use with caution)"
        echo "  drop             - Drop all database objects"
        echo "  create <name>    - Create new migration files"
        echo ""
        echo "Examples:"
        echo "  $0 up            - Apply all pending migrations"
        echo "  $0 up 1          - Apply 1 migration"
        echo "  $0 down 1        - Rollback 1 migration"
        echo "  $0 create add_users_table"
        exit 1
        ;;
esac

if [ $? -eq 0 ]; then
    echo ""
    echo "Migration completed successfully!"
else
    echo ""
    echo "Migration failed!"
    exit 1
fi