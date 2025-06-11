package main

import (
    "flag"
    "fmt"
    "log"
    "os"

    "github.com/golang-migrate/migrate/v4"
    _ "github.com/golang-migrate/migrate/v4/database/postgres"
    _ "github.com/golang-migrate/migrate/v4/source/file"
)

func main() {
    var command = flag.String("command", "up", "Migration command: up, down, version, force")
    var steps = flag.Int("steps", 0, "Number of steps for up/down migration")
    var version = flag.Uint("version", 0, "Version for force command")
    flag.Parse()

    // 从环境变量获取数据库连接信息
    dbHost := getEnv("DB_HOST", "localhost")
    dbPort := getEnv("DB_PORT", "5432")
    dbUser := getEnv("DB_USER", "postgres")
    dbPassword := getEnv("DB_PASSWORD", "postgres")
    dbName := getEnv("DB_NAME", "ai_agent")
    sslMode := getEnv("DB_SSLMODE", "disable")

    // 构建数据库连接字符串
    databaseURL := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=%s",
        dbUser, dbPassword, dbHost, dbPort, dbName, sslMode)

    // 迁移文件路径
    migrationsPath := "file://../"

    fmt.Printf("Connecting to database: %s@%s:%s/%s\n", dbUser, dbHost, dbPort, dbName)
    fmt.Printf("Migrations path: %s\n", migrationsPath)

    // 创建migrate实例
    m, err := migrate.New(migrationsPath, databaseURL)
    if err != nil {
        log.Fatalf("Failed to create migrate instance: %v", err)
    }
    defer func() {
        sourceErr, databaseErr := m.Close()
        if sourceErr != nil {
            log.Printf("Failed to close source: %v", sourceErr)
        }
        if databaseErr != nil {
            log.Printf("Failed to close database: %v", databaseErr)
        }
    }()

    // 执行迁移命令
    switch *command {
    case "up":
        err = executeUp(m, *steps)
    case "down":
        err = executeDown(m, *steps)
    case "version":
        err = showVersion(m)
    case "force":
        err = forceVersion(m, *version)
    case "drop":
        err = dropDatabase(m)
    default:
        log.Fatalf("Unknown command: %s. Available: up, down, version, force, drop", *command)
    }

    if err != nil {
        log.Fatalf("Migration failed: %v", err)
    }

    fmt.Println("Migration completed successfully!")
}

func executeUp(m *migrate.Migrate, steps int) error {
    fmt.Printf("Running migrations up")
    if steps > 0 {
        fmt.Printf(" (steps: %d)", steps)
        return m.Steps(steps)
    }
    fmt.Println()
    err := m.Up()
    if err == migrate.ErrNoChange {
        fmt.Println("No migrations to apply")
        return nil
    }
    return err
}

func executeDown(m *migrate.Migrate, steps int) error {
    if steps > 0 {
        fmt.Printf("Rolling back %d migration(s)\n", steps)
        return m.Steps(-steps)
    }
    
    fmt.Println("Rolling back all migrations")
    return m.Down()
}

func showVersion(m *migrate.Migrate) error {
    version, dirty, err := m.Version()
    if err != nil {
        return err
    }
    
    fmt.Printf("Current migration version: %d\n", version)
    if dirty {
        fmt.Println("WARNING: Database is in dirty state!")
    } else {
        fmt.Println("Database is clean")
    }
    return nil
}

func forceVersion(m *migrate.Migrate, version uint) error {
    if version == 0 {
        return fmt.Errorf("version must be specified for force command")
    }
    
    fmt.Printf("Forcing database version to: %d\n", version)
    fmt.Println("WARNING: This command should only be used to fix dirty database state!")
    return m.Force(int(version))
}

func dropDatabase(m *migrate.Migrate) error {
    fmt.Println("WARNING: This will drop all tables and data!")
    fmt.Print("Are you sure? (yes/no): ")
    
    var confirmation string
    fmt.Scanln(&confirmation)
    
    if confirmation != "yes" {
        fmt.Println("Operation cancelled")
        return nil
    }
    
    fmt.Println("Dropping database...")
    return m.Drop()
}

func getEnv(key, defaultValue string) string {
    if value := os.Getenv(key); value != "" {
        return value
    }
    return defaultValue
}