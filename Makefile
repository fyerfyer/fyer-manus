.PHONY: help build run test clean dev-up dev-down db-migrate db-migrate-down db-migrate-status db-migrate-create docker-build docker-run docker-stop docker-test setup all lint test-cover dev-up-all dev-logs

# 变量定义
APP_NAME := fyer-manus-api
GO_API_DIR := go-api
BUILD_DIR := bin
DOCKER_IMAGE := $(APP_NAME):latest

help: ## 显示帮助信息
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

deps: ## 安装Go依赖
	cd $(GO_API_DIR) && go mod download && go mod tidy

build: ## 构建Go应用
	@echo "Building $(APP_NAME)..."
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	    echo ".env file created! Please edit it with your actual configuration."; \
	fi
	cd $(GO_API_DIR) && CGO_ENABLED=0 GOOS=linux go build -o ../$(BUILD_DIR)/$(APP_NAME) ./cmd
	@echo "Build completed: $(BUILD_DIR)/$(APP_NAME)"

run: ## 本地运行Go应用
	@echo "Starting $(APP_NAME)..."
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	    echo ".env file created! Please edit it with your actual configuration."; \
	fi
	cd $(GO_API_DIR) && go run ./cmd

test: ## 运行测试
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	fi
	cd $(GO_API_DIR) && go test -v ./...

test-cover: ## 运行测试并生成覆盖率报告
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	fi
	cd $(GO_API_DIR) && go test -v -coverprofile=coverage.out ./...
	cd $(GO_API_DIR) && go tool cover -html=coverage.out -o coverage.html

lint: ## 代码检查
	cd $(GO_API_DIR) && go fmt ./...
	cd $(GO_API_DIR) && go vet ./...

clean: ## 清理构建文件
	@echo "Cleaning build files..."
	rm -rf $(BUILD_DIR)
	cd $(GO_API_DIR) && go clean
	cd $(GO_API_DIR) && rm -f coverage.out coverage.html

dev-up: ## 启动开发环境（包含监控）
	@echo "Starting development environment..."
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	    echo ".env file created! Please edit it with your actual configuration."; \
	fi
	docker-compose -f docker-compose.dev.yml --profile monitoring up -d
	@echo "Waiting for services to be ready..."
	@sleep 10

dev-up-all: ## 启动包含API的完整开发环境
	@echo "Starting full development environment..."
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	    echo ".env file created! Please edit it with your actual configuration."; \
	fi
	docker-compose -f docker-compose.dev.yml --profile api up -d
	@echo "Waiting for services to be ready..."
	@sleep 15

dev-down: ## 停止开发环境
	@echo "Stopping development environment..."
	docker-compose -f docker-compose.dev.yml --profile monitoring --profile api --profile tools down

dev-logs: ## 查看开发环境日志
	docker-compose -f docker-compose.dev.yml logs -f

db-migrate: ## 执行数据库迁移
	@echo "Running database migrations..."
	cd $(GO_API_DIR)/migrations/scripts && chmod +x migrate.sh && ./migrate.sh up

db-migrate-down: ## 回滚数据库迁移
	@echo "Rolling back database migrations..."
	@read -p "Enter number of steps to rollback (or press Enter for all): " steps; \
	cd $(GO_API_DIR)/migrations/scripts && chmod +x migrate.sh && ./migrate.sh down $$steps

db-migrate-status: ## 查看迁移状态
	@echo "Checking migration status..."
	cd $(GO_API_DIR)/migrations/scripts && chmod +x migrate.sh && ./migrate.sh version

db-migrate-create: ## 创建新的数据库迁移文件
	@read -p "Enter migration name: " name; \
	cd $(GO_API_DIR)/migrations/scripts && chmod +x migrate.sh && ./migrate.sh create $$name

docker-build: ## 构建Docker镜像
	@echo "Building Docker image: $(DOCKER_IMAGE)"
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	fi
	docker build -t $(DOCKER_IMAGE) -f $(GO_API_DIR)/Dockerfile .

docker-run: ## 运行Docker容器
	@echo "Running Docker container..."
	@if [ ! -f .env ]; then \
	    echo "Creating .env file from .env.example..."; \
	    cp .env.example .env; \
	fi
	docker run -d --name $(APP_NAME) \
	    -p 8080:8080 \
	    --env-file .env \
	    $(DOCKER_IMAGE)

docker-stop: ## 停止Docker容器
	@echo "Stopping Docker container..."
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true

docker-test: ## 测试Docker构建和运行
	@echo "Testing Docker setup..."
	make docker-build
	make dev-up
	sleep 10
	make docker-run
	sleep 5
	curl -f http://localhost:8080/health || echo "Health check failed"
	docker stop $(APP_NAME) && docker rm $(APP_NAME)
	make dev-down

setup: deps dev-up ## 初始化开发环境
	@echo "Development environment setup completed!"
	@echo "Run 'make db-migrate' to initialize database schema"
	@echo "Run 'make run' to start the API server"

all: clean deps lint test build ## 完整构建流程

# 开发辅助命令
dev-restart: dev-down dev-up ## 重启开发环境

docker-logs: ## 查看Docker容器日志
	docker logs -f $(APP_NAME)

docker-clean: ## 清理Docker资源
	@echo "Cleaning Docker resources..."
	docker stop $(APP_NAME) || true
	docker rm $(APP_NAME) || true
	docker rmi $(DOCKER_IMAGE) || true
	docker system prune -f

# API测试命令
test-api: ## 测试API端点
	@echo "Testing API endpoints..."
	@echo "Health check:"
	curl -s http://localhost:8080/health | jq .
	@echo "\nReadiness check:"
	curl -s http://localhost:8080/ready | jq .