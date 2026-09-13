# ssrfguard 常用命令入口。
#
# 约定：
#   - 所有目标都在仓库根目录执行，除 Go 工具链外不依赖任何第三方工具；
#   - 顶层变量都可以从命令行覆盖，例如：
#       make bench BENCHTIME=1s
#       make run ARGS="-config examples/ssrf.yaml http://a.example.com/"
#   - Windows 分支的删除命令是 cmd 语法；如果在 sh 环境（Git Bash / MSYS）下执行，
#     覆盖 RM_BIN / RM_COV / RM_DIR 即可。

GO        ?= go
ARGS      ?=
BENCHTIME ?= 100ms
TIMEOUT   ?= 60s
FUZZTIME  ?= 30s

ifeq ($(OS),Windows_NT)
BIN_DIR ?= bin
BIN     ?= $(BIN_DIR)\ssrfcheck.exe
# 用 if exist 包一层：产物本来就不存在时也返回 0，make clean 在干净树上才能完全静默
RM_BIN  ?= if exist $(BIN) del /Q /F $(BIN)
RM_COV  ?= if exist coverage.out del /Q /F coverage.out & if exist coverage.html del /Q /F coverage.html
RM_DIR  ?= if exist $(BIN_DIR) rd /Q $(BIN_DIR)
else
BIN_DIR ?= bin
BIN     ?= $(BIN_DIR)/ssrfcheck
RM_BIN  ?= rm -f $(BIN)
RM_COV  ?= rm -f coverage.out coverage.html
RM_DIR  ?= rmdir $(BIN_DIR) 2>/dev/null || true
endif

.PHONY: all help build install run demo test race cover bench fuzz vet fmt tidy clean

# all 故意不带 -race：提交前想跑得快点，需要竞态检测时走 make race
all: fmt vet test

help:
	@echo Targets:
	@echo   build    go build -o $(BIN) ./cmd/ssrfcheck
	@echo   install  go install ./cmd/ssrfcheck
	@echo   run      build and run the CLI, pass args via ARGS="..."
	@echo   demo     run the CLI against examples/ssrf.yaml with sample targets
	@echo   test     go test ./...
	@echo   race     go test -race ./...
	@echo   cover    coverage profile + coverage.html
	@echo   bench    run all benchmarks in ./ssrf (BENCHTIME=100ms)
	@echo   fuzz     run parser/config fuzz targets for FUZZTIME=30s each
	@echo   vet      go vet ./...
	@echo   fmt      go fmt ./...
	@echo   tidy     go mod tidy
	@echo   clean    remove bin/ and coverage.*

build:
	$(GO) build -o $(BIN) ./cmd/ssrfcheck

install:
	$(GO) install ./cmd/ssrfcheck

run: build
	$(BIN) $(ARGS)

# demo 故意只用字面量地址、不写域名：域名要走真实 DNS，而 .example.com 是保留域名、
# 永远解析不了，那样的演示会变成「全 REJECT」。这里固定演示四种结论：
# 显式信任的内网段放行、十进制回环地址在规范化后仍被拒、云 metadata 地址被拒、
# 内建高危端口被拒。
demo: build
	$(BIN) -config examples/ssrf.yaml http://10.0.0.5/ http://2130706433/ http://169.254.169.254/ http://10.0.0.5:6379/

test:
	$(GO) test ./... -count=1 -timeout $(TIMEOUT)

race:
	$(GO) test -race ./... -count=1 -timeout $(TIMEOUT)

cover:
	$(GO) test ./... -count=1 -covermode=atomic -coverprofile=coverage.out
	$(GO) tool cover -func=coverage.out
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo report: coverage.html

# -run XXX 让基准之外什么都不跑，避免把测试的执行时间算进基准结果
bench:
	$(GO) test ./ssrf -run XXX -bench . -benchmem -benchtime $(BENCHTIME) -count=1

# 解析器与配置解析是绕过入口，随机输入只允许「拒绝」不允许「panic / 不幂等」
fuzz:
	$(GO) test ./ssrf -run XXX -fuzz=FuzzCheck -fuzztime $(FUZZTIME)
	$(GO) test ./ssrf -run XXX -fuzz=FuzzParseConfig -fuzztime $(FUZZTIME)

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

tidy:
	$(GO) mod tidy

# @- 只是兜底：正常路径下这几个命令在产物不存在时也返回 0，所以 make clean
# 幂等且静默；万一在 sh 里执行到 cmd 语法的分支，也不该中断。
clean:
	@-$(RM_BIN)
	@-$(RM_COV)
	@-$(RM_DIR)
