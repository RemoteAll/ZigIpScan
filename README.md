# Zig IP Scan

一个使用 Zig 0.15.2+ 开发的 IP 扫描工具,支持主机发现和端口扫描。提供交互式菜单和命令行两种使用方式。

## 特性

- ✅ 交互式菜单:无需记忆参数,按提示操作
- ✅ 命令行模式:适合脚本自动化
- ✅ 跨平台支持:Windows/Linux/macOS
- ✅ 中文界面:完整的 UTF-8 支持
- 🚧 主机发现:IPv4/IPv6 CIDR 扫描(开发中)
- 🚧 端口扫描:TCP 连通性检测(开发中)

## 要求
- Zig 0.15.2 及以上版本

## 构建与运行
```bash
# 构建项目
zig build

# 交互式菜单(推荐新手使用)
zig build run
# 或直接运行:
./zig-out/bin/zig-ip-scan

# 查看命令行帮助
zig build run -- --help
```

## 使用方式

### 1. 交互式菜单

直接运行程序,无需任何参数:

```bash
zig build run
```

会看到如下菜单:
```
=== Zig IP Scan 交互式菜单 ===
请选择扫描模式:
  1) 本机子网 (local)    # 自动检测网卡,扫描本机所在子网
  2) 指定CIDR (cidr)     # 手动输入网段,如 192.168.1.0/24
  3) 局域网 (lan)         # 扫描所有网卡的子网
```

### 2. 命令行模式

适合脚本自动化:

```bash
### 2. 命令行模式

适合脚本自动化:

```bash
# 主机发现(默认行为)
zig build run -- --mode cidr --cidr 192.168.1.0/24
zig build run -- --mode cidr --cidr 2001:db8::/120     # IPv6
zig build run -- --mode local                          # 本机子网,自动检测
zig build run -- --mode lan                            # 局域网全扫描

# 端口扫描(需要 --action scan)
zig build run -- --mode cidr --cidr 192.168.1.0/24 --action scan --port 80
zig build run -- --mode local --action scan --port 443
```

#### 参数说明

- **`--mode <模式>`**: 扫描范围
  - `local`: 本机子网(自动检测网卡,无需手动指定)
  - `cidr`: 指定 CIDR 网段(需配合 `--cidr`)
  - `lan`: 局域网(所有活动网卡)

- **`--action <操作>`**: 操作类型(可选,默认 `discover`)
  - `discover`: 主机发现(不扫描端口)
  - `scan`: 端口扫描(需配合 `--port`)

- **`--cidr <网段>`**: CIDR 格式网段
  - 示例: `192.168.1.0/24`、`10.0.0.0/16`、`2001:db8::/120`

- **`--port <端口>`**: 扫描的端口号(仅用于 `--action scan`)
  - 示例: `80`、`443`、`22`

- **`--help`**: 显示帮助信息

## 依赖

- [zzig](https://github.com/PeiKeSmart/zzig.git): 控制台工具库,提供 UTF-8 支持和 ANSI 颜色

## 开发状态

- ✅ 项目结构搭建
- ✅ 交互式菜单实现
- ✅ 命令行参数解析
- ✅ zzig 依赖集成
- ✅ 跨平台 stdin/stdout 支持
- 🚧 网卡自动检测(待实现)
- 🚧 CIDR 解析与 IP 枚举(待实现)
- 🚧 TCP 连通性检测(待实现)
- 🚧 主机发现功能(待实现)
- 🚧 端口扫描功能(待实现)

## 技术特点

- **Zig 0.15.2+ 兼容**: 使用最新 API,符合官方最佳实践
- **零依赖启动**: 核心功能不依赖第三方网络库
- **跨平台原生支持**: Windows/Linux/macOS 统一代码
- **性能优先**: 避免不必要的内存分配,适合高并发场景

## 注意事项

- ICMP (ping) 需要原始套接字且可能需要管理员权限;优先采用 TCP 端口可达性判断
- IPv6 前缀空间巨大(如 `/64`),不宜全量枚举;建议使用较小前缀(如 `/120`)或目标清单
- 当前版本仅提供项目骨架,实际扫描功能正在开发中

## 许可证

MIT