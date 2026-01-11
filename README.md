# Zig IP Scan

一个使用 Zig 0.15.2+ 的基础项目骨架，后续将实现 IPv4/IPv6 网段的 IP/端口扫描。支持菜单化 CLI 参数：选择扫描本机子网、指定 CIDR 或局域网。

## 要求
- Zig 0.15.2 及以上版本

## 构建与运行
```bash
zig build
# 查看参数用法
zig build run -- --help
# 菜单用法
- **模式 `--mode`**: 选择扫描范围
	- `local`: 本机网卡所在子网（可选 `--iface` 指定网卡名）
	- `cidr`: 指定网段（需要 `--cidr <CIDR>`）
	- `lan`: 局域网（所有活动网卡的子网）
- **行为 `--action`**: 选择操作类型
	- `discover`（默认）: 主机发现，不进行端口扫描
	- `scan`: 端口扫描（需配合 `--port <端口>`）
- **常用选项**:
	- `--cidr <CIDR>`: 支持 IPv4/IPv6，例如 `192.168.1.0/24`、`2001:db8::/120`
	- `--port <端口>`: 端口扫描时指定单个端口（如 `80`、`443`）
	- `--iface <名称>`: 在 `local` 模式指定网卡名（如 `Ethernet`）
	- `--help`: 显示帮助

示例：
```bash
# 主机发现（默认行为）
zig build run -- --mode cidr --cidr 192.168.1.0/24
zig build run -- --mode cidr --cidr 2001:db8::/120
zig build run -- --mode local [--iface Ethernet]
zig build run -- --mode lan

# 端口扫描（显式指定）
zig build run -- --mode cidr --cidr 192.168.1.0/24 --action scan --port 80
zig build run -- --mode local --action scan --port 443 [--iface Ethernet]
```

# 主机发现（默认，不扫描端口）
zig build run -- --mode cidr --cidr 192.168.1.0/24
zig build run -- --mode cidr --cidr 2001:db8::/120
zig build run -- --mode local [--iface Ethernet]
zig build run -- --mode lan

# 端口扫描（显式指定）
zig build run -- --mode cidr --cidr 192.168.1.0/24 --action scan --port 80
zig build run -- --mode local --action scan --port 443 [--iface Ethernet]

# 扫描本机网卡所在子网（iface 可选）
zig build run -- --mode local --port 80 [--iface Ethernet]

# 扫描局域网（所有活动网卡子网）
zig build run -- --mode lan --port 443
```

> 提示：当前仅提供项目骨架，`src/ip_scan.zig` 中的扫描函数尚未实现。

## 计划实现
- CIDR 解析（如 `192.168.1.0/24`）
- 并发 TCP 连接尝试（可配置端口）
- 输出可达 IP 列表与端口状态
- 跨平台支持（Windows/Linux/macOS），使用 `std.net`/`std.os` API
- 本机网卡枚举与子网推断（local/lan 模式）
- IPv6 支持：解析 IPv6 CIDR（例如 `2001:db8::/120`）与端口探测（建议小前缀或目标清单）
	- 主机发现优先实现；端口扫描需显式 `--action scan`。

## 注意事项
- ICMP (ping) 需要原始套接字且可能需要管理员权限；优先采用 TCP 端口可达性判断。
- 遵循 Zig 0.15.2+ API 变更规范与性能最佳实践（尽量低分配、避免阻塞）。
- IPv6 前缀空间巨大（如 `/64`），不宜全量枚举；建议使用较小前缀（如 `/120`）或目标清单文件。
- 未来将增加 `--file targets.txt` 读取目标列表，统一支持 IPv4/IPv6 地址与端口。
