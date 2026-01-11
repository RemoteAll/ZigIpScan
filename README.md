# Zig IP Scan

一个使用 Zig 0.15.2+ 的基础项目骨架，后续将实现 IPv4 网段的 IP/端口扫描。支持菜单化 CLI 参数：选择扫描本机子网、指定 CIDR 或局域网。

## 要求
- Zig 0.15.2 及以上版本

## 构建与运行
```bash
zig build
# 查看菜单/用法
zig build run -- --help

# 扫描指定 CIDR
zig build run -- --mode cidr --cidr 192.168.1.0/24 --port 80

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

## 注意事项
- ICMP (ping) 需要原始套接字且可能需要管理员权限；优先采用 TCP 端口可达性判断。
- 遵循 Zig 0.15.2+ API 变更规范与性能最佳实践（尽量低分配、避免阻塞）。
