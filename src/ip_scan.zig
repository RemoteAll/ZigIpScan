const std = @import("std");
const zzig = @import("zzig");
const compat = zzig.compat;
const znet = zzig.Net;

/// CIDR 信息结构
const CidrInfo = znet.CidrInfo;

/// 解析 IPv4 CIDR 格式（如 "192.168.1.0/24"）
fn parseCidr(cidr: []const u8) !CidrInfo {
    return znet.parseCidr(cidr);
}

/// 主机信息结构
const HostInfo = znet.HostInfo;

/// 将 u32 IP 转换为字符串（主机字节序）
fn ipToString(ip: u32, buf: []u8) ![]u8 {
    return znet.ipToString(ip, buf);
}

/// 格式化 MAC 地址为字符串
fn macToString(mac: [6]u8, buf: []u8) ![]u8 {
    return znet.macToString(mac, buf);
}

/// 测试 TCP 端口连通性
fn testTcpPort(ip_str: []const u8, port: u16, timeout_ms: u32) bool {
    return znet.testTcpPort(std.heap.page_allocator, ip_str, port, timeout_ms);
}

fn printArpScanProgress(_: ?*anyopaque, progress: znet.ArpScanProgress) void {
    if (progress.total == 0 or progress.completed >= progress.total) return;

    const percent = @as(f64, @floatFromInt(progress.completed)) / @as(f64, @floatFromInt(progress.total)) * 100;
    const avg_speed = if (progress.completed > 0 and progress.elapsed_ms >= 500) blk: {
        const calculated = @divFloor(progress.completed * 1000, @as(usize, @intCast(progress.elapsed_ms)));
        break :blk if (calculated > 0) calculated else 1;
    } else if (progress.completed > 0)
        if (progress.completed * 2 > 0) progress.completed * 2 else 1
    else
        0;

    std.debug.print("\r  进度: {d:.1}% ({d}/{d}) 已发现: {d} 速度: ~{d}IP/s                    ", .{ percent, progress.completed, progress.total, progress.found, avg_speed });
}

fn printTcpPortScanProgress(_: ?*anyopaque, progress: znet.TcpPortScanProgress) void {
    if (progress.total == 0 or progress.completed >= progress.total) return;

    const percent = @as(f64, @floatFromInt(progress.completed)) / @as(f64, @floatFromInt(progress.total)) * 100;
    std.debug.print("  进度: {d:.1}% ({d}/{d}) 已发现: {d}        \r", .{ percent, progress.completed, progress.total, progress.found });
}

pub fn scanRange(allocator: std.mem.Allocator, cidr: []const u8, port: u16) !void {
    std.debug.print("\n🔍 开始端口扫描...\n", .{});
    std.debug.print("目标: {s}  端口: {d}\n\n", .{ cidr, port });

    const cidr_info = try parseCidr(cidr);

    std.debug.print("网段信息:\n", .{});
    var buf: [16]u8 = undefined;
    const base_str = try ipToString(cidr_info.base_ip, &buf);
    std.debug.print("  网络地址: {s}/{d}\n", .{ base_str, cidr_info.prefix_len });
    std.debug.print("  可扫描主机数: {d}\n\n", .{cidr_info.host_count});

    if (cidr_info.host_count > 1024) {
        std.debug.print("⚠️  网段较大，扫描可能需要较长时间\n\n", .{});
    }

    var found_ips = try znet.scanOpenTcpHostsInRange(allocator, cidr_info.base_ip, cidr_info.host_count, port, .{
        .timeout_ms = 1000,
        .progress_interval_hosts = 64,
        .progress_callback = printTcpPortScanProgress,
    });
    defer found_ips.deinit(allocator);

    for (found_ips.items) |ip| {
        var ip_buf: [16]u8 = undefined;
        const ip_str = try ipToString(ip, &ip_buf);
        std.debug.print("✓ {s}  端口 {d} 开放\n", .{ ip_str, port });
    }

    std.debug.print("\n\n📊 扫描完成: 发现 {d} 个开放端口的主机\n", .{found_ips.items.len});
}

fn discoverRangeWithPriority(allocator: std.mem.Allocator, cidr: []const u8, local_ip: ?u32) !void {
    std.debug.print("\n🔍 开始主机发现...\n", .{});
    std.debug.print("目标: {s}\n\n", .{cidr});

    const cidr_info = try parseCidr(cidr);

    std.debug.print("网段信息:\n", .{});
    var buf: [16]u8 = undefined;
    const base_str = try ipToString(cidr_info.base_ip, &buf);
    std.debug.print("  网络地址: {s}/{d}\n", .{ base_str, cidr_info.prefix_len });
    std.debug.print("  可扫描主机数: {d}\n", .{cidr_info.host_count});

    // ARP 扫描速度估算（非常快，每个 IP 约 5-10ms）
    const thread_count: usize = 64; // ARP 是 I/O 密集型，使用更多线程加速
    const estimated_seconds = (cidr_info.host_count * 8) / 1000; // 优化后约8ms/IP
    std.debug.print("  预估时间(ARP): ~{d} 秒 (使用 {d} 线程)\n\n", .{ estimated_seconds, thread_count });

    if (cidr_info.host_count > 1024) {
        std.debug.print("⚠️  网段较大，扫描可能需要较长时间\n\n", .{});
    }

    std.debug.print("🚀 使用 ARP 协议扫描（最快最准确的方法）\n\n", .{});
    const start_time = compat.milliTimestamp();
    var found_hosts = try znet.discoverHostsByArpConcurrent(allocator, cidr_info.base_ip, cidr_info.host_count, .{
        .thread_count = thread_count,
        .local_ip = local_ip,
        .progress_interval_ms = 500,
        .progress_callback = printArpScanProgress,
    });
    defer {
        for (found_hosts.items) |host| {
            if (host.hostname) |name| {
                allocator.free(name);
            }
        }
        found_hosts.deinit(allocator);
    }

    const total_time = @divFloor(compat.milliTimestamp() - start_time, 1000);
    const avg_speed = if (total_time > 0) @divFloor(cidr_info.host_count, @as(usize, @intCast(total_time))) else 0;
    std.debug.print("\n⚡ 扫描完成！用时 {d} 秒，平均速度 {d} IP/s                  \n\n", .{ total_time, avg_speed });

    // 清除进度行
    std.debug.print("\n", .{});

    // 打印发现的主机
    if (found_hosts.items.len > 0) {
        std.debug.print("发现的主机:\n", .{});
        std.debug.print("{s:<16}  {s:<18}  {s}\n", .{ "IP 地址", "MAC 地址", "状态" });
        std.debug.print("{s}\n", .{"-" ** 60});

        for (found_hosts.items) |host| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = try ipToString(host.ip, &ip_buf);

            var mac_buf: [18]u8 = undefined;
            const mac_str = try macToString(host.mac, &mac_buf);

            if (host.hostname) |hostname_str| {
                std.debug.print("{s:<16}  {s:<18}  {s}\n", .{ ip_str, mac_str, hostname_str });
            } else {
                std.debug.print("{s:<16}  {s:<18}  [在线]\n", .{ ip_str, mac_str });
            }
        }
    }

    std.debug.print("\n📊 扫描完成: 发现 {d} 个活跃主机\n", .{found_hosts.items.len});
}

pub fn discoverRange(allocator: std.mem.Allocator, cidr: []const u8) !void {
    try discoverRangeWithPriority(allocator, cidr, null);
}

/// 网卡信息结构
const NetworkInterface = znet.NetworkInterface;

/// 获取本机所有网卡信息
fn getNetworkInterfaces(allocator: std.mem.Allocator) ![]NetworkInterface {
    return znet.getNetworkInterfaces(allocator);
}

fn freeNetworkInterfaces(allocator: std.mem.Allocator, interfaces: []const NetworkInterface) void {
    znet.freeNetworkInterfaces(allocator, interfaces);
}

fn getInterfacePriority(iface: NetworkInterface) u8 {
    return znet.getInterfacePriority(iface);
}

fn findPreferredInterface(interfaces: []const NetworkInterface, iface_filter: ?[]const u8) ?NetworkInterface {
    return znet.selectBestInterface(interfaces, iface_filter);
}

fn printAvailableInterfaces(interfaces: []const NetworkInterface) void {
    std.debug.print("可用网卡:\n", .{});
    for (interfaces) |iface| {
        std.debug.print("  • {s}  [{s}]\n", .{ iface.cidr, iface.name });
        std.debug.print("    描述: {s}\n", .{iface.description});
    }
}

pub fn discoverLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8) !void {
    std.debug.print("\n🔍 开始当前网卡所在子网扫描...\n", .{});
    std.debug.print("正在枚举网卡...\n\n", .{});

    const interfaces = try getNetworkInterfaces(allocator);
    defer freeNetworkInterfaces(allocator, interfaces);

    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    const selected = findPreferredInterface(interfaces, iface_filter) orelse {
        if (iface_filter) |filter| {
            std.debug.print("❌ 未找到匹配的网卡: {s}\n\n", .{filter});
        } else {
            std.debug.print("❌ 未找到可用于当前网卡所在子网扫描的网卡\n\n", .{});
        }
        printAvailableInterfaces(interfaces);
        return;
    };

    var ip_buf: [16]u8 = undefined;
    const ip_str = try ipToString(selected.ip, &ip_buf);
    std.debug.print("已选择网卡:\n", .{});
    std.debug.print("  名称: {s}\n", .{selected.name});
    std.debug.print("  描述: {s}\n", .{selected.description});
    std.debug.print("  本机 IP: {s}\n", .{ip_str});
    std.debug.print("  子网: {s}\n\n", .{selected.cidr});

    try discoverRangeWithPriority(allocator, selected.cidr, selected.ip);
}

pub fn scanLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8, port: u16) !void {
    std.debug.print("\n🔍 开始当前网卡所在子网端口扫描...\n", .{});
    std.debug.print("目标端口: {d}\n", .{port});
    std.debug.print("正在枚举网卡...\n\n", .{});

    const interfaces = try getNetworkInterfaces(allocator);
    defer freeNetworkInterfaces(allocator, interfaces);

    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    const selected = findPreferredInterface(interfaces, iface_filter) orelse {
        if (iface_filter) |filter| {
            std.debug.print("❌ 未找到匹配的网卡: {s}\n\n", .{filter});
        } else {
            std.debug.print("❌ 未找到可用于当前网卡所在子网扫描的网卡\n\n", .{});
        }
        printAvailableInterfaces(interfaces);
        return;
    };

    var ip_buf: [16]u8 = undefined;
    const ip_str = try ipToString(selected.ip, &ip_buf);
    std.debug.print("已选择网卡:\n", .{});
    std.debug.print("  名称: {s}\n", .{selected.name});
    std.debug.print("  描述: {s}\n", .{selected.description});
    std.debug.print("  本机 IP: {s}\n", .{ip_str});
    std.debug.print("  子网: {s}\n\n", .{selected.cidr});

    try scanRange(allocator, selected.cidr, port);
}

/// 扫描所有网卡所在子网
pub fn discoverLan(allocator: std.mem.Allocator) !void {
    std.debug.print("\n🔍 开始所有网卡所在子网扫描...\n", .{});
    std.debug.print("正在枚举网卡...\n\n", .{});

    const interfaces = try getNetworkInterfaces(allocator);
    defer freeNetworkInterfaces(allocator, interfaces);

    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    // 智能排序：优先扫描物理网卡对应的常见家庭/办公网络子网
    // 判断依据：
    // 1. 网卡名称关键词（is_virtual）- 最可靠
    // 2. IP 地址末位模式 - 辅助判断
    // 3. 子网掩码大小 - 虚拟网卡常用较大子网
    const InterfaceWithPriority = struct {
        iface: NetworkInterface,
        priority: u8,
    };

    var sorted_interfaces = try allocator.alloc(InterfaceWithPriority, interfaces.len);
    defer allocator.free(sorted_interfaces);

    for (interfaces, 0..) |iface, i| {
        sorted_interfaces[i] = .{ .iface = iface, .priority = getInterfacePriority(iface) };
    }

    // 按优先级排序（冒泡排序）
    for (0..sorted_interfaces.len) |i| {
        for (i + 1..sorted_interfaces.len) |j| {
            if (sorted_interfaces[i].priority > sorted_interfaces[j].priority) {
                const temp = sorted_interfaces[i];
                sorted_interfaces[i] = sorted_interfaces[j];
                sorted_interfaces[j] = temp;
            }
        }
    }

    std.debug.print("检测到 {d} 个网卡（已智能排序）:\n", .{interfaces.len});
    for (sorted_interfaces) |item| {
        const iface = item.iface;
        var ip_buf: [16]u8 = undefined;
        const ip_str = try ipToString(iface.ip, &ip_buf);

        // 生成更准确的标签
        const tag = if (iface.is_virtual)
            "⚙️  虚拟网卡"
        else blk: {
            const last_octet = @as(u8, @intCast(iface.ip & 0xFF));
            if (last_octet >= 10 and last_octet <= 253) {
                break :blk "🌟 物理网卡 - 常见局域网子网";
            } else if (last_octet == 1) {
                break :blk "🔧 物理网卡 - 可能是网关";
            } else {
                break :blk "📡 物理网卡";
            }
        };

        std.debug.print("  • {s} - {s}\n", .{ iface.cidr, tag });
        std.debug.print("    本机 IP: {s}, 优先级: {d}\n", .{ ip_str, item.priority });
    }

    std.debug.print("\n开始扫描...\n", .{});

    var total_found: usize = 0;

    for (sorted_interfaces, 0..) |item, idx| {
        const iface = item.iface;
        std.debug.print("\n[{d}/{d}] 扫描网段: {s}\n", .{ idx + 1, interfaces.len, iface.cidr });

        const cidr_info = try parseCidr(iface.cidr);

        // ARP 扫描速度估算
        const thread_count: usize = 64;
        const estimated_seconds = (cidr_info.host_count * 8) / 1000;
        std.debug.print("  主机数: {d}, 预估: ~{d}秒 (ARP)\n", .{ cidr_info.host_count, estimated_seconds });

        // 使用 ARP 并发扫描
        std.debug.print("🚀 使用 ARP 协议扫描（最快最准确的方法）\n\n", .{});
        const start_time = compat.milliTimestamp();
        var found_hosts = try znet.discoverHostsByArpConcurrent(allocator, cidr_info.base_ip, cidr_info.host_count, .{
            .thread_count = thread_count,
            .local_ip = iface.ip,
            .progress_interval_ms = 500,
            .progress_callback = printArpScanProgress,
        });
        defer {
            for (found_hosts.items) |host| {
                if (host.hostname) |name| {
                    allocator.free(name);
                }
            }
            found_hosts.deinit(allocator);
        }

        const total_time = @divFloor(compat.milliTimestamp() - start_time, 1000);
        const avg_speed = if (total_time > 0) @divFloor(cidr_info.host_count, @as(usize, @intCast(total_time))) else 0;
        std.debug.print("\n⚡ 扫描完成！用时 {d} 秒，平均速度 {d} IP/s                  \n\n", .{ total_time, avg_speed });

        std.debug.print("\n", .{});

        // 打印发现的主机
        if (found_hosts.items.len > 0) {
            for (found_hosts.items) |host| {
                var ip_buf: [16]u8 = undefined;
                const ip_str = try ipToString(host.ip, &ip_buf);

                var mac_buf: [18]u8 = undefined;
                const mac_str = try macToString(host.mac, &mac_buf);

                const hostname_str = host.hostname orelse "";
                if (hostname_str.len > 0) {
                    std.debug.print("  ✓ {s:<16}  [{s}]  ({s})\n", .{ ip_str, mac_str, hostname_str });
                } else {
                    std.debug.print("  ✓ {s:<16}  [{s}]\n", .{ ip_str, mac_str });
                }
            }
        }

        std.debug.print("  子网发现: {d} 个活跃主机\n", .{found_hosts.items.len});
        total_found += found_hosts.items.len;
    }

    std.debug.print("\n\n📊 所有网卡所在子网扫描完成: 总计发现 {d} 个活跃主机\n", .{total_found});
}

/// 扫描所有网卡所在子网的端口
pub fn scanLan(allocator: std.mem.Allocator, port: u16) !void {
    std.debug.print("\n🔍 开始所有网卡所在子网端口扫描...\n", .{});
    std.debug.print("目标端口: {d}\n", .{port});
    std.debug.print("正在枚举网卡...\n\n", .{});

    const interfaces = try getNetworkInterfaces(allocator);
    defer freeNetworkInterfaces(allocator, interfaces);

    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    std.debug.print("检测到 {d} 个网卡:\n", .{interfaces.len});
    for (interfaces) |iface| {
        std.debug.print("  • {s}\n", .{iface.cidr});
    }

    std.debug.print("\n开始扫描...\n", .{});

    var total_found: usize = 0;

    for (interfaces, 0..) |iface, idx| {
        std.debug.print("\n[{d}/{d}] 扫描网段: {s}\n", .{ idx + 1, interfaces.len, iface.cidr });

        const cidr_info = try parseCidr(iface.cidr);

        // 显示预估时间
        const estimated_seconds = (cidr_info.host_count * 200) / 1000;
        std.debug.print("  主机数: {d}, 预估: ~{d}秒\n", .{ cidr_info.host_count, estimated_seconds });

        var found_ips = try znet.scanOpenTcpHostsInRange(allocator, cidr_info.base_ip, cidr_info.host_count, port, .{
            .timeout_ms = 200,
            .progress_interval_hosts = 10,
            .progress_callback = printTcpPortScanProgress,
        });
        defer found_ips.deinit(allocator);

        for (found_ips.items) |ip| {
            std.debug.print("                                                    \r", .{});
            var ip_buf: [16]u8 = undefined;
            const ip_str = try ipToString(ip, &ip_buf);
            std.debug.print("  ✓ {s}  端口 {d} 开放\n", .{ ip_str, port });
        }

        std.debug.print("                                                    \r", .{});
        std.debug.print("  子网发现: {d} 个开放端口\n", .{found_ips.items.len});
        total_found += found_ips.items.len;
    }

    std.debug.print("\n\n📊 所有网卡所在子网端口扫描完成: 总计发现 {d} 个开放端口的主机\n", .{total_found});
}
