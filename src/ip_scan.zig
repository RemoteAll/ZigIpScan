const std = @import("std");
const zzig = @import("zzig");
const compat = zzig.compat;
const znet = zzig.Net;

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

fn scanSubnetPorts(allocator: std.mem.Allocator, cidr_info: znet.CidrInfo, port: u16, timeout_ms: u32, progress_interval_hosts: usize, summary_label: []const u8) !usize {
    var found_ips = try znet.scanOpenTcpHostsInRange(allocator, cidr_info.base_ip, cidr_info.host_count, port, .{
        .timeout_ms = timeout_ms,
        .progress_interval_hosts = progress_interval_hosts,
        .progress_callback = printTcpPortScanProgress,
    });
    defer found_ips.deinit(allocator);

    for (found_ips.items) |ip| {
        std.debug.print("                                                    \r", .{});
        var ip_buf: [16]u8 = undefined;
        const ip_str = try znet.ipToString(ip, &ip_buf);
        std.debug.print("  ✓ {s}  端口 {d} 开放\n", .{ ip_str, port });
    }

    std.debug.print("                                                    \r", .{});
    if (summary_label.len > 0) std.debug.print("{s}{d} 个开放端口\n", .{ summary_label, found_ips.items.len });
    return found_ips.items.len;
}

fn discoverSubnetByArp(allocator: std.mem.Allocator, cidr_info: znet.CidrInfo, local_ip: ?u32, print_table: bool) !usize {
    const thread_count: usize = 64;
    std.debug.print("🚀 使用 ARP 协议扫描（最快最准确的方法）\n\n", .{});

    const start_time = compat.milliTimestamp();
    var found_hosts = try znet.discoverHostsByArpConcurrent(allocator, cidr_info.base_ip, cidr_info.host_count, .{
        .thread_count = thread_count,
        .local_ip = local_ip,
        .progress_interval_ms = 500,
        .progress_callback = printArpScanProgress,
    });
    defer znet.freeHostInfos(allocator, &found_hosts);

    const total_time = @divFloor(compat.milliTimestamp() - start_time, 1000);
    const avg_speed = if (total_time > 0) @divFloor(cidr_info.host_count, @as(usize, @intCast(total_time))) else 0;
    std.debug.print("\n⚡ 扫描完成！用时 {d} 秒，平均速度 {d} IP/s                  \n\n", .{ total_time, avg_speed });
    std.debug.print("\n", .{});

    if (found_hosts.items.len > 0) {
        if (print_table) {
            std.debug.print("发现的主机:\n", .{});
            std.debug.print("{s:<16}  {s:<18}  {s}\n", .{ "IP 地址", "MAC 地址", "状态" });
            std.debug.print("{s}\n", .{"-" ** 60});
        }

        for (found_hosts.items) |host| {
            var ip_buf: [16]u8 = undefined;
            const ip_str = try znet.ipToString(host.ip, &ip_buf);

            var mac_buf: [18]u8 = undefined;
            const mac_str = try znet.macToString(host.mac, &mac_buf);

            if (print_table) {
                if (host.hostname) |hostname_str| {
                    std.debug.print("{s:<16}  {s:<18}  {s}\n", .{ ip_str, mac_str, hostname_str });
                } else {
                    std.debug.print("{s:<16}  {s:<18}  [在线]\n", .{ ip_str, mac_str });
                }
            } else {
                const hostname_str = host.hostname orelse "";
                if (hostname_str.len > 0) {
                    std.debug.print("  ✓ {s:<16}  [{s}]  ({s})\n", .{ ip_str, mac_str, hostname_str });
                } else {
                    std.debug.print("  ✓ {s:<16}  [{s}]\n", .{ ip_str, mac_str });
                }
            }
        }
    }

    return found_hosts.items.len;
}

pub fn scanRange(allocator: std.mem.Allocator, cidr: []const u8, port: u16) !void {
    std.debug.print("\n🔍 开始端口扫描...\n", .{});
    std.debug.print("目标: {s}  端口: {d}\n\n", .{ cidr, port });

    const cidr_info = try znet.parseCidr(cidr);

    std.debug.print("网段信息:\n", .{});
    var buf: [16]u8 = undefined;
    const base_str = try znet.ipToString(cidr_info.base_ip, &buf);
    std.debug.print("  网络地址: {s}/{d}\n", .{ base_str, cidr_info.prefix_len });
    std.debug.print("  可扫描主机数: {d}\n\n", .{cidr_info.host_count});

    if (cidr_info.host_count > 1024) {
        std.debug.print("⚠️  网段较大，扫描可能需要较长时间\n\n", .{});
    }

    const found_count = try scanSubnetPorts(allocator, cidr_info, port, 1000, 64, "");
    std.debug.print("\n\n📊 扫描完成: 发现 {d} 个开放端口的主机\n", .{found_count});
}

fn discoverRangeWithPriority(allocator: std.mem.Allocator, cidr: []const u8, local_ip: ?u32) !void {
    std.debug.print("\n🔍 开始主机发现...\n", .{});
    std.debug.print("目标: {s}\n\n", .{cidr});

    const cidr_info = try znet.parseCidr(cidr);

    std.debug.print("网段信息:\n", .{});
    var buf: [16]u8 = undefined;
    const base_str = try znet.ipToString(cidr_info.base_ip, &buf);
    std.debug.print("  网络地址: {s}/{d}\n", .{ base_str, cidr_info.prefix_len });
    std.debug.print("  可扫描主机数: {d}\n", .{cidr_info.host_count});

    // ARP 扫描速度估算（非常快，每个 IP 约 5-10ms）
    const estimated_seconds = (cidr_info.host_count * 8) / 1000; // 优化后约8ms/IP
    std.debug.print("  预估时间(ARP): ~{d} 秒 (使用 64 线程)\n\n", .{estimated_seconds});

    if (cidr_info.host_count > 1024) {
        std.debug.print("⚠️  网段较大，扫描可能需要较长时间\n\n", .{});
    }

    const found_count = try discoverSubnetByArp(allocator, cidr_info, local_ip, true);
    std.debug.print("\n📊 扫描完成: 发现 {d} 个活跃主机\n", .{found_count});
}

pub fn discoverRange(allocator: std.mem.Allocator, cidr: []const u8) !void {
    try discoverRangeWithPriority(allocator, cidr, null);
}

/// 网卡信息结构
const NetworkInterface = znet.NetworkInterface;
const RankedNetworkInterface = znet.RankedNetworkInterface;
const InterfaceSelectionResult = znet.InterfaceSelectionResult;
const RankedInterfacesResult = znet.RankedInterfacesResult;
const ScanMode = enum {
    discover,
    scan,
};

fn printAvailableInterfaces(interfaces: []const NetworkInterface) void {
    std.debug.print("可用网卡:\n", .{});
    for (interfaces) |iface| {
        std.debug.print("  • {s}  [{s}]\n", .{ iface.cidr, iface.name });
        std.debug.print("    描述: {s}\n", .{iface.description});
    }
}

fn printInterfaceSelectionFailure(interfaces: []const NetworkInterface, iface_filter: ?[]const u8) void {
    if (iface_filter) |filter| {
        std.debug.print("❌ 未找到匹配的网卡: {s}\n\n", .{filter});
    } else {
        std.debug.print("❌ 未找到可用于当前网卡所在子网扫描的网卡\n\n", .{});
    }
    printAvailableInterfaces(interfaces);
}

fn printSelectedInterface(selected: NetworkInterface) !void {
    var ip_buf: [16]u8 = undefined;
    const ip_str = try znet.ipToString(selected.ip, &ip_buf);
    std.debug.print("已选择网卡:\n", .{});
    std.debug.print("  名称: {s}\n", .{selected.name});
    std.debug.print("  描述: {s}\n", .{selected.description});
    std.debug.print("  本机 IP: {s}\n", .{ip_str});
    std.debug.print("  子网: {s}\n\n", .{selected.cidr});
}

fn printRankedInterfaces(sorted_interfaces: []const RankedNetworkInterface, verbose: bool) !void {
    std.debug.print("检测到 {d} 个网卡（已智能排序）:\n", .{sorted_interfaces.len});
    for (sorted_interfaces) |item| {
        const iface = item.iface;
        if (!verbose) {
            std.debug.print("  • {s}\n", .{iface.cidr});
            continue;
        }

        var ip_buf: [16]u8 = undefined;
        const ip_str = try znet.ipToString(iface.ip, &ip_buf);
        std.debug.print("  • {s} - {s}\n", .{ iface.cidr, znet.getInterfaceTag(iface) });
        std.debug.print("    本机 IP: {s}, 优先级: {d}\n", .{ ip_str, item.priority });
    }
}

pub fn discoverLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8) !void {
    try runLocalScan(allocator, iface_filter, .discover, 0);
}

pub fn scanLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8, port: u16) !void {
    try runLocalScan(allocator, iface_filter, .scan, port);
}

fn runLocalScan(allocator: std.mem.Allocator, iface_filter: ?[]const u8, mode: ScanMode, port: u16) !void {
    switch (mode) {
        .discover => std.debug.print("\n🔍 开始当前网卡所在子网扫描...\n", .{}),
        .scan => {
            std.debug.print("\n🔍 开始当前网卡所在子网端口扫描...\n", .{});
            std.debug.print("目标端口: {d}\n", .{port});
        },
    }
    std.debug.print("正在枚举网卡...\n\n", .{});

    const selection: InterfaceSelectionResult = try znet.selectSystemInterface(allocator, iface_filter);
    defer selection.deinit(allocator);

    const interfaces = selection.interfaces;
    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    const selected = selection.selected orelse {
        printInterfaceSelectionFailure(interfaces, iface_filter);
        return;
    };

    try printSelectedInterface(selected);

    switch (mode) {
        .discover => try discoverRangeWithPriority(allocator, selected.cidr, selected.ip),
        .scan => try scanRange(allocator, selected.cidr, port),
    }
}

/// 扫描所有网卡所在子网
pub fn discoverLan(allocator: std.mem.Allocator) !void {
    try runLanScan(allocator, .discover, 0);
}

/// 扫描所有网卡所在子网的端口
pub fn scanLan(allocator: std.mem.Allocator, port: u16) !void {
    try runLanScan(allocator, .scan, port);
}

fn runLanScan(allocator: std.mem.Allocator, mode: ScanMode, port: u16) !void {
    switch (mode) {
        .discover => std.debug.print("\n🔍 开始所有网卡所在子网扫描...\n", .{}),
        .scan => {
            std.debug.print("\n🔍 开始所有网卡所在子网端口扫描...\n", .{});
            std.debug.print("目标端口: {d}\n", .{port});
        },
    }
    std.debug.print("正在枚举网卡...\n\n", .{});

    const ranked_result: RankedInterfacesResult = try znet.getRankedSystemInterfaces(allocator);
    defer ranked_result.deinit(allocator);

    const interfaces = ranked_result.interfaces;
    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    const sorted_interfaces: []const RankedNetworkInterface = ranked_result.ranked;
    try printRankedInterfaces(sorted_interfaces, true);

    std.debug.print("\n开始扫描...\n", .{});

    var total_found: usize = 0;
    for (sorted_interfaces, 0..) |item, idx| {
        const iface = item.iface;
        std.debug.print("\n[{d}/{d}] 扫描网段: {s}\n", .{ idx + 1, interfaces.len, iface.cidr });

        const cidr_info = try znet.parseCidr(iface.cidr);

        switch (mode) {
            .discover => {
                const estimated_seconds = (cidr_info.host_count * 8) / 1000;
                std.debug.print("  主机数: {d}, 预估: ~{d}秒 (ARP)\n", .{ cidr_info.host_count, estimated_seconds });
                const found_count = try discoverSubnetByArp(allocator, cidr_info, iface.ip, false);
                std.debug.print("  子网发现: {d} 个活跃主机\n", .{found_count});
                total_found += found_count;
            },
            .scan => {
                const estimated_seconds = (cidr_info.host_count * 200) / 1000;
                std.debug.print("  主机数: {d}, 预估: ~{d}秒\n", .{ cidr_info.host_count, estimated_seconds });

                const found_count = try scanSubnetPorts(allocator, cidr_info, port, 200, 10, "  子网发现: ");
                total_found += found_count;
            },
        }
    }

    switch (mode) {
        .discover => std.debug.print("\n\n📊 所有网卡所在子网扫描完成: 总计发现 {d} 个活跃主机\n", .{total_found}),
        .scan => std.debug.print("\n\n📊 所有网卡所在子网端口扫描完成: 总计发现 {d} 个开放端口的主机\n", .{total_found}),
    }
}
