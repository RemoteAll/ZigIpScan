const std = @import("std");
const compat = @import("zzig").compat;

// Windows ARP API
const windows = if (@import("builtin").os.tag == .windows) struct {
    const DWORD = u32;
    const ULONG = u32;

    // iphlpapi.dll 中的 SendARP 函数
    pub extern "iphlpapi" fn SendARP(
        DestIP: DWORD,
        SrcIP: DWORD,
        pMacAddr: [*]u8,
        PhyAddrLen: *ULONG,
    ) DWORD;
} else struct {};

/// 判断是否为虚拟网卡（基于适配器名称关键词）
fn isVirtualAdapter(name: []const u8) bool {
    // 虚拟网卡常见关键词（不区分大小写）
    const virtual_keywords = [_][]const u8{
        "vEthernet", // Hyper-V 虚拟交换机
        "VirtualBox", // Oracle VirtualBox
        "VMware", // VMware 虚拟网卡
        "Virtual", // 通用虚拟标识
        "Loopback", // 回环适配器
        "Tunnel", // 隧道适配器
        "Teredo", // IPv6 Teredo 隧道
        "6to4", // IPv6 过渡
        "isatap", // ISATAP 隧道
        "WSL", // Windows Subsystem for Linux
        "vNIC", // 虚拟网卡缩写
        "TAP", // TAP 虚拟网卡
        "VPN", // VPN 适配器
    };

    // 转换为小写进行比较
    var name_lower_buf: [256]u8 = undefined;
    if (name.len > name_lower_buf.len) return false;

    const name_lower = std.ascii.lowerString(&name_lower_buf, name);

    for (virtual_keywords) |keyword| {
        var keyword_lower_buf: [64]u8 = undefined;
        const keyword_lower = std.ascii.lowerString(&keyword_lower_buf, keyword);

        if (std.mem.indexOf(u8, name_lower, keyword_lower) != null) {
            return true;
        }
    }

    return false;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (std.mem.indexOf(u8, haystack, needle) != null) return true;
    if (needle.len > haystack.len) return false;

    for (0..haystack.len - needle.len + 1) |start| {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
    }

    return false;
}

/// 计算子网掩码中 1 的位数
fn countMaskBits(mask: u32) u8 {
    var count: u8 = 0;
    var m = mask;
    while (m != 0) : (m <<= 1) {
        if ((m & 0x80000000) != 0) {
            count += 1;
        } else {
            break;
        }
    }
    return count;
}

/// CIDR 信息结构
const CidrInfo = struct {
    base_ip: u32, // 网络地址（主机字节序）
    host_count: u32, // 可用主机数量
    prefix_len: u8, // 前缀长度
};

/// 解析 IPv4 CIDR 格式（如 "192.168.1.0/24"）
fn parseCidr(cidr: []const u8) !CidrInfo {
    // 查找 '/' 分隔符
    const slash_pos = std.mem.indexOfScalar(u8, cidr, '/') orelse return error.InvalidCidr;

    const ip_str = cidr[0..slash_pos];
    const prefix_str = cidr[slash_pos + 1 ..];

    // 解析前缀长度
    const prefix_len = try std.fmt.parseUnsigned(u8, prefix_str, 10);
    if (prefix_len > 32) return error.InvalidPrefix;

    // 解析 IP 地址
    var octets: [4]u8 = undefined;
    var iter = std.mem.splitScalar(u8, ip_str, '.');
    var i: usize = 0;

    while (iter.next()) |octet_str| : (i += 1) {
        if (i >= 4) return error.InvalidIp;
        octets[i] = try std.fmt.parseUnsigned(u8, octet_str, 10);
    }

    if (i != 4) return error.InvalidIp;

    // 转换为 u32（大端序转主机序）
    const base_ip = (@as(u32, octets[0]) << 24) |
        (@as(u32, octets[1]) << 16) |
        (@as(u32, octets[2]) << 8) |
        @as(u32, octets[3]);

    // 计算网络地址和主机数量
    const host_bits: u5 = @intCast(32 - prefix_len);
    const mask: u32 = if (prefix_len == 0) 0 else ~@as(u32, 0) << host_bits;
    const network_addr = base_ip & mask;
    const host_count = if (prefix_len == 32) 1 else (@as(u32, 1) << host_bits) - 2; // 排除网络地址和广播地址

    return CidrInfo{
        .base_ip = network_addr,
        .host_count = host_count,
        .prefix_len = prefix_len,
    };
}

/// 主机信息结构
const HostInfo = struct {
    ip: u32,
    mac: [6]u8,
    hostname: ?[]const u8, // 可选的主机名
};

/// 将 u32 IP 转换为字符串（主机字节序）
fn ipToString(ip: u32, buf: []u8) ![]u8 {
    const a = @as(u8, @intCast((ip >> 24) & 0xFF));
    const b = @as(u8, @intCast((ip >> 16) & 0xFF));
    const c = @as(u8, @intCast((ip >> 8) & 0xFF));
    const d = @as(u8, @intCast(ip & 0xFF));

    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}", .{ a, b, c, d });
}

/// 格式化 MAC 地址为字符串
fn macToString(mac: [6]u8, buf: []u8) ![]u8 {
    return std.fmt.bufPrint(buf, "{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}:{X:0>2}", .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] });
}

/// 测试 TCP 端口连通性
fn testTcpPort(ip_str: []const u8, port: u16, timeout_ms: u32) bool {
    _ = timeout_ms;

    // 尝试连接
    const stream = compat.net.connectTcp(ip_str, port) catch return false;
    defer stream.close(compat.currentIo());

    return true;
}

/// 主机发现：通过常见端口探测主机是否在线
fn discoverHost(allocator: std.mem.Allocator, ip: u32) !bool {
    _ = allocator;

    var buf: [16]u8 = undefined;
    const ip_str = try ipToString(ip, &buf);

    // 尝试常见端口：80(HTTP), 443(HTTPS), 22(SSH) - 快速探测
    const common_ports = [_]u16{ 80, 443, 22 };

    for (common_ports) |port| {
        if (testTcpPort(ip_str, port, 200)) { // 200ms 超时，更快
            return true;
        }
    }

    return false;
}

/// 使用 ARP 检测主机并获取 MAC 地址
fn arpScan(ip: u32, mac_out: *[6]u8) bool {
    const builtin = @import("builtin");

    if (builtin.os.tag == .windows) {
        // Windows: 使用 SendARP API
        var mac_len: windows.ULONG = 6;

        // IP 需要转换为网络字节序
        const net_ip = @byteSwap(ip);

        const result = windows.SendARP(net_ip, 0, mac_out, &mac_len);

        // NO_ERROR = 0 表示成功
        return result == 0 and mac_len == 6;
    } else {
        // Linux/Unix: 使用 ping 作为后备（ARP 需要 root）
        // TODO: 实现 raw socket ARP 扫描
        return false;
    }
}

/// 尝试获取主机名（通过 DNS 反向查询）
/// 使用 ARP 发现主机（推荐方法，最快）
fn discoverHostByArp(_: std.mem.Allocator, ip: u32) !bool {
    var mac: [6]u8 = undefined;
    return arpScan(ip, &mac);
}

/// 并发 ARP 扫描任务上下文
const ArpScanTask = struct {
    allocator: std.mem.Allocator,
    scan_list: []const u32, // 要扫描的 IP 列表
    start_idx: usize, // 起始索引
    end_idx: usize, // 结束索引
    found_hosts: *std.ArrayList(HostInfo),
    mutex: *compat.Mutex,
    progress_counter: *usize,
    total_count: usize,
};

/// ARP 工作线程
fn arpWorker(task: *ArpScanTask) void {
    // 批量缓存结果，减少锁竞争
    var local_hosts: std.ArrayList(HostInfo) = .empty;
    defer local_hosts.deinit(task.allocator);

    var local_progress: usize = 0;
    const batch_size: usize = 2; // 每 2 个 IP 更新一次进度，提高实时性

    for (task.start_idx..task.end_idx) |idx| {
        const ip = task.scan_list[idx];
        local_progress += 1;

        var mac: [6]u8 = undefined;
        if (arpScan(ip, &mac)) {
            local_hosts.append(task.allocator, .{
                .ip = ip,
                .mac = mac,
                .hostname = null, // 禁用主机名解析以提升速度
            }) catch {};
        }

        // 批量更新进度和结果
        if (local_progress >= batch_size or idx == task.end_idx - 1) {
            task.mutex.lock();
            defer task.mutex.unlock();

            task.progress_counter.* += local_progress;
            local_progress = 0;

            // 批量添加发现的主机
            for (local_hosts.items) |host| {
                task.found_hosts.append(task.allocator, host) catch {};
            }
            local_hosts.clearRetainingCapacity();
        }
    }
}

/// 并发 ARP 扫描（带智能顺序优化）
fn discoverHostByArpConcurrent(allocator: std.mem.Allocator, base_ip: u32, host_count: u32, thread_count: usize) !std.ArrayList(HostInfo) {
    return discoverHostByArpConcurrentWithPriority(allocator, base_ip, host_count, thread_count, null);
}

/// 并发 ARP 扫描（可指定优先扫描的 IP）
fn discoverHostByArpConcurrentWithPriority(allocator: std.mem.Allocator, base_ip: u32, host_count: u32, thread_count: usize, local_ip: ?u32) !std.ArrayList(HostInfo) {
    var found_hosts: std.ArrayList(HostInfo) = .empty;
    var mutex = compat.Mutex{};
    var progress_counter: usize = 0;

    // 生成扫描顺序：优先本机 IP，然后是邻近 IP，最后是远端 IP
    var scan_order = try allocator.alloc(u32, host_count);
    defer allocator.free(scan_order);

    if (local_ip) |my_ip| {
        // 智能排序：本机 → 邻近 → 远端
        const my_offset = my_ip - base_ip - 1;
        var idx: usize = 0;

        // 1. 先扫描本机
        if (my_offset < host_count) {
            scan_order[idx] = base_ip + my_offset + 1;
            idx += 1;
        }

        // 2. 扫描本机附近的 IP（螺旋扫描）
        var radius: u32 = 1;
        while (radius <= host_count and idx < host_count) : (radius += 1) {
            // 向上
            if (my_offset >= radius) {
                const offset = my_offset - radius;
                if (offset < host_count and offset != my_offset) {
                    scan_order[idx] = base_ip + offset + 1;
                    idx += 1;
                }
            }
            // 向下
            if (my_offset + radius < host_count and idx < host_count) {
                const offset = my_offset + radius;
                if (offset != my_offset) {
                    scan_order[idx] = base_ip + offset + 1;
                    idx += 1;
                }
            }
        }

        // 3. 补充剩余的 IP
        for (0..host_count) |i| {
            const ip = base_ip + @as(u32, @intCast(i)) + 1;
            var already_added = false;
            for (scan_order[0..idx]) |added_ip| {
                if (added_ip == ip) {
                    already_added = true;
                    break;
                }
            }
            if (!already_added and idx < host_count) {
                scan_order[idx] = ip;
                idx += 1;
            }
        }
    } else {
        // 无优先级，按顺序扫描
        for (0..host_count) |i| {
            scan_order[i] = base_ip + @as(u32, @intCast(i)) + 1;
        }
    }

    const ips_per_thread = (host_count + thread_count - 1) / thread_count;

    var threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    var tasks = try allocator.alloc(ArpScanTask, thread_count);
    defer allocator.free(tasks);

    std.debug.print("🚀 使用 ARP 协议扫描（最快最准确的方法）\n\n", .{});

    // 启动工作线程 - 使用索引方式分配任务
    for (0..thread_count) |i| {
        const start_idx = i * ips_per_thread;
        const end_idx = @min(start_idx + ips_per_thread, host_count);

        tasks[i] = ArpScanTask{
            .allocator = allocator,
            .scan_list = scan_order,
            .start_idx = start_idx,
            .end_idx = end_idx,
            .found_hosts = &found_hosts,
            .mutex = &mutex,
            .progress_counter = &progress_counter,
            .total_count = host_count,
        };

        if (start_idx < end_idx) {
            threads[i] = try std.Thread.spawn(.{}, arpWorker, .{&tasks[i]});
        }
    }

    // 显示进度（降低更新频率减少开销）
    const start_time = compat.milliTimestamp();

    // 进度显示循环
    while (true) {
        compat.sleep(500 * std.time.ns_per_ms); // 500ms 更新一次，提高响应性

        const current_time = compat.milliTimestamp();

        mutex.lock();
        const current_progress = progress_counter;
        const current_found = found_hosts.items.len;
        const is_complete = current_progress >= host_count;
        mutex.unlock();

        if (is_complete) break; // 扫描完成，跳出循环

        const progress = @as(f64, @floatFromInt(current_progress)) / @as(f64, @floatFromInt(host_count)) * 100;

        // 计算总体平均速度（从开始到现在）- 更稳定可靠
        const elapsed_ms = current_time - start_time;
        const avg_speed = if (current_progress > 0 and elapsed_ms >= 500) blk: {
            const calculated = @divFloor(current_progress * 1000, @as(usize, @intCast(elapsed_ms)));
            // 至少显示 1 IP/s，避免因整数除法导致的 0
            break :blk if (calculated > 0) calculated else 1;
        } else if (current_progress > 0) // 0.5秒内显示估算值
            if (current_progress * 2 > 0) current_progress * 2 else 1
        else
            0;

        std.debug.print("\r  进度: {d:.1}% ({d}/{d}) 已发现: {d} 速度: ~{d}IP/s                    ", .{ progress, current_progress, host_count, current_found, avg_speed });
    }

    // 等待所有线程完成
    for (0..thread_count) |i| {
        const start_idx = i * ips_per_thread;
        const end_idx = @min(start_idx + ips_per_thread, host_count);
        if (start_idx < end_idx) {
            threads[i].join();
        }
    }

    const total_time = @divFloor(compat.milliTimestamp() - start_time, 1000);
    const avg_speed = if (total_time > 0) @divFloor(host_count, @as(usize, @intCast(total_time))) else 0;
    std.debug.print("\n⚡ 扫描完成！用时 {d} 秒，平均速度 {d} IP/s                  \n\n", .{ total_time, avg_speed });

    return found_hosts;
}

/// 使用 ICMP Ping 检测主机（更快更准确）
fn pingHost(allocator: std.mem.Allocator, ip_str: []const u8) bool {
    const builtin = @import("builtin");

    if (builtin.os.tag == .windows) {
        // Windows: ping -n 1 -w 200 <ip>
        const result = compat.process.run(allocator, .{
            .argv = &[_][]const u8{ "ping", "-n", "1", "-w", "200", ip_str },
        }) catch return false;
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        // 检查是否收到回复（TTL= 表示成功）
        return std.mem.indexOf(u8, result.stdout, "TTL=") != null or
            std.mem.indexOf(u8, result.stdout, "ttl=") != null;
    } else {
        // Linux/Unix: ping -c 1 -W 1 <ip>
        const result = compat.process.run(allocator, .{
            .argv = &[_][]const u8{ "ping", "-c", "1", "-W", "1", ip_str },
        }) catch return false;
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        return std.mem.indexOf(u8, result.stdout, "ttl=") != null or
            std.mem.indexOf(u8, result.stdout, "TTL=") != null;
    }
}

/// 使用 ICMP Ping 发现主机（推荐方法）
fn discoverHostByPing(allocator: std.mem.Allocator, ip: u32) !bool {
    var buf: [16]u8 = undefined;
    const ip_str = try ipToString(ip, &buf);
    return pingHost(allocator, ip_str);
}

/// 并发扫描任务上下文（使用 Ping）
const PingScanTask = struct {
    allocator: std.mem.Allocator,
    start_ip: u32,
    end_ip: u32,
    found_ips: *std.ArrayList(u32),
    mutex: *compat.Mutex,
    progress_counter: *usize,
    total_count: usize,
};

/// Ping 工作线程
fn pingWorker(task: *PingScanTask) void {
    var ip = task.start_ip;
    while (ip < task.end_ip) : (ip += 1) {
        // 更新进度
        {
            task.mutex.lock();
            defer task.mutex.unlock();
            task.progress_counter.* += 1;
        }

        if (discoverHostByPing(task.allocator, ip) catch false) {
            task.mutex.lock();
            defer task.mutex.unlock();
            task.found_ips.append(task.allocator, ip) catch {};
        }
    }
}

/// 并发 ICMP Ping 扫描
fn discoverHostByPingConcurrent(allocator: std.mem.Allocator, base_ip: u32, host_count: u32, thread_count: usize) !std.ArrayList(u32) {
    var found_ips: std.ArrayList(u32) = .empty;
    var mutex = compat.Mutex{};
    var progress_counter: usize = 0;

    const ips_per_thread = (host_count + thread_count - 1) / thread_count;

    var threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    var tasks = try allocator.alloc(PingScanTask, thread_count);
    defer allocator.free(tasks);

    // 启动工作线程
    for (0..thread_count) |i| {
        const start = base_ip + 1 + @as(u32, @intCast(i * ips_per_thread));
        const end = @min(start + @as(u32, @intCast(ips_per_thread)), base_ip + host_count + 1);

        tasks[i] = PingScanTask{
            .allocator = allocator,
            .start_ip = start,
            .end_ip = end,
            .found_ips = &found_ips,
            .mutex = &mutex,
            .progress_counter = &progress_counter,
            .total_count = host_count,
        };

        if (start < end) {
            threads[i] = try std.Thread.spawn(.{}, pingWorker, .{&tasks[i]});
        }
    }

    // 显示进度
    const start_time = compat.milliTimestamp();
    while (progress_counter < host_count) {
        compat.sleep(300 * std.time.ns_per_ms);

        mutex.lock();
        const current_progress = progress_counter;
        const current_found = found_ips.items.len;
        mutex.unlock();

        const progress = @as(f64, @floatFromInt(current_progress)) / @as(f64, @floatFromInt(host_count)) * 100;
        const elapsed = @divFloor(compat.milliTimestamp() - start_time, 1000);
        std.debug.print("  进度: {d:.1}% ({d}/{d}) 已发现: {d} 用时: {d}s        \r", .{ progress, current_progress, host_count, current_found, elapsed });
    }

    // 等待所有线程完成
    for (0..thread_count) |i| {
        const start = base_ip + 1 + @as(u32, @intCast(i * ips_per_thread));
        const end = @min(start + @as(u32, @intCast(ips_per_thread)), base_ip + host_count + 1);
        if (start < end) {
            threads[i].join();
        }
    }

    return found_ips;
}

/// 并发扫描任务上下文（TCP 端口，备用方案）
const ScanTask = struct {
    allocator: std.mem.Allocator,
    start_ip: u32,
    end_ip: u32,
    found_ips: *std.ArrayList(u32),
    mutex: *compat.Mutex,
    progress_counter: *usize,
    total_count: usize,
};

/// 工作线程函数
fn scanWorker(task: *ScanTask) void {
    var ip = task.start_ip;
    while (ip < task.end_ip) : (ip += 1) {
        // 更新进度计数器
        {
            task.mutex.lock();
            defer task.mutex.unlock();
            task.progress_counter.* += 1;
        }

        if (discoverHost(task.allocator, ip) catch false) {
            task.mutex.lock();
            defer task.mutex.unlock();
            task.found_ips.append(task.allocator, ip) catch {};
        }
    }
}

/// 并发主机发现
fn discoverHostConcurrent(allocator: std.mem.Allocator, base_ip: u32, host_count: u32, thread_count: usize) !std.ArrayList(u32) {
    var found_ips: std.ArrayList(u32) = .empty;
    var mutex = compat.Mutex{};
    var progress_counter: usize = 0;

    const ips_per_thread = (host_count + thread_count - 1) / thread_count;

    var threads = try allocator.alloc(std.Thread, thread_count);
    defer allocator.free(threads);

    var tasks = try allocator.alloc(ScanTask, thread_count);
    defer allocator.free(tasks);

    // 启动工作线程
    for (0..thread_count) |i| {
        const start = base_ip + 1 + @as(u32, @intCast(i * ips_per_thread));
        const end = @min(start + @as(u32, @intCast(ips_per_thread)), base_ip + host_count + 1);

        tasks[i] = ScanTask{
            .allocator = allocator,
            .start_ip = start,
            .end_ip = end,
            .found_ips = &found_ips,
            .mutex = &mutex,
            .progress_counter = &progress_counter,
            .total_count = host_count,
        };

        if (start < end) {
            threads[i] = try std.Thread.spawn(.{}, scanWorker, .{&tasks[i]});
        }
    }

    // 显示进度
    const start_time = compat.milliTimestamp();
    while (progress_counter < host_count) {
        compat.sleep(500 * std.time.ns_per_ms);

        mutex.lock();
        const current_progress = progress_counter;
        const current_found = found_ips.items.len;
        mutex.unlock();

        const progress = @as(f64, @floatFromInt(current_progress)) / @as(f64, @floatFromInt(host_count)) * 100;
        const elapsed = @divFloor(compat.milliTimestamp() - start_time, 1000);
        std.debug.print("  进度: {d:.1}% ({d}/{d}) 已发现: {d} 用时: {d}s        \r", .{ progress, current_progress, host_count, current_found, elapsed });
    }

    // 等待所有线程完成
    for (0..thread_count) |i| {
        const start = base_ip + 1 + @as(u32, @intCast(i * ips_per_thread));
        const end = @min(start + @as(u32, @intCast(ips_per_thread)), base_ip + host_count + 1);
        if (start < end) {
            threads[i].join();
        }
    }

    return found_ips;
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

    var found: usize = 0;
    var ip = cidr_info.base_ip + 1; // 跳过网络地址
    const end_ip = cidr_info.base_ip + cidr_info.host_count + 1;

    while (ip < end_ip) : (ip += 1) {
        var ip_buf: [16]u8 = undefined;
        const ip_str = try ipToString(ip, &ip_buf);

        if (testTcpPort(ip_str, port, 1000)) {
            found += 1;
            std.debug.print("✓ {s}  端口 {d} 开放\n", .{ ip_str, port });
        }

        // 每扫描 64 个 IP 显示进度
        if ((ip - cidr_info.base_ip) % 64 == 0) {
            const progress = @as(f64, @floatFromInt(ip - cidr_info.base_ip)) / @as(f64, @floatFromInt(cidr_info.host_count)) * 100;
            std.debug.print("  进度: {d:.1}%\r", .{progress});
        }
    }

    std.debug.print("\n\n📊 扫描完成: 发现 {d} 个开放端口的主机\n", .{found});
    _ = allocator;
}

pub fn discoverRange(allocator: std.mem.Allocator, cidr: []const u8) !void {
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

    // 使用 ARP 并发扫描
    var found_hosts = try discoverHostByArpConcurrent(allocator, cidr_info.base_ip, cidr_info.host_count, thread_count);
    defer {
        for (found_hosts.items) |host| {
            if (host.hostname) |name| {
                allocator.free(name);
            }
        }
        found_hosts.deinit(allocator);
    }

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

/// 网卡信息结构
const NetworkInterface = struct {
    name: []const u8, // 适配器名称
    description: []const u8, // 网卡描述（用于判断类型）
    ip: u32, // IP 地址
    cidr: []const u8, // CIDR 表示
    prefix_len: u8, // 子网前缀长度
    is_virtual: bool, // 是否为虚拟网卡
};

/// 获取本机所有网卡信息
fn getNetworkInterfaces(allocator: std.mem.Allocator) ![]NetworkInterface {
    var interfaces: std.ArrayList(NetworkInterface) = .empty;
    errdefer interfaces.deinit(allocator);

    const builtin = @import("builtin");

    if (builtin.os.tag == .windows) {
        // Windows: 使用 ipconfig /all 命令解析（获取描述信息）
        const result = try compat.process.run(allocator, .{
            .argv = &[_][]const u8{ "cmd", "/c", "chcp 65001 >nul && ipconfig /all" },
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        var lines = std.mem.splitScalar(u8, result.stdout, '\n');
        var current_name: ?[]const u8 = null;
        var current_description: ?[]const u8 = null;
        var current_ip: ?u32 = null;
        var current_mask: ?u32 = null;

        while (lines.next()) |line| {
            const trimmed = std.mem.trim(u8, line, " \r\n\t");

            // 跳过空行
            if (trimmed.len == 0) continue;

            // 匹配适配器名称（包含"适配器"或"adapter"且以冒号结尾）
            const has_adapter = std.mem.indexOf(u8, trimmed, "适配器") != null or std.mem.indexOf(u8, trimmed, "adapter") != null;
            const ends_with_colon = trimmed.len > 0 and trimmed[trimmed.len - 1] == ':';

            if (has_adapter and ends_with_colon) {
                // 释放之前的名称和描述
                if (current_name) |old_name| {
                    allocator.free(old_name);
                }
                if (current_description) |old_desc| {
                    allocator.free(old_desc);
                }
                current_name = try allocator.dupe(u8, trimmed);
                current_description = null; // 重置描述
                current_ip = null; // 重置 IP
                current_mask = null; // 重置子网掩码
            }

            // 匹配描述信息（用于判断虚拟网卡）
            if (std.mem.indexOf(u8, trimmed, "描述") != null or
                std.mem.indexOf(u8, trimmed, "Description") != null)
            {
                if (std.mem.indexOf(u8, trimmed, ":") != null) {
                    var parts = std.mem.splitScalar(u8, trimmed, ':');
                    _ = parts.next();
                    if (parts.next()) |desc_part| {
                        const desc_str = std.mem.trim(u8, desc_part, " \r\n\t");
                        if (desc_str.len > 0) {
                            if (current_description) |old_desc| {
                                allocator.free(old_desc);
                            }
                            current_description = try allocator.dupe(u8, desc_str);
                        }
                    }
                }
            }

            // 匹配 IPv4 地址（同时支持中英文）
            if (std.mem.indexOf(u8, trimmed, "IPv4") != null) {
                if (std.mem.indexOf(u8, trimmed, ":") != null) {
                    var parts = std.mem.splitScalar(u8, trimmed, ':');
                    _ = parts.next(); // 跳过标签
                    if (parts.next()) |ip_part| {
                        // 去除空格、括号、"(Preferred)" 等后缀
                        var ip_str = std.mem.trim(u8, ip_part, " \r\n\t");

                        // 查找括号，截取之前的部分
                        if (std.mem.indexOf(u8, ip_str, "(")) |paren_pos| {
                            ip_str = ip_str[0..paren_pos];
                        }

                        // 解析 IP
                        var octets: [4]u8 = undefined;
                        var iter = std.mem.splitScalar(u8, ip_str, '.');
                        var i: usize = 0;
                        var valid = true;

                        while (iter.next()) |octet_str| : (i += 1) {
                            if (i >= 4) {
                                valid = false;
                                break;
                            }
                            octets[i] = std.fmt.parseUnsigned(u8, octet_str, 10) catch {
                                valid = false;
                                break;
                            };
                        }

                        if (valid and i == 4) {
                            current_ip = (@as(u32, octets[0]) << 24) |
                                (@as(u32, octets[1]) << 16) |
                                (@as(u32, octets[2]) << 8) |
                                @as(u32, octets[3]);
                        }
                    }
                }
            }

            // 匹配子网掩码
            if (std.mem.indexOf(u8, trimmed, "子网掩码") != null or
                std.mem.indexOf(u8, trimmed, "Subnet Mask") != null)
            {
                if (std.mem.indexOf(u8, trimmed, ":") != null) {
                    var parts = std.mem.splitScalar(u8, trimmed, ':');
                    _ = parts.next();
                    if (parts.next()) |mask_part| {
                        const mask_str = std.mem.trim(u8, mask_part, " \r\n\t");

                        var octets: [4]u8 = undefined;
                        var iter = std.mem.splitScalar(u8, mask_str, '.');
                        var i: usize = 0;
                        var valid = true;

                        while (iter.next()) |octet_str| : (i += 1) {
                            if (i >= 4) {
                                valid = false;
                                break;
                            }
                            octets[i] = std.fmt.parseUnsigned(u8, octet_str, 10) catch {
                                valid = false;
                                break;
                            };
                        }

                        if (valid and i == 4) {
                            current_mask = (@as(u32, octets[0]) << 24) |
                                (@as(u32, octets[1]) << 16) |
                                (@as(u32, octets[2]) << 8) |
                                @as(u32, octets[3]);

                            // 当收集到 IP 和掩码后，保存网卡信息
                            if (current_name != null and current_ip != null and current_mask != null) {
                                const ip = current_ip.?;
                                const mask = current_mask.?;

                                // 提取 IP 的各个字节
                                const ip_octets = [4]u8{
                                    @intCast((ip >> 24) & 0xFF),
                                    @intCast((ip >> 16) & 0xFF),
                                    @intCast((ip >> 8) & 0xFF),
                                    @intCast(ip & 0xFF),
                                };

                                // 忽略 127.x.x.x 和 169.254.x.x (APIPA)
                                if (ip_octets[0] != 127 and !(ip_octets[0] == 169 and ip_octets[1] == 254)) {
                                    // 计算网络地址和前缀长度
                                    const network_ip = ip & mask;
                                    const prefix_len = countMaskBits(mask);

                                    const network_octets = [4]u8{
                                        @intCast((network_ip >> 24) & 0xFF),
                                        @intCast((network_ip >> 16) & 0xFF),
                                        @intCast((network_ip >> 8) & 0xFF),
                                        @intCast(network_ip & 0xFF),
                                    };

                                    var cidr_buf: [20]u8 = undefined;
                                    const cidr = try std.fmt.bufPrint(&cidr_buf, "{d}.{d}.{d}.{d}/{d}", .{ network_octets[0], network_octets[1], network_octets[2], network_octets[3], prefix_len });

                                    // 判断是否为虚拟网卡（优先使用描述，其次使用名称）
                                    const check_str = if (current_description) |desc| desc else current_name.?;
                                    const is_virtual = isVirtualAdapter(check_str);

                                    // 保存到列表
                                    const saved_description = if (current_description) |desc|
                                        try allocator.dupe(u8, desc)
                                    else
                                        try allocator.dupe(u8, current_name.?);

                                    try interfaces.append(allocator, .{
                                        .name = try allocator.dupe(u8, current_name.?),
                                        .description = saved_description,
                                        .ip = ip,
                                        .cidr = try allocator.dupe(u8, cidr),
                                        .prefix_len = prefix_len,
                                        .is_virtual = is_virtual,
                                    });

                                    // 释放临时保存的适配器名称和描述
                                    allocator.free(current_name.?);
                                    if (current_description) |desc| {
                                        allocator.free(desc);
                                    }
                                    current_name = null;
                                    current_description = null;
                                    current_ip = null;
                                    current_mask = null;
                                }
                            }
                        }
                    }
                }
            }
        }

        // 清理未使用的 current_name 和 current_description
        if (current_name) |name| {
            allocator.free(name);
        }
        if (current_description) |desc| {
            allocator.free(desc);
        }
    } else {
        // Unix/Linux: 使用 ip addr 或 ifconfig
        const result = compat.process.run(allocator, .{
            .argv = &[_][]const u8{ "ip", "addr" },
        }) catch |err| {
            // 尝试 ifconfig
            if (err == error.FileNotFound) {
                const ifconfig_result = try compat.process.run(allocator, .{
                    .argv = &[_][]const u8{"ifconfig"},
                });
                defer allocator.free(ifconfig_result.stdout);
                defer allocator.free(ifconfig_result.stderr);
                // 这里可以解析 ifconfig 输出，暂时返回空
                return try interfaces.toOwnedSlice(allocator);
            }
            return err;
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        // 简单解析 ip addr 输出
        // 格式示例: inet 192.168.1.100/24
        var lines = std.mem.splitScalar(u8, result.stdout, '\n');

        while (lines.next()) |line| {
            if (std.mem.indexOf(u8, line, "inet ") != null) {
                var parts = std.mem.splitScalar(u8, line, ' ');
                var found_inet = false;

                while (parts.next()) |part| {
                    if (found_inet and part.len > 0) {
                        // 找到 IP/prefix
                        if (std.mem.indexOf(u8, part, ".") != null and std.mem.indexOf(u8, part, "/") != null) {
                            const cidr_str = std.mem.trim(u8, part, " \r\n\t");

                            // 解析 IP
                            const slash_pos = std.mem.indexOfScalar(u8, cidr_str, '/') orelse continue;
                            const ip_str = cidr_str[0..slash_pos];

                            var octets: [4]u8 = undefined;
                            var iter = std.mem.splitScalar(u8, ip_str, '.');
                            var i: usize = 0;
                            var valid = true;

                            while (iter.next()) |octet_str| : (i += 1) {
                                if (i >= 4) {
                                    valid = false;
                                    break;
                                }
                                octets[i] = std.fmt.parseUnsigned(u8, octet_str, 10) catch {
                                    valid = false;
                                    break;
                                };
                            }

                            if (valid and i == 4 and octets[0] != 127) {
                                const ip = (@as(u32, octets[0]) << 24) |
                                    (@as(u32, octets[1]) << 16) |
                                    (@as(u32, octets[2]) << 8) |
                                    @as(u32, octets[3]);

                                // 简单假设 /24 子网
                                const prefix_len: u8 = 24;

                                try interfaces.append(allocator, .{
                                    .name = try allocator.dupe(u8, "eth"),
                                    .description = try allocator.dupe(u8, "Linux Network Interface"),
                                    .ip = ip,
                                    .cidr = try allocator.dupe(u8, cidr_str),
                                    .prefix_len = prefix_len,
                                    .is_virtual = false, // Linux 暂时默认为物理网卡
                                });
                            }
                        }
                        break;
                    }

                    if (std.mem.eql(u8, part, "inet")) {
                        found_inet = true;
                    }
                }
            }
        }
    }

    return try interfaces.toOwnedSlice(allocator);
}

fn freeNetworkInterfaces(allocator: std.mem.Allocator, interfaces: []const NetworkInterface) void {
    for (interfaces) |iface| {
        allocator.free(iface.name);
        allocator.free(iface.description);
        allocator.free(iface.cidr);
    }
    allocator.free(interfaces);
}

fn getInterfacePriority(iface: NetworkInterface) u8 {
    const last_octet = @as(u8, @intCast(iface.ip & 0xFF));
    var priority: u8 = if (iface.is_virtual) 200 else 100;

    if (!iface.is_virtual) {
        if (last_octet >= 10 and last_octet <= 253)
            priority = 0
        else if (last_octet >= 2 and last_octet <= 9)
            priority = 30
        else if (last_octet == 1 or last_octet == 254)
            priority = 50;
    }

    if (iface.prefix_len < 20 and priority <= 245) priority += 10;
    return priority;
}

fn matchesInterfaceFilter(iface: NetworkInterface, iface_filter: []const u8) bool {
    return containsIgnoreCase(iface.name, iface_filter) or
        containsIgnoreCase(iface.description, iface_filter) or
        containsIgnoreCase(iface.cidr, iface_filter);
}

fn findPreferredInterface(interfaces: []const NetworkInterface, iface_filter: ?[]const u8) ?NetworkInterface {
    var best: ?NetworkInterface = null;
    var best_priority: u8 = std.math.maxInt(u8);

    for (interfaces) |iface| {
        if (iface_filter) |filter| {
            if (filter.len > 0 and !matchesInterfaceFilter(iface, filter)) continue;
        }

        const priority = getInterfacePriority(iface);
        if (best == null or priority < best_priority) {
            best = iface;
            best_priority = priority;
        }
    }

    return best;
}

fn printAvailableInterfaces(interfaces: []const NetworkInterface) void {
    std.debug.print("可用网卡:\n", .{});
    for (interfaces) |iface| {
        std.debug.print("  • {s}  [{s}]\n", .{ iface.cidr, iface.name });
        std.debug.print("    描述: {s}\n", .{iface.description});
    }
}

pub fn discoverLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8) !void {
    std.debug.print("\n🔍 开始本机子网扫描...\n", .{});
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
            std.debug.print("❌ 未找到可用于本机子网扫描的网卡\n\n", .{});
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

    try discoverRange(allocator, selected.cidr);
}

pub fn scanLocal(allocator: std.mem.Allocator, iface_filter: ?[]const u8, port: u16) !void {
    std.debug.print("\n🔍 开始本机子网端口扫描...\n", .{});
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
            std.debug.print("❌ 未找到可用于本机子网扫描的网卡\n\n", .{});
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

/// 扫描局域网（所有网卡的子网）
pub fn discoverLan(allocator: std.mem.Allocator) !void {
    std.debug.print("\n🔍 开始局域网扫描...\n", .{});
    std.debug.print("正在枚举网卡...\n\n", .{});

    const interfaces = try getNetworkInterfaces(allocator);
    defer freeNetworkInterfaces(allocator, interfaces);

    if (interfaces.len == 0) {
        std.debug.print("❌ 未检测到有效网卡\n", .{});
        return;
    }

    // 智能排序：优先扫描物理网卡的真实局域网
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
                break :blk "🌟 物理网卡 - 真实局域网";
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
        var found_hosts = try discoverHostByArpConcurrent(allocator, cidr_info.base_ip, cidr_info.host_count, thread_count);
        defer {
            for (found_hosts.items) |host| {
                if (host.hostname) |name| {
                    allocator.free(name);
                }
            }
            found_hosts.deinit(allocator);
        }

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

    std.debug.print("\n\n📊 局域网扫描完成: 总计发现 {d} 个活跃主机\n", .{total_found});
}

/// 扫描局域网端口
pub fn scanLan(allocator: std.mem.Allocator, port: u16) !void {
    std.debug.print("\n🔍 开始局域网端口扫描...\n", .{});
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

        var found: usize = 0;
        var ip = cidr_info.base_ip + 1;
        const end_ip = cidr_info.base_ip + cidr_info.host_count + 1;

        while (ip < end_ip) : (ip += 1) {
            // 显示进度
            const scanned = ip - cidr_info.base_ip - 1;
            if (scanned > 0 and scanned % 10 == 0) {
                const progress = @as(f64, @floatFromInt(scanned)) / @as(f64, @floatFromInt(cidr_info.host_count)) * 100;
                std.debug.print("  进度: {d:.1}% ({d}/{d}) 已发现: {d}        \r", .{ progress, scanned, cidr_info.host_count, found });
            }

            var ip_buf: [16]u8 = undefined;
            const ip_str = try ipToString(ip, &ip_buf);

            if (testTcpPort(ip_str, port, 200)) {
                found += 1;
                // 清除进度行
                std.debug.print("                                                    \r", .{});
                std.debug.print("  ✓ {s}  端口 {d} 开放\n", .{ ip_str, port });
            }
        }

        std.debug.print("                                                    \r", .{});
        std.debug.print("  子网发现: {d} 个开放端口\n", .{found});
        total_found += found;
    }

    std.debug.print("\n\n📊 局域网扫描完成: 总计发现 {d} 个开放端口的主机\n", .{total_found});
}
