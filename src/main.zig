const std = @import("std");
const Scan = @import("ip_scan.zig");
const zzig = @import("zzig");

fn printUsage() void {
    std.log.info(
        "zig-ip-scan\n" ++
            "使用方式:\n" ++
            "  1) 交互式菜单: zig build run (无参数，按提示选择)\n" ++
            "  2) 命令行参数: zig build run -- --mode <模式> [选项]\n" ++
            "参数说明:\n" ++
            "  --mode local|cidr|lan\n" ++
            "  --action discover|scan (默认 discover)\n" ++
            "  --cidr <网段>  --port <端口>  --iface <网卡名>\n" ++
            "示例:\n  zig build run -- --mode cidr --cidr 192.168.1.0/24\n",
        .{},
    );
}

/// 简单的交互式读取行输入
/// 适用于 Zig 0.15.2
fn readLineSimple(allocator: std.mem.Allocator) ![]u8 {
    const builtin = @import("builtin");

    var buffer: [4096]u8 = undefined;
    const bytes_read = if (builtin.os.tag == .windows) blk: {
        const w = std.os.windows;
        const stdin_handle = w.kernel32.GetStdHandle(w.STD_INPUT_HANDLE) orelse return error.InvalidHandle;
        if (stdin_handle == w.INVALID_HANDLE_VALUE) return error.InvalidHandle;

        var bytes: w.DWORD = 0;
        if (w.kernel32.ReadFile(stdin_handle, &buffer, buffer.len, &bytes, null) == 0) {
            return error.ReadFailed;
        }
        break :blk @as(usize, bytes);
    } else blk: {
        break :blk try std.posix.read(std.posix.STDIN_FILENO, &buffer);
    };

    if (bytes_read == 0) return error.EndOfStream;

    // 去除换行符
    const line = buffer[0..bytes_read];
    const trimmed = std.mem.trimRight(u8, line, &[_]u8{ '\r', '\n' });
    return try allocator.dupe(u8, trimmed);
}

fn runInteractiveMenu(allocator: std.mem.Allocator) !void {
    // 初始化控制台支持中文和颜色
    _ = zzig.Console.init(.{});

    std.debug.print("\n=== Zig IP Scan 交互式菜单 ===\n", .{});

    // 第一步: 选择操作类型
    std.debug.print("\n请选择操作:\n", .{});
    std.debug.print("  1) 主机发现 (discover) - 扫描活跃主机\n", .{});
    std.debug.print("  2) 端口扫描 (scan) - 检测端口开放情况\n", .{});
    std.debug.print("输入序号 (默认 1): ", .{});

    const action_input = readLineSimple(allocator) catch "";
    defer if (action_input.len > 0) allocator.free(action_input);

    const action = if (std.mem.eql(u8, action_input, "2")) "scan" else "discover";

    // 第二步: 选择扫描模式
    std.debug.print("\n请选择扫描范围:\n", .{});
    std.debug.print("  1) 本机子网 (local) - 自动检测网卡\n", .{});
    std.debug.print("  2) 指定网段 (cidr) - 手动输入 CIDR\n", .{});
    std.debug.print("  3) 局域网 (lan) - 所有网卡的子网\n", .{});
    std.debug.print("输入序号: ", .{});

    const mode_input = readLineSimple(allocator) catch |err| {
        std.log.err("读取输入失败: {}", .{err});
        return;
    };
    defer allocator.free(mode_input);

    const mode = if (std.mem.eql(u8, mode_input, "1"))
        "local"
    else if (std.mem.eql(u8, mode_input, "2"))
        "cidr"
    else if (std.mem.eql(u8, mode_input, "3"))
        "lan"
    else {
        std.log.err("无效选择: {s}", .{mode_input});
        return;
    };

    // 第三步: 根据模式获取额外参数
    var cidr_buf: []u8 = &[_]u8{};
    var port: u16 = 80;

    if (std.mem.eql(u8, mode, "cidr")) {
        std.debug.print("\n请输入 CIDR (如 192.168.1.0/24 或 2001:db8::/120): ", .{});
        cidr_buf = try readLineSimple(allocator);
        if (cidr_buf.len == 0) {
            std.log.err("CIDR 不能为空", .{});
            return;
        }
    } else if (std.mem.eql(u8, mode, "local")) {
        // 本机子网模式:自动检测网卡,无需用户输入
        std.debug.print("\n正在自动检测本机网卡...\n", .{});
        // 稍后实现网卡检测逻辑
    }

    // 第四步: 如果是端口扫描,获取端口号
    if (std.mem.eql(u8, action, "scan")) {
        std.debug.print("\n请输入端口 (默认 80): ", .{});
        const port_input = readLineSimple(allocator) catch "";
        defer if (port_input.len > 0) allocator.free(port_input);
        if (port_input.len > 0) {
            port = std.fmt.parseUnsigned(u16, port_input, 10) catch 80;
        }
    }

    std.debug.print("\n开始执行...\n", .{});

    // 执行逻辑
    if (std.mem.eql(u8, mode, "cidr")) {
        defer allocator.free(cidr_buf);
        if (std.mem.eql(u8, action, "discover")) {
            try Scan.discoverRange(allocator, cidr_buf);
        } else {
            try Scan.scanRange(allocator, cidr_buf, port);
        }
    } else if (std.mem.eql(u8, mode, "local")) {
        if (std.mem.eql(u8, action, "discover")) {
            std.log.info("主机发现 本机子网", .{});
            std.debug.print("\n🚧 [开发中] 将实现:\n", .{});
            std.debug.print("  - 自动检测本机活跃网卡\n", .{});
            std.debug.print("  - 获取网卡 IP 和子网掩码\n", .{});
            std.debug.print("  - 计算 CIDR 网段\n", .{});
            std.debug.print("  - 扫描同子网的活跃主机\n", .{});
        } else {
            std.log.info("端口扫描 本机子网, port={d}", .{port});
            std.debug.print("\n🚧 [开发中] 将实现:\n", .{});
            std.debug.print("  - 自动检测本机活跃网卡\n", .{});
            std.debug.print("  - 扫描同子网的端口 {} 开放情况\n", .{port});
        }
    } else if (std.mem.eql(u8, mode, "lan")) {
        if (std.mem.eql(u8, action, "discover")) {
            try Scan.discoverLan(allocator);
        } else {
            try Scan.scanLan(allocator, port);
        }
    }
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1) {
        // 无参数时进入交互式菜单
        try runInteractiveMenu(allocator);
        return;
    }

    if (args.len >= 2 and std.mem.eql(u8, args[1], "--help")) {
        printUsage();
        return;
    }

    var mode: []const u8 = "";
    var action: []const u8 = "discover"; // 默认进行主机发现而非端口扫描
    var cidr: []const u8 = "";
    var iface: []const u8 = "";
    var port: u16 = 80;

    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--mode") and i + 1 < args.len) {
            mode = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, a, "--cidr") and i + 1 < args.len) {
            cidr = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, a, "--iface") and i + 1 < args.len) {
            iface = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, a, "--port") and i + 1 < args.len) {
            port = try std.fmt.parseUnsigned(u16, args[i + 1], 10);
            i += 1;
        } else if (std.mem.eql(u8, a, "--action") and i + 1 < args.len) {
            action = args[i + 1];
            i += 1;
        } else if (std.mem.eql(u8, a, "--help")) {
            printUsage();
            return;
        } else {
            std.log.warn("未知参数: {s}", .{a});
        }
    }

    if (mode.len == 0) {
        std.log.info("未指定 --mode，显示菜单并退出。", .{});
        printUsage();
        return;
    }

    if (std.mem.eql(u8, mode, "cidr")) {
        if (cidr.len == 0) {
            std.log.err("CIDR 模式需要 --cidr", .{});
            return;
        }
        if (std.mem.eql(u8, action, "discover")) {
            std.log.info("主机发现 CIDR={s}", .{cidr});
            try Scan.discoverRange(allocator, cidr);
        } else {
            std.log.info("端口扫描 CIDR={s}, port={d}", .{ cidr, port });
            try Scan.scanRange(allocator, cidr, port);
        }
    } else if (std.mem.eql(u8, mode, "local")) {
        if (std.mem.eql(u8, action, "discover")) {
            std.log.info("主机发现 本机子网 (iface={s})", .{iface});
            // TODO: 列举本机网卡并解析子网，调用 Scan.discoverRange
        } else {
            std.log.info("端口扫描 本机子网 (iface={s}), port={d}", .{ iface, port });
            // TODO: 列举本机网卡并解析子网，调用 Scan.scanRange
        }
    } else if (std.mem.eql(u8, mode, "lan")) {
        if (std.mem.eql(u8, action, "discover")) {
            try Scan.discoverLan(allocator);
        } else {
            try Scan.scanLan(allocator, port);
        }
    } else {
        std.log.err("不支持的模式: {s}", .{mode});
        printUsage();
        return;
    }

    std.log.info("执行结束", .{});
}
