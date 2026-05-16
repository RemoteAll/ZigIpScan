const std = @import("std");
const Scan = @import("ip_scan.zig");
const zzig = @import("zzig");

fn executeScanMode(allocator: std.mem.Allocator, mode: []const u8, action: []const u8, cidr: []const u8, iface: ?[]const u8, port: u16, announce: bool) !void {
    if (std.mem.eql(u8, mode, "cidr")) {
        if (cidr.len == 0) return error.InvalidArguments;

        if (std.mem.eql(u8, action, "discover")) {
            if (announce) std.log.info("主机发现 CIDR={s}", .{cidr});
            try Scan.discoverRange(allocator, cidr);
        } else {
            if (announce) std.log.info("端口扫描 CIDR={s}, port={d}", .{ cidr, port });
            try Scan.scanRange(allocator, cidr, port);
        }
        return;
    }

    if (std.mem.eql(u8, mode, "local")) {
        const iface_value = iface orelse "";
        const iface_filter = if (iface_value.len > 0) iface_value else null;

        if (std.mem.eql(u8, action, "discover")) {
            if (announce) std.log.info("主机发现 当前网卡所在子网 (iface={s})", .{iface_value});
            try Scan.discoverLocal(allocator, iface_filter);
        } else {
            if (announce) std.log.info("端口扫描 当前网卡所在子网 (iface={s}), port={d}", .{ iface_value, port });
            try Scan.scanLocal(allocator, iface_filter, port);
        }
        return;
    }

    if (std.mem.eql(u8, mode, "lan")) {
        if (std.mem.eql(u8, action, "discover")) {
            try Scan.discoverLan(allocator);
        } else {
            try Scan.scanLan(allocator, port);
        }
        return;
    }

    return error.InvalidMode;
}

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
            "模式含义:\n" ++
            "  local: 当前网卡所在子网\n" ++
            "  cidr: 指定 CIDR 网段\n" ++
            "  lan: 所有网卡所在子网\n" ++
            "示例:\n  zig build run -- --mode cidr --cidr 192.168.1.0/24\n",
        .{},
    );
}

fn runInteractiveMenu(allocator: std.mem.Allocator) !void {
    std.debug.print("\n=== Zig IP Scan 交互式菜单 ===\n", .{});

    // 第一步: 选择操作类型
    std.debug.print("\n请选择操作:\n", .{});
    std.debug.print("  1) 主机发现 (discover) - 扫描活跃主机\n", .{});
    std.debug.print("  2) 端口扫描 (scan) - 检测端口开放情况\n", .{});
    std.debug.print("输入序号 (默认 1): ", .{});

    const action_input = zzig.Menu.readLine(allocator) catch |err| switch (err) {
        error.EndOfStream => try allocator.dupe(u8, ""),
        else => return err,
    };
    defer if (action_input.len > 0) allocator.free(action_input);

    const action = if (std.mem.eql(u8, action_input, "2")) "scan" else "discover";

    // 第二步: 选择扫描模式
    std.debug.print("\n请选择扫描范围:\n", .{});
    std.debug.print("  1) 当前网卡所在子网 (local) - 自动检测并选择一个网卡\n", .{});
    std.debug.print("  2) 指定网段 (cidr) - 手动输入 CIDR\n", .{});
    std.debug.print("  3) 所有网卡所在子网 (lan) - 扫描全部检测到的网卡子网\n", .{});
    std.debug.print("输入序号: ", .{});

    const mode_input = zzig.Menu.readLine(allocator) catch |err| {
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
        cidr_buf = try zzig.Menu.readLine(allocator);
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
        const port_input = zzig.Menu.readLine(allocator) catch |err| switch (err) {
            error.EndOfStream => try allocator.dupe(u8, ""),
            else => return err,
        };
        defer if (port_input.len > 0) allocator.free(port_input);
        if (port_input.len > 0) {
            port = std.fmt.parseUnsigned(u16, port_input, 10) catch 80;
        }
    }

    std.debug.print("\n开始执行...\n", .{});
    defer if (cidr_buf.len > 0) allocator.free(cidr_buf);

    try executeScanMode(allocator, mode, action, cidr_buf, null, port, false);
}

pub fn main(init: std.process.Init) !void {
    zzig.compat.setCurrentIo(init.io);
    _ = zzig.Console.init(.{});

    const allocator = init.gpa;
    const args = try init.minimal.args.toSlice(init.arena.allocator());

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

    executeScanMode(allocator, mode, action, cidr, if (iface.len > 0) iface else null, port, true) catch |err| switch (err) {
        error.InvalidArguments => {
            std.log.err("CIDR 模式需要 --cidr", .{});
            return;
        },
        error.InvalidMode => {
            std.log.err("不支持的模式: {s}", .{mode});
            printUsage();
            return;
        },
        else => return err,
    };

    std.log.info("执行结束", .{});
}
