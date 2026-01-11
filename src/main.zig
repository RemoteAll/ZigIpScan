const std = @import("std");
const Scan = @import("ip_scan.zig");

fn printUsage() void {
    std.log.info(
        "zig-ip-scan\n" ++
            "菜单/参数用法:\n" ++
            "  1) 扫描本机网卡所在子网: zig build run -- --mode local --port <p> [--iface <name>]\n" ++
            "  2) 扫描指定CIDR:        zig build run -- --mode cidr --cidr <CIDR> --port <p>\n" ++
            "  3) 扫描局域网(多网卡):   zig build run -- --mode lan --port <p>\n" ++
            "示例:\n  zig build run -- --mode cidr --cidr 192.168.1.0/24 --port 80\n",
        .{},
    );
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);

    if (args.len == 1 or (args.len >= 2 and std.mem.eql(u8, args[1], "--help"))) {
        printUsage();
        return;
    }

    var mode: []const u8 = "";
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
        std.log.info("开始扫描 CIDR={s}, port={d}", .{ cidr, port });
        try Scan.scanRange(allocator, cidr, port);
    } else if (std.mem.eql(u8, mode, "local")) {
        std.log.info("扫描本机网卡所在子网 (iface={s} 可选), port={d} (未实现)", .{ iface, port });
        // TODO: 列举本机网卡并解析子网，调用 Scan.scanRange
    } else if (std.mem.eql(u8, mode, "lan")) {
        std.log.info("扫描局域网所有网卡子网, port={d} (未实现)", .{port});
        // TODO: 列举所有活动网卡并对其子网进行扫描
    } else {
        std.log.err("不支持的模式: {s}", .{mode});
        printUsage();
        return;
    }

    std.log.info("执行结束", .{});
}
