const std = @import("std");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const result = try std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{"ipconfig"},
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    var count: usize = 0;

    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \r\n\t");

        if (std.mem.indexOf(u8, trimmed, "适配器") != null) {
            std.debug.print("\n[适配器] {s}\n", .{trimmed});
        }

        if (std.mem.indexOf(u8, trimmed, "IPv4") != null) {
            std.debug.print("[IPv4行] {s}\n", .{trimmed});

            if (std.mem.indexOf(u8, trimmed, ":") != null) {
                var parts = std.mem.splitScalar(u8, trimmed, ':');
                _ = parts.next();
                if (parts.next()) |ip_part| {
                    const ip_str = std.mem.trim(u8, ip_part, " \r\n\t()");
                    std.debug.print("  提取的IP: '{s}'\n", .{ip_str});
                }
            }

            count += 1;
            if (count >= 5) break;
        }
    }
}
