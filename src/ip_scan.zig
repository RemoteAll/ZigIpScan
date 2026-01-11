const std = @import("std");

pub fn scanRange(allocator: std.mem.Allocator, cidr: []const u8, port: u16) !void {
    _ = allocator;
    _ = cidr;
    _ = port;
    // TODO: 实现 IPv4 CIDR 解析与并发 TCP 端口探测
}
