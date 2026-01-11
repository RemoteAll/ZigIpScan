const std = @import("std");

pub fn scanRange(allocator: std.mem.Allocator, cidr: []const u8, port: u16) !void {
    _ = allocator;
    _ = cidr;
    _ = port;
    // TODO: 实现 IPv4 CIDR 解析与并发 TCP 端口探测
}

pub fn discoverRange(allocator: std.mem.Allocator, cidr: []const u8) !void {
    _ = allocator;
    _ = cidr;
    // TODO: 主机发现：优先 ICMP/ARP（跨平台权限受限），回退为轻探测（如 TCP connect 常见端口）或反向DNS
}
