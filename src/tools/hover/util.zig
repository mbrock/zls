const std = @import("std");
const DiffMatchPatch = @import("diffz");

pub fn outPrint(comptime fmt: []const u8, args: anytype) void {
    var buf: [4096]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buf);
    _ = std.fmt.format(fbs.writer(), fmt, args) catch return;
    const slice = fbs.getWritten();
    _ = std.posix.write(std.posix.STDOUT_FILENO, slice) catch {};
}

pub fn printDiff(allocator: std.mem.Allocator, before: []const u8, after: []const u8, path: []const u8) void {
    outPrint("--- {s}\n+++ {s}\n", .{ path, path });
    var d = DiffMatchPatch{ .diff_timeout = 250 };
    var diffs = d.diff(allocator, before, after, true) catch return;
    defer DiffMatchPatch.deinitDiffList(allocator, &diffs);
    var shown: usize = 0;
    for (diffs.items) |df| {
        const prefix: u8 = switch (df.operation) { .delete => '-', .insert => '+', .equal => ' ' };
        var i: usize = 0;
        while (i < df.text.len and shown < 4000) : (i += 120) {
            const e = @min(i + 120, df.text.len);
            outPrint("{c}{s}\n", .{ prefix, df.text[i..e] });
            shown += e - i;
        }
        if (shown >= 4000) break;
    }
}

pub fn runZigFmt(allocator: std.mem.Allocator, paths: []const []const u8) void {
    if (paths.len == 0) return;
    var argv = std.ArrayList([]const u8).init(allocator);
    defer argv.deinit();
    _ = argv.append("zig") catch return;
    _ = argv.append("fmt") catch return;
    for (paths) |p| _ = argv.append(p) catch {};
    var child = std.process.Child.init(argv.items, allocator);
    _ = child.spawnAndWait() catch {};
}

pub fn ensureDirForFile(path: []const u8) void {
    const dir = std.fs.path.dirname(path) orelse return;
    std.fs.cwd().makePath(dir) catch {};
}

