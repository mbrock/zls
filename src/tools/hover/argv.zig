const std = @import("std");

pub fn printUsage(comptime T: type, writer: anytype, program_name: []const u8) !void {
    var w = writer;
    try w.interface.print("Usage: {s}", .{program_name});
    
    // Print positional arguments first
    inline for (std.meta.fields(T)) |f| {
        if (!std.mem.startsWith(u8, f.name, "--")) {
            if (f.type == ?[]const u8) {
                try w.interface.print(" [{s}]", .{f.name});
            } else {
                try w.interface.print(" <{s}>", .{f.name});
            }
        }
    }
    
    try w.interface.print(" [OPTIONS]\n\nOptions:\n", .{});
    
    // Print flag options
    inline for (std.meta.fields(T)) |f| {
        if (std.mem.startsWith(u8, f.name, "--")) {
            if (f.type == bool) {
                const flag_name = f.name[2..];
                try w.interface.print("  {s}, --no-{s}\n", .{ f.name, flag_name });
            } else if (f.type == ?[]const u8) {
                try w.interface.print("  {s}[=VALUE]\n", .{f.name});
            } else {
                try w.interface.print("  {s}=VALUE\n", .{f.name});
            }
        }
    }
    
    try w.interface.print("  --help                    Show this help message\n", .{});
}

fn findFieldIdx(comptime T: type, name: []const u8) ?usize {
    inline for (std.meta.fields(T), 0..) |f, idx| {
        if (std.mem.eql(u8, name, f.name)) return idx;
    }
    return null;
}

fn setFieldValueAt(comptime T: type, outp: *T, field_idx: usize, value_opt: ?[]const u8, set_bool_true: bool) !void {
    var matched = false;
    inline for (std.meta.fields(T), 0..) |f, idx| {
        if (idx == field_idx) {
            const FieldType = @TypeOf(@field(outp.*, f.name));
            if (FieldType == bool) {
            const v = if (value_opt) |vs| blk: {
                if (std.ascii.eqlIgnoreCase(vs, "1") or std.ascii.eqlIgnoreCase(vs, "true") or std.ascii.eqlIgnoreCase(vs, "yes")) break :blk true;
                if (std.ascii.eqlIgnoreCase(vs, "0") or std.ascii.eqlIgnoreCase(vs, "false") or std.ascii.eqlIgnoreCase(vs, "no")) break :blk false;
                break :blk set_bool_true;
            } else set_bool_true;
            @field(outp.*, f.name) = v;
            matched = true;
        } else if (FieldType == ?[]const u8) {
            @field(outp.*, f.name) = value_opt;
            matched = true;
            return;
        } else if (FieldType == []const u8) {
            if (value_opt) |vs| { @field(outp.*, f.name) = vs; matched = true; return; } else return error.MissingValue;
        } else {
            const ti = @typeInfo(FieldType);
            switch (ti) {
                .int => {
                    if (value_opt) |vs| {
                        @field(outp.*, f.name) = try std.fmt.parseInt(FieldType, vs, 10);
                        matched = true;
                        return;
                    } else return error.MissingValue;
                },
                .optional => |optinfo| {
                    const Base = optinfo.child;
                    if (@typeInfo(Base) == .int) {
                        if (value_opt) |vs| {
                            @field(outp.*, f.name) = try std.fmt.parseInt(Base, vs, 10);
                            matched = true;
                            return;
                        } else return error.MissingValue;
                    } else if (Base == []const u8) {
                        @field(outp.*, f.name) = value_opt;
                        matched = true;
                        return;
                    } else {
                        return error.UnsupportedFieldType;
                    }
                },
                else => {
                    if (@hasDecl(FieldType, "parse")) {
                        if (value_opt) |vs| {
                            @field(outp.*, f.name) = try @field(FieldType, "parse")(vs);
                            matched = true;
                            return;
                        } else return error.MissingValue;
                    }
                    return error.UnsupportedFieldType;
                },
            }
        }
        }
    }
    if (!matched) return error.InvalidArgs;
}

// Int/custom parsing will be added in later TDD steps.

fn nextPositionalIndex(comptime T: type, filled: []const bool, start_idx: usize) ?usize {
    inline for (std.meta.fields(T), 0..) |f, idx| {
        const cond = idx >= start_idx and !std.mem.startsWith(u8, f.name, "--") and !filled[idx];
        if (cond) return idx;
    }
    return null;
}

fn parseStructArgs(comptime T: type, argv: [][:0]u8, start: usize) !T {
    var out: T = .{};
    var filled: [std.meta.fields(T).len]bool = undefined;
    {
        var j: usize = 0;
        while (j < filled.len) : (j += 1) filled[j] = false;
    }

    var i: usize = start;
    if (i < argv.len and !std.mem.startsWith(u8, argv[i], "-")) {
        if (nextPositionalIndex(T, filled[0..], 0)) |pidx| {
            try setFieldValueAt(T, &out, pidx, argv[i], true);
            filled[pidx] = true;
            i += 1;
        }
    }

    while (i < argv.len) : (i += 1) {
        const a = argv[i];
        if (!std.mem.startsWith(u8, a, "--")) {
            if (nextPositionalIndex(T, filled[0..], 0)) |pidx| {
                try setFieldValueAt(T, &out, pidx, a, true);
                filled[pidx] = true;
                continue;
            }
            break;
        }
        
        // Handle --help
        if (std.mem.eql(u8, a, "--help")) {
            const stderr_writer = std.fs.File.stderr().writer(&.{});
            try printUsage(T, stderr_writer, argv[0]);
            std.process.exit(0);
        }
        
        var negated = false;
        var fidx_opt: ?usize = null;
        var flag_val: ?[]const u8 = null;
        if (std.mem.startsWith(u8, a, "--no-")) {
            negated = true;
            const eq = std.mem.indexOfScalar(u8, a, '=');
            const token = a[5 .. eq orelse a.len]; // after --no-
            inline for (std.meta.fields(T), 0..) |f, idx| {
                var is_match = false;
                const name_len = f.name.len;
                if (name_len >= 2 and std.mem.startsWith(u8, f.name, "--") and name_len == token.len + 2) {
                    var same = true;
                    var j: usize = 0;
                    while (j < token.len) : (j += 1) {
                        if (f.name[2 + j] != token[j]) { same = false; break; }
                    }
                    is_match = same;
                }
                if (is_match) { fidx_opt = idx; }
            }
            // ignore any explicit value for negated bools
        } else {
            const eq = std.mem.indexOfScalar(u8, a, '=');
            const flag_name = a[0 .. eq orelse a.len];
            fidx_opt = findFieldIdx(T, flag_name);
            flag_val = if (eq) |pos| a[pos + 1 ..] else null;
        }
        if (fidx_opt) |fidx| {
            const is_bool = blk: {
                var res = false;
                inline for (std.meta.fields(T), 0..) |f, idx| {
                    if (idx == fidx) { res = (@TypeOf(@field(out, f.name)) == bool); break; }
                }
                break :blk res;
            };
            if (flag_val == null) {
                if (!is_bool) {
                    if (i + 1 < argv.len and !std.mem.startsWith(u8, argv[i + 1], "-")) {
                        try setFieldValueAt(T, &out, fidx, argv[i + 1], true);
                        i += 1;
                    } else try setFieldValueAt(T, &out, fidx, null, true);
                } else {
                    try setFieldValueAt(T, &out, fidx, null, !negated);
                }
            } else {
                try setFieldValueAt(T, &out, fidx, flag_val, !negated);
            }
            filled[fidx] = true;
        } else {
            // Unrecognized option - print usage and exit with code 1
            var stderr_writer = std.fs.File.stderr().writer(&.{});
            try stderr_writer.interface.print("Error: Unrecognized option '{s}'\n\n", .{a});
            try printUsage(T, stderr_writer, argv[0]);
            std.process.exit(1);
        }
    }

    return out;
}

pub fn parseArgs(comptime T: type, _allocator: std.mem.Allocator, argv: [][:0]u8, start: usize) !T {
    _ = _allocator;
    const ti = @typeInfo(T);
    return switch (ti) {
        .@"struct" => parseStructArgs(T, argv, start),
        .@"union" => blk: {
            const ui = ti.@"union";
            if (ui.tag_type == null) return error.UnsupportedTopLevelType;
            if (start >= argv.len) return error.MissingSubcommand;
            const sub = argv[start];
            inline for (ui.fields) |uf| {
                if (std.mem.eql(u8, sub, uf.name)) {
                    if (uf.type == void) break :blk @unionInit(T, uf.name, {});
                    const payload = try parseStructArgs(uf.type, argv, start + 1);
                    break :blk @unionInit(T, uf.name, payload);
                }
            }
            return error.UnknownSubcommand;
        },
        else => error.UnsupportedTopLevelType,
    };
}

pub fn dispatch(comptime U: type, allocator: std.mem.Allocator, argv: [][:0]u8, start: usize, context: anytype, handlers: anytype) !void {
    const ti = @typeInfo(U);
    if (ti != .@"union" or ti.@"union".tag_type == null) return error.UnsupportedTopLevelType;
    const parsed = try parseArgs(U, allocator, argv, start);
    const tag = @tagName(parsed);
    inline for (ti.@"union".fields) |uf| {
        if (std.mem.eql(u8, tag, uf.name)) {
            const handler = @field(handlers, uf.name);
            if (uf.type == void) {
                try handler(context, {});
            } else {
                try handler(context, @field(parsed, uf.name));
            }
            return;
        }
    }
    return error.UnknownSubcommand;
}

fn makeArgv(allocator: std.mem.Allocator, args: []const []const u8) ![][:0]u8 {
    var list: std.ArrayList([:0]u8) = .{};
    for (args) |arg| {
        const owned = try allocator.allocSentinel(u8, arg.len, 0);
        @memcpy(owned, arg);
        try list.append(allocator, owned);
    }
    return list.items;
}

fn testParse(comptime T: type, allocator: std.mem.Allocator, args: []const []const u8) !T {
    const argv = try makeArgv(allocator, args);
    return parseArgs(T, allocator, argv, 1);
}

test "basic flag parsing" {
    const TestArgs = struct {
        @"--verbose": bool = false,
        @"--count": ?[]const u8 = null,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = try testParse(TestArgs, arena.allocator(), &.{ "test", "--verbose", "--count=5" });
    try std.testing.expect(result.@"--verbose" == true);
    try std.testing.expectEqualStrings("5", result.@"--count".?);
}

test "positional arguments" {
    const TestArgs = struct {
        file: []const u8 = "",
        line: []const u8 = "",
        @"--verbose": bool = false,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const result = try testParse(TestArgs, arena.allocator(), &.{ "test", "main.zig", "42", "--verbose" });
    try std.testing.expectEqualStrings("main.zig", result.file);
    try std.testing.expectEqualStrings("42", result.line);
    try std.testing.expect(result.@"--verbose" == true);
}

test "union subcommand parsing" {
    const Info = struct { file: []const u8 = "", line: u32 = 0, col: u32 = 0 };
    const Syms = struct { file: []const u8 = "", @"--public": bool = false };
    const Cmd = union(enum) { info: Info, symbols: Syms };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try makeArgv(arena.allocator(), &.{ "hover", "symbols", "main.zig", "--public" });
    const res = try parseArgs(Cmd, arena.allocator(), argv, 1);
    try std.testing.expect(std.mem.eql(u8, @tagName(res), @tagName(Cmd.symbols)));
    try std.testing.expectEqualStrings("main.zig", res.symbols.file);
    try std.testing.expect(res.symbols.@"--public" == true);
}

test "int parsing for positional and optional flag" {
    const Args = struct {
        a: u32 = 0,
        @"--opt": ?u16 = null,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try makeArgv(arena.allocator(), &.{ "prog", "123", "--opt=7" });
    const parsed = try parseArgs(Args, arena.allocator(), argv, 1);
    try std.testing.expectEqual(@as(u32, 123), parsed.a);
    try std.testing.expectEqual(@as(u16, 7), parsed.@"--opt".?);
}

test "custom type parsing via parse()" {
    const Pair = struct {
        a: u8,
        b: u8,
        pub fn parse(s: []const u8) !@This() {
            var it = std.mem.splitScalar(u8, s, ',');
            const a = try std.fmt.parseInt(u8, it.next() orelse return error.Invalid, 10);
            const b = try std.fmt.parseInt(u8, it.next() orelse return error.Invalid, 10);
            return .{ .a = a, .b = b };
        }
    };
    const Args = struct { @"--pair": Pair = .{ .a = 0, .b = 0 } };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const argv = try makeArgv(arena.allocator(), &.{ "prog", "--pair=1,2" });
    const parsed = try parseArgs(Args, arena.allocator(), argv, 1);
    try std.testing.expectEqual(@as(u8, 1), parsed.@"--pair".a);
    try std.testing.expectEqual(@as(u8, 2), parsed.@"--pair".b);
}

test "dispatcher routes to handler with context" {
    const A = struct { v: u8 = 0 };
    const B = struct { s: []const u8 = "" };
    const Cmd = union(enum) { a: A, b: B };
    const Ctx = struct { a_sum: usize = 0, b_hits: usize = 0 };
    var ctx = Ctx{};
    const handlers = .{
        .a = struct { fn f(c: *Ctx, a: A) !void { c.a_sum += a.v; } }.f,
        .b = struct { fn f(c: *Ctx, b: B) !void { _ = b; c.b_hits += 1; } }.f,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try dispatch(Cmd, arena.allocator(), try makeArgv(arena.allocator(), &.{ "prog", "a", "3" }), 1, &ctx, handlers);
    try dispatch(Cmd, arena.allocator(), try makeArgv(arena.allocator(), &.{ "prog", "b", "hi" }), 1, &ctx, handlers);
    try std.testing.expectEqual(@as(usize, 3), ctx.a_sum);
    try std.testing.expectEqual(@as(usize, 1), ctx.b_hits);
}
