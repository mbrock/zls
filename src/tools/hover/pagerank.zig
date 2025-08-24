const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;
const util = @import("util.zig");
const hover_server = @import("server.zig");

const outPrint = util.outPrint;

const PRNode = struct {
    name: []const u8,
    uri: []const u8,
    pos: types.Position,
    score: f64 = 0.0,
    out_edges: std.ArrayList(u32),
};

fn computePageRank(nodes: []PRNode, iters: u32, damping: f64, allocator: std.mem.Allocator) void {
    if (nodes.len == 0) return;
    var scores = std.ArrayList(f64).empty;
    if (scores.resize(allocator, nodes.len)) |_| {} else |_| return;
    const n: f64 = @floatFromInt(nodes.len);
    for (scores.items) |*s| s.* = 1.0 / n;
    var next = std.ArrayList(f64).empty;
    if (next.resize(allocator, nodes.len)) |_| {} else |_| return;
    var it: u32 = 0;
    while (it < iters) : (it += 1) {
        for (next.items) |*s| s.* = (1.0 - damping) / n;
        for (nodes, 0..) |nd, i| {
            if (nd.out_edges.items.len == 0) {
                const c = damping * scores.items[i] / n;
                for (next.items) |*v| v.* += c;
            } else {
                const c = damping * scores.items[i] / @as(f64, @floatFromInt(nd.out_edges.items.len));
                for (nd.out_edges.items) |j| next.items[j] += c;
            }
        }
        for (scores.items, 0..) |*s, i| s.* = next.items[i];
    }
    for (nodes, 0..) |*nd, i| nd.score = scores.items[i];
}

fn walkZigFiles(allocator: std.mem.Allocator, root_dir_path: []const u8, out_list: *std.ArrayList([]const u8)) !void {
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(allocator, try allocator.dupe(u8, root_dir_path));
    const ignore_dirs = [_][]const u8{ ".git", "zig-cache", "zig-out", ".zig-cache", "target", "node_modules" };
    while (stack.items.len > 0 and out_list.items.len < 2000) {
        const last_i = stack.items.len - 1;
        const dir_path = stack.items[last_i];
        stack.items.len = last_i;
        var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch {
            continue;
        };
        defer dir.close();
        var it = dir.iterate();
        while (try it.next()) |ent| {
            if (ent.kind == .directory) {
                var skip = false;
                for (ignore_dirs) |name| {
                    if (std.mem.eql(u8, ent.name, name)) { skip = true; break; }
                }
                if (skip) continue;
                const sub = try std.fs.path.join(allocator, &.{ dir_path, ent.name });
                try stack.append(allocator, sub);
                continue;
            }
            if (ent.kind == .file and std.mem.endsWith(u8, ent.name, ".zig")) {
                const full = try std.fs.path.join(allocator, &.{ dir_path, ent.name });
                try out_list.append(allocator, full);
            }
        }
    }
}

pub fn pagerank(server: *zls.Server, allocator: std.mem.Allocator, root_path: []const u8) !void {
    var timer = std.time.Timer.start() catch return;

    // Discover files
    const abs_root = try std.fs.cwd().realpathAlloc(allocator, root_path);
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(allocator);
    const stat = std.fs.cwd().statFile(abs_root) catch null;
    if (stat) |s| {
        if (s.kind == .file and std.mem.endsWith(u8, abs_root, ".zig")) {
            try files.append(allocator, abs_root);
        } else if (s.kind == .directory) {
            try walkZigFiles(allocator, abs_root, &files);
        }
    } else {
        try walkZigFiles(allocator, abs_root, &files);
    }

    const file_walk_time = timer.lap();
    std.debug.print("[PR] File discovery: {}ms ({} files)\n", .{file_walk_time / std.time.ns_per_ms, files.items.len});

    // Node set = all functions/methods via document symbols
    var nodes: std.ArrayList(PRNode) = .empty;
    defer {
        for (nodes.items) |*n| n.out_edges.deinit(allocator);
        nodes.deinit(allocator);
    }
    var index_by_key = std.StringHashMap(u32).init(allocator);
    defer index_by_key.deinit();

    const max_files: usize = @min(files.items.len, 300);
    for (files.items[0..max_files]) |p| {
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = hover_server.openDocument(server, allocator, p, content) catch continue;
        const arr = zls.document_symbol.getDocumentSymbols(allocator, h.tree, server.offset_encoding) catch continue;
        for (arr) |s| {
            if (!(s.kind == .Function or s.kind == .Method)) continue;
            const key = std.fmt.allocPrint(allocator, "{s}:{d}", .{ h.uri, s.selectionRange.start.line }) catch continue;
            if (index_by_key.get(key)) |_| continue;
            const node = PRNode{
                .name = allocator.dupe(u8, s.name) catch continue,
                .uri = allocator.dupe(u8, h.uri) catch continue,
                .pos = s.selectionRange.start,
                .out_edges = .empty,
            };
            const idx: u32 = @intCast(nodes.items.len);
            nodes.append(allocator, node) catch break;
            index_by_key.put(key, idx) catch {};
        }
    }

    const node_build_time = timer.lap();
    std.debug.print("[PR] Node building: {}ms ({} nodes from {} files)\n", .{ node_build_time / std.time.ns_per_ms, nodes.items.len, max_files });

    // Build edges by scanning call expressions and resolving to decls
    var edges_added_count: usize = 0;

    for (files.items[0..max_files]) |p| {
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = hover_server.openDocument(server, allocator, p, content) catch continue;
        var analyser = server.initAnalyser(allocator, h);
        defer analyser.deinit();
        const tree = h.tree;
        const Context = struct {
            server: *zls.Server,
            analyser: *zls.Analyser,
            h: *zls.DocumentStore.Handle,
            allocator: std.mem.Allocator,
            nodes: *std.ArrayList(PRNode),
            index_by_key: *std.StringHashMap(u32),
            caller_idx: ?u32,
            edges_added: *usize,

            fn callback(self: *@This(), tree_: std.zig.Ast, node: std.zig.Ast.Node.Index) error{OutOfMemory}!void {
                _ = tree_;
                var new_ctx = self.*;
                const tag = self.h.tree.nodeTag(node);
                switch (tag) {
                    .fn_decl => {
                        var buf: [1]std.zig.Ast.Node.Index = undefined;
                        const fn_info = self.h.tree.fullFnProto(&buf, node).?;
                        const name_tok = fn_info.name_token orelse return;
                        const pos = zls.offsets.tokenToPosition(self.h.tree, name_tok, self.server.offset_encoding);
                        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.h.uri, pos.line });
                        new_ctx.caller_idx = self.index_by_key.get(key) orelse null;
                    },
                    .call => {
                        if (self.caller_idx) |caller| {
                            var buf: [1]std.zig.Ast.Node.Index = undefined;
                            const call = self.h.tree.fullCall(&buf, node).?;
                            if (self.h.tree.nodeTag(call.ast.fn_expr) == .identifier) {
                                const name_tok = self.h.tree.nodeMainToken(call.ast.fn_expr);
                                const name = zls.offsets.tokenToSlice(self.h.tree, name_tok);
                                const src_index = self.h.tree.tokenStart(name_tok);
                                if (self.analyser.lookupSymbolGlobal(self.h, name, src_index) catch null) |decl| {
                                    const def_tok = decl.definitionToken(self.analyser, true) catch return;
                                    const pos = zls.offsets.tokenToPosition(def_tok.handle.tree, def_tok.token, self.server.offset_encoding);
                                    const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ def_tok.handle.uri, pos.line });
                                    if (self.index_by_key.get(key)) |to| {
                                        self.nodes.items[@intCast(caller)].out_edges.append(self.allocator, to) catch {};
                                        self.edges_added.* += 1;
                                    }
                                }
                            }
                        }
                    },
                    else => {},
                }
                try zls.ast.iterateChildren(self.h.tree, node, &new_ctx, error{OutOfMemory}, @This().callback);
            }
        };

        var ctx = Context{
            .server = server,
            .analyser = &analyser,
            .h = h,
            .allocator = allocator,
            .nodes = &nodes,
            .index_by_key = &index_by_key,
            .caller_idx = null,
            .edges_added = &edges_added_count,
        };
        zls.ast.iterateChildren(tree, .root, &ctx, error{OutOfMemory}, Context.callback) catch {};
    }

    const edge_time = timer.lap();
    std.debug.print("[PR] Edges: {} ({}ms)\n", .{ edges_added_count, edge_time / std.time.ns_per_ms });

    computePageRank(nodes.items, 20, 0.85, allocator);
    var idxs = std.ArrayList(u32).empty;
    if (idxs.resize(allocator, nodes.items.len)) |_| {} else |_| return;
    for (idxs.items, 0..) |*v, k| v.* = @intCast(k);
    const Cmp = struct { nodes: []PRNode, pub fn lt(ctx: @This(), a: u32, b: u32) bool { return ctx.nodes[a].score > ctx.nodes[b].score; } };
    std.mem.sort(u32, idxs.items, Cmp{ .nodes = nodes.items }, Cmp.lt);

    const top = @min(@as(usize, 20), idxs.items.len);
    outPrint("PageRank Top {d} (functions/methods)\n", .{top});
    var k: usize = 0;
    while (k < top) : (k += 1) {
        const nd = nodes.items[idxs.items[k]];
        outPrint("  {d:2}. {s} ({s}) score={d:.5}\n", .{ k + 1, nd.name, nd.uri, nd.score });
    }
}
