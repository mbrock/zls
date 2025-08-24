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

fn getDeadlineNs(allocator: std.mem.Allocator) u64 {
    const env = std.process.getEnvVarOwned(allocator, "HOVER_PAGERANK_TIMEOUT_MS") catch return 2000 * std.time.ns_per_ms;
    defer allocator.free(env);
    const ms = std.fmt.parseUnsigned(u64, env, 10) catch 2000;
    return ms * std.time.ns_per_ms;
}

pub fn pagerank(server: *zls.Server, allocator: std.mem.Allocator, root_path: []const u8) !void {
    var timer = try std.time.Timer.start();
    const deadline_ns = getDeadlineNs(allocator);

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
    if (timer.read() > deadline_ns) { outPrint("[pagerank] Timeout during file discovery.\n", .{}); return; }

    // Node set = all functions/methods via AST walk
    var nodes: std.ArrayList(PRNode) = .empty;
    defer {
        for (nodes.items) |*n| n.out_edges.deinit(allocator);
        nodes.deinit(allocator);
    }
    var index_by_key = std.StringHashMap(u32).init(allocator);
    defer index_by_key.deinit();

    const max_files: usize = @min(files.items.len, 400);
    var fi: usize = 0;
    while (fi < max_files) : (fi += 1) {
        if (timer.read() > deadline_ns) { outPrint("[pagerank] Timeout building nodes.\n", .{}); break; }
        const p = files.items[fi];
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = hover_server.openDocument(server, allocator, p, content) catch continue;
        const tree = h.tree;
        const Ctx = struct {
            allocator: std.mem.Allocator,
            server: *zls.Server,
            h: *zls.DocumentStore.Handle,
            nodes: *std.ArrayList(PRNode),
            index_by_key: *std.StringHashMap(u32),
            fn cb(self: *@This(), tree_: std.zig.Ast, node: std.zig.Ast.Node.Index) error{OutOfMemory}!void {
                _ = tree_;
                switch (self.h.tree.nodeTag(node)) {
                    .fn_decl => {
                        var buf: [1]std.zig.Ast.Node.Index = undefined;
                        const fn_info = self.h.tree.fullFnProto(&buf, node).?;
                        const name_tok = fn_info.name_token orelse return;
                        const pos = zls.offsets.tokenToPosition(self.h.tree, name_tok, self.server.offset_encoding);
                        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.h.uri, pos.line });
                        if (self.index_by_key.get(key)) |_| return;
                        const nd = PRNode{
                            .name = self.allocator.dupe(u8, zls.offsets.identifierTokenToNameSlice(self.h.tree, name_tok)) catch return,
                            .uri = self.allocator.dupe(u8, self.h.uri) catch return,
                            .pos = pos,
                            .out_edges = .empty,
                        };
                        const idx: u32 = @intCast(self.nodes.items.len);
                        self.nodes.append(self.allocator, nd) catch return;
                        _ = self.index_by_key.put(key, idx) catch {};
                    },
                    else => {},
                }
                try zls.ast.iterateChildren(self.h.tree, node, self, error{OutOfMemory}, @This().cb);
            }
        };
        var ctx = Ctx{ .allocator = allocator, .server = server, .h = h, .nodes = &nodes, .index_by_key = &index_by_key };
        zls.ast.iterateChildren(tree, .root, &ctx, error{OutOfMemory}, Ctx.cb) catch {};
    }

    const node_build_time = timer.lap();
    std.debug.print("[PR] Node building: {}ms ({} nodes from {} files)\n", .{ node_build_time / std.time.ns_per_ms, nodes.items.len, @min(files.items.len, max_files) });
    if (timer.read() > deadline_ns) { outPrint("[pagerank] Timeout after node build.\n", .{}); return; }

    // Build edges by scanning calls; resolve with analyser
    var edges_added: usize = 0;
    fi = 0;
    while (fi < max_files) : (fi += 1) {
        if (timer.read() > deadline_ns) { outPrint("[pagerank] Timeout during edge build.\n", .{}); break; }
        const p = files.items[fi];
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = hover_server.openDocument(server, allocator, p, content) catch continue;
        var analyser = server.initAnalyser(allocator, h);
        defer analyser.deinit();
        const tree = h.tree;
        const Ctx2 = struct {
            allocator: std.mem.Allocator,
            server: *zls.Server,
            analyser: *zls.Analyser,
            h: *zls.DocumentStore.Handle,
            nodes: *std.ArrayList(PRNode),
            index_by_key: *std.StringHashMap(u32),
            caller_idx: ?u32 = null,
            edges_added: *usize,
            fn cb(self: *@This(), tree_: std.zig.Ast, node: std.zig.Ast.Node.Index) error{OutOfMemory}!void {
                _ = tree_;
                var next = self.*;
                switch (self.h.tree.nodeTag(node)) {
                    .fn_decl => {
                        var buf: [1]std.zig.Ast.Node.Index = undefined;
                        const info = self.h.tree.fullFnProto(&buf, node).?;
                        const name_tok = info.name_token orelse return;
                        const pos = zls.offsets.tokenToPosition(self.h.tree, name_tok, self.server.offset_encoding);
                        const key = try std.fmt.allocPrint(self.allocator, "{s}:{d}", .{ self.h.uri, pos.line });
                        next.caller_idx = self.index_by_key.get(key) orelse null;
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
                try zls.ast.iterateChildren(self.h.tree, node, &next, error{OutOfMemory}, @This().cb);
            }
        };
        var ctx2 = Ctx2{ .allocator = allocator, .server = server, .analyser = &analyser, .h = h, .nodes = &nodes, .index_by_key = &index_by_key, .edges_added = &edges_added };
        zls.ast.iterateChildren(tree, .root, &ctx2, error{OutOfMemory}, Ctx2.cb) catch {};
    }

    const edge_time = timer.lap();
    std.debug.print("[PR] Edges: {} ({}ms)\n", .{ edges_added, edge_time / std.time.ns_per_ms });
    if (timer.read() > deadline_ns) { outPrint("[pagerank] Timeout before ranking.\n", .{}); return; }

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
