const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;
const util = @import("util.zig");
const hover_server = @import("server.zig");

const outPrint = util.outPrint;

const PagerankOptions = struct {
    surf_main: bool = false,
    surf_from: ?[]const u8 = null,
    show_sites: bool = true,
    show_chains: bool = true,
};

const PRNode = struct {
    name: []const u8,
    uri: []const u8,
    pos: types.Position,
    /// AST node index for this function declaration (avoids re-finding later).
    fn_node: std.zig.Ast.Node.Index,
    /// Optional container/type name if this function is a method.
    container_name: ?[]const u8 = null,
    score: f64 = 0.0,
    out_edges: std.ArrayList(u32),
};

fn computePageRank(nodes: []PRNode, iters: u32, damping: f64, allocator: std.mem.Allocator, personalized: ?[]const u32) void {
    if (nodes.len == 0) return;
    var scores = std.ArrayList(f64).empty;
    if (scores.resize(allocator, nodes.len)) |_| {} else |_| return;
    const n: f64 = @floatFromInt(nodes.len);
    for (scores.items) |*s| s.* = 1.0 / n;
    var next = std.ArrayList(f64).empty;
    if (next.resize(allocator, nodes.len)) |_| {} else |_| return;
    // Build teleport distribution
    const tele: f64 = (1.0 - damping) / n;
    var tele_custom = std.ArrayList(f64).empty;
    if (personalized) |starts| {
        if (tele_custom.resize(allocator, nodes.len)) |_| {} else |_| {}
        for (tele_custom.items) |*v| v.* = 0.0;
        const m: f64 = if (starts.len != 0) 1.0 / @as(f64, @floatFromInt(starts.len)) else 0.0;
        for (starts) |idx| tele_custom.items[idx] = (1.0 - damping) * m;
    }
    var it: u32 = 0;
    while (it < iters) : (it += 1) {
        if (personalized) |_| {
            for (next.items, 0..) |*s, i| s.* = tele_custom.items[i];
        } else {
            for (next.items) |*s| s.* = tele;
        }
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
                    if (std.mem.eql(u8, ent.name, name)) {
                        skip = true;
                        break;
                    }
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
    // Default bumped from 2000ms to 10000ms for more complete runs.
    const env = std.process.getEnvVarOwned(allocator, "HOVER_PAGERANK_TIMEOUT_MS") catch return 10000 * std.time.ns_per_ms;
    defer allocator.free(env);
    const ms = std.fmt.parseUnsigned(u64, env, 10) catch 10000;
    return ms * std.time.ns_per_ms;
}

fn getBoolEnv(allocator: std.mem.Allocator, name: []const u8, default: bool) bool {
    const raw = std.process.getEnvVarOwned(allocator, name) catch return default;
    defer allocator.free(raw);
    if (std.mem.eql(u8, raw, "1") or std.ascii.eqlIgnoreCase(raw, "true") or std.ascii.eqlIgnoreCase(raw, "yes")) return true;
    if (std.mem.eql(u8, raw, "0") or std.ascii.eqlIgnoreCase(raw, "false") or std.ascii.eqlIgnoreCase(raw, "no")) return false;
    return default;
}

fn getUnsignedEnv(allocator: std.mem.Allocator, name: []const u8, default: usize) usize {
    const raw = std.process.getEnvVarOwned(allocator, name) catch return default;
    defer allocator.free(raw);
    return std.fmt.parseUnsigned(usize, raw, 10) catch default;
}

pub fn pagerank(
    server: *zls.Server,
    allocator: std.mem.Allocator,
    root_path: []const u8,
    opts: PagerankOptions,
) !void {
    var args = Pagerankator{
        .server = server,
        .allocator = allocator,
        .root_path = root_path,
        .opts = opts,
    };
    _ = try args.pagerank();
}

const Pagerankator = struct {
    server: *zls.Server,
    allocator: std.mem.Allocator,
    root_path: []const u8,
    opts: PagerankOptions,

    pub fn pagerank(this: *@This()) !void {
        var timer = try std.time.Timer.start();
        const deadline_ns = getDeadlineNs(this.allocator);
        const node_limit: usize = getUnsignedEnv(this.allocator, "HOVER_PAGERANK_NODE_LIMIT", std.math.maxInt(usize));
        const max_files_env: usize = getUnsignedEnv(this.allocator, "HOVER_PAGERANK_MAX_FILES", 400);

        // Discover files
        const abs_root = try std.fs.cwd().realpathAlloc(this.allocator, this.root_path);
        var files: std.ArrayList([]const u8) = .empty;
        defer files.deinit(this.allocator);
        const stat = std.fs.cwd().statFile(abs_root) catch null;
        if (stat) |s| {
            if (s.kind == .file and std.mem.endsWith(u8, abs_root, ".zig")) {
                try files.append(this.allocator, abs_root);
            } else if (s.kind == .directory) {
                try walkZigFiles(this.allocator, abs_root, &files);
            }
        } else {
            try walkZigFiles(this.allocator, abs_root, &files);
        }

        const file_walk_time = timer.lap();
        std.debug.print("[PR] File discovery: {}ms ({} files)\n", .{ file_walk_time / std.time.ns_per_ms, files.items.len });
        if (timer.read() > deadline_ns) {
            outPrint("[pagerank] Timeout during file discovery.\n", .{});
            return;
        }

        // Node set = all functions/methods via AST walk
        var nodes: std.ArrayList(PRNode) = .empty;
        defer {
            for (nodes.items) |*n| n.out_edges.deinit(this.allocator);
            nodes.deinit(this.allocator);
        }
        var index_by_key = std.StringHashMap(u32).init(this.allocator);
        defer index_by_key.deinit();

        const max_files: usize = @min(files.items.len, max_files_env);
        var fi: usize = 0;
        while (fi < max_files) : (fi += 1) {
            if (timer.read() > deadline_ns) {
                outPrint("[pagerank] Timeout building nodes.\n", .{});
                break;
            }
            const p = files.items[fi];
            const abs_path = std.fs.cwd().realpathAlloc(this.allocator, p) catch p;
            defer if (abs_path.ptr != p.ptr) this.allocator.free(abs_path);
            const uri = zls.URI.fromPath(this.allocator, abs_path) catch continue;
            defer this.allocator.free(uri);
            const h = this.server.document_store.getOrLoadHandle(uri) orelse continue;
            const tree = h.tree;
            // Build a map from function line to enclosing container name using document symbols
            const sym_arr = zls.document_symbol.getDocumentSymbols(this.allocator, tree, this.server.offset_encoding) catch &[_]types.DocumentSymbol{};
            const LineToContainer = std.AutoHashMap(u32, []const u8);
            var line_to_container = LineToContainer.init(this.allocator);
            defer line_to_container.deinit();
            const Walker = struct {
                allocator: std.mem.Allocator,
                map: *LineToContainer,
                fn walk(self: *@This(), syms: []const types.DocumentSymbol, parent_name: ?[]const u8) void {
                    for (syms) |s| {
                        const is_container = s.kind == .Class or s.kind == .Struct or s.kind == .Enum or s.kind == .Interface or s.kind == .Namespace or s.kind == .Object;
                        const next_parent = if (is_container or s.kind == .Constant or s.kind == .Variable) s.name else parent_name;
                        if (s.kind == .Function) {
                            if (parent_name) |pn| {
                                _ = self.map.put(@intCast(s.selectionRange.start.line), pn) catch {};
                            }
                        }
                        if (s.children) |ch| self.walk(ch, next_parent);
                    }
                }
            };
            var walker = Walker{ .allocator = this.allocator, .map = &line_to_container };
            walker.walk(sym_arr, null);
            const Ctx = struct {
                allocator: std.mem.Allocator,
                server: *zls.Server,
                h: *zls.DocumentStore.Handle,
                nodes: *std.ArrayList(PRNode),
                index_by_key: *std.StringHashMap(u32),
                node_limit: usize,
                line_to_container: *LineToContainer,
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
                            if (self.nodes.items.len >= self.node_limit) return;
                            const nd = PRNode{
                                .name = self.allocator.dupe(u8, zls.offsets.identifierTokenToNameSlice(self.h.tree, name_tok)) catch return,
                                .uri = self.allocator.dupe(u8, self.h.uri) catch return,
                                .pos = pos,
                                .fn_node = node,
                                .container_name = blk: {
                                    if (self.line_to_container.get(pos.line)) |cn| break :blk self.allocator.dupe(u8, cn) catch null;
                                    break :blk null;
                                },
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
            var ctx = Ctx{ .allocator = this.allocator, .server = this.server, .h = h, .nodes = &nodes, .index_by_key = &index_by_key, .node_limit = node_limit, .line_to_container = &line_to_container };
            zls.ast.iterateChildren(tree, .root, &ctx, error{OutOfMemory}, Ctx.cb) catch {};
            if (nodes.items.len >= node_limit) break;
        }

        const node_build_time = timer.lap();
        std.debug.print("[PR] Node building: {}ms ({} nodes from {} files)\n", .{ node_build_time / std.time.ns_per_ms, nodes.items.len, @min(files.items.len, max_files) });
        if (timer.read() > deadline_ns) {
            outPrint("[pagerank] Timeout after node build.\n", .{});
            return;
        }

        // Build edges in a single pass per file: walk calls and resolve once.
        var edges_added: usize = 0;
        const Example = struct { caller_idx: u32, caller_name: []const u8, caller_container: ?[]const u8, uri: []const u8, line: u32 };
        var incoming_examples = try this.allocator.alloc(std.ArrayList(Example), nodes.items.len);
        defer {
            var ii: usize = 0;
            while (ii < incoming_examples.len) : (ii += 1) incoming_examples[ii].deinit(this.allocator);
            this.allocator.free(incoming_examples);
        }
        {
            var ii: usize = 0;
            while (ii < incoming_examples.len) : (ii += 1) incoming_examples[ii] = .empty;
        }
        var fi_edges: usize = 0;
        var fi2: usize = 0;
        while (fi2 < max_files) : (fi2 += 1) {
            if (timer.read() > deadline_ns) {
                outPrint("[pagerank] Timeout during edge build.\n", .{});
                break;
            }
            const p = files.items[fi2];
            const abs_path = std.fs.cwd().realpathAlloc(this.allocator, p) catch p;
            defer if (abs_path.ptr != p.ptr) this.allocator.free(abs_path);
            const uri = zls.URI.fromPath(this.allocator, abs_path) catch continue;
            defer this.allocator.free(uri);
            const h = this.server.document_store.getOrLoadHandle(uri) orelse continue;
            var analyser = this.server.initAnalyser(this.allocator, h);
            defer analyser.deinit();
            var edges = zls.references.collectCallEdgesInHandle(this.allocator, &analyser, h) catch continue;
            defer edges.deinit(this.allocator);
            fi_edges = edges.items.len;
            for (edges.items) |e| {
                // Filter to function/method callees only
                const callee_handle = e.callee.handle;
                const callee_tree = callee_handle.tree;
                var buf1: [1]std.zig.Ast.Node.Index = undefined;
                const maybe_proto = switch (e.callee.decl) {
                    .ast_node => |node| switch (callee_tree.nodeTag(node)) {
                        .fn_decl, .fn_proto, .fn_proto_one, .fn_proto_multi, .fn_proto_simple => callee_tree.fullFnProto(&buf1, node),
                        else => null,
                    },
                    else => null,
                };
                const callee_proto = maybe_proto orelse continue;
                const callee_name_tok = callee_proto.name_token orelse continue;
                const callee_pos = zls.offsets.tokenToPosition(callee_tree, callee_name_tok, this.server.offset_encoding);
                const callee_key = std.fmt.allocPrint(this.allocator, "{s}:{d}", .{ callee_handle.uri, callee_pos.line }) catch continue;
                defer this.allocator.free(callee_key);
                const callee_idx_opt = index_by_key.get(callee_key) orelse continue;

                // Map caller function
                const ch = this.server.document_store.getOrLoadHandle(e.caller_uri) orelse continue;
                var buf2: [1]std.zig.Ast.Node.Index = undefined;
                const caller_proto = ch.tree.fullFnProto(&buf2, e.caller_fn_node) orelse continue;
                const caller_name_tok = caller_proto.name_token orelse continue;
                const caller_pos = zls.offsets.tokenToPosition(ch.tree, caller_name_tok, this.server.offset_encoding);
                const caller_key = std.fmt.allocPrint(this.allocator, "{s}:{d}", .{ ch.uri, caller_pos.line }) catch continue;
                defer this.allocator.free(caller_key);
                if (index_by_key.get(caller_key)) |caller_idx| {
                    nodes.items[caller_idx].out_edges.append(this.allocator, callee_idx_opt) catch {};
                    edges_added += 1;
                    // Record up to 3 example callers per callee
                    var ex_list = &incoming_examples[callee_idx_opt];
                    if (ex_list.items.len < 3) {
                        // Deduplicate by caller_idx
                        var dup = false;
                        for (ex_list.items) |ex| {
                            if (ex.caller_idx == caller_idx) {
                                dup = true;
                                break;
                            }
                        }
                        if (!dup) {
                            const caller_name = zls.offsets.identifierTokenToNameSlice(ch.tree, caller_name_tok);
                            ex_list.append(this.allocator, .{
                                .caller_idx = caller_idx,
                                .caller_name = caller_name,
                                .caller_container = nodes.items[caller_idx].container_name,
                                .uri = ch.uri,
                                .line = caller_pos.line + 1,
                            }) catch {};
                        }
                    }
                }
            }
        }

        const edge_time = timer.lap();
        std.debug.print("[PR] Edges: {} ({}ms)\n", .{ edges_added, edge_time / std.time.ns_per_ms });
        if (timer.read() > deadline_ns) {
            outPrint("[pagerank] Timeout before ranking.\n", .{});
            return;
        }

        // Personalized teleport: optionally bias to 'main' functions
        var start_idxs: std.ArrayList(u32) = .empty;
        defer start_idxs.deinit(this.allocator);
        const surf_from = this.opts.surf_from;
        if (this.opts.surf_main or getBoolEnv(this.allocator, "HOVER_PAGERANK_SURF_MAIN", false) or surf_from != null) {
            if (surf_from) |sf| {
                // sf may be NAME or FILE:NAME
                const maybe_idx = std.mem.lastIndexOfScalar(u8, sf, ':');
                if (maybe_idx) |colon| {
                    const path = sf[0..colon];
                    const fname = sf[colon + 1 ..];
                    const abs = std.fs.cwd().realpathAlloc(this.allocator, path) catch path;
                    defer if (abs.ptr != path.ptr) this.allocator.free(abs);
                    const uri = zls.URI.fromPath(this.allocator, abs) catch abs;
                    defer if (uri.ptr != abs.ptr) this.allocator.free(uri);
                    for (nodes.items, 0..) |nd, i| {
                        if (std.mem.eql(u8, nd.name, fname) and std.mem.eql(u8, nd.uri, uri)) start_idxs.append(this.allocator, @intCast(i)) catch {};
                    }
                } else {
                    for (nodes.items, 0..) |nd, i| {
                        if (std.mem.eql(u8, nd.name, sf)) start_idxs.append(this.allocator, @intCast(i)) catch {};
                    }
                }
            } else {
                for (nodes.items, 0..) |nd, i| {
                    if (std.mem.eql(u8, nd.name, "main")) start_idxs.append(this.allocator, @intCast(i)) catch {};
                }
            }
        }
        const starts_slice: ?[]const u32 = if (start_idxs.items.len != 0) start_idxs.items else null;
        computePageRank(nodes.items, 20, 0.85, this.allocator, starts_slice);
        var idxs = std.ArrayList(u32).empty;
        if (idxs.resize(this.allocator, nodes.items.len)) |_| {} else |_| return;
        for (idxs.items, 0..) |*v, k| v.* = @intCast(k);
        const Cmp = struct {
            nodes: []PRNode,
            pub fn lt(ctx: @This(), a: u32, b: u32) bool {
                return ctx.nodes[a].score > ctx.nodes[b].score;
            }
        };
        std.mem.sort(u32, idxs.items, Cmp{ .nodes = nodes.items }, Cmp.lt);

        const top = @min(@as(usize, 20), idxs.items.len);
        outPrint("PageRank Top {d} (functions/methods)\n", .{top});
        var k: usize = 0;
        while (k < top) : (k += 1) {
            const nd = nodes.items[idxs.items[k]];
            if (nd.container_name) |cn| {
                outPrint("  {d:2}. {s}.{s} ({s}) score={d:.5}\n", .{ k + 1, cn, nd.name, nd.uri, nd.score });
            } else {
                outPrint("  {d:2}. {s} ({s}) score={d:.5}\n", .{ k + 1, nd.name, nd.uri, nd.score });
            }
            if (this.opts.show_sites) {
                const ex_list = incoming_examples[idxs.items[k]].items;
                const show_n = @min(@as(usize, 2), ex_list.len);
                var eix: usize = 0;
                while (eix < show_n) : (eix += 1) {
                    const ex = ex_list[eix];
                    if (ex.caller_container) |cc|
                        outPrint("      e.g. called by {s}.{s} at {s}:{d}\n", .{ cc, ex.caller_name, ex.uri, ex.line })
                    else
                        outPrint("      e.g. called by {s} at {s}:{d}\n", .{ ex.caller_name, ex.uri, ex.line });
                }
            }
            // Edge chain example (up to depth 3) using inbound adjacency built from out_edges
            // Build inbound adjacency on-demand to keep memory overhead low
            var tmp_in: std.ArrayList(u32) = .empty;
            defer tmp_in.deinit(this.allocator);
            // Collect inbound callers of this node
            var ni: usize = 0;
            while (ni < nodes.items.len) : (ni += 1) {
                const outs = nodes.items[ni].out_edges.items;
                var found = false;
                for (outs) |tgt| {
                    if (tgt == idxs.items[k]) {
                        found = true;
                        break;
                    }
                }
                if (found) tmp_in.append(this.allocator, @intCast(ni)) catch {};
            }
            if (this.opts.show_chains and tmp_in.items.len > 0) {
                // Print up to 2 inbound chains (depth <= 3)
                const max_chains: usize = @min(@as(usize, 2), tmp_in.items.len);
                var chain_idx: usize = 0;
                while (chain_idx < max_chains) : (chain_idx += 1) {
                    const first = tmp_in.items[chain_idx];
                    // Greedy chain starting at 'first'
                    var chain: [4]u32 = undefined;
                    var used: [4]u32 = undefined;
                    var used_len: usize = 0;
                    var chain_len: usize = 0;
                    const target_idx: u32 = idxs.items[k];
                    chain[chain_len] = target_idx;
                    chain_len += 1;
                    used[used_len] = target_idx;
                    used_len += 1;
                    var cur = target_idx;
                    var depth2: usize = 0;
                    while (depth2 < 3) : (depth2 += 1) {
                        // Build inbound for cur
                        var inbound_for_cur: std.ArrayList(u32) = .empty;
                        defer inbound_for_cur.deinit(this.allocator);
                        var xi: usize = 0;
                        while (xi < nodes.items.len) : (xi += 1) {
                            const outs2 = nodes.items[xi].out_edges.items;
                            var found2 = false;
                            for (outs2) |t2| {
                                if (t2 == cur) {
                                    found2 = true;
                                    break;
                                }
                            }
                            if (found2) inbound_for_cur.append(this.allocator, @intCast(xi)) catch {};
                        }
                        // pick first not used
                        var picked: ?u32 = null;
                        var yi: usize = 0;
                        while (yi < inbound_for_cur.items.len) : (yi += 1) {
                            const cand = inbound_for_cur.items[yi];
                            var seen = false;
                            var uj: usize = 0;
                            while (uj < used_len) : (uj += 1) {
                                if (used[uj] == cand) {
                                    seen = true;
                                    break;
                                }
                            }
                            if (depth2 == 0 and cand != first) continue; // force first hop
                            if (!seen and cand != cur) {
                                picked = cand;
                                break;
                            }
                        }
                        if (picked) |p| {
                            cur = p;
                            chain[chain_len] = cur;
                            chain_len += 1;
                            used[used_len] = cur;
                            used_len += 1;
                        } else break;
                    }
                    if (chain_len > 1) {
                        outPrint("      chain{d}: ", .{chain_idx + 1});
                        var ci: isize = @as(isize, @intCast(chain_len)) - 1;
                        while (ci >= 0) : (ci -= 1) {
                            const ni2: u32 = chain[@intCast(ci)];
                            const nd2 = nodes.items[ni2];
                            if (nd2.container_name) |cn| {
                                outPrint("{s}.{s}{s}", .{ cn, nd2.name, if (ci == 0) "" else " -> " });
                            } else {
                                outPrint("{s}{s}", .{ nd2.name, if (ci == 0) "" else " -> " });
                            }
                        }
                        outPrint("\n", .{});
                    }
                }
            }
        }
    }
};
