//! Minimal, robust CLI for ZLS hover and symbols
//! Usage:
//!   hover info <file> [line] [column]  # Shows symbols for file/dir, or hover info for line/col
//!   hover pagerank [path]
//!   hover xref <file> <line> <column>
//!   hover refactor <file> <line> <column> [<end_line> <end_col>] [--apply N]

const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;
const offsets = zls.offsets;
const Analyser = zls.Analyser;
const hover_util = @import("hover/util.zig");
const hover_server = @import("hover/server.zig");
const hover_opts = @import("hover/options.zig");
const hover_symbols = @import("hover/symbols.zig");
const hover_pagerank = @import("hover/pagerank.zig");
const hover_argv = @import("hover/argv.zig");

// TODO: When ZLS exposes symbol→decl mapping and structured signature/type
// APIs, migrate printing to use those directly for richer details (visibility,
// attributes, fully-qualified types) without additional AST probing here.

const outPrint = hover_util.outPrint;


const Command = enum { info, pagerank, xref, refactor };

const SymbolsOptions = hover_opts.SymbolsOptions;

const InfoArgs = struct {
    file: []const u8 = "",
    line: u32 = 0,
    col: u32 = 0,
    @"--public": bool = false,
    @"--private": bool = false,
    @"--imports": bool = false,
    @"--locations": bool = false,
    @"--api": bool = false,
    @"--minimal": bool = false,
};


const PagerankArgs = struct {
    path: []const u8 = ".",
    @"--surf-main": bool = false,
    @"--surf-from": ?[]const u8 = null,
    @"--show-sites": bool = true,
    @"--show-chains": bool = true,
};

const XrefArgs = struct {
    file: []const u8 = "",
    line: u32 = 0,
    col: u32 = 0,
};


const RefactorArgs = struct {
    file: []const u8 = "",
    line: u32 = 0,
    col: u32 = 0,
    end_line: ?u32 = null,
    end_col: ?u32 = null,
    @"--apply": ?usize = null,
};


// Union-based subcommand parsing via argv.parseArgs/dispatch
const Cli = union(enum) {
    pagerank: PagerankArgs,
    xref: XrefArgs,
    refactor: RefactorArgs,
    info: InfoArgs,
};

const HoverCtx = struct {
    allocator: std.mem.Allocator,
    server: ?*zls.Server = null,
    pub fn ensureServer(self: *HoverCtx) !*zls.Server {
        if (self.server) |s| return s;
        const s = try initServer(self.allocator, false);
        self.server = s;
        return s;
    }
};

fn freeArgs(_: std.mem.Allocator, _: [][:0]u8) void {
    // Program-scoped arena: no-op deallocation
}

const initServer = hover_server.initServer;

const openDocument = hover_server.openDocument;

const analyzeSymbolsWithZLS = hover_symbols.analyzeSymbolsWithZLS;

// moved to hover/symbols.zig

// moved to hover/symbols.zig


// Print a top-level function symbol with its structured signature when available.
// Leverages symbol.detail which document_symbol fills using ZLS analysis.
// moved to hover/symbols.zig

// Print a method inside a container with indentation and signature when available.
// moved to hover/symbols.zig








// moved to hover/symbols.zig

// moved to hover/symbols.zig



const printSymbols = hover_symbols.printSymbols;

const printSymbolInformation = hover_symbols.printSymbolInformation;

// moved to hover/symbols.zig

const printDiff = hover_util.printDiff;

const runZigFmt = hover_util.runZigFmt;

fn walkZigFiles(allocator: std.mem.Allocator, root_dir_path: []const u8, out_list: *std.ArrayList([]const u8)) !void {
    var stack: std.ArrayList([]const u8) = .empty;
    try stack.append(allocator, try allocator.dupe(u8, root_dir_path));

    const ignore_dirs = [_][]const u8{ ".git", "zig-cache", "zig-out", ".zig-cache", "target", "node_modules" };

    while (stack.items.len > 0 and out_list.items.len < 800) {
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
        // No-op free with program-scoped arena
    }
}


const PRNode = struct {
    name: []const u8,
    kind: types.SymbolKind,
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

fn handlePagerank(allocator: std.mem.Allocator, server: *zls.Server, root_path: []const u8) !void {
    var timer = std.time.Timer.start() catch return;
    
    const abs_root = try std.fs.cwd().realpathAlloc(allocator, root_path);
    var files: std.ArrayList([]const u8) = .empty;
    
    // Check if it's a single file or directory
    const stat = std.fs.cwd().statFile(abs_root) catch blk: {
        // Try as directory if file stat fails
        try walkZigFiles(allocator, abs_root, &files);
        break :blk null;
    };
    
    if (stat) |s| {
        if (s.kind == .file and std.mem.endsWith(u8, abs_root, ".zig")) {
            try files.append(allocator, abs_root);
        } else if (s.kind == .directory) {
            try walkZigFiles(allocator, abs_root, &files);
        }
    }
    
    const file_walk_time = timer.lap();
    std.debug.print("[DEBUG] File discovery: {}ms (found {} files)\n", .{file_walk_time / std.time.ns_per_ms, files.items.len});

    var nodes: std.ArrayList(PRNode) = .empty;
    var index_by_key = std.StringHashMap(u32).init(allocator);

    const max_files: usize = @min(files.items.len, 150);
    var i: usize = 0;
    while (i < max_files and nodes.items.len < 600) : (i += 1) {
        const p = files.items[i];
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = openDocument(server, allocator, p, content) catch continue;
        // Use internal symbol builder directly (no LSP roundtrip)
        const arr = zls.document_symbol.getDocumentSymbols(allocator, h.tree, server.offset_encoding) catch continue;
        for (arr) |s| {
            if (!(s.kind == .Function or s.kind == .Method)) continue;
            const key = std.fmt.allocPrint(allocator, "{s}:{d}", .{ h.uri, s.selectionRange.start.line }) catch continue;
            if (index_by_key.get(key)) |_| { continue; }
            const node = PRNode{
                .name = allocator.dupe(u8, s.name) catch continue,
                .kind = s.kind,
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
    std.debug.print("[DEBUG] Node building: {}ms ({} nodes from {} files)\n", .{node_build_time / std.time.ns_per_ms, nodes.items.len, max_files});

    var syms_cache = std.StringHashMap([]const types.DocumentSymbol).init(allocator);

    var j: usize = 0;
    var refs_processed: usize = 0;
    var total_ref_requests: usize = 0;
    var total_symbol_requests: usize = 0;
    var cache_hits: usize = 0;
    var edges_added: usize = 0;
    var node_batch_timer = timer.lap();
    
    while (j < nodes.items.len) : (j += 1) {
        const node_start = timer.read();
        const n = nodes.items[j];
        
        // Time the reference request
        const ref_start = timer.read();
        // Use internal references handler directly (no LSP transport)
        const refs_response = zls.references.referencesHandler(server, allocator, .{ .references = .{
            .textDocument = .{ .uri = n.uri },
            .position = n.pos,
            .context = .{ .includeDeclaration = false },
        } }) catch continue;
        const refs = if (refs_response) |rep| rep.references else null;
        total_ref_requests += 1;
        const ref_time = timer.read() - ref_start;
        
        if (refs) |locs| {
            refs_processed += locs.len;
            for (locs) |loc| {
                const caller_uri = loc.uri;
                const sym_start = timer.read();
                const caller_syms = blk: {
                    if (syms_cache.get(caller_uri)) |arr| {
                        cache_hits += 1;
                        break :blk arr;
                    }
                    const h2 = server.document_store.getOrLoadHandle(caller_uri) orelse break :blk &[_]types.DocumentSymbol{};
                    const arr2 = zls.document_symbol.getDocumentSymbols(allocator, h2.tree, server.offset_encoding) catch break :blk &[_]types.DocumentSymbol{};
                    total_symbol_requests += 1;
                    _ = syms_cache.put(allocator.dupe(u8, caller_uri) catch break :blk arr2, arr2) catch {};
                    break :blk arr2;
                };
                _ = timer.read() - sym_start; // sym_time unused
                
                var caller_idx: ?u32 = null;
                for (caller_syms) |s| {
                    const r = s.range;
                    const p = loc.range.start;
                    const within = (p.line >= r.start.line and p.line <= r.end.line);
                    if (within and (s.kind == .Function or s.kind == .Method)) {
                        const key = std.fmt.allocPrint(allocator, "{s}:{d}", .{ caller_uri, s.selectionRange.start.line }) catch continue;
                        if (index_by_key.get(key)) |idx| caller_idx = idx;
                        break;
                    }
                }
                if (caller_idx) |from| {
                    nodes.items[@intCast(from)].out_edges.append(allocator, @intCast(j)) catch {};
                    edges_added += 1;
                }
            }
        }
        
        _ = timer.read() - node_start; // node_time unused
        if ((j + 1) % 5 == 0 or j + 1 == nodes.items.len) {
            const batch_time = timer.lap() - node_batch_timer;
            const progress_time = timer.read() / std.time.ns_per_ms;
            std.debug.print("[DEBUG] Batch {}-{}: {}ms | Node '{s}': refs={}, refTime={}ms | Total: {}ms, edges={}\n", 
                .{j - 4, j + 1, batch_time / std.time.ns_per_ms, n.name, if (refs) |r| r.len else 0, 
                  ref_time / std.time.ns_per_ms, progress_time, edges_added});
            node_batch_timer = timer.read();
        }
        if ((j + 1) % 20 == 0 or j + 1 == nodes.items.len) {
            std.debug.print("[DEBUG] Stats: refReqs={}, symReqs={}, cacheHits={}, edges={}, refs={}\n", 
                .{total_ref_requests, total_symbol_requests, cache_hits, edges_added, refs_processed});
        }
    }
    
    const ref_analysis_time = timer.lap();
    std.debug.print("[DEBUG] Reference analysis complete: {}ms ({} total references)\n", .{ref_analysis_time / std.time.ns_per_ms, refs_processed});

    std.debug.print("[DEBUG] Starting PageRank computation (20 iterations, damping=0.85)...\n", .{});
    computePageRank(nodes.items, 20, 0.85, allocator);
    
    const pagerank_time = timer.lap();
    std.debug.print("[DEBUG] PageRank computation: {}ms\n", .{pagerank_time / std.time.ns_per_ms});
    
    var idxs = std.ArrayList(u32).empty;
    if (idxs.resize(allocator, nodes.items.len)) |_| {} else |_| return;
    for (idxs.items, 0..) |*v, k| v.* = @intCast(k);
    const Ctx = struct { nodes: []PRNode, pub fn lessThan(ctx: @This(), a: u32, b: u32) bool { return ctx.nodes[a].score > ctx.nodes[b].score; } };
    std.mem.sort(u32, idxs.items, Ctx{ .nodes = nodes.items }, Ctx.lessThan);
    
    const sort_time = timer.lap();
    std.debug.print("[DEBUG] Sorting results: {}ms\n", .{sort_time / std.time.ns_per_ms});
    
    const total_time = timer.read() / std.time.ns_per_ms;
    std.debug.print("[DEBUG] Total pagerank time: {}ms\n", .{total_time});
    
    const top = @min(@as(usize, 20), idxs.items.len);
    outPrint("PageRank Top {d} (functions/methods)\n", .{top});
    var k: usize = 0;
    while (k < top) : (k += 1) {
        const nd = nodes.items[idxs.items[k]];
        outPrint("  {d:2}. {s} ({s}) score={d:.5}\n", .{ k + 1, nd.name, nd.uri, nd.score });
    }
}

fn handleXref(allocator: std.mem.Allocator, server: *zls.Server, file: []const u8, line: u32, col: u32) !void {
    const content = try std.fs.cwd().readFileAlloc(allocator, file, std.math.maxInt(usize));
    const h = try openDocument(server, allocator, file, content);
    const refs = try server.sendRequestSync(allocator, "textDocument/references", .{
        .textDocument = .{ .uri = h.uri },
        .position = .{ .line = line - 1, .character = col - 1 },
        .context = .{ .includeDeclaration = false },
    });
    if (refs) |locs| {
        outPrint("References: {d}\n", .{locs.len});
        for (locs) |loc| {
            const path = zls.URI.toFsPath(allocator, loc.uri) catch loc.uri;
            outPrint("  {s}:{d}:{d}\n", .{ path, loc.range.start.line + 1, loc.range.start.character + 1 });
        }
    } else {
        outPrint("References: 0\n", .{});
    }
}


const ensureDirForFile = hover_util.ensureDirForFile;

fn applyWorkspaceEditToFs(allocator: std.mem.Allocator, server: *zls.Server, edit: types.WorkspaceEdit, dry_run: bool) !void {
    _ = dry_run; // suppress unused parameter warning
    if (edit.changes) |chg| {
        var it = chg.map.iterator();
        while (it.next()) |kv| {
            const uri = kv.key_ptr.*;
            const edits = kv.value_ptr.*;
            const path = zls.URI.toFsPath(allocator, uri) catch uri;
            const src = std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize)) catch "";
            const updated = try zls.diff.applyTextEdits(allocator, src, edits, server.offset_encoding);
            ensureDirForFile(path);
            try std.fs.cwd().writeFile(.{ .sub_path = path, .data = updated });
        }
    }

    if (edit.documentChanges) |ops| {
        for (ops) |op| switch (op) {
            .CreateFile => |cf| {
                const path = zls.URI.toFsPath(allocator, cf.uri) catch cf.uri;
                ensureDirForFile(path);
                // Create empty file if not exists
                _ = std.fs.cwd().createFile(path, .{ .truncate = false }) catch {};
            },
            .RenameFile => |rf| {
                const oldp = zls.URI.toFsPath(allocator, rf.oldUri) catch rf.oldUri;
                const newp = zls.URI.toFsPath(allocator, rf.newUri) catch rf.newUri;
                ensureDirForFile(newp);
                std.fs.cwd().rename(oldp, newp) catch |e| outPrint("Rename failed: {any}\n", .{e});
            },
            .DeleteFile => |df| {
                const path = zls.URI.toFsPath(allocator, df.uri) catch df.uri;
                std.fs.cwd().deleteFile(path) catch {};
            },
            .TextDocumentEdit => |tde| {
                const path = zls.URI.toFsPath(allocator, tde.textDocument.uri) catch tde.textDocument.uri;
                const src = std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(usize)) catch "";
                // Convert union array edits to plain TextEdits
                const edits_buf = try allocator.alloc(types.TextEdit, tde.edits.len);
                defer allocator.free(edits_buf);
                for (tde.edits, edits_buf) |e, *out| {
                    out.* = switch (e) {
                        .TextEdit => |te| te,
                        .AnnotatedTextEdit => |ae| .{ .range = ae.range, .newText = ae.newText },
                    };
                }
                const updated = try zls.diff.applyTextEdits(allocator, src, edits_buf, server.offset_encoding);
                ensureDirForFile(path);
                try std.fs.cwd().writeFile(.{ .sub_path = path, .data = updated });
            },
        };
    }
}

pub fn main() !u8 {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const argv = try std.process.argsAlloc(allocator);

    var ctx = HoverCtx{ .allocator = allocator };
    defer if (ctx.server) |s| s.destroy();

    const handlers = .{
        .pagerank = struct { fn f(c: *HoverCtx, args: PagerankArgs) !void {
            const server = try c.ensureServer();
            try hover_pagerank.pagerank(server, c.allocator, args.path, .{ .surf_main = args.@"--surf-main", .surf_from = args.@"--surf-from", .show_sites = args.@"--show-sites", .show_chains = args.@"--show-chains" });
        } }.f,
        .xref = struct { fn f(c: *HoverCtx, args: XrefArgs) !void {
            const server = try c.ensureServer();
            try handleXref(c.allocator, server, args.file, args.line, args.col);
        } }.f,
        .refactor = struct { fn f(c: *HoverCtx, args: RefactorArgs) !void {
            const server = try c.ensureServer();
            const content = try std.fs.cwd().readFileAlloc(c.allocator, args.file, std.math.maxInt(usize));
            const handle = try openDocument(server, c.allocator, args.file, content);
            const start_pos: types.Position = .{ .line = args.line - 1, .character = args.col - 1 };
            const end_pos: types.Position = if (args.end_line) |el| .{ .line = el - 1, .character = (args.end_col orelse 1) - 1 } else start_pos;
            const params: types.CodeActionParams = .{
                .textDocument = .{ .uri = handle.uri },
                .range = .{ .start = start_pos, .end = end_pos },
                .context = .{ .diagnostics = &.{}, .only = &.{ .refactor } },
            };
            const response = try server.sendRequestSync(c.allocator, "textDocument/codeAction", params);
            if (response == null) return error.NoActions;
            const actions = response.?;
            
            if (args.@"--apply") |idx| {
                if (idx >= actions.len) return error.InvalidIndex;
                const chosen = actions[idx].CodeAction;
                if (chosen.edit) |we| {
                    try applyWorkspaceEditToFs(c.allocator, server, we, false);
                    outPrint("Applied: {s}\n", .{chosen.title});
                } else return error.NoEdit;
            } else {
                // List available refactor actions
                var count: usize = 0;
                for (actions, 0..) |item, idx| {
                    const action = item.CodeAction;
                    const kind_str = if (action.kind) |k| @tagName(k) else "";
                    outPrint("{d}: {s}{s}{s}{s}\n", .{ idx, action.title, if (kind_str.len != 0) " [" else "", if (kind_str.len != 0) kind_str else "", if (kind_str.len != 0) "]" else "" });
                    count += 1;
                }
                if (count == 0) outPrint("No refactor actions.\n", .{});
            }
        } }.f,
        .info = struct { fn f(c: *HoverCtx, args: InfoArgs) !void {
            const server = try c.ensureServer();
            const abs_path = try std.fs.cwd().realpathAlloc(c.allocator, args.file);
            const stat = try std.fs.cwd().statFile(abs_path);
            
            if (args.line != 0 and args.col != 0) {
                // Always show hover info when line/column provided
                const content = try std.fs.cwd().readFileAlloc(c.allocator, args.file, std.math.maxInt(usize));
                const handle = try openDocument(server, c.allocator, args.file, content);
                const params: types.HoverParams = .{
                    .textDocument = .{ .uri = handle.uri },
                    .position = .{ .line = args.line - 1, .character = args.col - 1 },
                };
                const result = try server.sendRequestSync(c.allocator, "textDocument/hover", params);
                if (result) |hover_val| {
                    const mc = hover_val.contents.MarkupContent;
                    outPrint("{s}\n", .{mc.value});
                    
                    // Check if this position points to a container type and show its symbols
                    var analyser = server.initAnalyser(c.allocator, handle);
                    defer analyser.deinit();
                    const source_index = offsets.positionToIndex(handle.tree.source, .{ .line = args.line - 1, .character = args.col - 1 }, server.offset_encoding);
                    const pos_context = Analyser.getPositionContext(c.allocator, handle.tree, source_index, true) catch return;
                    
                    // Only show container members when pointing directly at type names, not variables of those types
                    const should_show_container = switch (pos_context) {
                        .var_access => blk: {
                            // Check if we're pointing at a type (not a variable instance)
                            if (Analyser.lookupSymbolGlobal(&analyser, handle, offsets.locToSlice(handle.tree.source, pos_context.var_access), source_index) catch null) |decl_with_handle| {
                                const resolved_type = decl_with_handle.resolveType(&analyser) catch null;
                                // Only show if this is a type value (like pointing at "Hasher" not "hasher")
                                if (resolved_type) |ty| {
                                    if (ty.is_type_val and (ty.isStructType() or ty.isEnumType() or ty.isUnionType())) {
                                        break :blk true;
                                    }
                                }
                            }
                            break :blk false;
                        },
                        else => false,
                    };
                    
                    if (should_show_container) {
                            const sym_params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = handle.uri } };
                            const syms = try server.sendRequestSync(c.allocator, "textDocument/documentSymbol", sym_params);
                            if (syms) |resp| {
                                outPrint("\nContainer members:\n", .{});
                                const opts: SymbolsOptions = .{
                                    .show_public = !args.@"--private",
                                    .show_private = args.@"--private",
                                    .show_imports = args.@"--imports",
                                    .show_locations = args.@"--locations",
                                    .api_only = args.@"--api",
                                    .minimal = args.@"--minimal",
                                };
                                switch (resp) {
                                    .array_of_DocumentSymbol => |arr| printSymbols(c.allocator, server, handle, arr, opts),
                                    .array_of_SymbolInformation => |infos| printSymbolInformation(infos),
                                }
                            }
                    }
                } else {
                    outPrint("No hover info.\n", .{});
                }
            } else if (stat.kind == .directory or (stat.kind == .file and std.mem.endsWith(u8, abs_path, ".zig"))) {
                // Handle symbols for file or directory when no line/column
                const opts: SymbolsOptions = .{
                    .show_public = !args.@"--private",
                    .show_private = args.@"--private",
                    .show_imports = args.@"--imports",
                    .show_locations = args.@"--locations",
                    .api_only = args.@"--api",
                    .minimal = args.@"--minimal",
                };
                if (stat.kind == .file and std.mem.endsWith(u8, abs_path, ".zig")) {
                    const content = try std.fs.cwd().readFileAlloc(c.allocator, abs_path, std.math.maxInt(usize));
                    const handle = try openDocument(server, c.allocator, abs_path, content);
                    const params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = handle.uri } };
                    const syms = try server.sendRequestSync(c.allocator, "textDocument/documentSymbol", params);
                    if (syms) |resp| {
                        outPrint("File: {s}\n", .{abs_path});
                        switch (resp) {
                            .array_of_DocumentSymbol => |arr| printSymbols(c.allocator, server, handle, arr, opts),
                            .array_of_SymbolInformation => |infos| printSymbolInformation(infos),
                        }
                    } else outPrint("No symbols in {s}.\n", .{abs_path});
                } else if (stat.kind == .directory) {
                    var files: std.ArrayList([]const u8) = .empty;
                    try walkZigFiles(c.allocator, abs_path, &files);
                    var total_symbols: usize = 0;
                    const max_files: usize = @min(files.items.len, 50);
                    for (files.items[0..max_files]) |file_path| {
                        const content = std.fs.cwd().readFileAlloc(c.allocator, file_path, std.math.maxInt(usize)) catch continue;
                        const handle = openDocument(server, c.allocator, file_path, content) catch continue;
                        const params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = handle.uri } };
                        const syms = server.sendRequestSync(c.allocator, "textDocument/documentSymbol", params) catch continue;
                        if (syms) |resp| {
                            const rel_path = if (std.mem.startsWith(u8, file_path, abs_path)) file_path[abs_path.len..] else file_path;
                            switch (resp) {
                                .array_of_DocumentSymbol => |arr| {
                                    if (arr.len > 0) {
                                        outPrint("\n📁 {s} ({d} symbols)\n", .{rel_path, arr.len});
                                        printSymbols(c.allocator, server, handle, arr, opts);
                                        total_symbols += arr.len;
                                    }
                                },
                                .array_of_SymbolInformation => |infos| {
                                    if (infos.len > 0) {
                                        outPrint("\n📁 {s} ({d} symbols)\n", .{rel_path, infos.len});
                                        printSymbolInformation(infos);
                                        total_symbols += infos.len;
                                    }
                                },
                            }
                        }
                    }
                    outPrint("\n📊 Summary: {d} symbols across {d} files\n", .{total_symbols, max_files});
                }
            } else {
                outPrint("Provide a .zig file or directory path.\n", .{});
                return error.InvalidUsage;
            }
        } }.f,
    };

    hover_argv.dispatch(Cli, allocator, argv, 1, &ctx, handlers) catch |e| {
        outPrint("Error: {any}\n", .{e});
        return 1;
    };
    return 0;
}
