//! Minimal, robust CLI for ZLS hover and symbols
//! Usage:
//!   hover info <file> <line> <column> [--plaintext]
//!   hover symbols <file> [--plain]
//!   hover actions <file> <line> <column> [<end_line> <end_col>] [--kind refactor|quickfix|source]
//!   hover apply <file> <line> <column> [<end_line> <end_col>] <index>
//!   hover refactor <file> <line> <column> [<end_line> <end_col>] [--apply N]
//!   hover [path]                  # Project overview report (default)
//!   hover --help

const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;
const hover_util = @import("hover/util.zig");
const hover_server = @import("hover/server.zig");
const hover_opts = @import("hover/options.zig");
const hover_symbols = @import("hover/symbols.zig");
const hover_pagerank = @import("hover/pagerank.zig");

// TODO: When ZLS exposes symbol→decl mapping and structured signature/type
// APIs, migrate printing to use those directly for richer details (visibility,
// attributes, fully-qualified types) without additional AST probing here.

const outPrint = hover_util.outPrint;

const Usage =
    \\\hover - Simple ZLS helper
    \\\n+    \\\USAGE:
    \\\  hover info <file> <line> <column> [--markdown|--plaintext]
    \\\  hover symbols <file> [--public] [--private] [--imports] [--locations] [--api] [--minimal]
    \\\  hover actions <file> <line> <column> [<end_line> <end_col>] [--kind refactor|quickfix|source]
    \\\  hover apply <file> <line> <column> [<end_line> <end_col>] <index>
    \\\  hover refactor <file> <line> <column> [<end_line> <end_col>] [--apply N]
    \\\  hover --help
    \\\n+    \\\SYMBOLS OPTIONS:
    \\\  --public       Show only public symbols (default)
    \\\  --private      Include private symbols
    \\\  --imports      Show imports section (default)
    \\\  --locations    Show line numbers
    \\\  --api          Public API only (types + functions, no imports)
    \\\  --minimal      Types and public functions only
    \\\n+    \\\NOTES:
    \\\  - line/column are 1-based (as shown by editors)
    \\\  - info prints hover text at the given position
    \\\  - symbols prints the document symbol tree
;

const Command = enum { info, symbols, report, pagerank, xref, actions, apply, refactor };

const SymbolsOptions = hover_opts.SymbolsOptions;

fn parseArgs(allocator: std.mem.Allocator) !struct {
    cmd: Command,
    file: []const u8,
    line: u32,
    col: u32,
    end_line: u32,
    end_col: u32,
    action_index: ?usize,
    kind_filter: ?types.CodeActionKind,
    do_apply: bool,
    markdown: bool,
    symbols_opts: SymbolsOptions,
    args_mem: [][:0]u8,
} {
    const argv = try std.process.argsAlloc(allocator);
    if (argv.len >= 2 and (std.mem.eql(u8, argv[1], "--help") or std.mem.eql(u8, argv[1], "-h"))) {
        outPrint("{s}", .{Usage});
        std.process.exit(0);
    }

    // Default: report
    var cmd: Command = .report;
    var argi: usize = 1;
    if (argv.len >= 2) {
        if (std.mem.eql(u8, argv[1], "info")) { cmd = .info; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "symbols")) { cmd = .symbols; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "pagerank")) { cmd = .pagerank; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "xref")) { cmd = .xref; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "actions")) { cmd = .actions; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "apply")) { cmd = .apply; argi = 2; }
        else if (std.mem.eql(u8, argv[1], "refactor")) { cmd = .refactor; argi = 2; }
        else if (std.mem.startsWith(u8, argv[1], "-")) { cmd = .report; argi = 1; }
        else { cmd = .report; argi = 1; }
    }

    // Defaults
    var file: []const u8 = if (argv.len > 2) argv[2] else "";
    var line: u32 = 0;
    var col: u32 = 0;
    var markdown = false; // default plaintext per requirements
    var end_line: u32 = 0;
    var end_col: u32 = 0;
    var action_index: ?usize = null;
    var kind_filter: ?types.CodeActionKind = null;
    var do_apply = false;
    var symbols_opts = SymbolsOptions{};

    switch (cmd) {
        .info => {
            if (argv.len < 5) {
                std.debug.print("Error: info needs <file> <line> <column>\n\n{s}", .{Usage});
                return error.InvalidArgs;
            }
            line = try std.fmt.parseInt(u32, argv[3], 10);
            col = try std.fmt.parseInt(u32, argv[4], 10);
            var i: usize = 5;
            while (i < argv.len) : (i += 1) {
                if (std.mem.eql(u8, argv[i], "--plaintext") or std.mem.eql(u8, argv[i], "--plain")) markdown = false;
                if (std.mem.eql(u8, argv[i], "--markdown")) markdown = true;
            }
        },
        .symbols => {
            if (argv.len < 3) {
                outPrint("Error: symbols needs <file>\n\n{s}", .{Usage});
                return error.InvalidArgs;
            }
            var i: usize = 3;
            while (i < argv.len) : (i += 1) {
                if (std.mem.eql(u8, argv[i], "--public")) {
                    symbols_opts.show_public = true;
                    symbols_opts.show_private = false;
                } else if (std.mem.eql(u8, argv[i], "--private")) {
                    symbols_opts.show_private = true;
                } else if (std.mem.eql(u8, argv[i], "--imports")) {
                    symbols_opts.show_imports = true;
                } else if (std.mem.eql(u8, argv[i], "--locations")) {
                    symbols_opts.show_locations = true;
                } else if (std.mem.eql(u8, argv[i], "--api")) {
                    symbols_opts.api_only = true;
                    symbols_opts.show_imports = false;
                } else if (std.mem.eql(u8, argv[i], "--minimal")) {
                    symbols_opts.minimal = true;
                    symbols_opts.show_imports = false;
                } else if (std.mem.eql(u8, argv[i], "--plaintext") or std.mem.eql(u8, argv[i], "--plain")) {
                    markdown = false;
                } else if (std.mem.eql(u8, argv[i], "--markdown")) {
                    markdown = true;
                }
            }
        },
        .pagerank => {
            if (argv.len >= 3 and !std.mem.startsWith(u8, argv[2], "-")) {
                file = argv[2];
            } else if (file.len == 0) {
                file = ".";
            }
        },
        .xref => {
            if (argv.len < 5) return error.InvalidArgs;
            file = argv[2];
            line = try std.fmt.parseInt(u32, argv[3], 10);
            col = try std.fmt.parseInt(u32, argv[4], 10);
        },
        .actions => {
            if (argv.len < 5) return error.InvalidArgs;
            file = argv[2];
            line = try std.fmt.parseInt(u32, argv[3], 10);
            col = try std.fmt.parseInt(u32, argv[4], 10);
            var i: usize = 5;
            if (argv.len >= 7) {
                const maybe_end_line: ?u32 = std.fmt.parseInt(u32, argv[5], 10) catch null;
                const maybe_end_col: ?u32 = if (argv.len >= 7) std.fmt.parseInt(u32, argv[6], 10) catch null else null;
                if (maybe_end_line != null and maybe_end_col != null) {
                    end_line = maybe_end_line.?;
                    end_col = maybe_end_col.?;
                    i = 7;
                }
            }
            while (i < argv.len) : (i += 1) {
                if (std.mem.eql(u8, argv[i], "--kind") and i + 1 < argv.len) {
                    const k = argv[i + 1];
                    if (std.mem.eql(u8, k, "refactor")) kind_filter = .refactor
                    else if (std.mem.eql(u8, k, "quickfix")) kind_filter = .quickfix
                    else if (std.mem.eql(u8, k, "source")) kind_filter = .source;
                    i += 1;
                } else if (std.mem.eql(u8, argv[i], "--apply")) {
                    do_apply = true;
                }
            }
        },
        .apply => {
            if (argv.len < 6) return error.InvalidArgs;
            file = argv[2];
            line = try std.fmt.parseInt(u32, argv[3], 10);
            col = try std.fmt.parseInt(u32, argv[4], 10);
            var i: usize = 5;
            if (argv.len >= 7 and !std.mem.startsWith(u8, argv[5], "-")) {
                end_line = try std.fmt.parseInt(u32, argv[5], 10);
                end_col = try std.fmt.parseInt(u32, argv[6], 10);
                i = 7;
            }
            while (i < argv.len) : (i += 1) {
                if (std.mem.eql(u8, argv[i], "--kind") and i + 1 < argv.len) {
                    const k = argv[i + 1];
                    if (std.mem.eql(u8, k, "refactor")) kind_filter = .refactor
                    else if (std.mem.eql(u8, k, "quickfix")) kind_filter = .quickfix
                    else if (std.mem.eql(u8, k, "source")) kind_filter = .source;
                    i += 1;
                } else if (std.mem.eql(u8, argv[i], "--apply")) {
                    do_apply = true;
                } else {
                    action_index = std.fmt.parseInt(usize, argv[i], 10) catch null;
                }
            }
            if (action_index == null) return error.InvalidArgs;
        },
        .refactor => {
            if (argv.len < 5) return error.InvalidArgs;
            file = argv[2];
            line = try std.fmt.parseInt(u32, argv[3], 10);
            col = try std.fmt.parseInt(u32, argv[4], 10);
            kind_filter = .refactor;
            var i: usize = 5;
            if (argv.len >= 7) {
                const maybe_end_line: ?u32 = std.fmt.parseInt(u32, argv[5], 10) catch null;
                const maybe_end_col: ?u32 = if (argv.len >= 7) std.fmt.parseInt(u32, argv[6], 10) catch null else null;
                if (maybe_end_line != null and maybe_end_col != null) {
                    end_line = maybe_end_line.?;
                    end_col = maybe_end_col.?;
                    i = 7;
                }
            }
            while (i < argv.len) : (i += 1) {
                if (std.mem.eql(u8, argv[i], "--apply")) {
                    // If followed by a number, it's the index selector; otherwise it's the write flag
                    if (i + 1 < argv.len) {
                        const nxt = argv[i + 1];
                        const idx = std.fmt.parseInt(usize, nxt, 10) catch null;
                        if (idx) |val| { action_index = val; i += 1; }
                        else do_apply = true;
                    } else do_apply = true;
                }
            }
        },
        .report => {
            // Optional path argument
            if (argv.len >= 2 and !std.mem.eql(u8, argv[1], "report") and !std.mem.eql(u8, argv[1], "info") and !std.mem.eql(u8, argv[1], "symbols") and !std.mem.startsWith(u8, argv[1], "-")) {
                file = argv[1];
            } else {
                file = ".";
            }
        },
    }

    return .{ .cmd = cmd, .file = file, .line = line, .col = col, .end_line = end_line, .end_col = end_col, .action_index = action_index, .kind_filter = kind_filter, .do_apply = do_apply, .markdown = markdown, .symbols_opts = symbols_opts, .args_mem = argv };
}

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

fn reportProject(allocator: std.mem.Allocator, server: *zls.Server, root_path: []const u8) !void {
    const abs_root = try std.fs.cwd().realpathAlloc(allocator, root_path);
    var files: std.ArrayList([]const u8) = .empty;
    try walkZigFiles(allocator, abs_root, &files);

    var total_syms: usize = 0;
    var kind_counts = std.AutoHashMap(types.SymbolKind, usize).init(allocator);

    const max_files: usize = @min(files.items.len, 200);
    var i: usize = 0;
    while (i < max_files) : (i += 1) {
        const p = files.items[i];
        const content = std.fs.cwd().readFileAlloc(allocator, p, std.math.maxInt(usize)) catch continue;
        const h = openDocument(server, allocator, p, content) catch continue;
        const params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = h.uri } };
        const syms = server.sendRequestSync(allocator, "textDocument/documentSymbol", params) catch continue;
        if (syms) |resp| switch (resp) {
            .array_of_DocumentSymbol => |arr| {
                total_syms += arr.len;
                for (arr) |s| {
                    const e = try kind_counts.getOrPut(s.kind);
                    if (!e.found_existing) e.value_ptr.* = 0;
                    e.value_ptr.* += 1;
                }
            },
            .array_of_SymbolInformation => |infos| {
                total_syms += infos.len;
                for (infos) |si| {
                    const e = try kind_counts.getOrPut(si.kind);
                    if (!e.found_existing) e.value_ptr.* = 0;
                    e.value_ptr.* += 1;
                }
            },
        };
    }

    outPrint("Project: {s}\n", .{abs_root});
    outPrint("Files scanned: {d}\nSymbols: {d}\n", .{ max_files, total_syms });
    outPrint("Top kinds:\n", .{});
    // Dump a few counts
    var it = kind_counts.iterator();
    var shown: usize = 0;
    while (it.next()) |kv| : (shown += 1) {
        if (shown >= 10) break;
        outPrint("  {s:<12} {d}\n", .{ @tagName(kv.key_ptr.*), kv.value_ptr.* });
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

fn listCodeActions(allocator: std.mem.Allocator, server: *zls.Server, file: []const u8, line: u32, col: u32, end_line: u32, end_col: u32, kind_filter: ?types.CodeActionKind) !void {
    const content = try std.fs.cwd().readFileAlloc(allocator, file, std.math.maxInt(usize));
    const handle = try openDocument(server, allocator, file, content);

    const start_pos: types.Position = .{ .line = line - 1, .character = col - 1 };
    const end_pos: types.Position = if (end_line != 0) .{ .line = end_line - 1, .character = end_col - 1 } else start_pos;
    const params: types.CodeActionParams = .{
        .textDocument = .{ .uri = handle.uri },
        .range = .{ .start = start_pos, .end = end_pos },
        .context = .{ .diagnostics = &.{}, .only = if (kind_filter) |k| &.{k} else null },
    };
    const response = try server.sendRequestSync(allocator, "textDocument/codeAction", params) orelse {
        outPrint("No actions.\n", .{});
        return;
    };

    var count: usize = 0;
    for (response, 0..) |item, idx| {
        const action = item.CodeAction;
        const kind_str = if (action.kind) |k| @tagName(k) else "";
        outPrint("{d}: {s}{s}{s}{s}\n", .{ idx, action.title, if (kind_str.len != 0) " [" else "", if (kind_str.len != 0) kind_str else "", if (kind_str.len != 0) "]" else "" });
        count += 1;
    }
    if (count == 0) outPrint("No actions.\n", .{});
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
    // Program-scoped arena allocator: allocate all memory from here and
    // skip fine-grained deallocation throughout the CLI.
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const parsed = parseArgs(allocator) catch {
        std.debug.print("{s}", .{Usage});
        return 1;
    };
    // No-op with program-scoped arena
    defer freeArgs(allocator, parsed.args_mem);

    const server = initServer(allocator, parsed.markdown) catch |e| {
        outPrint("Error initializing server: {any}\n", .{e});
        return 1;
    };
    defer server.destroy();

    switch (parsed.cmd) {
        .report => {
            reportProject(allocator, server, parsed.file) catch |e| {
                outPrint("Report error: {any}\n", .{e});
                return 1;
            };
            return 0;
        },
        .pagerank => {
            hover_pagerank.pagerank(server, allocator, parsed.file) catch |e| {
                outPrint("Pagerank error: {any}\n", .{e});
                return 1;
            };
            return 0;
        },
        .xref => {
            handleXref(allocator, server, parsed.file, parsed.line, parsed.col) catch |e| {
                outPrint("Xref error: {any}\n", .{e});
                return 1;
            };
            return 0;
        },
        .actions => {
            listCodeActions(allocator, server, parsed.file, parsed.line, parsed.col, parsed.end_line, parsed.end_col, parsed.kind_filter) catch |e| {
                outPrint("Actions error: {any}\n", .{e});
                return 1;
            };
            return 0;
        },
        .apply => {
            const content = std.fs.cwd().readFileAlloc(allocator, parsed.file, std.math.maxInt(usize)) catch |e| {
                outPrint("Error reading '{s}': {any}\n", .{ parsed.file, e });
                return 1;
            };
            const handle = openDocument(server, allocator, parsed.file, content) catch |e| {
                outPrint("Failed to open document: {any}\n", .{e});
                return 1;
            };
            const start_pos: types.Position = .{ .line = parsed.line - 1, .character = parsed.col - 1 };
            const end_pos: types.Position = if (parsed.end_line != 0) .{ .line = parsed.end_line - 1, .character = parsed.end_col - 1 } else start_pos;
            const params: types.CodeActionParams = .{
                .textDocument = .{ .uri = handle.uri },
                .range = .{ .start = start_pos, .end = end_pos },
                .context = .{ .diagnostics = &.{}, .only = if (parsed.kind_filter) |k| &.{k} else null },
            };
            const response = server.sendRequestSync(allocator, "textDocument/codeAction", params) catch |e| {
                outPrint("Actions request error: {any}\n", .{e});
                return 1;
            };
            if (response == null) {
                outPrint("No actions.\n", .{});
                return 1;
            }
            const actions = response.?;
            if (parsed.action_index == null or parsed.action_index.? >= actions.len) {
                outPrint("Invalid action index. Run 'hover actions' to list.\n", .{});
                return 1;
            }
            const chosen = actions[parsed.action_index.?].CodeAction;
            if (chosen.edit) |we| {
                // Dry-run by default; require --apply to write and format
                const dry = !parsed.do_apply;
                applyWorkspaceEditToFs(allocator, server, we, dry) catch |e| {
                    outPrint("Apply error: {any}\n", .{e});
                    return 1;
                };
                if (dry) {
                    outPrint("\nPreview only. Re-run with --apply to write changes.\n", .{});
                } else {
                    outPrint("Applied: {s}\n", .{chosen.title});
                }
                return 0;
            } else {
                outPrint("Selected action has no edit.\n", .{});
                return 1;
            }
        },
        .refactor => {
            // If no --apply is given, list refactor options for the range
            if (parsed.action_index == null) {
                listCodeActions(allocator, server, parsed.file, parsed.line, parsed.col, parsed.end_line, parsed.end_col, .refactor) catch |e| {
                    outPrint("Refactor error: {any}\n", .{e});
                    return 1;
                };
                return 0;
            }

            const content = std.fs.cwd().readFileAlloc(allocator, parsed.file, std.math.maxInt(usize)) catch |e| {
                outPrint("Error reading '{s}': {any}\n", .{ parsed.file, e });
                return 1;
            };
            const handle = openDocument(server, allocator, parsed.file, content) catch |e| {
                outPrint("Failed to open document: {any}\n", .{e});
                return 1;
            };
            const start_pos: types.Position = .{ .line = parsed.line - 1, .character = parsed.col - 1 };
            const end_pos: types.Position = if (parsed.end_line != 0) .{ .line = parsed.end_line - 1, .character = parsed.end_col - 1 } else start_pos;
            const params: types.CodeActionParams = .{
                .textDocument = .{ .uri = handle.uri },
                .range = .{ .start = start_pos, .end = end_pos },
                .context = .{ .diagnostics = &.{}, .only = &.{ .refactor } },
            };
            const response = server.sendRequestSync(allocator, "textDocument/codeAction", params) catch |e| {
                outPrint("Refactor request error: {any}\n", .{e});
                return 1;
            };
            if (response == null) {
                outPrint("No refactors.\n", .{});
                return 1;
            }
            const actions = response.?;
            if (parsed.action_index.? >= actions.len) {
                outPrint("Invalid refactor index.\n", .{});
                return 1;
            }
            const chosen = actions[parsed.action_index.?].CodeAction;
            if (chosen.edit) |we| {
                const dry = !parsed.do_apply;
                applyWorkspaceEditToFs(allocator, server, we, dry) catch |e| {
                    outPrint("Apply error: {any}\n", .{e});
                    return 1;
                };
                if (dry) {
                    outPrint("\nPreview only. Re-run with --apply to write changes.\n", .{});
                } else {
                    outPrint("Applied: {s}\n", .{chosen.title});
                }
                return 0;
            } else {
                outPrint("Selected refactor has no edit.\n", .{});
                return 1;
            }
        },
        .info => {
            const content = std.fs.cwd().readFileAlloc(allocator, parsed.file, std.math.maxInt(usize)) catch |e| {
                outPrint("Error reading '{s}': {any}\n", .{ parsed.file, e });
                return 1;
            };
            const handle = openDocument(server, allocator, parsed.file, content) catch |e| {
                outPrint("Failed to open document: {any}\n", .{e});
                return 1;
            };
            const params: types.HoverParams = .{
                .textDocument = .{ .uri = handle.uri },
                .position = .{ .line = parsed.line - 1, .character = parsed.col - 1 },
            };
            const result = server.sendRequestSync(allocator, "textDocument/hover", params) catch |e| {
                outPrint("Hover error: {any}\n", .{e});
                return 1;
            };
            if (result) |hover_val| {
                const mc = hover_val.contents.MarkupContent;
                outPrint("{s}\n", .{mc.value});
            } else {
                outPrint("No hover info.\n", .{});
            }
        },
        .symbols => {
            const abs_path = std.fs.cwd().realpathAlloc(allocator, parsed.file) catch |e| {
                outPrint("Error resolving path '{s}': {any}\n", .{ parsed.file, e });
                return 1;
            };
            
            // Check if it's a single file or directory
            const stat = std.fs.cwd().statFile(abs_path) catch |e| {
                outPrint("Error accessing '{s}': {any}\n", .{ abs_path, e });
                return 1;
            };
            
            if (stat.kind == .file and std.mem.endsWith(u8, abs_path, ".zig")) {
                // Handle single file
                const content = std.fs.cwd().readFileAlloc(allocator, abs_path, std.math.maxInt(usize)) catch |e| {
                    outPrint("Error reading '{s}': {any}\n", .{ abs_path, e });
                    return 1;
                };
                const handle = openDocument(server, allocator, abs_path, content) catch |e| {
                    outPrint("Failed to open document: {any}\n", .{e});
                    return 1;
                };
                const params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = handle.uri } };
                const syms = server.sendRequestSync(allocator, "textDocument/documentSymbol", params) catch |e| {
                    outPrint("Symbols error: {any}\n", .{e});
                    return 1;
                };
                if (syms) |resp| {
                    outPrint("File: {s}\n", .{abs_path});
                    switch (resp) {
                        .array_of_DocumentSymbol => |arr| printSymbols(allocator, server, handle, arr, parsed.symbols_opts),
                        .array_of_SymbolInformation => |infos| printSymbolInformation(infos),
                    }
                } else {
                    outPrint("No symbols in {s}.\n", .{abs_path});
                }
            } else if (stat.kind == .directory) {
                // Handle directory - walk all .zig files
                var files: std.ArrayList([]const u8) = .empty;
                walkZigFiles(allocator, abs_path, &files) catch |e| {
                    outPrint("Error walking directory '{s}': {any}\n", .{ abs_path, e });
                    return 1;
                };
                
                var total_symbols: usize = 0;
                const max_files: usize = @min(files.items.len, 50); // Limit to avoid spam
                for (files.items[0..max_files]) |file_path| {
                    const content = std.fs.cwd().readFileAlloc(allocator, file_path, std.math.maxInt(usize)) catch continue;
                    const handle = openDocument(server, allocator, file_path, content) catch continue;
                    const params: types.DocumentSymbolParams = .{ .textDocument = .{ .uri = handle.uri } };
                    const syms = server.sendRequestSync(allocator, "textDocument/documentSymbol", params) catch continue;
                    if (syms) |resp| {
                        const rel_path = if (std.mem.startsWith(u8, file_path, abs_path)) 
                            file_path[abs_path.len..] 
                        else 
                            file_path;
                        switch (resp) {
                            .array_of_DocumentSymbol => |arr| {
                                if (arr.len > 0) {
                                    outPrint("\n📁 {s} ({d} symbols)\n", .{rel_path, arr.len});
                                    printSymbols(allocator, server, handle, arr, parsed.symbols_opts);
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
            } else {
                outPrint("'{s}' is not a .zig file or directory\n", .{abs_path});
                return 1;
            }
        },
    }

    return 0;
}
