const std = @import("std");
const Ast = std.zig.Ast;
const DocumentScope = @import("../DocumentScope.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");

const GenerateExtractFunctionCodeActionator = @This();

builder: *@import("code_actions.zig").Builder,
loc: offsets.Loc,

pub fn generateExtractFunctionCodeAction(this: *@This()) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!this.builder.wantKind(.refactor)) return;

    const tree = this.builder.handle.tree;
    const source = tree.source;

    // Selected code
    if (this.loc.end <= this.loc.start) return;

    // Trim whitespace and detect trailing semicolon
    var start_index = this.loc.start;
    var end_index = this.loc.end;
    while (start_index < end_index and std.ascii.isWhitespace(source[start_index])) start_index += 1;
    while (end_index > start_index and std.ascii.isWhitespace(source[end_index - 1])) end_index -= 1;
    if (end_index <= start_index) return;

    var has_trailing_semicolon = false;
    if (source[end_index - 1] == ';') {
        has_trailing_semicolon = true;
        end_index -= 1;
        while (end_index > start_index and std.ascii.isWhitespace(source[end_index - 1])) end_index -= 1;
    }

    // Identify token span covering selection
    var left_token = offsets.sourceIndexToTokenIndex(tree, start_index).preferRight(&tree);
    var right_token = offsets.sourceIndexToTokenIndex(tree, end_index).preferLeft();
    if (right_token < left_token) return; // shouldn't happen, but guard

    // Scan for control flow and semicolons to decide whether this is an expression or statements.
    var semicolon_count: usize = 0;
    var has_return = false;
    var has_defer = false;
    var has_break_or_continue = false;
    var i: Ast.TokenIndex = left_token;
    while (i <= right_token) : (i += 1) {
        switch (tree.tokenTag(i)) {
            .semicolon => semicolon_count += 1,
            .keyword_return => has_return = true,
            .keyword_defer, .keyword_errdefer => has_defer = true,
            .keyword_break, .keyword_continue => has_break_or_continue = true,
            else => {},
        }
    }

    // Check if the selection exactly matches a labeled block expression node; if so, allow breaks/semicolons.
    var selection_is_expression = !has_return and !has_defer and semicolon_count == 0 and !has_break_or_continue;
    if (!selection_is_expression) {
        const mid_index = start_index + (end_index - start_index) / 2;
        const nodes_exact = try ast.nodesOverlappingIndex(this.builder.arena, tree, mid_index);
        if (nodes_exact.len != 0) {
            for (nodes_exact) |n| {
                const first_tok = tree.firstToken(n);
                const last_tok = ast.lastToken(tree, n);
                if (first_tok == left_token and last_tok == right_token) {
                    switch (tree.nodeTag(n)) {
                        .block,
                        .block_two,
                        .block_semicolon,
                        .block_two_semicolon,
                        => {
                            // Ensure it's a labeled block form (blk: { ... }) to be used as expression
                            if (ast.blockLabel(tree, n) != null and !has_return and !has_defer) {
                                selection_is_expression = true;
                            }
                        },
                        else => {},
                    }
                    break;
                }
            }
        }
    }

    // Depending on mode, prepare the body text and the replacement range.
    var body_start_index: usize = undefined;
    var body_end_index: usize = undefined;
    var call_replace_loc: offsets.Loc = .{ .start = start_index, .end = this.loc.end };
    var expr_text: []const u8 = &.{};
    var is_statements: bool = false;
    // Collected outputs (multiple) as pointer-out params
    const Out = struct {
        param_name: []const u8,
        lhs_node: Ast.Node.Index,
        rhs_node: Ast.Node.Index,
        stmt_node: Ast.Node.Index,
        lhs_text: []const u8,
        base_type_text: ?[]const u8,
    };
    var outs: std.ArrayList(Out) = .empty;

    if (selection_is_expression) {
        expr_text = source[start_index..end_index];
        if (expr_text.len == 0) return;
        body_start_index = start_index;
        body_end_index = end_index;
    } else {
        // Attempt statements extraction: detect contiguous statements inside the same enclosing block.
        const doc_scope = try this.builder.handle.getDocumentScope();
        const start_block = Analyser.innermostScopeAtIndexWithTag(doc_scope, start_index, .initOne(.block)).unwrap() orelse return;
        const end_block = Analyser.innermostScopeAtIndexWithTag(doc_scope, end_index - 1, .initOne(.block)).unwrap() orelse return;
        if (@intFromEnum(start_block) != @intFromEnum(end_block)) return;
        const block_node = DocumentScope.getScopeAstNode(doc_scope, start_block).?;
        var buf: [2]Ast.Node.Index = undefined;
        const statements = tree.blockStatements(&buf, block_node) orelse return; // only inside proper blocks

        // Find contiguous statements fully covered by selection.
        var first_idx: usize = statements.len;
        var last_idx: usize = 0;
        for (statements, 0..) |stmt, idx| {
            const stmt_loc = offsets.nodeToLoc(tree, stmt);
            if (stmt_loc.end <= start_index or end_index <= stmt_loc.start) continue;
            // if any partial overlap, require full coverage for v1
            if (!(start_index <= stmt_loc.start and stmt_loc.end <= end_index)) return;
            if (first_idx == statements.len) first_idx = idx;
            last_idx = idx;
        }
        if (first_idx == statements.len) return; // no statements covered
        // Ensure contiguity: there must be no gaps between first_idx and last_idx
        // since we required full coverage and overlap, this is implicit.

        // v1 restriction: reject if any var decl inside the selection
        for (statements[first_idx .. last_idx + 1]) |stmt| {
            switch (tree.nodeTag(stmt)) {
                .local_var_decl, .simple_var_decl, .aligned_var_decl => return,
                else => {},
            }
        }

        // Collect external assignments as outputs (multiple)
        for (statements[first_idx .. last_idx + 1]) |stmt| {
            if (tree.nodeTag(stmt) == .assign) {
                const lhs, const rhs = tree.nodeData(stmt).node_and_node;
                // Determine parameter name and type
                var param_name: []const u8 = undefined;
                var base_type_text: ?[]const u8 = null;
                const lhs_tag = tree.nodeTag(lhs);
                if (lhs_tag == .identifier) {
                    const name_tok = tree.nodeMainToken(lhs);
                    const name = offsets.identifierTokenToNameSlice(tree, name_tok);
                    // declaration must be outside selection to consider as output of existing variable
                    const decl = (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, tree.tokenStart(name_tok))) orelse null;
                    if (decl) |d| {
                        const decl_tok = d.nameToken();
                        const decl_loc = offsets.tokenToLoc(tree, decl_tok);
                        if (!(start_index <= decl_loc.start and decl_loc.end <= end_index)) {
                            param_name = try std.fmt.allocPrint(this.builder.arena, "out_{s}", .{name});
                            if (try d.typeDeclarationNode()) |tn| {
                                base_type_text = offsets.nodeToSlice(tn.handle.tree, tn.node);
                            } else if (try d.resolveType(this.builder.analyser)) |ty| {
                                base_type_text = try ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false });
                            }
                        } else {
                            // declared inside selection; skip as output
                            continue;
                        }
                    } else {
                        // unknown decl; skip
                        continue;
                    }
                } else {
                    // For non-identifier lvalues (fields, index, etc.) accept as output
                    param_name = try std.fmt.allocPrint(this.builder.arena, "out{d}", .{outs.items.len + 1});
                    if (try this.builder.analyser.resolveTypeOfNode(.of(lhs, this.builder.handle))) |ty| {
                        base_type_text = try ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false });
                    }
                }
                const lhs_loc = offsets.nodeToLoc(tree, lhs);
                const lhs_text = source[lhs_loc.start..lhs_loc.end];
                try outs.append(this.builder.arena, .{
                    .param_name = param_name,
                    .lhs_node = lhs,
                    .rhs_node = rhs,
                    .stmt_node = stmt,
                    .lhs_text = lhs_text,
                    .base_type_text = base_type_text,
                });
            }
        }

        // Determine replacement range bounds based on selected statements
        const first_stmt = statements[first_idx];
        const last_stmt = statements[last_idx];
        const first_loc = offsets.nodeToLoc(tree, first_stmt);
        var last_loc = offsets.nodeToLoc(tree, last_stmt);
        // Include a trailing semicolon if present immediately after the last token
        const last_tok = ast.lastToken(tree, last_stmt);
        if (last_tok + 1 < tree.tokens.len and tree.tokenTag(last_tok + 1) == .semicolon) {
            const semi_loc = offsets.tokensToLoc(tree, last_tok + 1, last_tok + 1);
            if (semi_loc.end > last_loc.end) last_loc.end = semi_loc.end;
        }
        // Extend to end-of-line whitespace
        var scan_end = last_loc.end;
        while (scan_end < source.len and (source[scan_end] == ' ' or source[scan_end] == '\t')) scan_end += 1;
        if (scan_end < source.len and source[scan_end] == '\n') scan_end += 1;
        last_loc.end = scan_end;

        body_start_index = first_loc.start;
        body_end_index = last_loc.end;
        call_replace_loc = .{ .start = body_start_index, .end = body_end_index };
        is_statements = true;
    }

    // Collect external identifiers to use as parameters
    var seen_params = std.StringHashMapUnmanaged(void){};
    defer seen_params.deinit(this.builder.arena);

    // Use a stable order of appearance
    var param_names: std.ArrayList([]const u8) = .empty;
    var param_decls: std.ArrayList(Analyser.DeclWithHandle) = .empty;

    // Recompute tokens if statements mode adjusted boundaries
    if (is_statements) {
        left_token = offsets.sourceIndexToTokenIndex(tree, body_start_index).preferRight(&tree);
        right_token = offsets.sourceIndexToTokenIndex(tree, body_end_index).preferLeft();
    }
    i = left_token;
    while (i <= right_token) : (i += 1) {
        const tag = tree.tokenTag(i);
        if (tag != .identifier) continue;
        const name = offsets.identifierTokenToNameSlice(tree, i);
        if (std.mem.eql(u8, name, "_")) continue;

        // Resolve declaration in current context
        const decl = (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, tree.tokenStart(i))) orelse continue;

        // Ignore if declared inside the selection
        const decl_token = decl.nameToken();
        const decl_loc = offsets.tokenToLoc(tree, decl_token);
        if (decl_loc.start >= start_index and decl_loc.end <= end_index) continue;

        // No special-casing for outs here; outs are passed separately

        // If declaration is static/global or container field, it is accessible without params
        const is_static = blk: {
            // best-effort: errors mean unknown -> treat as non-static to be safe
            break :blk decl.isStatic() catch false;
        };
        if (is_static) continue;

        // Deduplicate and record param
        const gop = try seen_params.getOrPut(this.builder.arena, name);
        if (!gop.found_existing) {
            gop.key_ptr.* = try this.builder.arena.dupe(u8, name);
            try param_names.append(this.builder.arena, name);
            try param_decls.append(this.builder.arena, decl);
        }
    }

    // Append out-parameters (names only; types handled later)
    if (is_statements and outs.items.len > 0) {
        for (outs.items) |oadd| {
            try param_names.append(this.builder.arena, oadd.param_name);
        }
    }

    // Determine target container for context
    const container_ty = try this.builder.analyser.innermostContainer(this.builder.handle, start_index);

    // Order parameters heuristically: out-params first, then self-like, then allocator, then mutable struct pointers, then immutable struct pointers, then others by appearance.
    if (param_names.items.len > 1) {
        const Entry = struct { idx: usize, score: u32, appear: usize };
        var entries: std.ArrayList(Entry) = .empty;
        try entries.ensureTotalCapacity(this.builder.arena, param_names.items.len);
        const container_instance = (try container_ty.instanceTypeVal(this.builder.analyser)) orelse container_ty;
        for (param_names.items, 0..) |_, idx| {
            var score: u32 = 0;
            // Out-params: big boost
            for (outs.items) |o4| {
                if (std.mem.eql(u8, o4.param_name, param_names.items[idx])) {
                    score += 5000;
                    break;
                }
            }
            if (idx < param_decls.items.len) {
                const decl = param_decls.items[idx];
                if (try decl.resolveType(this.builder.analyser)) |ty| {
                    if (ty.is_type_val) {
                        score += 1000;
                    }

                    switch (ty.data) {
                        .pointer => |info| {
                            // Highest: pointer to the current container instance
                            if (info.elem_ty.eql(container_instance)) score += 2000;
                            switch (info.elem_ty.data) {
                                .container => {
                                    if (info.is_const) {
                                        score += 800;
                                    } else {
                                        score += 100;
                                    }
                                },
                                else => score += 100,
                            }
                        },
                        .container => |info| {
                            _ = info; // autofix
                            score += 700;
                        },
                        else => {},
                    }
                    const type_str = ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false }) catch null;
                    if (type_str) |ts| {
                        if (std.mem.indexOf(u8, ts, "Allocator") != null) score += 950;
                    }
                }
            } else {
                // likely an out-param without decl
                score += 1500;
            }
            entries.appendAssumeCapacity(.{ .idx = idx, .score = score, .appear = idx });
        }
        const Ctx = struct {
            fn lessThan(_: void, a: Entry, b: Entry) bool {
                if (a.score != b.score) return a.score > b.score;
                return a.appear < b.appear;
            }
        };
        std.mem.sort(Entry, entries.items, {}, Ctx.lessThan);

        var new_names: std.ArrayList([]const u8) = .empty;
        var new_decls: std.ArrayList(Analyser.DeclWithHandle) = .empty;
        try new_names.ensureTotalCapacity(this.builder.arena, param_names.items.len);
        try new_decls.ensureTotalCapacity(this.builder.arena, param_decls.items.len);
        for (entries.items) |e| {
            new_names.appendAssumeCapacity(param_names.items[e.idx]);
            new_decls.appendAssumeCapacity(param_decls.items[e.idx]);
        }
        param_names.items = new_names.items;
        param_decls.items = new_decls.items;
    }

    // After reordering, nothing further to track; out-params recognized by name

    // Determine target container and function name avoiding conflicts

    const base_name: []const u8 = "extracted";
    var chosen_name = base_name;
    var suffix: usize = 1;
    while (try Analyser.lookupSymbolContainer(container_ty, chosen_name, .other)) |_| {
        // name conflict; try next
        const buf = try std.fmt.allocPrint(this.builder.arena, "{s}{d}", .{ base_name, suffix });
        suffix += 1;
        chosen_name = buf;
    }

    // Attempt to infer return type from the selected expression/statements.
    var inferred_return_type: ?[]const u8 = null;
    if (!is_statements) {
        const mid_index = start_index + (end_index - start_index) / 2;
        const nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, mid_index);
        if (nodes.len != 0) {
            var expr_node = nodes[0];
            var expr_node_idx_in_nodes: usize = 0;
            // pick the largest node fully contained in [left_token, right_token]
            for (nodes, 0..) |n, ni| {
                const first_tok = tree.firstToken(n);
                const last_tok = ast.lastToken(tree, n);
                if (first_tok < left_token or last_tok > right_token) continue;
                expr_node = n;
                expr_node_idx_in_nodes = ni;
                if (first_tok == left_token and last_tok == right_token) break;
            }
            const ancestors = nodes[expr_node_idx_in_nodes + 1 ..];
            // Prefer literal type from surrounding declaration when obvious.
            if (ancestors.len > 0 and inferred_return_type == null) {
                switch (tree.nodeTag(ancestors[0])) {
                    .global_var_decl, .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                        const var_decl = tree.fullVarDecl(ancestors[0]).?;
                        if (expr_node.toOptional() == var_decl.ast.init_node) {
                            if (var_decl.ast.type_node.unwrap()) |type_node| {
                                inferred_return_type = offsets.nodeToSlice(tree, type_node);
                            }
                        }
                    },
                    .assign => {
                        const lhs, const rhs = tree.nodeData(ancestors[0]).node_and_node;
                        if (expr_node == rhs and tree.nodeTag(lhs) == .identifier) {
                            const name_tok = tree.nodeMainToken(lhs);
                            const name = offsets.identifierTokenToNameSlice(tree, name_tok);
                            if (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, tree.tokenStart(name_tok))) |decl| {
                                if (try decl.typeDeclarationNode()) |type_node| {
                                    inferred_return_type = offsets.nodeToSlice(type_node.handle.tree, type_node.node);
                                }
                            }
                        }
                    },
                    else => {},
                }
            }
            // Fallback to resolved type text
            if (inferred_return_type == null) {
                if (try this.builder.analyser.resolveExpressionType(this.builder.handle, expr_node, ancestors)) |ret_ty| {
                    inferred_return_type = try ret_ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false });
                }
            }
        }
    } else {
        // statements mode -> void (pointer-out params return via pointers)
        inferred_return_type = "void";
    }

    // Build function text: fn <name>(params) <ret> { body }
    var fn_text: std.ArrayList(u8) = .empty;
    try fn_text.appendSlice(this.builder.arena, "fn ");
    try fn_text.appendSlice(this.builder.arena, chosen_name);
    try fn_text.appendSlice(this.builder.arena, "(");
    for (param_names.items, 0..) |p, idx| {
        if (idx != 0) try fn_text.appendSlice(this.builder.arena, ", ");
        try fn_text.appendSlice(this.builder.arena, p);
        // Prefer the literal type expression from the declaration; fallback to resolved type, then anytype.
        var out_base: ?[]const u8 = null;
        for (outs.items) |o3| {
            if (std.mem.eql(u8, o3.param_name, p)) {
                out_base = o3.base_type_text;
                break;
            }
        }
        const type_text = if (out_base) |ob| ob else blk: {
            if (idx < param_decls.items.len) {
                const decl = param_decls.items[idx];
                if (try decl.typeDeclarationNode()) |type_node| break :blk offsets.nodeToSlice(type_node.handle.tree, type_node.node);
                if (try decl.resolveType(this.builder.analyser)) |ty|
                    break :blk ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false }) catch null;
            }
            break :blk null;
        };
        if (type_text) |tt| {
            try fn_text.appendSlice(this.builder.arena, ": ");
            // Out params are pointers to the base type
            if (out_base != null) {
                try fn_text.appendSlice(this.builder.arena, "*");
                try fn_text.appendSlice(this.builder.arena, tt);
            } else {
                try fn_text.appendSlice(this.builder.arena, tt);
            }
        } else {
            try fn_text.appendSlice(this.builder.arena, ": anytype");
        }
    }
    try fn_text.appendSlice(this.builder.arena, ") ");
    // Return type
    if (is_statements) {
        // pointer-out semantics => void
        try fn_text.appendSlice(this.builder.arena, "void");
    } else if (inferred_return_type) |rt| {
        try fn_text.appendSlice(this.builder.arena, rt);
    } else {
        try fn_text.appendSlice(this.builder.arena, "@TypeOf(");
        try fn_text.appendSlice(this.builder.arena, expr_text);
        try fn_text.appendSlice(this.builder.arena, ")");
    }
    if (!is_statements) {
        try fn_text.appendSlice(this.builder.arena, " {\n    return ");
        try fn_text.appendSlice(this.builder.arena, source[body_start_index..body_end_index]);
        try fn_text.appendSlice(this.builder.arena, ";\n}\n\n");
    } else {
        try fn_text.appendSlice(this.builder.arena, " {\n");
        if (outs.items.len == 0) {
            try fn_text.appendSlice(this.builder.arena, source[body_start_index..body_end_index]);
        } else {
            // Replace each output assignment with outN.* = rhs;
            const Repl = struct { start: usize, end: usize, text: []const u8 };
            var repls: std.ArrayList(Repl) = .empty;
            for (outs.items, 0..) |o, oi| {
                _ = oi;
                var stmt_loc = offsets.nodeToLoc(tree, o.stmt_node);
                // include trailing semicolon
                const last_tok = ast.lastToken(tree, o.stmt_node);
                if (last_tok + 1 < tree.tokens.len and tree.tokenTag(last_tok + 1) == .semicolon) {
                    const semi_loc = offsets.tokensToLoc(tree, last_tok + 1, last_tok + 1);
                    if (semi_loc.end > stmt_loc.end) stmt_loc.end = semi_loc.end;
                }
                const rhs_loc = offsets.nodeToLoc(tree, o.rhs_node);
                var line: std.ArrayList(u8) = .empty;
                try line.appendSlice(this.builder.arena, o.param_name);
                try line.appendSlice(this.builder.arena, ".* = ");
                try line.appendSlice(this.builder.arena, source[rhs_loc.start..rhs_loc.end]);
                try line.appendSlice(this.builder.arena, ";\n");
                try repls.append(this.builder.arena, .{ .start = stmt_loc.start, .end = stmt_loc.end, .text = line.items });
            }
            std.mem.sort(Repl, @ptrCast(repls.items), {}, struct {
                fn lessThan(_: void, a: Repl, b: Repl) bool {
                    return a.start < b.start;
                }
            }.lessThan);
            var cursor = body_start_index;
            for (repls.items) |r| {
                if (r.start < cursor) continue;
                try fn_text.appendSlice(this.builder.arena, source[cursor..r.start]);
                try fn_text.appendSlice(this.builder.arena, r.text);
                cursor = r.end;
            }
            try fn_text.appendSlice(this.builder.arena, source[cursor..body_end_index]);
        }
        if (source[body_end_index - 1] != '\n') try fn_text.append(this.builder.arena, '\n');
        try fn_text.appendSlice(this.builder.arena, "}\n\n");
    }

    // Build call replacement
    var call_text: std.ArrayList(u8) = .empty;
    var instance_call = false;
    var receiver_idx: usize = 0;
    // Determine if any parameter is a (mutable) pointer to the current container instance type.
    switch (container_ty.data) {
        .container => |info| {
            if (info.scope_handle.scope != .root) {
                const container_instance = (try container_ty.instanceTypeVal(this.builder.analyser)) orelse container_ty;
                for (param_decls.items, 0..) |d, idx| {
                    if (try d.resolveType(this.builder.analyser)) |ty| {
                        const deref = try this.builder.analyser.resolveDerefType(ty) orelse ty;
                        if (deref.eql(container_instance)) {
                            instance_call = true;
                            receiver_idx = idx;
                            break;
                        }
                    }
                }
            }
        },
        else => {},
    }
    // pointer-out: no assignment at callsite
    if (instance_call) try call_text.appendSlice(this.builder.arena, param_names.items[receiver_idx]);
    if (instance_call) try call_text.appendSlice(this.builder.arena, ".");
    try call_text.appendSlice(this.builder.arena, chosen_name);
    try call_text.appendSlice(this.builder.arena, "(");
    var wrote_any = false;
    for (param_names.items, 0..) |p, idx| {
        if (instance_call and idx == receiver_idx) continue;
        if (wrote_any) try call_text.appendSlice(this.builder.arena, ", ");
        // If this param is one of our outs, pass &<lhs>
        var handled = false;
        for (outs.items) |o2| {
            if (std.mem.eql(u8, o2.param_name, p)) {
                try call_text.appendSlice(this.builder.arena, "&");
                try call_text.appendSlice(this.builder.arena, o2.lhs_text);
                handled = true;
                break;
            }
        }
        if (!handled) {
            try call_text.appendSlice(this.builder.arena, p);
        } else {
            // nothing
        }
        wrote_any = true;
    }
    try call_text.appendSlice(this.builder.arena, ")");
    // In expression mode, preserve trailing semicolon from original selection; in statements, we always insert one.
    if (is_statements or has_trailing_semicolon) try call_text.append(this.builder.arena, ';');
    if (is_statements) try call_text.append(this.builder.arena, '\n');

    // Choose insertion point: after enclosing function if available, else EOF
    var insert_index: usize = source.len;
    const doc_scope = try this.builder.handle.getDocumentScope();
    if (Analyser.innermostScopeAtIndexWithTag(doc_scope, start_index, .initOne(.function)).unwrap()) |fn_scope| {
        if (DocumentScope.getScopeAstNode(doc_scope, fn_scope)) |fn_node| {
            const fn_loc = offsets.nodeToLoc(tree, fn_node);
            insert_index = fn_loc.end;
        }
    }

    // Ensure there is at least one blank line between neighbors.
    // We achieve this by prepending up to two newlines depending on what's already there.
    var leading_needed: usize = 0;
    var have_newlines: usize = 0;
    var scan: usize = insert_index;
    while (scan > 0 and have_newlines < 2 and source[scan - 1] == '\n') : (scan -= 1) {
        have_newlines += 1;
    }
    if (have_newlines < 2) leading_needed = 2 - have_newlines; // 2 newlines => one blank line

    var padded_fn_text: std.ArrayList(u8) = .empty;
    try padded_fn_text.ensureTotalCapacity(this.builder.arena, leading_needed + fn_text.items.len);
    for (0..leading_needed) |_| padded_fn_text.appendAssumeCapacity('\n');
    padded_fn_text.appendSliceAssumeCapacity(fn_text.items);

    var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
    try this.builder.addWorkspaceTextEdit(&workspace_edit, this.builder.handle.uri, &.{
        this.builder.createTextEditPos(insert_index, padded_fn_text.items),
        this.builder.createTextEditLoc(call_replace_loc, call_text.items),
    });

    try this.builder.actions.append(this.builder.arena, .{
        .title = "extract to function",
        .kind = .refactor,
        .isPreferred = false,
        .edit = workspace_edit,
    });
}
