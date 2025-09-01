const std = @import("std");
const Ast = std.zig.Ast;
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const tracy = @import("tracy");

const GenerateEncapsulateParamsStructActionator = @This();

builder: *@import("code_actions.zig").Builder,
source_index: usize,

pub fn generateEncapsulateParamsStructAction(this: *GenerateEncapsulateParamsStructActionator) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!this.builder.wantKind(.refactor)) return;

    const tree = this.builder.handle.tree;
    const nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
    if (nodes.len == 0) return;

    var fn_node: ?Ast.Node.Index = null;
    for (nodes) |n| {
        switch (tree.nodeTag(n)) {
            .fn_decl => {
                fn_node = n;
                break;
            },
            else => {},
        }
    }
    const target = fn_node orelse return;

    // Resolve proto and name
    var buf: [1]Ast.Node.Index = undefined;
    const proto_node = blk: {
        switch (tree.nodeTag(target)) {
            .fn_decl => {
                const proto = tree.nodeData(target).node_and_node[0];
                break :blk proto;
            },

            else => return,
        }
    };
    const fnp = tree.fullFnProto(&buf, proto_node).?;
    const name_token = fnp.name_token orelse return; // unnamed function not supported
    const fn_name = offsets.identifierTokenToNameSlice(tree, name_token);

    // Collect parameters (names and type literals)
    var it = fnp.iterate(&tree);
    var params_names: std.ArrayList([]const u8) = .empty;
    var params_types: std.ArrayList([]const u8) = .empty;
    var synth_index: usize = 0;
    while (ast.nextFnParam(&it)) |param| {
        // Skip 'comptime' and 'noalias' handled by iterator already; just read name+type
        const name_slice: []const u8 = blk_name: {
            if (param.name_token) |nt| {
                const s = offsets.identifierTokenToNameSlice(tree, nt);
                if (!std.mem.eql(u8, s, "_")) break :blk_name s;
            }
            const syn = try std.fmt.allocPrint(this.builder.arena, "arg{d}", .{synth_index});
            synth_index += 1;
            break :blk_name syn;
        };
        const type_slice: []const u8 = blk_type: {
            if (param.type_expr) |te| break :blk_type offsets.nodeToSlice(tree, te);
            // anytype parameter
            break :blk_type "anytype";
        };
        try params_names.append(this.builder.arena, name_slice);
        try params_types.append(this.builder.arena, type_slice);
    }

    // Compute return type literal
    const has_inferred_error = ast.hasInferredError(tree, fnp);
    const return_type_slice: []const u8 = blk_ret: {
        if (fnp.ast.return_type.unwrap()) |rt| break :blk_ret offsets.nodeToSlice(tree, rt);
        break :blk_ret "void";
    };

    // Determine if function has a body to move
    var has_body = false;
    if (tree.nodeTag(target) == .fn_decl) {
        const __proto, const body = tree.nodeData(target).node_and_node;
        _ = __proto;
        has_body = body != .root;
    }

    // Build struct text
    var struct_text: std.ArrayList(u8) = .empty;
    var struct_name = try std.fmt.allocPrint(this.builder.arena, "{s}ator", .{fn_name});
    struct_name[0] = std.ascii.toUpper(struct_name[0]);
    try struct_text.appendSlice(this.builder.arena, "const ");
    try struct_text.appendSlice(this.builder.arena, struct_name);
    try struct_text.appendSlice(this.builder.arena, " = struct {\n");
    // fields
    for (params_names.items, 0..) |pname, i| {
        try struct_text.appendSlice(this.builder.arena, "    ");
        try struct_text.appendSlice(this.builder.arena, pname);
        try struct_text.appendSlice(this.builder.arena, ": ");
        try struct_text.appendSlice(this.builder.arena, params_types.items[i]);
        try struct_text.appendSlice(this.builder.arena, ",\n");
    }
    // method header with pointer receiver named 'this'
    try struct_text.appendSlice(this.builder.arena, "\n    pub fn ");
    try struct_text.appendSlice(this.builder.arena, fn_name);
    try struct_text.appendSlice(this.builder.arena, "(this: *@This()) ");
    if (has_inferred_error) {
        try struct_text.appendSlice(this.builder.arena, "!");
    }
    try struct_text.appendSlice(this.builder.arena, return_type_slice);
    try struct_text.appendSlice(this.builder.arena, " {\n");
    if (has_body) {
        // Move function body, replacing parameter references with this.<param>
        const body_node = tree.nodeData(target).node_and_node[1];
        const lbrace_tok = tree.firstToken(body_node);
        const rbrace_tok = ast.lastToken(tree, body_node);
        const lbrace_loc = offsets.tokenToLoc(tree, lbrace_tok);
        const rbrace_loc = offsets.tokenToLoc(tree, rbrace_tok);
        const inner_start = lbrace_loc.end;
        const inner_end = rbrace_loc.start;
        var body_src = tree.source[inner_start..inner_end];

        // Map param name -> function_parameter declaration for identity checking
        var param_decl_map = std.StringHashMapUnmanaged(Analyser.DeclWithHandle){};
        defer param_decl_map.deinit(this.builder.arena);
        {
            var pit = fnp.iterate(&tree);
            var pidx: usize = 0;
            while (ast.nextFnParam(&pit)) |param| : (pidx += 1) {
                const nt = param.name_token orelse continue;
                const name = offsets.identifierTokenToNameSlice(tree, nt);
                if (std.mem.eql(u8, name, "_")) continue;
                const decl: Analyser.DeclWithHandle = .{
                    .decl = .{
                        .function_parameter = .{ .param_index = @intCast(pidx), .func = target },
                    },
                    .handle = this.builder.handle,
                };
                const gop = try param_decl_map.getOrPut(this.builder.arena, name);

                if (!gop.found_existing) gop.key_ptr.* = try this.builder.arena.dupe(u8, name);
                gop.value_ptr.* = decl;
            }
        }

        // Collect identifier replacements inside body by token scan
        var repl_indices: std.ArrayList(struct { start: usize, end: usize, name: []const u8 }) = .empty;
        defer repl_indices.deinit(this.builder.arena);
        var tok = lbrace_tok + 1;
        while (tok < rbrace_tok) : (tok += 1) {
            if (tree.tokenTag(tok) != .identifier) continue;
            const tok_loc = offsets.tokenToLoc(tree, tok);
            const name = offsets.identifierTokenToNameSlice(tree, tok);
            const pd = param_decl_map.get(name) orelse continue;
            const resolved = (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, tok_loc.start)) orelse continue;

            if (!resolved.eql(pd)) continue;
            // record replacement relative to body_src
            try repl_indices.append(this.builder.arena, .{ .start = tok_loc.start - inner_start, .end = tok_loc.end - inner_start, .name = name });
        }

        // Apply replacements into method body
        const Repl = struct { start: usize, end: usize, name: []const u8 };
        std.mem.sort(Repl, @ptrCast(repl_indices.items), {}, struct {
            fn lessThan(_: void, a: Repl, b: Repl) bool {
                return a.start < b.start;
            }
        }.lessThan);
        var cursor: usize = 0;
        for (repl_indices.items) |r| {
            if (r.start < cursor) continue;
            try struct_text.appendSlice(this.builder.arena, body_src[cursor..r.start]);
            try struct_text.appendSlice(this.builder.arena, "this.");
            try struct_text.appendSlice(this.builder.arena, r.name);
            cursor = r.end;
        }
        try struct_text.appendSlice(this.builder.arena, body_src[cursor..]);
        if (inner_end > inner_start and tree.source[inner_end - 1] != '\n') try struct_text.append(this.builder.arena, '\n');
    } else {
        // No body: forward to function
        try struct_text.appendSlice(this.builder.arena, "        return ");
        try struct_text.appendSlice(this.builder.arena, fn_name);
        try struct_text.appendSlice(this.builder.arena, "(");
        for (params_names.items, 0..) |pname, i| {
            if (i != 0) try struct_text.appendSlice(this.builder.arena, ", ");
            try struct_text.appendSlice(this.builder.arena, "this.");
            try struct_text.appendSlice(this.builder.arena, pname);
        }
        try struct_text.appendSlice(this.builder.arena, ");\n");
    }
    try struct_text.appendSlice(this.builder.arena, "    }\n};\n\n");

    // Insert after the function body if present, otherwise after the prototype
    var insert_index: usize = undefined;
    if (tree.nodeTag(target) == .fn_decl) {
        const body_node = tree.nodeData(target).node_and_node[1];
        const body_loc = offsets.nodeToLoc(tree, body_node);
        insert_index = body_loc.end;
    } else {
        const proto_loc = offsets.nodeToLoc(tree, proto_node);
        insert_index = proto_loc.end;
    }

    // Ensure blank line separation
    const source = tree.source;
    var leading_needed: usize = 0;
    var have_newlines: usize = 0;
    var scan: usize = insert_index;
    while (scan > 0 and have_newlines < 2 and source[scan - 1] == '\n') : (scan -= 1) have_newlines += 1;
    if (have_newlines < 2) leading_needed = 2 - have_newlines;

    var padded: std.ArrayList(u8) = .empty;
    try padded.ensureTotalCapacity(this.builder.arena, leading_needed + struct_text.items.len);
    for (0..leading_needed) |_| padded.appendAssumeCapacity('\n');
    padded.appendSliceAssumeCapacity(struct_text.items);

    var edits: std.ArrayList(types.TextEdit) = .empty;
    try edits.append(this.builder.arena, this.builder.createTextEditPos(insert_index, padded.items));

    // If we moved the body, replace the original function body with a wrapper
    if (has_body) {
        const body_node = tree.nodeData(target).node_and_node[1];
        const lbrace_tok = tree.firstToken(body_node);
        const rbrace_tok = ast.lastToken(tree, body_node);
        const lbrace_loc = offsets.tokenToLoc(tree, lbrace_tok);
        const rbrace_loc = offsets.tokenToLoc(tree, rbrace_tok);
        const inner_loc: offsets.Loc = .{ .start = lbrace_loc.end, .end = rbrace_loc.start };

        var wrapper: std.ArrayList(u8) = .empty;
        try wrapper.appendSlice(this.builder.arena, "\n        var args = ");
        try wrapper.appendSlice(this.builder.arena, struct_name);
        try wrapper.appendSlice(this.builder.arena, "{ ");
        for (params_names.items) |pname| {
            try wrapper.appendSlice(this.builder.arena, ".");
            try wrapper.appendSlice(this.builder.arena, pname);
            try wrapper.appendSlice(this.builder.arena, " = ");
            try wrapper.appendSlice(this.builder.arena, pname);
            try wrapper.appendSlice(this.builder.arena, ", ");
        }
        try wrapper.appendSlice(this.builder.arena, " };\n");
        const is_void = std.mem.eql(u8, std.mem.trim(u8, return_type_slice, " \t\n\r"), "void");
        if (is_void) {
            if (has_inferred_error) {
                try wrapper.appendSlice(this.builder.arena, "        _ = try args.");
            } else {
                try wrapper.appendSlice(this.builder.arena, "        _ = args.");
            }
        } else {
            if (has_inferred_error) {
                try wrapper.appendSlice(this.builder.arena, "        return try args.");
            } else {
                try wrapper.appendSlice(this.builder.arena, "        return args.");
            }
        }
        try wrapper.appendSlice(this.builder.arena, fn_name);
        try wrapper.appendSlice(this.builder.arena, "();\n");
        try edits.append(this.builder.arena, this.builder.createTextEditLoc(inner_loc, wrapper.items));
    }

    var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
    try this.builder.addWorkspaceTextEdit(&workspace_edit, this.builder.handle.uri, edits.items);

    try this.builder.actions.append(this.builder.arena, .{
        .title = try std.fmt.allocPrint(this.builder.arena, "encapsulate params in struct '{s}'", .{struct_name}),
        .kind = .refactor,
        .isPreferred = false,
        .edit = workspace_edit,
    });
}
