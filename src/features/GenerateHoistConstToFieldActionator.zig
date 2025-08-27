const std = @import("std");
const Ast = std.zig.Ast;
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const tracy = @import("tracy");
const Analyser = @import("../analysis.zig");
const Builder = @import("code_actions.zig").Builder;
const EditBuilder = @import("code_actions.zig").EditBuilder;

pub const GenerateHoistConstToFieldActionator = struct {
    builder: *Builder,
    source_index: usize,

    pub fn generateHoistConstToFieldAction(this: *@This()) !void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        if (this.builder.only_kinds) |set| {
            if (!set.contains(.refactor)) return;
        }

        const tree = this.builder.handle.tree;
        const nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
        if (nodes.len == 0) return;

        // Find nearest var decl node
        var var_node_opt: ?Ast.Node.Index = null;
        for (nodes) |n| {
            switch (tree.nodeTag(n)) {
                .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                    var_node_opt = n;
                    break;
                },
                else => {},
            }
        }
        const var_node = var_node_opt orelse return;

        const var_decl = tree.fullVarDecl(var_node).?;
        const init_node = var_decl.ast.init_node.unwrap() orelse return;

        // Get var name
        const name_tok = var_decl.ast.mut_token + 1;
        if (tree.tokenTag(name_tok) != .identifier) return;
        const var_name = offsets.identifierTokenToNameSlice(tree, name_tok);
        if (std.mem.eql(u8, var_name, "_")) return;

        // Locate enclosing function and block
        var func_node_opt: ?Ast.Node.Index = null;
        for (nodes) |n| {
            switch (tree.nodeTag(n)) {
                .fn_decl => {
                    func_node_opt = n;
                    break;
                },
                else => {},
            }
        }
        const func_node = func_node_opt orelse return;
        const fn_proto, const fn_body = tree.nodeData(func_node).node_and_node;
        if (fn_body == .root) return; // no body
        const func_ty = try this.builder.analyser.resolveTypeOfNode(.of(func_node, this.builder.handle));

        // Determine receiver param name by type identity to container
        var buf: [1]Ast.Node.Index = undefined;
        const proto = tree.fullFnProto(&buf, fn_proto).?;
        const container_ty = try this.builder.analyser.innermostContainer(this.builder.handle, tree.tokenStart(proto.ast.fn_token));
        const container_instance = (try container_ty.instanceTypeVal(this.builder.analyser)) orelse container_ty;
        _ = container_instance; // autofix

        // Only proceed for methods with a receiver parameter
        const receiver = blk_recv: {
            const ft = func_ty orelse break :blk_recv null;
            if (ft.data != .function) break :blk_recv null;
            const fndata = ft.data.function;
            if (fndata.parameters.len == 0) break :blk_recv null;
            const p0 = fndata.parameters[0];
            if (p0.name) |nm| {
                break :blk_recv nm;
            } else break :blk_recv null;
        } orelse return; // no receiver => not a method, skip this refactor

        // Prepare container field insertion (infer type)
        // Find enclosing container decl node
        var container_node_opt: ?Ast.Node.Index = null;
        for (nodes) |n| {
            var cbuf: [2]Ast.Node.Index = undefined;
            if (tree.fullContainerDecl(&cbuf, n)) |_| {
                container_node_opt = n;
                break;
            }
        }
        const container_node = container_node_opt orelse return;
        // Infer field type: prefer explicit type in decl, otherwise infer from initializer
        const field_type_text = blk_ft: {
            if (var_decl.ast.type_node.unwrap()) |tn| break :blk_ft offsets.nodeToSlice(tree, tn);
            if (try this.builder.analyser.resolveTypeOfNode(.of(init_node, this.builder.handle))) |ty|
                break :blk_ft try ty.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false });
            break :blk_ft "var"; // fallback unlikely
        };
        // Compute insertion point: before rbrace
        // Choose indentation: use first member indent if available else 4 spaces inside container
        var cbuf2: [2]Ast.Node.Index = undefined;
        const cdecl = tree.fullContainerDecl(&cbuf2, container_node).?;
        const field_indent = blk_ind: {
            if (cdecl.ast.members.len > 0) {
                const first_member = cdecl.ast.members[0];
                const line = offsets.lineLocAtIndex(tree.source, offsets.nodeToLoc(tree, first_member).start);
                var j: usize = line.start;
                while (j < line.end and (tree.source[j] == ' ' or tree.source[j] == '\t')) j += 1;
                break :blk_ind tree.source[line.start..j];
            } else {
                // indent = container line indent + 4 spaces
                const cline = offsets.lineLocAtIndex(tree.source, offsets.nodeToLoc(tree, container_node).start);
                var j: usize = cline.start;
                while (j < cline.end and (tree.source[j] == ' ' or tree.source[j] == '\t')) j += 1;
                const base = tree.source[cline.start..j];
                break :blk_ind try std.mem.concat(this.builder.arena, u8, &.{ base, "    " });
            }
        };
        // Choose insertion position: after last existing field; otherwise at top of container
        var insert_pos: usize = undefined;
        var last_field_node_opt: ?Ast.Node.Index = null;
        for (cdecl.ast.members) |m| {
            switch (tree.nodeTag(m)) {
                .container_field, .container_field_init, .container_field_align => last_field_node_opt = m,
                else => {},
            }
        }
        if (last_field_node_opt) |last_field_node| {
            insert_pos = offsets.nodeToLoc(tree, last_field_node).end;
        } else if (cdecl.ast.members.len > 0) {
            insert_pos = offsets.nodeToLoc(tree, cdecl.ast.members[0]).start;
        } else {
            // after '{'
            var t = tree.firstToken(container_node);
            while (t < tree.tokens.len and tree.tokenTag(t) != .l_brace) : (t += 1) {}
            insert_pos = if (t < tree.tokens.len) tree.tokenStart(t) + 1 else offsets.nodeToLoc(tree, container_node).start;
        }

        var field_line: std.ArrayList(u8) = .empty;
        // ensure there's a newline before rbrace, rely on formatter for commas
        try field_line.appendSlice(this.builder.arena, "\n");
        try field_line.appendSlice(this.builder.arena, field_indent);
        try field_line.appendSlice(this.builder.arena, var_name);
        try field_line.appendSlice(this.builder.arena, ": ");
        try field_line.appendSlice(this.builder.arena, field_type_text);
        try field_line.appendSlice(this.builder.arena, ",");
        // Replace declaration with receiver.field assignment and update references to var_name -> receiver.var_name
        const body_loc = offsets.nodeToLoc(tree, fn_body);
        const decl_loc = offsets.nodeToLoc(tree, var_node);
        // Include trailing semicolon if present
        var decl_end = decl_loc.end;
        const last_tok = ast.lastToken(tree, var_node);
        if (last_tok + 1 < tree.tokens.len and tree.tokenTag(last_tok + 1) == .semicolon) {
            const semi_loc = offsets.tokensToLoc(tree, last_tok + 1, last_tok + 1);
            if (semi_loc.end > decl_end) decl_end = semi_loc.end;
        }
        const init_loc = offsets.nodeToLoc(tree, init_node);
        // Compute indentation prefix from decl line
        const decl_line = offsets.lineLocAtIndex(tree.source, decl_loc.start);
        const indent_slice = blk: {
            var j: usize = decl_line.start;
            while (j < decl_loc.start and (tree.source[j] == ' ' or tree.source[j] == '\t')) j += 1;
            break :blk tree.source[decl_line.start..j];
        };
        var assign_line: std.ArrayList(u8) = .empty;
        try assign_line.appendSlice(this.builder.arena, indent_slice);
        try assign_line.appendSlice(this.builder.arena, receiver);
        try assign_line.appendSlice(this.builder.arena, ".");
        try assign_line.appendSlice(this.builder.arena, var_name);
        try assign_line.appendSlice(this.builder.arena, " = ");
        try assign_line.appendSlice(this.builder.arena, tree.source[init_loc.start..init_loc.end]);
        try assign_line.appendSlice(this.builder.arena, ";\n");
        // Collect identifier references to this var after the decl
        var repls: std.ArrayList(types.TextEdit) = .empty;
        // Replace the decl
        try repls.append(this.builder.arena, this.builder.createTextEditLoc(.{ .start = decl_loc.start, .end = decl_end }, assign_line.items));
        // Insert the field at computed position
        try repls.append(this.builder.arena, this.builder.createTextEditPos(insert_pos, field_line.items));
        // Replace usages from end of decl to end of body
        var tok_i = offsets.sourceIndexToTokenIndex(tree, decl_end).preferRight(&tree);
        const end_tok = offsets.sourceIndexToTokenIndex(tree, body_loc.end).preferLeft();
        // Resolve the declaration handle for equality
        const decl_handle = (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, var_name, decl_loc.start)) orelse null;
        if (decl_handle) |target_decl| {
            while (tok_i <= end_tok) : (tok_i += 1) {
                if (tree.tokenTag(tok_i) != .identifier) continue;
                const name = offsets.identifierTokenToNameSlice(tree, tok_i);
                if (!std.mem.eql(u8, name, var_name)) continue;
                const tok_start = tree.tokenStart(tok_i);
                if (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, tok_start)) |ref_decl| {
                    if (!ref_decl.eql(target_decl)) continue;
                    const tok_loc = offsets.tokenToLoc(tree, tok_i);
                    var repl_text: std.ArrayList(u8) = .empty;
                    try repl_text.appendSlice(this.builder.arena, receiver);
                    try repl_text.appendSlice(this.builder.arena, ".");
                    try repl_text.appendSlice(this.builder.arena, var_name);
                    try repls.append(this.builder.arena, this.builder.createTextEditLoc(tok_loc, repl_text.items));
                }
            }
        }
        // Emit the action
        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try this.builder.addWorkspaceTextEdit(&workspace_edit, this.builder.handle.uri, repls.items);
        try this.builder.actions.append(this.builder.arena, .{
            .title = "hoist local to field",
            .kind = .refactor,
            .isPreferred = false,
            .edit = workspace_edit,
        });
    }
};
