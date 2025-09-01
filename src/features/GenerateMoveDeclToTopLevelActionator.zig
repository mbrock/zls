const std = @import("std");
const Builder = @import("code_actions.zig").Builder;
const tracy = @import("tracy");

const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const Ast = std.zig.Ast;

const lsp = @import("lsp");
const types = lsp.types;

pub const GenerateMoveDeclToTopLevelActionator = @This();

builder: *Builder,
source_index: usize,

pub fn generateMoveDeclToTopLevelAction(this: *@This()) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!this.builder.wantKind(.refactor)) return;

    const tree = this.builder.handle.tree;
    const nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
    if (nodes.len == 0) return;

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

    // only const for now
    if (tree.tokenTag(var_decl.ast.mut_token) != .keyword_const) return;
    const init_node = var_decl.ast.init_node.unwrap() orelse return;

    // name
    const name_tok = var_decl.ast.mut_token + 1;
    if (tree.tokenTag(name_tok) != .identifier) return;
    const name = offsets.identifierTokenToNameSlice(tree, name_tok);
    if (std.mem.eql(u8, name, "_")) return;

    // ensure no collision at top-level
    if (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, name, 0)) |_| return;

    // Build top-level const text
    const init_loc = offsets.nodeToLoc(tree, init_node);
    var top_text: std.ArrayList(u8) = .empty;
    try top_text.appendSlice(this.builder.arena, "\n");
    try top_text.appendSlice(this.builder.arena, "const ");
    try top_text.appendSlice(this.builder.arena, name);
    try top_text.appendSlice(this.builder.arena, " = ");
    try top_text.appendSlice(this.builder.arena, tree.source[init_loc.start..init_loc.end]);
    try top_text.appendSlice(this.builder.arena, ";\n");

    // Remove local decl (with semicolon)
    var decl_loc = offsets.nodeToLoc(tree, var_node);
    const last_tok = ast.lastToken(tree, var_node);
    if (last_tok + 1 < tree.tokens.len and tree.tokenTag(last_tok + 1) == .semicolon) {
        const semi_loc = offsets.tokensToLoc(tree, last_tok + 1, last_tok + 1);
        if (semi_loc.end > decl_loc.end) decl_loc.end = semi_loc.end;
    }

    // Multi-doc workspace edit: append new top-level const and remove local decl
    var we: types.WorkspaceEdit = .{ .changes = .{} };
    var cur_edits = try this.builder.arena.alloc(types.TextEdit, 2);
    // append at EOF and remove local decl
    cur_edits[0] = this.builder.createTextEditPos(tree.source.len, top_text.items);
    cur_edits[1] = this.builder.createTextEditLoc(decl_loc, "");
    try we.changes.?.map.put(this.builder.arena, this.builder.handle.uri, cur_edits);

    try this.builder.actions.append(this.builder.arena, .{
        .title = try std.fmt.allocPrint(this.builder.arena, "move '{s}' to top level", .{name}),
        .kind = .refactor,
        .isPreferred = false,
        .edit = we,
    });
}
