const std = @import("std");
const Ast = std.zig.Ast;
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const Uri = @import("../uri.zig");
const tracy = @import("tracy");
const Analyser = @import("../analysis.zig");

const code_actions = @import("code_actions.zig");
const Builder = @import("code_actions.zig").Builder;
const EditBuilder = @import("code_actions.zig").EditBuilder;
const Render = @import("../Render.zig");

pub const GenerateMoveTopLevelStructToFileActionator = @This();

builder: *Builder,
source_index: usize,

/// Extracts a top-level struct declaration into its own file.
/// Creates MyStruct.zig with the struct definition and replaces the original
/// with an import statement. Automatically generates necessary imports.
pub fn generateMoveTopLevelStructToFileAction(this: *@This()) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    // Only offer this refactor for refactor code action requests
    if (this.builder.only_kinds) |kind_filter| {
        if (!kind_filter.contains(.refactor)) return;
    }

    const tree = this.builder.handle.tree;
    const overlapping_nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
    if (overlapping_nodes.len == 0) return;

    // Find a top-level struct declaration at the cursor position
    var target_struct_declaration: ?Ast.Node.Index = null;
    for (overlapping_nodes) |node| {
        if (tree.nodeTag(node) == .global_var_decl) {
            target_struct_declaration = node;
            break;
        }
        if (tree.nodeTag(node) == .simple_var_decl) {
            if (tree.fullVarDecl(node)) |variable_declaration| {
                if (tree.tokenTag(variable_declaration.ast.mut_token) == .keyword_const) {
                    target_struct_declaration = node;
                    break;
                }
            }
        }
    }
    const struct_declaration_node = target_struct_declaration orelse return;
    const struct_variable_declaration = tree.fullVarDecl(struct_declaration_node).?;
    //        const is_public = struct_variable_declaration.visib_token != null;

    // Validate this is a const declaration
    if (tree.tokenTag(struct_variable_declaration.ast.mut_token) != .keyword_const) return;

    // Validate the initializer is a struct
    const struct_initializer = struct_variable_declaration.ast.init_node.unwrap() orelse return;
    if (tree.tokenTag(tree.nodeMainToken(struct_initializer)) != .keyword_struct) return;

    // Extract the struct name
    const struct_name_token = struct_variable_declaration.ast.mut_token + 1;
    if (tree.tokenTag(struct_name_token) != .identifier) return;
    const struct_name = offsets.identifierTokenToNameSlice(tree, struct_name_token);
    if (std.mem.eql(u8, struct_name, "_")) return; // Skip anonymous structs

    // Extract the struct body
    var buf: [2]Ast.Node.Index = undefined;
    const foo = tree.fullContainerDecl(&buf, struct_initializer) orelse unreachable;
    const body1 = tree.tokenStart(tree.firstToken(foo.ast.members[0]));
    const tok2 = tree.lastToken(foo.ast.members[foo.ast.members.len - 1]);
    const body2 = tree.tokenStart(tok2) + @as(u32, @intCast(tree.tokenSlice(tok2).len));

    const arena = this.builder.arena;

    var new_file_buffer = std.Io.Writer.Allocating.init(arena);
    defer new_file_buffer.deinit();

    var ais = Render.AutoIndentingStream.init(arena, &new_file_buffer.writer, 4);
    var render = Render{
        .ais = &ais,
        .fixups = .{},
        .gpa = arena,
        .tree = tree,
    };

    const imports = try code_actions.getImportsDecls(this.builder, this.builder.arena);

    // we should iterate over tokens in the struct body,
    // find identifiers that resolve to decls in the parent container,
    // make a list of relative positions where to insert "@import(...)."
    // and do that before creating the new file
    //
    // i think we could simply insert n copies of the import expr at first
    // and then consider it a separate refactoring to consolidate those
    // into a named const X = @import(...)

    var import_positions = std.ArrayList(u32){};
    var used_imports = try std.DynamicBitSet.initEmpty(arena, imports.len);

    const tokens = try ast.nodeChildrenRecursiveAlloc(arena, tree, target_struct_declaration.?);
    tkn: for (tokens) |token| {
        const mainTokenU32 = tree.nodeMainToken(token);
        const tag = tree.tokenTag(mainTokenU32);
        std.debug.print("main token {s} ({s}) for node {s}\n\n", .{
            tree.tokenSlice(mainTokenU32),
            @tagName(tag),
            tree.getNodeSource(token),
        });
        if (tag != .identifier) continue;
        const slice = tree.tokenSlice(mainTokenU32);

        for (imports, 0..imports.len) |imp, idx| {
            if (std.mem.eql(u8, slice, imp.name)) {
                // This is an imported symbol; skip
                used_imports.set(idx);
                continue :tkn;
            }
        }

        const ctx = try Analyser.getPositionContext(arena, tree, mainTokenU32, true);
        switch (ctx) {
            .var_access => |_| {
                const docscope = try this.builder.handle.getDocumentScope();
                if (docscope.getScopeDeclaration(.{ .scope = .root, .name = slice, .kind = .other }) != .none) {
                    try import_positions.append(arena, mainTokenU32);
                } else {
                    std.debug.print("skipping extra import for {s}; not in root container\n", .{slice});
                }
            },
            else => {
                std.debug.print("skipping import for {s} in ctx {s}\n", .{ slice, @tagName(ctx) });
                continue;
            },
        }
    }

    for (imports, 0..imports.len) |import_decl, idx| {
        if (used_imports.isSet(idx)) {
            const decl = tree.fullVarDecl(import_decl.var_decl) orelse unreachable;
            try render.renderVarDeclWithoutFixups(decl, false, .semicolon);
            try render.ais.maybeInsertNewline();
        }
    }

    try render.ais.insertNewline();

    const current_file_system_path = try Uri.toFsPath(this.builder.arena, this.builder.handle.uri);
    const current_filename = std.fs.path.basename(current_file_system_path);
    const current_directory = std.fs.path.dirname(current_file_system_path) orelse ".";

    const selfimport = try std.fmt.allocPrint(
        arena,
        "@import(\"{s}\").",
        .{current_filename},
    );

    var edits = try std.ArrayList(types.TextEdit).initCapacity(arena, import_positions.items.len);

    //        const src = tree.getNodeSource(struct_declaration_node);
    const src = tree.source[body1..body2];

    for (import_positions.items) |import_position| {
        const startabs = tree.tokenStart(import_position);
        const startrel = startabs - body1; //tree.tokenStart(tree.firstToken(struct_declaration_node));
        const pos = offsets.indexToPosition(src, startrel, this.builder.offset_encoding);
        try edits.append(arena, .{
            .range = .{ .start = pos, .end = pos },
            .newText = selfimport,
        });
    }

    const newsrc = try @import("../diff.zig").applyTextEdits(
        arena,
        src,
        edits.items,
        this.builder.offset_encoding,
    );

    try render.ais.print("const {s} = @This();\n\n", .{struct_name});
    try render.ais.writeAll(newsrc);
    try render.ais.insertNewline();

    var replacement_location = offsets.nodeToLoc(tree, struct_declaration_node);
    const last_token = ast.lastToken(tree, struct_declaration_node);
    if (last_token + 1 < tree.tokens.len and tree.tokenTag(last_token + 1) == .semicolon) {
        const semicolon_location = offsets.tokensToLoc(tree, last_token + 1, last_token + 1);
        if (semicolon_location.end > replacement_location.end) {
            replacement_location.end = semicolon_location.end;
        }
    }

    const new_filename = try std.fmt.allocPrint(arena, "{s}.zig", .{struct_name});
    const replacement = try std.fmt.allocPrint(
        arena,
        "pub const {s} = @import(\"{s}.zig\");\n",
        .{
            struct_name,
            struct_name,
        },
    );

    const new_file_path = try std.fs.path.join(
        this.builder.arena,
        &.{ current_directory, new_filename },
    );

    const new_file_uri = try Uri.fromPath(this.builder.arena, new_file_path);

    var edit_builder = EditBuilder.init(this.builder.arena);
    try edit_builder.createFile(new_file_uri);
    try edit_builder.insertAtPosition(
        new_file_uri,
        .{ .line = 0, .character = 0 },
        try new_file_buffer.toOwnedSlice(),
    );
    const replacement_range = offsets.locToRange(
        tree.source,
        replacement_location,
        this.builder.offset_encoding,
    );

    try edit_builder.replaceRange(
        this.builder.handle.uri,
        replacement_range,
        replacement,
    );

    // for (import_positions.items) |import_position| {
    //     const range = offsets.nodeToRange(tree, import_position, this.builder.offset_encoding);
    //     try edit_builder.insertAtPosition(
    //         this.builder.handle.uri,
    //         range.start,
    //         selfimport,
    //     );
    // }

    const edit = try edit_builder.build();
    try this.builder.actions.append(this.builder.arena, .{
        .title = "move struct to new file",
        .kind = .refactor,
        .isPreferred = false,
        .edit = edit,
    });

    std.debug.print("Generated edit:\n{f}\n", .{std.json.fmt(edit, .{ .whitespace = .indent_2 })});
}
