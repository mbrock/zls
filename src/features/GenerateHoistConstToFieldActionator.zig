const std = @import("std");
const Ast = std.zig.Ast;
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const tracy = @import("tracy");
const Analyser = @import("../analysis.zig");
const Builder = @import("code_actions.zig").Builder;
const EditBuilder = @import("code_actions.zig").EditBuilder;

pub const GenerateHoistConstToFieldActionator = @This();

builder: *Builder,
source_index: usize,

pub fn generateHoistConstToFieldAction(this: *@This()) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    // Only offer this refactor for refactor code action requests
    if (this.builder.only_kinds) |kind_filter| {
        if (!kind_filter.contains(.refactor)) return;
    }

    const tree = this.builder.handle.tree;
    const overlapping_nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
    if (overlapping_nodes.len == 0) return;

    // Find the variable declaration node at the cursor position
    var target_var_node: ?Ast.Node.Index = null;
    for (overlapping_nodes) |node| {
        switch (tree.nodeTag(node)) {
            .local_var_decl, .simple_var_decl, .aligned_var_decl => {
                target_var_node = node;
                break;
            },
            else => {},
        }
    }
    const var_declaration_node = target_var_node orelse return;

    const variable_declaration = tree.fullVarDecl(var_declaration_node).?;
    const initializer_node = variable_declaration.ast.init_node.unwrap() orelse return;

    // Extract the variable name from the declaration
    const name_token = variable_declaration.ast.mut_token + 1;
    if (tree.tokenTag(name_token) != .identifier) return;
    const variable_name = offsets.identifierTokenToNameSlice(tree, name_token);
    if (std.mem.eql(u8, variable_name, "_")) return; // Skip anonymous variables

    // Find the enclosing function that contains this variable
    var enclosing_function_node: ?Ast.Node.Index = null;
    for (overlapping_nodes) |node| {
        switch (tree.nodeTag(node)) {
            .fn_decl => {
                enclosing_function_node = node;
                break;
            },
            else => {},
        }
    }
    const function_node = enclosing_function_node orelse return;
    const function_prototype, const function_body = tree.nodeData(function_node).node_and_node;
    if (function_body == .root) return; // Function has no body
    const function_type = try this.builder.analyser.resolveTypeOfNode(.of(function_node, this.builder.handle));

    // Analyze the function to determine if it's a method with a receiver parameter
    var proto_buffer: [1]Ast.Node.Index = undefined;
    const prototype = tree.fullFnProto(&proto_buffer, function_prototype).?;
    const container_type = try this.builder.analyser.innermostContainer(this.builder.handle, tree.tokenStart(prototype.ast.fn_token));
    const container_instance = (try container_type.instanceTypeVal(this.builder.analyser)) orelse container_type;
    _ = container_instance; // Unused but kept for potential future use

    // Extract the receiver parameter name (first parameter of the method)
    // Only proceed if this is a method with a receiver parameter
    const receiver_parameter_name = blk_recv: {
        const function_type_info = function_type orelse break :blk_recv null;
        if (function_type_info.data != .function) break :blk_recv null;
        const function_data = function_type_info.data.function;
        if (function_data.parameters.len == 0) break :blk_recv null;
        const first_parameter = function_data.parameters[0];
        if (first_parameter.name) |parameter_name| {
            break :blk_recv parameter_name;
        } else break :blk_recv null;
    } orelse return; // Not a method - skip this refactor

    // Find the enclosing container (struct/union) where we'll add the field
    var target_container_node: ?Ast.Node.Index = null;
    for (overlapping_nodes) |node| {
        var container_buffer: [2]Ast.Node.Index = undefined;
        if (tree.fullContainerDecl(&container_buffer, node)) |_| {
            target_container_node = node;
            break;
        }
    }
    const container_node = target_container_node orelse return;

    // Determine the field type: use explicit type if available, otherwise infer from initializer
    const field_type_text = blk_field_type: {
        if (variable_declaration.ast.type_node.unwrap()) |type_node|
            break :blk_field_type offsets.nodeToSlice(tree, type_node);
        if (try this.builder.analyser.resolveTypeOfNode(.of(initializer_node, this.builder.handle))) |inferred_type|
            break :blk_field_type try inferred_type.stringifyTypeOf(this.builder.analyser, .{ .truncate_container_decls = false });
        break :blk_field_type "var"; // Fallback (unlikely case)
    };
    // Calculate proper indentation for the new field by examining existing container members
    var container_decl_buffer: [2]Ast.Node.Index = undefined;
    const container_declaration = tree.fullContainerDecl(&container_decl_buffer, container_node).?;
    const field_indentation = blk_indent: {
        if (container_declaration.ast.members.len > 0) {
            // Use the same indentation as the first existing member
            const first_member = container_declaration.ast.members[0];
            const member_line = offsets.lineLocAtIndex(tree.source, offsets.nodeToLoc(tree, first_member).start);
            var indent_end: usize = member_line.start;
            while (indent_end < member_line.end and (tree.source[indent_end] == ' ' or tree.source[indent_end] == '\t')) {
                indent_end += 1;
            }
            break :blk_indent tree.source[member_line.start..indent_end];
        } else {
            // No existing members - use container indentation + 4 spaces
            const container_line = offsets.lineLocAtIndex(tree.source, offsets.nodeToLoc(tree, container_node).start);
            var indent_end: usize = container_line.start;
            while (indent_end < container_line.end and (tree.source[indent_end] == ' ' or tree.source[indent_end] == '\t')) {
                indent_end += 1;
            }
            const base_indentation = tree.source[container_line.start..indent_end];
            break :blk_indent try std.mem.concat(this.builder.arena, u8, &.{ base_indentation, "    " });
        }
    };
    // Determine where to insert the new field within the container
    var field_insertion_position: usize = undefined;
    var last_existing_field: ?Ast.Node.Index = null;

    // Find the last existing field in the container
    for (container_declaration.ast.members) |member| {
        switch (tree.nodeTag(member)) {
            .container_field, .container_field_init, .container_field_align => last_existing_field = member,
            else => {},
        }
    }

    if (last_existing_field) |last_field| {
        // Insert after the last existing field
        field_insertion_position = offsets.nodeToLoc(tree, last_field).end;
    } else if (container_declaration.ast.members.len > 0) {
        // No fields but other members exist - insert before first member
        field_insertion_position = offsets.nodeToLoc(tree, container_declaration.ast.members[0]).start;
    } else {
        // Empty container - insert after the opening brace
        var token_index = tree.firstToken(container_node);
        while (token_index < tree.tokens.len and tree.tokenTag(token_index) != .l_brace) : (token_index += 1) {}
        field_insertion_position = if (token_index < tree.tokens.len)
            tree.tokenStart(token_index) + 1
        else
            offsets.nodeToLoc(tree, container_node).start;
    }

    // Build the field declaration text (e.g., "field_name: FieldType,")
    var field_declaration_text: std.ArrayList(u8) = .empty;
    try field_declaration_text.appendSlice(this.builder.arena, "\n"); // Ensure newline before the field
    try field_declaration_text.appendSlice(this.builder.arena, field_indentation);
    try field_declaration_text.appendSlice(this.builder.arena, variable_name);
    try field_declaration_text.appendSlice(this.builder.arena, ": ");
    try field_declaration_text.appendSlice(this.builder.arena, field_type_text);
    try field_declaration_text.appendSlice(this.builder.arena, ",");

    // Prepare to replace the local variable declaration with field assignment
    const function_body_location = offsets.nodeToLoc(tree, function_body);
    const variable_declaration_location = offsets.nodeToLoc(tree, var_declaration_node);
    // Include trailing semicolon in the replacement range if present
    var declaration_end_position = variable_declaration_location.end;
    const last_declaration_token = ast.lastToken(tree, var_declaration_node);
    if (last_declaration_token + 1 < tree.tokens.len and tree.tokenTag(last_declaration_token + 1) == .semicolon) {
        const semicolon_location = offsets.tokensToLoc(tree, last_declaration_token + 1, last_declaration_token + 1);
        if (semicolon_location.end > declaration_end_position) {
            declaration_end_position = semicolon_location.end;
        }
    }

    const initializer_location = offsets.nodeToLoc(tree, initializer_node);

    // Extract indentation from the original declaration line to maintain consistent formatting
    const declaration_line = offsets.lineLocAtIndex(tree.source, variable_declaration_location.start);
    const declaration_indentation = blk_declaration_indent: {
        var indent_end: usize = declaration_line.start;
        while (indent_end < variable_declaration_location.start and
            (tree.source[indent_end] == ' ' or tree.source[indent_end] == '\t'))
        {
            indent_end += 1;
        }
        break :blk_declaration_indent tree.source[declaration_line.start..indent_end];
    };
    // Build the assignment statement to replace the variable declaration
    // (e.g., "self.field_name = initializer_value;")
    var assignment_statement: std.ArrayList(u8) = .empty;
    try assignment_statement.appendSlice(this.builder.arena, declaration_indentation);
    try assignment_statement.appendSlice(this.builder.arena, receiver_parameter_name);
    try assignment_statement.appendSlice(this.builder.arena, ".");
    try assignment_statement.appendSlice(this.builder.arena, variable_name);
    try assignment_statement.appendSlice(this.builder.arena, " = ");
    try assignment_statement.appendSlice(this.builder.arena, tree.source[initializer_location.start..initializer_location.end]);
    try assignment_statement.appendSlice(this.builder.arena, ";\n");

    // Collect all the text edits needed for this refactoring
    var text_edits: std.ArrayList(types.TextEdit) = .empty;

    // Replace the original variable declaration with the field assignment
    try text_edits.append(this.builder.arena, this.builder.createTextEditLoc(.{ .start = variable_declaration_location.start, .end = declaration_end_position }, assignment_statement.items));

    // Insert the field declaration in the container
    try text_edits.append(this.builder.arena, this.builder.createTextEditPos(field_insertion_position, field_declaration_text.items));
    // Find and update all usages of the variable within the function body
    // Replace "variable_name" with "receiver.variable_name"
    var current_token = offsets.sourceIndexToTokenIndex(tree, declaration_end_position).preferRight(&tree);
    const function_end_token = offsets.sourceIndexToTokenIndex(tree, function_body_location.end).preferLeft();

    // Get a handle to the original variable declaration for comparison
    const original_declaration_handle = (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, variable_name, variable_declaration_location.start)) orelse null;

    if (original_declaration_handle) |target_declaration| {
        while (current_token <= function_end_token) : (current_token += 1) {
            if (tree.tokenTag(current_token) != .identifier) continue;

            const token_name = offsets.identifierTokenToNameSlice(tree, current_token);
            if (!std.mem.eql(u8, token_name, variable_name)) continue;

            const token_start_position = tree.tokenStart(current_token);
            if (try this.builder.analyser.lookupSymbolGlobal(this.builder.handle, token_name, token_start_position)) |reference_declaration| {
                if (!reference_declaration.eql(target_declaration)) continue;

                // This is a reference to our variable - replace it with receiver.variable_name
                const token_location = offsets.tokenToLoc(tree, current_token);
                var replacement_text: std.ArrayList(u8) = .empty;
                try replacement_text.appendSlice(this.builder.arena, receiver_parameter_name);
                try replacement_text.appendSlice(this.builder.arena, ".");
                try replacement_text.appendSlice(this.builder.arena, variable_name);
                try text_edits.append(this.builder.arena, this.builder.createTextEditLoc(token_location, replacement_text.items));
            }
        }
    }
    // Create and register the code action
    var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
    try this.builder.addWorkspaceTextEdit(&workspace_edit, this.builder.handle.uri, text_edits.items);
    try this.builder.actions.append(this.builder.arena, .{
        .title = "hoist local to field",
        .kind = .refactor,
        .isPreferred = false,
        .edit = workspace_edit,
    });
}
