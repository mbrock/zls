const std = @import("std");
const Ast = std.zig.Ast;
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const ast = @import("../ast.zig");
const Uri = @import("../uri.zig");
const tracy = @import("tracy");
const Analyser = @import("../analysis.zig");
// Reuse shared builder types from code_actions to avoid duplication. This is a benign cycle.
const Builder = @import("code_actions.zig").Builder;
const EditBuilder = @import("code_actions.zig").EditBuilder;

pub const GenerateMoveTopLevelStructToFileActionator = struct {
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

        // Determine visibility for the new file content
        const visibility_modifier = if (struct_variable_declaration.visib_token != null) "pub " else "";
        
        // Scan the struct definition for external references that need to be imported
        const struct_first_token = tree.firstToken(struct_initializer);
        const struct_last_token = ast.lastToken(tree, struct_initializer);
        var needs_std_import = false;
        
        // Track dependencies to generate proper import statements
        const ImportDependency = struct { 
            alias: []const u8, 
            import_path: []const u8, 
            symbol: []const u8 
        };
        var import_dependencies: std.ArrayList(ImportDependency) = .empty;
        var used_alias_names: std.StringHashMapUnmanaged(void) = .empty; // Prevents alias name collisions
        var processed_imports: std.StringHashMapUnmanaged(void) = .empty; // Deduplicates imports by path+symbol
        defer used_alias_names.deinit(this.builder.arena);
        defer processed_imports.deinit(this.builder.arena);
        // Iterate through all tokens in the struct definition to find external references
        var current_token = struct_first_token;
        while (current_token <= struct_last_token) : (current_token += 1) {
            if (tree.tokenTag(current_token) != .identifier) continue;
            
            const identifier_name = offsets.identifierTokenToNameSlice(tree, current_token);
            if (std.mem.eql(u8, identifier_name, "_")) continue; // Skip anonymous identifiers
            
            // Check if this references the standard library
            if (std.mem.eql(u8, identifier_name, "std")) {
                needs_std_import = true;
                continue;
            }
            // Look up the symbol this identifier refers to
            const referenced_declaration = (try this.builder.analyser.lookupSymbolGlobal(
                this.builder.handle,
                identifier_name,
                tree.tokenStart(current_token),
            )) orelse continue;
            
            const referenced_name_token = referenced_declaration.nameToken();
            const referenced_tree = referenced_declaration.handle.tree;
            // Validate that this declaration can be imported
            var is_importable = false;
            switch (referenced_declaration.decl) {
                .ast_node => |node| {
                    // Only importable categories
                    switch (referenced_tree.nodeTag(node)) {
                        .global_var_decl, .simple_var_decl, .aligned_var_decl,
                        .fn_decl, .fn_proto, .fn_proto_one, .fn_proto_multi, .fn_proto_simple,
                        => is_importable = true,
                        else => is_importable = false,
                    }
                    if (is_importable) {
                        // Same-file: require it to be a root declaration
                        if (std.mem.eql(u8, referenced_declaration.handle.uri, this.builder.handle.uri)) {
                            var is_root_declaration = false;
                            for (referenced_tree.rootDecls()) |root_decl| {
                                if (root_decl == node) { is_root_declaration = true; break; }
                            }
                            is_importable = is_root_declaration;
                        } else {
                            // Cross-file: container check is enough here; visibility checked below
                            const source_index = referenced_tree.tokenStart(referenced_name_token);
                            const document_scope = try referenced_declaration.handle.getDocumentScope();
                            const scope_result = Analyser.innermostScopeAtIndexWithTag(document_scope, source_index, .init(.{ .container = true }));
                            is_importable = if (scope_result.unwrap()) |scope_index| scope_index == .root else false;
                        }
                    }
                },
                else => is_importable = false,
            }
            if (!is_importable) continue;

            const referenced_symbol_name = offsets.identifierTokenToNameSlice(referenced_tree, referenced_name_token);
            if (std.mem.eql(u8, referenced_symbol_name, struct_name)) continue; // Skip self-reference
            // Skip members declared within the moved container's init
            if (std.mem.eql(u8, referenced_declaration.handle.uri, this.builder.handle.uri)) {
                if (referenced_name_token >= struct_first_token and referenced_name_token <= struct_last_token) continue;
            }
            // For cross-file imports, require public visibility
            if (!std.mem.eql(u8, referenced_declaration.handle.uri, this.builder.handle.uri)) {
                if (!referenced_declaration.isPublic()) continue;
            }

            // Determine import path
            const dependency_uri = referenced_declaration.handle.uri;
            var import_path: []const u8 = undefined;
            if (std.mem.eql(u8, dependency_uri, this.builder.handle.uri)) {
                const current_file_path = Uri.toFsPath(this.builder.arena, dependency_uri) catch dependency_uri;
                import_path = std.fs.path.basename(current_file_path);
            } else {
                // prefer relative path from new file's directory if possible; fallback to absolute path
                const current_fs_path = Uri.toFsPath(this.builder.arena, this.builder.handle.uri) catch dependency_uri;
                const current_directory = std.fs.path.dirname(current_fs_path) orelse ".";
                const dependency_file_path = Uri.toFsPath(this.builder.arena, dependency_uri) catch dependency_uri;
                import_path = std.fs.path.relative(this.builder.arena, current_directory, dependency_file_path) catch dependency_file_path;
            }
            // Dedupe by (import_path, symbol)
            const deduplication_key = try std.fmt.allocPrint(this.builder.arena, "{s}\x1f{s}", .{ import_path, referenced_symbol_name });
            const already_processed = try processed_imports.getOrPut(this.builder.arena, deduplication_key);
            if (already_processed.found_existing) continue;
            already_processed.key_ptr.* = deduplication_key;

            // Ensure unique alias name
            var alias_name = referenced_symbol_name;
            var suffix: usize = 1;
            while (used_alias_names.get(alias_name) != null) : (suffix += 1) {
                alias_name = try std.fmt.allocPrint(this.builder.arena, "{s}{d}", .{ referenced_symbol_name, suffix });
            }
            const alias_entry = try used_alias_names.getOrPut(this.builder.arena, alias_name);
            if (!alias_entry.found_existing) alias_entry.key_ptr.* = alias_name;
            try import_dependencies.append(this.builder.arena, .{ .alias = alias_name, .import_path = import_path, .symbol = referenced_symbol_name });
        }

        var new_file_content: std.ArrayList(u8) = .empty;
        if (needs_std_import) {
            try new_file_content.appendSlice(this.builder.arena, "const std = @import(\"std\");\n");
        }
        for (import_dependencies.items) |dependency| {
            try new_file_content.appendSlice(this.builder.arena, "const ");
            try new_file_content.appendSlice(this.builder.arena, dependency.alias);
            try new_file_content.appendSlice(this.builder.arena, " = @import(\"");
            try new_file_content.appendSlice(this.builder.arena, dependency.import_path);
            // Close string and call, then access symbol: ") .symbol;
            try new_file_content.appendSlice(this.builder.arena, "\").");
            try new_file_content.appendSlice(this.builder.arena, dependency.symbol);
            try new_file_content.appendSlice(this.builder.arena, ";\n");
        }
        if (needs_std_import or import_dependencies.items.len != 0) try new_file_content.appendSlice(this.builder.arena, "\n");
        try new_file_content.appendSlice(this.builder.arena, visibility_modifier);
        try new_file_content.appendSlice(this.builder.arena, "const ");
        try new_file_content.appendSlice(this.builder.arena, struct_name);
        try new_file_content.appendSlice(this.builder.arena, " = ");
        try new_file_content.appendSlice(this.builder.arena, offsets.nodeToSlice(tree, struct_initializer));
        try new_file_content.appendSlice(this.builder.arena, ";\n");

        // Replace original with import alias
        var replacement_location = offsets.nodeToLoc(tree, struct_declaration_node);
        const last_token = ast.lastToken(tree, struct_declaration_node);
        if (last_token + 1 < tree.tokens.len and tree.tokenTag(last_token + 1) == .semicolon) {
            const semicolon_location = offsets.tokensToLoc(tree, last_token + 1, last_token + 1);
            if (semicolon_location.end > replacement_location.end) replacement_location.end = semicolon_location.end;
        }
        var import_statement: std.ArrayList(u8) = .empty;
        try import_statement.appendSlice(this.builder.arena, visibility_modifier);
        try import_statement.appendSlice(this.builder.arena, "const ");
        try import_statement.appendSlice(this.builder.arena, struct_name);
        try import_statement.appendSlice(this.builder.arena, " = @import(\"");
        const new_filename = try std.fmt.allocPrint(this.builder.arena, "{s}.zig", .{struct_name});
        try import_statement.appendSlice(this.builder.arena, new_filename);
        try import_statement.appendSlice(this.builder.arena, "\").");
        try import_statement.appendSlice(this.builder.arena, struct_name);
        try import_statement.appendSlice(this.builder.arena, ";\n");

        // Build proper URIs and documentChanges (CreateFile + TextDocumentEdits)
        const current_file_system_path = Uri.toFsPath(this.builder.arena, this.builder.handle.uri) catch return;
        const current_directory = std.fs.path.dirname(current_file_system_path) orelse ".";
        const new_file_path = try std.fs.path.join(this.builder.arena, &.{ current_directory, new_filename });
        const new_file_uri = Uri.fromPath(this.builder.arena, new_file_path) catch return;

        var edit_builder = EditBuilder.init(this.builder.arena);
        try edit_builder.createFile(new_file_uri);
        try edit_builder.insertAtPosition(new_file_uri, .{ .line = 0, .character = 0 }, new_file_content.items);
        const replacement_range = offsets.locToRange(tree.source, replacement_location, this.builder.offset_encoding);
        try edit_builder.replaceRange(this.builder.handle.uri, replacement_range, import_statement.items);

        try this.builder.actions.append(this.builder.arena, .{
            .title = try std.fmt.allocPrint(this.builder.arena, "move to new file", .{}),
            .kind = .refactor,
            .isPreferred = false,
            .edit = try edit_builder.build(),
        });
    }
};
