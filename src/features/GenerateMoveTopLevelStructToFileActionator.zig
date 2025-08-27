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

    pub fn generateMoveTopLevelStructToFileAction(this: *@This()) !void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        if (this.builder.only_kinds) |set| {
            if (!set.contains(.refactor)) return;
        }

        const tree = this.builder.handle.tree;
        const nodes = try ast.nodesOverlappingIndex(this.builder.arena, tree, this.source_index);
        if (nodes.len == 0) return;

        var top_decl: ?Ast.Node.Index = null;
        for (nodes) |n| {
            if (tree.nodeTag(n) == .global_var_decl) {
                top_decl = n;
                break;
            }
            if (tree.nodeTag(n) == .simple_var_decl) {
                if (tree.fullVarDecl(n)) |v| {
                    if (tree.tokenTag(v.ast.mut_token) == .keyword_const) {
                        top_decl = n;
                        break;
                    }
                }
            }
        }
        const decl_node = top_decl orelse return;
        const v = tree.fullVarDecl(decl_node).?;
        if (tree.tokenTag(v.ast.mut_token) != .keyword_const) return;
        const init = v.ast.init_node.unwrap() orelse return;
        if (tree.tokenTag(tree.nodeMainToken(init)) != .keyword_struct) return;
        const name_tok = v.ast.mut_token + 1;
        if (tree.tokenTag(name_tok) != .identifier) return;
        const name = offsets.identifierTokenToNameSlice(tree, name_tok);
        if (std.mem.eql(u8, name, "_")) return;

        // New file content with alias prelude (std + referenced decls from any file)
        const vis = if (v.visib_token != null) "pub " else "";
        // Scan init subtree tokens for references
        const init_first = tree.firstToken(init);
        const init_last = ast.lastToken(tree, init);
        var needs_std = false;
        // Keep a stable list for emission and maps to dedupe/avoid alias collisions.
        const Alias = struct { alias: []const u8, import_path: []const u8, symbol: []const u8 };
        var aliases: std.ArrayList(Alias) = .empty;
        var used_aliases: std.StringHashMapUnmanaged(void) = .empty; // tracks alias names
        var seen_imports: std.StringHashMapUnmanaged(void) = .empty; // tracks unique import_path+"\x1f"+symbol
        defer used_aliases.deinit(this.builder.arena);
        defer seen_imports.deinit(this.builder.arena);
        var tok = init_first;
        while (tok <= init_last) : (tok += 1) {
            if (tree.tokenTag(tok) != .identifier) continue;
            const id_name = offsets.identifierTokenToNameSlice(tree, tok);
            if (std.mem.eql(u8, id_name, "_")) continue;
            if (std.mem.eql(u8, id_name, "std")) {
                needs_std = true;
                continue;
            }
            const ref_decl = (try this.builder.analyser.lookupSymbolGlobal(
                this.builder.handle,
                id_name,
                tree.tokenStart(tok),
            )) orelse continue;
            const ref_name_tok = ref_decl.nameToken();
            const ref_tree = ref_decl.handle.tree;
            // Accept only AST decls that are importable and top-level
            var allow = false;
            switch (ref_decl.decl) {
                .ast_node => |node| {
                    // Only importable categories
                    switch (ref_tree.nodeTag(node)) {
                        .global_var_decl, .simple_var_decl, .aligned_var_decl,
                        .fn_decl, .fn_proto, .fn_proto_one, .fn_proto_multi, .fn_proto_simple,
                        => allow = true,
                        else => allow = false,
                    }
                    if (allow) {
                        // Same-file: require it to be a root declaration
                        if (std.mem.eql(u8, ref_decl.handle.uri, this.builder.handle.uri)) {
                            var is_root = false;
                            for (ref_tree.rootDecls()) |rd| {
                                if (rd == node) { is_root = true; break; }
                            }
                            allow = is_root;
                        } else {
                            // Cross-file: container check is enough here; visibility checked below
                            const src_idx = ref_tree.tokenStart(ref_name_tok);
                            const doc_scope = try ref_decl.handle.getDocumentScope();
                            const scope_opt = Analyser.innermostScopeAtIndexWithTag(doc_scope, src_idx, .init(.{ .container = true }));
                            allow = if (scope_opt.unwrap()) |scope_idx| scope_idx == .root else false;
                        }
                    }
                },
                else => allow = false,
            }
            if (!allow) continue;

            const ref_name = offsets.identifierTokenToNameSlice(ref_tree, ref_name_tok);
            if (std.mem.eql(u8, ref_name, name)) continue; // skip self
            // Skip members declared within the moved container's init
            if (std.mem.eql(u8, ref_decl.handle.uri, this.builder.handle.uri)) {
                if (ref_name_tok >= init_first and ref_name_tok <= init_last) continue;
            }
            // For cross-file imports, require public visibility
            if (!std.mem.eql(u8, ref_decl.handle.uri, this.builder.handle.uri)) {
                if (!ref_decl.isPublic()) continue;
            }

            // Determine import path
            const dep_uri = ref_decl.handle.uri;
            var import_path: []const u8 = undefined;
            if (std.mem.eql(u8, dep_uri, this.builder.handle.uri)) {
                const cur_path = Uri.toFsPath(this.builder.arena, dep_uri) catch dep_uri;
                import_path = std.fs.path.basename(cur_path);
            } else {
                // prefer relative path from new file's directory if possible; fallback to absolute path
                const cur_fs_path = Uri.toFsPath(this.builder.arena, this.builder.handle.uri) catch dep_uri;
                const cur_dir = std.fs.path.dirname(cur_fs_path) orelse ".";
                const dep_fs_path = Uri.toFsPath(this.builder.arena, dep_uri) catch dep_uri;
                import_path = std.fs.path.relative(this.builder.arena, cur_dir, dep_fs_path) catch dep_fs_path;
            }
            // Dedupe by (import_path, symbol)
            const key = try std.fmt.allocPrint(this.builder.arena, "{s}\x1f{s}", .{ import_path, ref_name });
            const seen = try seen_imports.getOrPut(this.builder.arena, key);
            if (seen.found_existing) continue;
            seen.key_ptr.* = key;

            // Ensure unique alias name
            var alias_name = ref_name;
            var suffix: usize = 1;
            while (used_aliases.get(alias_name) != null) : (suffix += 1) {
                alias_name = try std.fmt.allocPrint(this.builder.arena, "{s}{d}", .{ ref_name, suffix });
            }
            const gop = try used_aliases.getOrPut(this.builder.arena, alias_name);
            if (!gop.found_existing) gop.key_ptr.* = alias_name;
            try aliases.append(this.builder.arena, .{ .alias = alias_name, .import_path = import_path, .symbol = ref_name });
        }

        var file_text: std.ArrayList(u8) = .empty;
        if (needs_std) {
            try file_text.appendSlice(this.builder.arena, "const std = @import(\"std\");\n");
        }
        for (aliases.items) |a| {
            try file_text.appendSlice(this.builder.arena, "const ");
            try file_text.appendSlice(this.builder.arena, a.alias);
            try file_text.appendSlice(this.builder.arena, " = @import(\"");
            try file_text.appendSlice(this.builder.arena, a.import_path);
            // Close string and call, then access symbol: ") .symbol;
            try file_text.appendSlice(this.builder.arena, "\").");
            try file_text.appendSlice(this.builder.arena, a.symbol);
            try file_text.appendSlice(this.builder.arena, ";\n");
        }
        if (needs_std or aliases.items.len != 0) try file_text.appendSlice(this.builder.arena, "\n");
        try file_text.appendSlice(this.builder.arena, vis);
        try file_text.appendSlice(this.builder.arena, "const ");
        try file_text.appendSlice(this.builder.arena, name);
        try file_text.appendSlice(this.builder.arena, " = ");
        try file_text.appendSlice(this.builder.arena, offsets.nodeToSlice(tree, init));
        try file_text.appendSlice(this.builder.arena, ";\n");

        // Replace original with import alias
        var replace_loc = offsets.nodeToLoc(tree, decl_node);
        const end_tok = ast.lastToken(tree, decl_node);
        if (end_tok + 1 < tree.tokens.len and tree.tokenTag(end_tok + 1) == .semicolon) {
            const semi_loc = offsets.tokensToLoc(tree, end_tok + 1, end_tok + 1);
            if (semi_loc.end > replace_loc.end) replace_loc.end = semi_loc.end;
        }
        var import_text: std.ArrayList(u8) = .empty;
        try import_text.appendSlice(this.builder.arena, vis);
        try import_text.appendSlice(this.builder.arena, "const ");
        try import_text.appendSlice(this.builder.arena, name);
        try import_text.appendSlice(this.builder.arena, " = @import(\"");
        const filename = try std.fmt.allocPrint(this.builder.arena, "{s}.zig", .{name});
        try import_text.appendSlice(this.builder.arena, filename);
        try import_text.appendSlice(this.builder.arena, "\").");
        try import_text.appendSlice(this.builder.arena, name);
        try import_text.appendSlice(this.builder.arena, ";\n");

        // Build proper URIs and documentChanges (CreateFile + TextDocumentEdits)
        const cur_fs_path = Uri.toFsPath(this.builder.arena, this.builder.handle.uri) catch return;
        const cur_dir = std.fs.path.dirname(cur_fs_path) orelse ".";
        const new_fs_path = try std.fs.path.join(this.builder.arena, &.{ cur_dir, filename });
        const new_uri = Uri.fromPath(this.builder.arena, new_fs_path) catch return;

        var eb = EditBuilder.init(this.builder.arena);
        try eb.createFile(new_uri);
        try eb.insertAtPosition(new_uri, .{ .line = 0, .character = 0 }, file_text.items);
        const replace_range = offsets.locToRange(tree.source, replace_loc, this.builder.offset_encoding);
        try eb.replaceRange(this.builder.handle.uri, replace_range, import_text.items);

        try this.builder.actions.append(this.builder.arena, .{
            .title = try std.fmt.allocPrint(this.builder.arena, "move to new file", .{}),
            .kind = .refactor,
            .isPreferred = false,
            .edit = try eb.build(),
        });
    }
};
