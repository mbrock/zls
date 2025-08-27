//! Implementation of [`textDocument/codeAction`](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_codeAction)

const std = @import("std");
const Ast = std.zig.Ast;
const Token = std.zig.Token;

const DocumentStore = @import("../DocumentStore.zig");
const DocumentScope = @import("../DocumentScope.zig");
const Analyser = @import("../analysis.zig");
const ast = @import("../ast.zig");
const types = @import("lsp").types;
const offsets = @import("../offsets.zig");
const Uri = @import("../uri.zig");
const tracy = @import("tracy");

pub const Builder = struct {
    arena: std.mem.Allocator,
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    offset_encoding: offsets.Encoding,
    only_kinds: ?std.EnumSet(std.meta.Tag(types.CodeActionKind)),

    actions: std.ArrayList(types.CodeAction) = .empty,
    fixall_text_edits: std.ArrayList(types.TextEdit) = .empty,

    pub fn generateCodeAction(
        builder: *Builder,
        error_bundle: std.zig.ErrorBundle,
    ) error{OutOfMemory}!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        var remove_capture_actions: std.AutoHashMapUnmanaged(types.Range, void) = .empty;

        try handleUnorganizedImport(builder);
        try handleNormalizeImport(builder);

        if (error_bundle.errorMessageCount() == 0) return; // `getMessages` can't be called on an empty ErrorBundle
        for (error_bundle.getMessages()) |msg_index| {
            const err = error_bundle.getErrorMessage(msg_index);
            const message = error_bundle.nullTerminatedString(err.msg);
            const kind = DiagnosticKind.parse(message) orelse continue;

            if (err.src_loc == .none) continue;
            const src_loc = error_bundle.getSourceLocation(err.src_loc);

            const loc: offsets.Loc = .{
                .start = src_loc.span_start,
                .end = src_loc.span_end,
            };

            switch (kind) {
                .unused => |id| switch (id) {
                    .@"function parameter" => try handleUnusedFunctionParameter(builder, loc),
                    .@"local constant" => try handleUnusedVariableOrConstant(builder, loc),
                    .@"local variable" => try handleUnusedVariableOrConstant(builder, loc),
                    .@"switch tag capture", .capture => try handleUnusedCapture(builder, loc, &remove_capture_actions),
                },
                .non_camelcase_fn => try handleNonCamelcaseFunction(builder, loc),
                .pointless_discard => try handlePointlessDiscard(builder, loc),
                .omit_discard => |id| switch (id) {
                    .@"error capture; omit it instead" => {},
                    .@"error capture" => try handleUnusedCapture(builder, loc, &remove_capture_actions),
                },
                // the undeclared identifier may be a discard
                .undeclared_identifier => try handlePointlessDiscard(builder, loc),
                .unreachable_code => {
                    // TODO
                    // autofix: comment out code
                    // fix: remove code
                },
                .var_never_mutated => try handleVariableNeverMutated(builder, loc),
            }
        }

        if (builder.fixall_text_edits.items.len != 0) {
            try builder.actions.append(builder.arena, .{
                .title = "apply fixall",
                .kind = .@"source.fixAll",
                .edit = try builder.createWorkspaceEdit(builder.fixall_text_edits.items),
            });
        }
    }

    /// Returns `false` if the client explicitly specified that they are not interested in this code action kind.
    fn wantKind(builder: *Builder, kind: std.meta.Tag(types.CodeActionKind)) bool {
        const only_kinds = builder.only_kinds orelse return true;
        return only_kinds.contains(kind);
    }

    pub fn generateCodeActionsInRange(
        builder: *Builder,
        range: types.Range,
    ) error{OutOfMemory}!void {
        const tracy_zone = tracy.trace(@src());
        defer tracy_zone.end();

        const tree = builder.handle.tree;

        const start_index = offsets.positionToIndex(tree.source, range.start, builder.offset_encoding);
        const range_loc = offsets.rangeToLoc(tree.source, range, builder.offset_encoding);

        try generateExtractFunctionCodeAction(builder, range_loc);
        try generateEncapsulateParamsStructAction(builder, start_index);
        try generateHoistConstToFieldAction(builder, start_index);
        try generateMoveDeclToTopLevelAction(builder, start_index);
        try generateMoveTopLevelStructToFileAction(builder, start_index);

        const ctx = try Analyser.getPositionContext(builder.arena, builder.handle.tree, start_index, true);
        if (ctx != .string_literal) return;

        var token_idx = offsets.sourceIndexToTokenIndex(tree, start_index).pickPreferred(&.{ .string_literal, .multiline_string_literal_line }, &tree) orelse return;

        // if `offsets.sourceIndexToTokenIndex` is called with a source index between two tokens, it will be the token to the right.
        switch (tree.tokenTag(token_idx)) {
            .string_literal, .multiline_string_literal_line => {},
            else => token_idx -|= 1,
        }

        switch (tree.tokenTag(token_idx)) {
            .multiline_string_literal_line => try generateMultilineStringCodeActions(builder, token_idx),
            .string_literal => try generateStringLiteralCodeActions(builder, token_idx),
            else => {},
        }
    }

    fn generateMoveDeclToTopLevelAction(builder: *Builder, source_index: usize) !void {
        var args = GenerateMoveDeclToTopLevelActionator{
            .builder = builder,
            .source_index = source_index,
        };
        _ = try args.generateMoveDeclToTopLevelAction();
    }

    fn generateHoistConstToFieldAction(builder: *Builder, source_index: usize) !void {
        var args = GenerateHoistConstToFieldActionator{
            .builder = builder,
            .source_index = source_index,
        };
        _ = try args.generateHoistConstToFieldAction();
    }

    fn generateEncapsulateParamsStructAction(builder: *Builder, source_index: usize) !void {
        var args = GenerateEncapsulateParamsStructActionator{ .builder = builder, .source_index = source_index };
        _ = try args.generateEncapsulateParamsStructAction();
    }

    fn generateExtractFunctionCodeAction(builder: *Builder, loc: offsets.Loc) !void {
        var args = GenerateExtractFunctionCodeActionator{
            .builder = builder,
            .loc = loc,
        };
        _ = try args.generateExtractFunctionCodeAction();
    }

    pub fn createTextEditLoc(self: *Builder, loc: offsets.Loc, new_text: []const u8) types.TextEdit {
        const range = offsets.locToRange(self.handle.tree.source, loc, self.offset_encoding);
        return .{ .range = range, .newText = new_text };
    }

    pub fn createTextEditPos(self: *Builder, index: usize, new_text: []const u8) types.TextEdit {
        const position = offsets.indexToPosition(self.handle.tree.source, index, self.offset_encoding);
        return .{ .range = .{ .start = position, .end = position }, .newText = new_text };
    }

    pub fn addWorkspaceTextEdit(
        self: *Builder,
        workspace_edit: *types.WorkspaceEdit,
        uri: types.DocumentUri,
        edits: []const types.TextEdit,
    ) error{OutOfMemory}!void {
        try workspace_edit.changes.?.map.putNoClobber(
            self.arena,
            uri,
            try self.arena.dupe(types.TextEdit, edits),
        );
    }

    pub fn createWorkspaceEdit(
        self: *Builder,
        edits: []const types.TextEdit,
    ) error{OutOfMemory}!types.WorkspaceEdit {
        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try self.addWorkspaceTextEdit(&workspace_edit, self.handle.uri, edits);
        return workspace_edit;
    }
};

const DocumentChange = types.TypePaths.@"WorkspaceEdit/documentChanges";
const TextEdit = types.TypePaths.@"TextDocumentEdit/edits";

pub const EditBuilder = struct {
    alloc: std.mem.Allocator,
    dcs: std.ArrayList(DocumentChange) = .{},
    changes: std.json.ArrayHashMap([]const types.TextEdit) = .{},

    pub fn init(a: std.mem.Allocator) EditBuilder {
        return .{ .alloc = a };
    }

    pub fn deinit(self: *EditBuilder) void {
        self.dcs.deinit();
    }

    pub fn createFile(
        self: *EditBuilder,
        uri: types.DocumentUri,
    ) !void {
        try self.dcs.append(self.alloc, .{
            .CreateFile = .{
                .uri = uri,
                .options = .{ .overwrite = true },
            },
        });
    }

    pub fn textDocumentEdit(
        self: *EditBuilder,
        tde: types.TextDocumentEdit,
    ) !void {
        try self.dcs.append(self.alloc, DocumentChange{ .TextDocumentEdit = tde });
    }

    pub fn insertAtPosition(
        self: *EditBuilder,
        uri: types.DocumentUri,
        position: types.Position,
        text: []const u8,
    ) !void {
        try self.replaceRange(uri, .{ .start = position, .end = position }, text);
    }

    pub fn replaceRange(
        self: *EditBuilder,
        uri: types.DocumentUri,
        range: types.Range,
        text: []const u8,
    ) !void {
        var edits: []TextEdit = try self.alloc.alloc(TextEdit, 1);
        edits[0] = TextEdit{ .TextEdit = types.TextEdit{
            .range = range,
            .newText = try self.alloc.dupe(u8, text),
        } };

        const tde = types.TextDocumentEdit{
            .edits = try self.alloc.dupe(TextEdit, edits),
            .textDocument = .{ .uri = uri, .version = 100 },
        };

        try self.textDocumentEdit(tde);
    }

    pub fn build(self: *EditBuilder) !types.WorkspaceEdit {
        return types.WorkspaceEdit{
            .documentChanges = try self.dcs.toOwnedSlice(self.alloc),
        };
    }
};

pub fn generateStringLiteralCodeActions(
    builder: *Builder,
    token: Ast.TokenIndex,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.refactor)) return;

    const tree = builder.handle.tree;
    switch (tree.tokenTag(token -| 1)) {
        // Not covered by position context
        .keyword_test, .keyword_extern => return,
        else => {},
    }

    const token_text = offsets.tokenToSlice(tree, token); // Includes quotes
    const parsed = std.zig.string_literal.parseAlloc(builder.arena, token_text) catch |err| switch (err) {
        error.InvalidLiteral => return,
        else => |other| return other,
    };
    // Check for disallowed characters and utf-8 validity
    for (parsed) |c| {
        if (c == '\n') continue;
        if (std.ascii.isControl(c)) return;
    }
    if (!std.unicode.utf8ValidateSlice(parsed)) return;
    const with_slashes = try std.mem.replaceOwned(u8, builder.arena, parsed, "\n", "\n    \\\\"); // Hardcoded 4 spaces

    var result: std.ArrayList(u8) = try .initCapacity(builder.arena, with_slashes.len + 3);
    result.appendSliceAssumeCapacity("\\\\");
    result.appendSliceAssumeCapacity(with_slashes);
    result.appendAssumeCapacity('\n');

    const loc = offsets.tokenToLoc(tree, token);
    try builder.actions.append(builder.arena, .{
        .title = "convert to a multiline string literal",
        .kind = .refactor,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, result.items)}),
    });
}

pub fn generateMultilineStringCodeActions(
    builder: *Builder,
    token: Ast.TokenIndex,
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.refactor)) return;

    const tree = builder.handle.tree;
    std.debug.assert(.multiline_string_literal_line == tree.tokenTag(token));
    // Collect (exclusive) token range of the literal (one token per literal line)
    const start = if (std.mem.lastIndexOfNone(Token.Tag, tree.tokens.items(.tag)[0..(token + 1)], &.{.multiline_string_literal_line})) |i| i + 1 else 0;
    const end = std.mem.indexOfNonePos(Token.Tag, tree.tokens.items(.tag), token, &.{.multiline_string_literal_line}) orelse tree.tokens.len;

    // collect the text in the literal
    const loc = offsets.tokensToLoc(builder.handle.tree, @intCast(start), @intCast(end));
    var str_escaped: std.ArrayList(u8) = try .initCapacity(builder.arena, 2 * (loc.end - loc.start));
    str_escaped.appendAssumeCapacity('"');
    for (start..end) |i| {
        std.debug.assert(tree.tokenTag(@intCast(i)) == .multiline_string_literal_line);
        const string_part = offsets.tokenToSlice(builder.handle.tree, @intCast(i));
        // Iterate without the leading \\
        for (string_part[2..]) |c| {
            const chunk = switch (c) {
                '\\' => "\\\\",
                '"' => "\\\"",
                '\n' => "\\n",
                0x01...0x09, 0x0b...0x0c, 0x0e...0x1f, 0x7f => unreachable,
                else => &.{c},
            };
            str_escaped.appendSliceAssumeCapacity(chunk);
        }
        if (i != end - 1) {
            str_escaped.appendSliceAssumeCapacity("\\n");
        }
    }
    str_escaped.appendAssumeCapacity('"');

    // Get Loc of the whole literal to delete it
    // Multiline string literal ends before the \n or \r, but it must be deleted too
    const first_token_start = builder.handle.tree.tokenStart(@intCast(start));
    const last_token_end = std.mem.indexOfNonePos(
        u8,
        builder.handle.tree.source,
        offsets.tokenToLoc(builder.handle.tree, @intCast(end - 1)).end + 1,
        "\n\r",
    ) orelse builder.handle.tree.source.len;
    const remove_loc: offsets.Loc = .{ .start = first_token_start, .end = last_token_end };

    try builder.actions.append(builder.arena, .{
        .title = "convert to a string literal",
        .kind = .refactor,
        .isPreferred = false,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(remove_loc, str_escaped.items)}),
    });
}

/// To report server capabilities
pub const supported_code_actions: []const types.CodeActionKind = &.{
    .quickfix,
    .refactor,
    .source,
    .@"source.organizeImports",
    .@"source.fixAll",
};

pub fn collectAutoDiscardDiagnostics(
    analyser: *Analyser,
    handle: *DocumentStore.Handle,
    arena: std.mem.Allocator,
    diagnostics: *std.ArrayList(types.Diagnostic),
    offset_encoding: offsets.Encoding,
) error{OutOfMemory}!void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();
    const tree = handle.tree;

    // search for the following pattern:
    // _ = some_identifier; // autofix

    var i: usize = 0;
    while (i < tree.tokens.len) {
        const first_token: Ast.TokenIndex = @intCast(std.mem.indexOfPos(
            Token.Tag,
            tree.tokens.items(.tag),
            i,
            &.{ .identifier, .equal, .identifier, .semicolon },
        ) orelse break);
        defer i = first_token + 4;

        const underscore_token = first_token;
        const identifier_token = first_token + 2;
        const semicolon_token = first_token + 3;

        if (!std.mem.eql(u8, offsets.tokenToSlice(tree, underscore_token), "_")) continue;

        const autofix_comment_start = std.mem.indexOfNonePos(u8, tree.source, tree.tokenStart(semicolon_token) + 1, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_comment_start..], "//")) continue;
        const autofix_str_start = std.mem.indexOfNonePos(u8, tree.source, autofix_comment_start + "//".len, " ") orelse continue;
        if (!std.mem.startsWith(u8, tree.source[autofix_str_start..], "autofix")) continue;

        const related_info = blk: {
            const decl = (try analyser.lookupSymbolGlobal(
                handle,
                offsets.tokenToSlice(tree, identifier_token),
                tree.tokenStart(identifier_token),
            )) orelse break :blk &.{};
            const def = try decl.definitionToken(analyser, false);
            const range = offsets.tokenToRange(tree, def.token, offset_encoding);
            break :blk try arena.dupe(types.DiagnosticRelatedInformation, &.{.{
                .location = .{
                    .uri = handle.uri,
                    .range = range,
                },
                .message = "variable declared here",
            }});
        };

        try diagnostics.append(arena, .{
            .range = offsets.tokenToRange(tree, identifier_token, offset_encoding),
            .severity = .Information,
            .code = null,
            .source = "zls",
            .message = "auto discard for unused variable",
            .relatedInformation = related_info,
        });
    }
}

fn handleNonCamelcaseFunction(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    if (std.mem.allEqual(u8, identifier_name, '_')) return;

    const new_text = try createCamelcaseText(builder.arena, identifier_name);

    try builder.actions.append(builder.arena, .{
        .title = "make function name camelCase",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, new_text)}),
    });
}

fn handleUnusedFunctionParameter(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const payload = switch (decl.decl) {
        .function_parameter => |pay| pay,
        else => return,
    };

    std.debug.assert(tree.nodeTag(payload.func) == .fn_decl);

    const block = tree.nodeData(payload.func).node_and_node[1];

    // If we are on the "last parameter" that requires a discard, then we need to append a newline,
    // as well as any relevant indentations, such that the next line is indented to the same column.
    // To do this, you may have a function like:
    // fn(a: i32, b: i32, c: i32) void { _ = a; _ = b; _ = c; }
    // or
    // fn(
    //     a: i32,
    //     b: i32,
    //     c: i32,
    // ) void { ... }
    // We have to be able to detect both cases.
    const fn_proto_param = payload.get(tree).?;
    const last_param_token = ast.paramLastToken(tree, fn_proto_param);

    const potential_comma_token = last_param_token + 1;
    const found_comma = potential_comma_token < tree.tokens.len and tree.tokenTag(potential_comma_token) == .comma;

    const potential_r_paren_token = potential_comma_token + @intFromBool(found_comma);
    const is_last_param = potential_r_paren_token < tree.tokens.len and tree.tokenTag(potential_r_paren_token) == .r_paren;

    const insert_token = tree.nodeMainToken(block);
    const add_suffix_newline = is_last_param and tree.tokenTag(insert_token + 1) == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);
    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.insert(builder.arena, 0, builder.createTextEditPos(insert_index, new_text));
    }

    if (builder.wantKind(.quickfix)) {
        // TODO add no `// autofix` comment
        // TODO fix formatting
        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try builder.addWorkspaceTextEdit(&workspace_edit, builder.handle.uri, &.{
            builder.createTextEditLoc(getParamRemovalRange(tree, fn_proto_param), ""),
        });
        try builder.actions.append(builder.arena, .{
            .title = "remove function parameter",
            .kind = .quickfix,
            .isPreferred = false,
            .edit = workspace_edit,
        });
    }
}

fn handleUnusedVariableOrConstant(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const identifier_name = offsets.locToSlice(builder.handle.tree.source, loc);

    const tree = builder.handle.tree;

    const decl = (try builder.analyser.lookupSymbolGlobal(
        builder.handle,
        identifier_name,
        loc.start,
    )) orelse return;

    const node = switch (decl.decl) {
        .ast_node => |node| node,
        .assign_destructure => |payload| payload.node,
        else => return,
    };

    const insert_token = ast.lastToken(tree, node) + 1;

    if (insert_token >= tree.tokens.len) return;
    if (tree.tokenTag(insert_token) != .semicolon) return;

    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, false, false);

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.append(builder.arena, builder.createTextEditPos(insert_index, new_text));
    }

    if (builder.wantKind(.quickfix)) {
        // TODO add no `// autofix` comment
        var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
        try builder.addWorkspaceTextEdit(&workspace_edit, builder.handle.uri, &.{
            builder.createTextEditPos(insert_index, new_text),
        });
        try builder.actions.append(builder.arena, .{
            .title = "discard value",
            .kind = .quickfix,
            .isPreferred = true,
            .edit = workspace_edit,
        });
    }
}

fn handleUnusedCapture(
    builder: *Builder,
    loc: offsets.Loc,
    remove_capture_actions: *std.AutoHashMapUnmanaged(types.Range, void),
) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const tree = builder.handle.tree;

    const source = tree.source;

    const identifier_token = offsets.sourceIndexToTokenIndex(tree, loc.start).pickPreferred(&.{.identifier}, &tree) orelse return;
    if (tree.tokenTag(identifier_token) != .identifier) return;

    const identifier_name = offsets.locToSlice(source, loc);

    // Zig can report incorrect "unused capture" errors
    // https://github.com/ziglang/zig/pull/22209
    if (std.mem.eql(u8, identifier_name, "_")) return;

    if (builder.wantKind(.quickfix)) {
        const capture_loc = getCaptureLoc(source, loc) orelse return;

        const remove_cap_loc = builder.createTextEditLoc(capture_loc, "");

        try builder.actions.append(builder.arena, .{
            .title = "discard capture name",
            .kind = .quickfix,
            .isPreferred = false,
            .edit = try builder.createWorkspaceEdit(&.{builder.createTextEditLoc(loc, "_")}),
        });

        // prevent adding duplicate 'remove capture' action.
        // search for a matching action by comparing ranges.
        const gop = try remove_capture_actions.getOrPut(builder.arena, remove_cap_loc.range);
        if (!gop.found_existing) {
            try builder.actions.append(builder.arena, .{
                .title = "remove capture",
                .kind = .quickfix,
                .isPreferred = false,
                .edit = try builder.createWorkspaceEdit(&.{remove_cap_loc}),
            });
        }
    }

    if (!builder.wantKind(.@"source.fixAll")) return;

    const capture_end: Ast.TokenIndex = @intCast(std.mem.indexOfScalarPos(
        Token.Tag,
        tree.tokens.items(.tag),
        identifier_token,
        .pipe,
    ) orelse return);

    var lbrace_token = capture_end + 1;

    // handle while loop continue statements such as `while(foo) |bar| : (x += 1) {}`
    if (tree.tokenTag(capture_end + 1) == .colon) {
        var token_index = capture_end + 2;
        if (token_index >= tree.tokens.len) return;
        if (tree.tokenTag(token_index) != .l_paren) return;
        token_index += 1;

        var depth: u32 = 1;
        while (true) : (token_index += 1) {
            const tag = tree.tokenTag(token_index);
            switch (tag) {
                .eof => return,
                .l_paren => {
                    depth += 1;
                },
                .r_paren => {
                    depth -= 1;
                    if (depth == 0) {
                        token_index += 1;
                        break;
                    }
                },
                else => {},
            }
        }
        lbrace_token = token_index;
    }

    if (lbrace_token + 1 >= tree.tokens.len) return;
    if (tree.tokenTag(lbrace_token) != .l_brace) return;

    const is_last_capture = tree.tokenTag(identifier_token + 1) == .pipe;

    const insert_token = lbrace_token;
    // if we are on the last capture of the block, we need to add an additional newline
    // i.e |a, b| { ... } -> |a, b| { ... \n_ = a; \n_ = b;\n }
    const add_suffix_newline = is_last_capture and tree.tokenTag(insert_token + 1) == .r_brace and tree.tokensOnSameLine(insert_token, insert_token + 1);
    const insert_index, const new_text = try createDiscardText(builder, identifier_name, insert_token, true, add_suffix_newline);

    try builder.fixall_text_edits.insert(builder.arena, 0, builder.createTextEditPos(insert_index, new_text));
}

fn handlePointlessDiscard(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.fixAll") and !builder.wantKind(.quickfix)) return;

    const edit_loc = getDiscardLoc(builder.handle.tree.source, loc) orelse return;

    if (builder.wantKind(.@"source.fixAll")) {
        try builder.fixall_text_edits.append(builder.arena, builder.createTextEditLoc(edit_loc, ""));
    }

    if (builder.wantKind(.quickfix)) {
        try builder.actions.append(builder.arena, .{
            .title = "remove pointless discard",
            .kind = .@"source.fixAll",
            .isPreferred = true,
            .edit = try builder.createWorkspaceEdit(&.{
                builder.createTextEditLoc(edit_loc, ""),
            }),
        });
    }
}

fn handleVariableNeverMutated(builder: *Builder, loc: offsets.Loc) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.quickfix)) return;

    const source = builder.handle.tree.source;

    const var_keyword_end = 1 + (std.mem.lastIndexOfNone(u8, source[0..loc.start], &std.ascii.whitespace) orelse return);

    const var_keyword_loc: offsets.Loc = .{
        .start = var_keyword_end -| "var".len,
        .end = var_keyword_end,
    };

    if (!std.mem.eql(u8, offsets.locToSlice(source, var_keyword_loc), "var")) return;

    try builder.actions.append(builder.arena, .{
        .title = "use 'const'",
        .kind = .quickfix,
        .isPreferred = true,
        .edit = try builder.createWorkspaceEdit(&.{
            builder.createTextEditLoc(var_keyword_loc, "const"),
        }),
    });
}

const ImportPlacement = enum {
    top,
    bottom,
};

fn analyzeImportPlacement(tree: Ast, imports: []const ImportDecl) ImportPlacement {
    const root_decls = tree.rootDecls();

    if (root_decls.len == 0 or imports.len == 0) return .top;

    const first_import = imports[0].var_decl;
    const last_import = imports[imports.len - 1].var_decl;

    const first_decl = root_decls[0];
    const last_decl = root_decls[root_decls.len - 1];

    const starts_with_import = first_decl == first_import;
    const ends_with_import = last_decl == last_import;

    if (starts_with_import and ends_with_import) {
        // If there are only imports, choose "top" to avoid unnecessary newlines.
        // Otherwise, having an import at the bottom is a strong signal that that is the preferred style.
        const has_gaps = root_decls.len != imports.len;

        return if (has_gaps) .bottom else .top;
    }

    return if (!starts_with_import and ends_with_import) .bottom else .top;
}

fn handleUnorganizedImport(builder: *Builder) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.organizeImports")) return;

    const tree = builder.handle.tree;
    if (tree.errors.len != 0) return;

    const imports = try getImportsDecls(builder, builder.arena);

    if (imports.len == 0) return;

    // The optimization is disabled because it does not detect the case where imports and other decls are mixed
    // if (std.sort.isSorted(ImportDecl, imports.items, tree, ImportDecl.lessThan)) return;

    const placement = analyzeImportPlacement(tree, imports);

    const sorted_imports = try builder.arena.dupe(ImportDecl, imports);
    std.mem.sort(ImportDecl, sorted_imports, tree, ImportDecl.lessThan);

    var edits: std.ArrayList(types.TextEdit) = .empty;

    // add sorted imports
    {
        var new_text: std.ArrayList(u8) = .empty;

        if (placement == .bottom) {
            try new_text.append(builder.arena, '\n');
        }

        for (sorted_imports, 0..) |import_decl, i| {
            if (i != 0 and ImportDecl.addSeperator(sorted_imports[i - 1], import_decl)) {
                try new_text.append(builder.arena, '\n');
            }

            try new_text.print(builder.arena, "{s}\n", .{offsets.locToSlice(tree.source, import_decl.getLoc(tree, false))});
        }

        try new_text.append(builder.arena, '\n');

        const range: offsets.Range = switch (placement) {
            .top => blk: {
                // Current behavior: insert at top after doc comments
                const first_token = std.mem.indexOfNone(Token.Tag, tree.tokens.items(.tag), &.{.container_doc_comment}) orelse tree.tokens.len;
                const insert_pos = offsets.tokenToPosition(tree, @intCast(first_token), builder.offset_encoding);
                break :blk .{ .start = insert_pos, .end = insert_pos };
            },
            .bottom => blk: {
                // Current behavior: insert at eof
                break :blk offsets.tokenToRange(tree, @intCast(tree.tokens.len - 1), builder.offset_encoding);
            },
        };

        try edits.append(builder.arena, .{
            .range = range,
            .newText = new_text.items,
        });
    }

    {
        // remove previous imports
        const import_locs = try builder.arena.alloc(offsets.Loc, imports.len);
        for (imports, import_locs) |import_decl, *loc| {
            loc.* = import_decl.getLoc(tree, true);
        }

        const import_ranges = try builder.arena.alloc(types.Range, imports.len);
        try offsets.multiple.locToRange(builder.arena, tree.source, import_locs, import_ranges, builder.offset_encoding);

        for (import_ranges) |range| {
            try edits.append(builder.arena, .{
                .range = range,
                .newText = "",
            });
        }
    }

    var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
    try builder.addWorkspaceTextEdit(&workspace_edit, builder.handle.uri, edits.items);

    try builder.actions.append(builder.arena, .{
        .title = "organize @import",
        .kind = .@"source.organizeImports",
        .isPreferred = true,
        .edit = workspace_edit,
    });
}

fn getImportStringToken(tree: Ast, var_decl_node: Ast.Node.Index) ?Ast.TokenIndex {
    if (tree.nodeTag(var_decl_node) != .simple_var_decl) return null;
    const var_decl = tree.simpleVarDecl(var_decl_node);
    var current_node = var_decl.ast.init_node.unwrap() orelse return null;
    while (true) {
        switch (tree.nodeTag(current_node)) {
            .field_access => {
                // Drill down to base of field access: left side
                current_node = tree.nodeData(current_node).node_and_token[0];
                continue;
            },
            .builtin_call_two, .builtin_call_two_comma => {
                const first_param, const second_param = tree.nodeData(current_node).opt_node_and_opt_node;
                const param_node = first_param.unwrap() orelse return null;
                if (second_param != .none) return null;
                if (tree.nodeTag(param_node) != .string_literal) return null;
                return tree.nodeMainToken(param_node);
            },
            else => return null,
        }
    }
}

fn normalizeImportPath(allocator: std.mem.Allocator, current_dir: []const u8, quoted: []const u8) !?[]const u8 {
    if (quoted.len < 2 or quoted[0] != '"' or quoted[quoted.len - 1] != '"') return null;
    const inner = quoted[1 .. quoted.len - 1];
    // Quick no-op for already relative simple paths
    if (inner.len != 0 and inner[0] != '/' and !(inner.len >= 3 and inner[1] == ':' and inner[2] == '\\')) {
        return null;
    }
    // Resolve absolute to relative if possible
    const abs = inner;
    const rel = std.fs.path.relative(allocator, current_dir, abs) catch abs;
    if (std.mem.eql(u8, rel, inner)) return null;
    return try std.fmt.allocPrint(allocator, "\"{s}\"", .{rel});
}

fn handleNormalizeImport(builder: *Builder) !void {
    const tracy_zone = tracy.trace(@src());
    defer tracy_zone.end();

    if (!builder.wantKind(.@"source.organizeImports")) return;

    const tree = builder.handle.tree;
    if (tree.errors.len != 0) return;

    const imports = try getImportsDecls(builder, builder.arena);
    if (imports.len == 0) return;

    const cur_fs_path = Uri.toFsPath(builder.arena, builder.handle.uri) catch return;
    const cur_dir = std.fs.path.dirname(cur_fs_path) orelse ".";

    var edits: std.ArrayList(types.TextEdit) = .empty;
    for (imports) |imp| {
        if (imp.getKind() != .file) continue;
        const tok = getImportStringToken(tree, imp.var_decl) orelse continue;
        const range = offsets.tokenToRange(tree, tok, builder.offset_encoding);
        const old_text = offsets.tokenToSlice(tree, tok);
        const maybe_new = try normalizeImportPath(builder.arena, cur_dir, old_text);
        if (maybe_new) |new_text| {
            if (!std.mem.eql(u8, new_text, old_text)) {
                try edits.append(builder.arena, .{ .range = range, .newText = new_text });
            }
        }
    }

    if (edits.items.len == 0) return;

    var workspace_edit: types.WorkspaceEdit = .{ .changes = .{} };
    try builder.addWorkspaceTextEdit(&workspace_edit, builder.handle.uri, edits.items);

    try builder.actions.append(builder.arena, .{
        .title = "normalize @import paths",
        .kind = .@"source.organizeImports",
        .isPreferred = false,
        .edit = workspace_edit,
    });
}

/// const name_slice = @import(value_slice);
pub const ImportDecl = struct {
    var_decl: Ast.Node.Index,
    first_comment_token: ?Ast.TokenIndex,
    name: []const u8,
    value: []const u8,

    /// Strings for sorting second order imports (e.g. `const ascii = std.ascii`)
    parent_name: ?[]const u8 = null,
    parent_value: ?[]const u8 = null,

    pub const AstNodeAdapter = struct {
        pub fn hash(ctx: @This(), ast_node: Ast.Node.Index) u32 {
            _ = ctx;
            const hash_fn = std.array_hash_map.getAutoHashFn(Ast.Node.Index, void);
            return hash_fn({}, ast_node);
        }

        pub fn eql(ctx: @This(), a: Ast.Node.Index, b: ImportDecl, b_index: usize) bool {
            _ = ctx;
            _ = b_index;
            return a == b.var_decl;
        }
    };

    /// declaration order controls sorting order
    pub const Kind = enum {
        std,
        builtin,
        build_options,
        package,
        file,
    };

    pub const sort_case_sensitive: bool = false;
    pub const sort_public_decls_first: bool = false;

    pub fn lessThan(context: Ast, lhs: ImportDecl, rhs: ImportDecl) bool {
        const lhs_kind = lhs.getKind();
        const rhs_kind = rhs.getKind();
        if (lhs_kind != rhs_kind) return @intFromEnum(lhs_kind) < @intFromEnum(rhs_kind);

        if (sort_public_decls_first) {
            const node_tokens = context.nodes.items(.main_token);
            const is_lhs_pub = node_tokens[lhs.var_decl] > 0 and context.tokenTag(node_tokens[lhs.var_decl] - 1) == .keyword_pub;
            const is_rhs_pub = node_tokens[rhs.var_decl] > 0 and context.tokenTag(node_tokens[rhs.var_decl] - 1) == .keyword_pub;
            if (is_lhs_pub != is_rhs_pub) return is_lhs_pub;
        }

        // First the parent @import, then the child using it
        if (lhs.isParent(rhs)) return true;

        // 'root' gets sorted after 'builtin'
        if (sort_case_sensitive) {
            return std.mem.lessThan(u8, lhs.getSortSlice(), rhs.getSortSlice());
        } else {
            return std.ascii.lessThanIgnoreCase(lhs.getSortSlice(), rhs.getSortSlice());
        }
    }

    pub fn isParent(self: ImportDecl, child: ImportDecl) bool {
        const parent_name = child.parent_name orelse return false;
        const parent_value = child.parent_value orelse return false;
        return std.mem.eql(u8, self.name, parent_name) and std.mem.eql(u8, self.value, parent_value);
    }

    pub fn getKind(self: ImportDecl) Kind {
        const name = self.getSortValue()[1 .. self.getSortValue().len - 1];

        if (std.mem.endsWith(u8, name, ".zig")) return .file;

        if (std.mem.eql(u8, name, "std")) return .std;
        if (std.mem.eql(u8, name, "builtin")) return .builtin;
        if (std.mem.eql(u8, name, "root")) return .builtin;
        if (std.mem.eql(u8, name, "build_options")) return .build_options;

        return .package;
    }

    /// returns the string by which this import should be sorted
    pub fn getSortSlice(self: ImportDecl) []const u8 {
        switch (self.getKind()) {
            .file => {
                if (std.mem.indexOfScalar(u8, self.getSortValue(), '/') != null) {
                    return self.getSortValue()[1 .. self.getSortValue().len - 1];
                }
                return self.getSortName();
            },
            // There used to be unreachable for other than file and package, but the user
            // can just write @import("std") twice.
            else => return self.getSortName(),
        }
    }

    pub fn getSortName(self: ImportDecl) []const u8 {
        return self.parent_name orelse self.name;
    }

    pub fn getSortValue(self: ImportDecl) []const u8 {
        return self.parent_value orelse self.value;
    }

    /// returns true if there should be an empty line between these two imports
    /// assumes `lessThan(void, lhs, rhs) == true`
    pub fn addSeperator(lhs: ImportDecl, rhs: ImportDecl) bool {
        const lhs_kind = @intFromEnum(lhs.getKind());
        const rhs_kind = @intFromEnum(rhs.getKind());
        if (rhs_kind <= @intFromEnum(Kind.build_options)) return false;
        return lhs_kind != rhs_kind;
    }

    pub fn getSourceStartIndex(self: ImportDecl, tree: Ast) usize {
        return tree.tokenStart(self.first_comment_token orelse tree.firstToken(self.var_decl));
    }

    pub fn getSourceEndIndex(self: ImportDecl, tree: Ast, include_line_break: bool) usize {
        var last_token = ast.lastToken(tree, self.var_decl);
        if (last_token + 1 < tree.tokens.len - 1 and tree.tokenTag(last_token + 1) == .semicolon) {
            last_token += 1;
        }

        const end = offsets.tokenToLoc(tree, last_token).end;
        if (!include_line_break) return end;
        return std.mem.indexOfNonePos(u8, tree.source, end, &.{ ' ', '\t', '\n' }) orelse tree.source.len;
    }

    /// similar to `offsets.nodeToLoc` but will also include preceding comments and postfix semicolon and line break
    pub fn getLoc(self: ImportDecl, tree: Ast, include_line_break: bool) offsets.Loc {
        return .{
            .start = self.getSourceStartIndex(tree),
            .end = self.getSourceEndIndex(tree, include_line_break),
        };
    }
};

pub fn getImportsDecls(builder: *Builder, allocator: std.mem.Allocator) error{OutOfMemory}![]ImportDecl {
    const tree = builder.handle.tree;

    const root_decls = tree.rootDecls();

    var skip_set: std.DynamicBitSetUnmanaged = try .initEmpty(allocator, root_decls.len);
    defer skip_set.deinit(allocator);

    var imports: std.ArrayHashMapUnmanaged(ImportDecl, void, void, true) = .empty;
    defer imports.deinit(allocator);

    // iterate until no more imports are found
    var updated = true;
    while (updated) {
        updated = false;
        var it = skip_set.iterator(.{ .kind = .unset });
        next_decl: while (it.next()) |root_decl_index| {
            const node = root_decls[root_decl_index];

            var do_skip: bool = true;
            defer if (do_skip) skip_set.set(root_decl_index);

            if (skip_set.isSet(root_decl_index)) continue;

            if (tree.nodeTag(node) != .simple_var_decl) continue;
            const var_decl = tree.simpleVarDecl(node);

            var current_node = var_decl.ast.init_node.unwrap() orelse continue;
            const import: ImportDecl = found_decl: while (true) {
                const token = tree.nodeMainToken(current_node);
                switch (tree.nodeTag(current_node)) {
                    .builtin_call_two, .builtin_call_two_comma => {
                        // `>@import("string")<` case
                        const builtin_name = offsets.tokenToSlice(tree, token);
                        if (!std.mem.eql(u8, builtin_name, "@import")) continue :next_decl;
                        // TODO what about @embedFile ?

                        const first_param, const second_param = tree.nodeData(current_node).opt_node_and_opt_node;
                        const param_node = first_param.unwrap() orelse continue :next_decl;
                        if (second_param != .none) continue :next_decl;
                        if (tree.nodeTag(param_node) != .string_literal) continue :next_decl;

                        const name_token = var_decl.ast.mut_token + 1;
                        const value_token = tree.nodeMainToken(param_node);

                        break :found_decl .{
                            .var_decl = node,
                            .first_comment_token = Analyser.getDocCommentTokenIndex(&tree, tree.nodeMainToken(node)),
                            .name = offsets.tokenToSlice(tree, name_token),
                            .value = offsets.tokenToSlice(tree, value_token),
                        };
                    },
                    .field_access => {
                        // `@import("foo").>bar<` or `foo.>bar<` case
                        // drill down to the base import
                        current_node = tree.nodeData(current_node).node_and_token[0];
                        continue;
                    },
                    .identifier => {
                        // `>std<.ascii` case - Might be an alias
                        const name_token = ast.identifierTokenFromIdentifierNode(tree, current_node) orelse continue :next_decl;
                        const name = offsets.identifierTokenToNameSlice(tree, name_token);

                        // calling `lookupSymbolGlobal` is slower than just looking up a symbol at the root scope directly.
                        // const decl = try builder.analyser.lookupSymbolGlobal(builder.handle, name, source_index) orelse continue :next_decl;
                        const document_scope = try builder.handle.getDocumentScope();

                        const decl_index = document_scope.getScopeDeclaration(.{
                            .scope = .root,
                            .name = name,
                            .kind = .other,
                        }).unwrap() orelse continue :next_decl;

                        const decl = document_scope.declarations.get(@intFromEnum(decl_index));

                        if (decl != .ast_node) continue :next_decl;
                        const decl_found = decl.ast_node;

                        const import_decl = imports.getKeyAdapted(decl_found, ImportDecl.AstNodeAdapter{}) orelse {
                            // We may find the import in a future loop iteration
                            do_skip = false;
                            continue :next_decl;
                        };
                        const ident_name_token = var_decl.ast.mut_token + 1;
                        const var_name = offsets.tokenToSlice(tree, ident_name_token);
                        break :found_decl .{
                            .var_decl = node,
                            .first_comment_token = Analyser.getDocCommentTokenIndex(&tree, tree.nodeMainToken(node)),
                            .name = var_name,
                            .value = var_name,
                            .parent_name = import_decl.getSortName(),
                            .parent_value = import_decl.getSortValue(),
                        };
                    },
                    else => continue :next_decl,
                }
            };
            const gop = try imports.getOrPutContextAdapted(allocator, import.var_decl, ImportDecl.AstNodeAdapter{}, {});
            if (!gop.found_existing) gop.key_ptr.* = import;
            updated = true;
        }
    }

    return try allocator.dupe(ImportDecl, imports.keys());
}

fn detectIndentation(source: []const u8) []const u8 {
    // Essentially I'm looking for the first indentation in the file.
    var i: usize = 0;
    const len = source.len - 1; // I need 1 look-ahead
    while (i < len) : (i += 1) {
        if (source[i] != '\n') continue;
        i += 1;
        if (source[i] == '\t') return "\t";
        var space_count: usize = 0;
        while (i < source.len and source[i] == ' ') : (i += 1) {
            space_count += 1;
        }
        if (source[i] == '\n') { // Some editors mess up indentation of empty lines
            i -= 1;
            continue;
        }
        if (space_count == 0) continue;
        if (source[i] == '/') continue; // Comments sometimes have additional alignment.
        if (source[i] == '\\') continue; // multi-line strings might as well.
        return source[i - space_count .. i];
    }
    return "    "; // recommended style
}

// attempts to converts a slice of text into camelcase 'FUNCTION_NAME' -> 'functionName'
fn createCamelcaseText(allocator: std.mem.Allocator, identifier: []const u8) ![]const u8 {
    // skip initial & ending underscores
    const trimmed_identifier = std.mem.trim(u8, identifier, "_");

    const num_separators = std.mem.count(u8, trimmed_identifier, "_");

    const new_text_len = trimmed_identifier.len - num_separators;
    var new_text: std.ArrayList(u8) = try .initCapacity(allocator, new_text_len);
    errdefer new_text.deinit(allocator);

    var idx: usize = 0;
    while (idx < trimmed_identifier.len) {
        const ch = trimmed_identifier[idx];
        if (ch == '_') {
            // the trimmed identifier is guaranteed to not have underscores at the end,
            // so it can be assumed that ptr dereferences are safe until an alnum char is found
            while (trimmed_identifier[idx] == '_') : (idx += 1) {}
            const ch2 = trimmed_identifier[idx];
            new_text.appendAssumeCapacity(std.ascii.toUpper(ch2));
        } else {
            new_text.appendAssumeCapacity(std.ascii.toLower(ch));
        }

        idx += 1;
    }

    return new_text.toOwnedSlice(allocator);
}

/// returns a discard string `_ = identifier_name; // autofix` with appropriate newlines and
/// indentation so that a discard is on a new line after the `insert_token`.
///
/// `add_block_indentation` is used to add one level of indentation to the discard.
/// `add_suffix_newline` is used to add a trailing newline with indentation.
fn createDiscardText(
    builder: *Builder,
    identifier_name: []const u8,
    insert_token: Ast.TokenIndex,
    add_block_indentation: bool,
    add_suffix_newline: bool,
) !struct {
    /// insert index
    usize,
    /// new text
    []const u8,
} {
    const tree = builder.handle.tree;
    const insert_token_end = offsets.tokenToLoc(tree, insert_token).end;
    const source_until_next_token = tree.source[0..tree.tokenStart(insert_token + 1)];
    // skip comments between the insert tokena and the token after it
    const insert_index = std.mem.indexOfScalarPos(u8, source_until_next_token, insert_token_end, '\n') orelse source_until_next_token.len;

    const indent = find_indent: {
        const line = offsets.lineSliceUntilIndex(tree.source, insert_index);
        for (line, 0..) |char, i| {
            if (!std.ascii.isWhitespace(char)) {
                break :find_indent line[0..i];
            }
        }
        break :find_indent line;
    };
    const additional_indent = if (add_block_indentation) detectIndentation(tree.source) else "";

    const new_text_len =
        "\n".len +
        indent.len +
        additional_indent.len +
        "_ = ".len +
        identifier_name.len +
        "; // autofix".len +
        if (add_suffix_newline) 1 + indent.len else 0;
    var new_text: std.ArrayList(u8) = try .initCapacity(builder.arena, new_text_len);

    new_text.appendAssumeCapacity('\n');
    new_text.appendSliceAssumeCapacity(indent);
    new_text.appendSliceAssumeCapacity(additional_indent);
    new_text.appendSliceAssumeCapacity("_ = ");
    new_text.appendSliceAssumeCapacity(identifier_name);
    new_text.appendSliceAssumeCapacity("; // autofix");
    if (add_suffix_newline) {
        new_text.appendAssumeCapacity('\n');
        new_text.appendSliceAssumeCapacity(indent);
    }

    return .{ insert_index, try new_text.toOwnedSlice(builder.arena) };
}

fn getParamRemovalRange(tree: Ast, param: Ast.full.FnProto.Param) offsets.Loc {
    var loc = ast.paramLoc(tree, param, true);

    var trim_end = false;
    while (loc.start != 0) : (loc.start -= 1) {
        switch (tree.source[loc.start - 1]) {
            ' ', '\n' => continue,
            ',' => {
                loc.start -= 1;
                break;
            },
            '(' => {
                trim_end = true;
                break;
            },
            else => break,
        }
    }

    var found_comma = false;
    while (trim_end and loc.end < tree.source.len) : (loc.end += 1) {
        switch (tree.source[loc.end]) {
            ' ', '\n' => continue,
            ',' => if (!found_comma) {
                found_comma = true;
                continue;
            } else {
                loc.end += 1;
                break;
            },
            ')' => break,
            else => break,
        }
    }

    return loc;
}

const DiagnosticKind = union(enum) {
    unused: IdCat,
    pointless_discard: IdCat,
    omit_discard: DiscardCat,
    non_camelcase_fn,
    undeclared_identifier,
    unreachable_code,
    var_never_mutated,

    const IdCat = enum {
        @"function parameter",
        @"local constant",
        @"local variable",
        @"switch tag capture",
        capture,
    };

    const DiscardCat = enum {
        @"error capture; omit it instead",
        @"error capture",
    };

    fn parse(diagnostic_message: []const u8) ?DiagnosticKind {
        const msg = diagnostic_message;

        if (std.mem.startsWith(u8, msg, "unused ")) {
            return .{
                .unused = parseEnum(IdCat, msg["unused ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "pointless discard of ")) {
            return .{
                .pointless_discard = parseEnum(IdCat, msg["pointless discard of ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "discard of ")) {
            return .{
                .omit_discard = parseEnum(DiscardCat, msg["discard of ".len..]) orelse return null,
            };
        } else if (std.mem.startsWith(u8, msg, "Functions should be camelCase")) {
            return .non_camelcase_fn;
        } else if (std.mem.startsWith(u8, msg, "use of undeclared identifier")) {
            return .undeclared_identifier;
        } else if (std.mem.eql(u8, msg, "local variable is never mutated")) {
            return .var_never_mutated;
        }
        return null;
    }

    fn parseEnum(comptime T: type, message: []const u8) ?T {
        inline for (std.meta.fields(T)) |field| {
            if (std.mem.startsWith(u8, message, field.name)) {
                // is there a better way to achieve this?
                return @as(T, @enumFromInt(field.value));
            }
        }

        return null;
    }
};

/// takes the location of an identifier which is part of a discard `_ = location_here;`
/// and returns the location from '_' until ';' or null on failure
fn getDiscardLoc(text: []const u8, loc: offsets.Loc) ?offsets.Loc {
    // check of the loc points to a valid identifier
    for (offsets.locToSlice(text, loc)) |c| {
        if (!Analyser.isSymbolChar(c)) return null;
    }

    // check if the identifier is followed by a colon
    const colon_position = found: {
        var i = loc.end;
        while (i < text.len) : (i += 1) {
            switch (text[i]) {
                ' ' => continue,
                ';' => break :found i,
                else => return null,
            }
        }
        return null;
    };

    // check if the colon is followed by the autofix comment
    const autofix_comment_start = std.mem.indexOfNonePos(u8, text, colon_position + ";".len, " ") orelse return null;
    if (!std.mem.startsWith(u8, text[autofix_comment_start..], "//")) return null;
    const autofix_str_start = std.mem.indexOfNonePos(u8, text, autofix_comment_start + "//".len, " ") orelse return null;
    if (!std.mem.startsWith(u8, text[autofix_str_start..], "autofix")) return null;
    const autofix_comment_end = std.mem.indexOfNonePos(u8, text, autofix_str_start + "autofix".len, " ") orelse autofix_str_start + "autofix".len;

    // check if the identifier is precede by a equal sign and then an underscore
    var i: usize = loc.start - 1;
    var found_equal_sign = false;
    const underscore_position = found: {
        while (true) : (i -= 1) {
            if (i == 0) return null;
            switch (text[i]) {
                ' ' => {},
                '=' => {
                    if (found_equal_sign) return null;
                    found_equal_sign = true;
                },
                '_' => if (found_equal_sign) break :found i else return null,
                else => return null,
            }
        }
    };

    // move backwards until we find a newline
    i = underscore_position - 1;
    const start_position = found: {
        while (true) : (i -= 1) {
            if (i == 0) break :found underscore_position;
            switch (text[i]) {
                ' ', '\t' => {},
                '\n' => break :found i,
                else => break :found underscore_position,
            }
        }
    };

    return .{
        .start = start_position,
        .end = autofix_comment_end,
    };
}

/// takes the location of a capture ie `value` from `...|value...|...`.
/// returns the location from '|' until '|'
fn getCaptureLoc(text: []const u8, loc: offsets.Loc) ?offsets.Loc {
    const start_pipe_position = blk: {
        var i = loc.start;
        while (true) : (i -= 1) {
            if (text[i] == '|') break;
            if (i == 0) return null;
        }
        break :blk i;
    };

    const end_pipe_position = (std.mem.indexOfScalarPos(u8, text, start_pipe_position + 1, '|') orelse
        return null) + 1;

    const trimmed = std.mem.trim(u8, text[start_pipe_position + 1 .. end_pipe_position - 1], &std.ascii.whitespace);
    if (trimmed.len == 0) return null;

    return .{ .start = start_pipe_position, .end = end_pipe_position };
}

test getCaptureLoc {
    {
        const text = "|i|";
        const caploc = getCaptureLoc(text, .{ .start = 1, .end = 2 }) orelse
            return std.testing.expect(false);
        const captext = text[caploc.start..caploc.end];
        try std.testing.expectEqualStrings(text, captext);
    }
    {
        const text = "|i, jjj, foobar|";
        const caploc = getCaptureLoc(text, .{ .start = 1, .end = 17 }) orelse
            return std.testing.expect(false);
        const captext = text[caploc.start..caploc.end];
        try std.testing.expectEqualStrings(text, captext);
    }

    try std.testing.expect(getCaptureLoc("||", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc(" |", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc("| ", .{ .start = 1, .end = 2 }) == null);
    try std.testing.expect(getCaptureLoc("||", .{ .start = 1, .end = 1 }) == null);
    try std.testing.expect(getCaptureLoc("| |", .{ .start = 1, .end = 3 }) == null);
    try std.testing.expect(getCaptureLoc("|    |", .{ .start = 1, .end = 6 }) == null);
}

const GenerateMoveDeclToTopLevelActionator = struct {
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
};

fn generateMoveTopLevelStructToFileAction(builder: *Builder, source_index: usize) !void {
    var args = GenerateMoveTopLevelStructToFileActionator{ .builder = builder, .source_index = source_index };
    _ = try args.generateMoveTopLevelStructToFileAction();
}

pub const GenerateMoveTopLevelStructToFileActionator = @import("GenerateMoveTopLevelStructToFileActionator.zig").GenerateMoveTopLevelStructToFileActionator;


const GenerateHoistConstToFieldActionator = @import("GenerateHoistConstToFieldActionator.zig").GenerateHoistConstToFieldActionator;


const GenerateEncapsulateParamsStructActionator = struct {
    builder: *Builder,
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
};

const GenerateExtractFunctionCodeActionator = struct {
    builder: *Builder,
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
};
