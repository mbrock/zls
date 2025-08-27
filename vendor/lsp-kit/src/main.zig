const std = @import("std");
const MetaModel = @import("MetaModel.zig");

pub fn main() !void {
    var debug_allocator: std.heap.DebugAllocator(.{}) = .init;
    defer _ = debug_allocator.deinit();

    const gpa = debug_allocator.allocator();

    var arg_it: std.process.ArgIterator = try .initWithAllocator(gpa);
    defer arg_it.deinit();

    _ = arg_it.skip(); // skip self exe

    const out_file_path = try gpa.dupe(u8, arg_it.next() orelse std.process.fatal("second argument must be the output path to the generated zig code", .{}));
    defer gpa.free(out_file_path);

    const parsed_meta_model = try std.json.parseFromSlice(MetaModel, gpa, @embedFile("meta-model"), .{});
    defer parsed_meta_model.deinit();

    var aw: std.io.Writer.Allocating = .init(gpa);
    defer aw.deinit();

    @setEvalBranchQuota(100_000);
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();

    writeMetaModel(&aw.writer, parsed_meta_model.value, gpa, &arena) catch return error.OutOfMemory;

    const source = try aw.toOwnedSliceSentinel(0);
    defer gpa.free(source);

    var zig_tree: std.zig.Ast = try .parse(gpa, source, .zig);
    defer zig_tree.deinit(gpa);

    std.fs.cwd().makePath(std.fs.path.dirname(out_file_path) orelse ".") catch {};

    var out_file = try std.fs.cwd().createFile(out_file_path, .{});
    defer out_file.close();

    if (zig_tree.errors.len != 0) {
        std.log.warn("generated file contains syntax errors! (cannot format file)", .{});
        try out_file.writeAll(source);
    } else {
        var buf: [1024]u8 = undefined;
        var out = out_file.writer(&buf);
        const w = &out.interface;
        try zig_tree.render(gpa, w, .{});
        try w.flush();
    }
}

const FormatDocs = struct {
    text: []const u8,
    comment_kind: CommentKind,

    const CommentKind = enum {
        normal,
        doc,
        top_level,
    };
};

fn renderDocs(ctx: FormatDocs, writer: *std.io.Writer) std.io.Writer.Error!void {
    const prefix = switch (ctx.comment_kind) {
        .normal => "// ",
        .doc => "/// ",
        .top_level => "//! ",
    };
    var iterator = std.mem.splitScalar(u8, ctx.text, '\n');
    while (iterator.next()) |line| try writer.print("{s}{s}\n", .{ prefix, line });
}

fn fmtDocs(text: []const u8, comment_kind: FormatDocs.CommentKind) std.fmt.Formatter(FormatDocs, renderDocs) {
    return .{ .data = .{ .text = text, .comment_kind = comment_kind } };
}

const AliasCollector = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    key_to_name: std.StringHashMapUnmanaged([]const u8) = .{},
    ordered_aliases: std.ArrayListUnmanaged(struct { name: []const u8, definition: [:0]const u8 }) = .{},
    keys: std.ArrayListUnmanaged([]const u8) = .{},
    path_to_alias: std.StringHashMapUnmanaged([]const u8) = .{},
    ordered_paths: std.ArrayListUnmanaged([]const u8) = .{},

    fn init(allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator) AliasCollector {
        return .{ .allocator = allocator, .arena = arena };
    }

    fn deinit(self: *AliasCollector) void {
        for (self.keys.items) |k| self.allocator.free(k);
        for (self.ordered_aliases.items) |entry| {
            self.allocator.free(entry.name);
            self.allocator.free(entry.definition);
        }
        self.key_to_name.deinit(self.allocator);
        self.ordered_aliases.deinit(self.allocator);
        self.keys.deinit(self.allocator);
        for (self.ordered_paths.items) |p| self.allocator.free(p);
        self.ordered_paths.deinit(self.allocator);
        self.path_to_alias.deinit(self.allocator);
    }

    fn appendTypeKey(self: *AliasCollector, writer: *std.io.Writer, meta_model: *const MetaModel, ty: MetaModel.Type) std.io.Writer.Error!void {
        switch (ty) {
            .base => |b| try writer.print("base:{s}", .{@tagName(b.name)}),
            .reference => |r| try writer.print("ref:{s}", .{r.name}),
            .array => |arr| {
                try writer.writeAll("array:[");
                try self.appendTypeKey(writer, meta_model, arr.element.*);
                try writer.writeByte(']');
            },
            .map => |m| {
                try writer.writeAll("map{key:");
                switch (m.key) {
                    .base => |kb| try writer.print("base:{s}", .{@tagName(kb.name)}),
                    .reference => |r| try writer.print("ref:{s}", .{r.name}),
                }
                try writer.writeAll(",value:");
                try self.appendTypeKey(writer, meta_model, m.value.*);
                try writer.writeByte('}');
            },
            .@"and" => |andt| {
                try writer.writeAll("and(");
                for (andt.items, 0..) |it, i| {
                    if (i != 0) try writer.writeByte('|');
                    try self.appendTypeKey(writer, meta_model, it);
                }
                try writer.writeByte(')');
            },
            .@"or" => |ort| {
                try writer.writeAll("or(");
                for (ort.items, 0..) |it, i| {
                    if (i != 0) try writer.writeByte('|');
                    try self.appendTypeKey(writer, meta_model, it);
                }
                try writer.writeByte(')');
            },
            .tuple => |tup| {
                try writer.writeAll("tuple(");
                for (tup.items, 0..) |it, i| {
                    if (i != 0) try writer.writeByte(',');
                    try self.appendTypeKey(writer, meta_model, it);
                }
                try writer.writeByte(')');
            },
            .literal => |lit| {
                try writer.writeAll("literal{");
                for (lit.value.properties, 0..) |p, i| {
                    if (i != 0) try writer.writeByte(',');
                    try writer.print("{s}:", .{p.name});
                    try self.appendTypeKey(writer, meta_model, p.type);
                }
                try writer.writeByte('}');
            },
            .stringLiteral => |sl| try writer.print("strlit:{s}", .{sl.value}),
            .integerLiteral => |il| try writer.print("intlit:{d}", .{il.value}),
            .booleanLiteral => |bl| try writer.print("boollit:{}", .{bl.value}),
        }
    }

    fn getOrCreateUnionAlias(self: *AliasCollector, meta_model: *const MetaModel, items: []const MetaModel.Type) []const u8 {
        var aw: std.io.Writer.Allocating = .init(self.allocator);
        defer aw.deinit();
        const w = &aw.writer;
        w.writeAll("union:") catch std.debug.panic("OOM while building union key", .{});
        for (items, 0..) |it, i| {
            if (i != 0) w.writeByte('|') catch std.debug.panic("OOM key write", .{});
            self.appendTypeKey(w, meta_model, it) catch std.debug.panic("OOM while appending type key", .{});
        }
        const key = aw.toOwnedSlice() catch std.debug.panic("OOM taking union key slice", .{});
        if (self.key_to_name.get(key)) |existing| {
            self.allocator.free(key);
            return existing;
        }

        var hasher = std.hash.Wyhash.init(0);
        hasher.update(key);
        const h = hasher.final();
        const name = self.encodeTicketName(h) catch std.debug.panic("OOM allocating alias name", .{});

        var aw2: std.io.Writer.Allocating = .init(self.allocator);
        defer aw2.deinit();
        const w2 = &aw2.writer;
        w2.writeAll("union(enum) {\n") catch std.debug.panic("OOM writing alias body", .{});
        for (items, 0..) |sub_type, i| {
            guessTypeName(meta_model.*, w2, sub_type, i) catch std.debug.panic("OOM guessTypeName", .{});
            w2.print(": {f},\n", .{fmtType(sub_type, meta_model, self, "")}) catch std.debug.panic("OOM printing alias variant", .{});
        }
        w2.writeAll(
            \\pub const jsonParse = parser.UnionParser(@This()).jsonParse;
            \\pub const jsonParseFromValue = parser.UnionParser(@This()).jsonParseFromValue;
            \\pub const jsonStringify = parser.UnionParser(@This()).jsonStringify;
            \\}
        ) catch std.debug.panic("OOM writing alias tail", .{});
        const def_body = aw2.toOwnedSliceSentinel(0) catch std.debug.panic("OOM finalizing alias body", .{});

        self.key_to_name.put(self.allocator, key, name) catch std.debug.panic("OOM mapping alias key", .{});
        self.keys.append(self.allocator, key) catch std.debug.panic("OOM appending key", .{});
        self.ordered_aliases.append(self.allocator, .{ .name = name, .definition = def_body }) catch std.debug.panic("OOM appending alias", .{});
        return name;
    }

    fn writeAliases(self: *AliasCollector, writer: *std.io.Writer) !void {
        if (self.ordered_aliases.items.len == 0) return;
        try writer.writeAll("\n// Type path index\n\n");
        try self.writeTypeIndex(writer);
        try writer.writeAll("\n// Union type aliases\n\n");
        for (self.ordered_aliases.items) |entry| {
            try writer.print("pub const {s} = {s};\n\n", .{ entry.name, entry.definition });
        }
    }

    fn registerPathAlias(self: *AliasCollector, path: []const u8, alias: []const u8) void {
        if (path.len == 0) return;
        if (self.path_to_alias.get(path) != null) return; // first-wins for stability
        const path_copy = self.allocator.dupe(u8, path) catch std.debug.panic("OOM duplicating path", .{});
        self.path_to_alias.put(self.allocator, path_copy, alias) catch std.debug.panic("OOM in path_to_alias.put", .{});
        self.ordered_paths.append(self.allocator, path_copy) catch std.debug.panic("OOM appending path", .{});
    }

    fn writeTypeIndex(self: *AliasCollector, writer: *std.io.Writer) !void {
        if (self.ordered_paths.items.len == 0) return;
        try writer.writeAll("pub const TypePaths = struct {\n");
        for (self.ordered_paths.items) |p| {
            const alias = self.path_to_alias.get(p) orelse @panic("Path not found in path_to_alias");
            try writer.print("  pub const @\"{s}\" = {s};\n", .{ p, alias });
        }
        try writer.writeAll("};\n\n");
    }

    const Cell = enum { CVN, CV };
    const consonants = "BCDFGHJKMNPQRSTVWXYZ";
    const vowels = "AEIOU";
    const digits = "23456789";

    fn encodeTicketName(self: *AliasCollector, hash64: u64) ![]const u8 {
        const pattern = [_]Cell{ .CVN, .CVN, .CVN, .CVN, .CVN, .CVN, .CVN };
        // Note: pattern is comptime-known; no runtime check needed
        const out_len: usize = 2 + 3 * pattern.len; // 'U_' + each CVN is 3 chars
        var buf = try self.allocator.alloc(u8, out_len);
        buf[0] = 'U';
        buf[1] = '_';
        var n = hash64;
        var i: usize = 2;
        inline for (pattern) |cell| {
            switch (cell) {
                .CVN => {
                    const base: u64 = 20 * 5 * 8;
                    const rem: u64 = n % base;
                    n /= base;
                    const c_idx: u64 = rem / (5 * 8);
                    const r2: u64 = rem % (5 * 8);
                    const v_idx: u64 = r2 / 8;
                    const d_idx: u64 = r2 % 8;
                    buf[i + 0] = consonants[@intCast(c_idx)];
                    buf[i + 1] = vowels[@intCast(v_idx)];
                    buf[i + 2] = digits[@intCast(d_idx)];
                    i += 3;
                },
                .CV => {
                    const base: u64 = 20 * 5;
                    const rem: u64 = n % base;
                    n /= base;
                    const c_idx: u64 = rem / 5;
                    const v_idx: u64 = rem % 5;
                    buf[i + 0] = consonants[@intCast(c_idx)];
                    buf[i + 1] = vowels[@intCast(v_idx)];
                    i += 2;
                },
            }
        }
        return buf;
    }
};

fn messageDirectionName(message_direction: MetaModel.MessageDirection) []const u8 {
    return switch (message_direction) {
        .clientToServer => "client_to_server",
        .serverToClient => "server_to_client",
        .both => "both",
    };
}

fn guessTypeName(meta_model: MetaModel, writer: *std.io.Writer, typ: MetaModel.Type, i: usize) std.io.Writer.Error!void {
    switch (typ) {
        .base => |base| switch (base.name) {
            .URI => try writer.writeAll("uri"),
            .DocumentUri => try writer.writeAll("document_uri"),
            .integer => try writer.writeAll("integer"),
            .uinteger => try writer.writeAll("uinteger"),
            .decimal => try writer.writeAll("decimal"),
            .RegExp => try writer.writeAll("regexp"),
            .string => try writer.writeAll("string"),
            .boolean => try writer.writeAll("bool"),
            .null => try writer.writeAll("@\"null\""),
        },
        .reference => |ref| try writer.print("{f}", .{std.zig.fmtId(ref.name)}),
        .array => |arr| {
            try writer.writeAll("array_of_");
            try guessTypeName(meta_model, writer, arr.element.*, 0);
        },
        .map => try writer.print("map_{d}", .{i}),
        .@"and" => try writer.print("and_{d}", .{i}),
        .@"or" => try writer.print("or_{d}", .{i}),
        .tuple => try writer.print("tuple_{d}", .{i}),
        .literal,
        .stringLiteral,
        .integerLiteral,
        .booleanLiteral,
        => try writer.print("literal_{d}", .{i}),
    }
}

fn isOrActuallyEnum(ort: MetaModel.OrType) bool {
    for (ort.items) |t| {
        if (t != .stringLiteral) return false;
    }
    return true;
}

fn isTypeNull(typ: MetaModel.Type) bool {
    if (typ != .@"or") return false;
    const ort = typ.@"or";
    return (ort.items.len == 2 and ort.items[1] == .base and ort.items[1].base.name == .null) or (ort.items[ort.items.len - 1] == .base and ort.items[ort.items.len - 1].base.name == .null);
}

const FormatType = struct {
    meta_model: *const MetaModel,
    ty: MetaModel.Type,
    aliaser: *AliasCollector,
    current_path: []const u8,
};

fn renderType(ctx: FormatType, writer: *std.io.Writer) std.io.Writer.Error!void {
    switch (ctx.ty) {
        .base => |base| switch (base.name) {
            .URI => try writer.writeAll("URI"),
            .DocumentUri => try writer.writeAll("DocumentUri"),
            .integer => try writer.writeAll("i32"),
            .uinteger => try writer.writeAll("u32"),
            .decimal => try writer.writeAll("f32"),
            .RegExp => try writer.writeAll("RegExp"),
            .string => try writer.writeAll("[]const u8"),
            .boolean => try writer.writeAll("bool"),
            .null => try writer.writeAll("?void"),
        },
        .reference => |ref| try writer.print("{f}", .{std.zig.fmtId(ref.name)}),
        .array => |arr| try writer.print("[]const {f}", .{fmtType(arr.element.*, ctx.meta_model, ctx.aliaser, ctx.current_path)}),
        .map => |map| {
            try writer.writeAll("parser.Map(");
            switch (map.key) {
                .base => |base| try switch (base.name) {
                    .Uri => writer.writeAll("Uri"),
                    .DocumentUri => writer.writeAll("DocumentUri"),
                    .integer => writer.writeAll("i32"),
                    .string => writer.writeAll("[]const u8"),
                },
                .reference => |ref| try writer.print("{f}", .{fmtType(.{ .reference = ref }, ctx.meta_model, ctx.aliaser, ctx.current_path)}),
            }
            try writer.print(", {f})", .{fmtType(map.value.*, ctx.meta_model, ctx.aliaser, ctx.current_path)});
        },
        .@"and" => |andt| {
            try writer.writeAll("struct {\n");
            for (andt.items) |item| {
                if (item != .reference) @panic("Unimplemented and subject encountered!");
                try writer.print("// And {s}\n{f}\n\n", .{
                    item.reference.name,
                    fmtReference(item.reference, null, ctx.meta_model, ctx.aliaser, ctx.current_path),
                });
            }
            try writer.writeAll("}");
        },
        .@"or" => |ort| {
            // NOTE: Hack to get optionals working
            // There are no triple optional ors (I believe),
            // so this should work every time
            if (ort.items.len == 2 and ort.items[1] == .base and ort.items[1].base.name == .null) {
                try writer.print("?{f}", .{fmtType(ort.items[0], ctx.meta_model, ctx.aliaser, ctx.current_path)});
            } else if (isOrActuallyEnum(ort)) {
                try writer.writeAll("enum {");
                for (ort.items) |sub_type| {
                    try writer.print("{s},\n", .{sub_type.stringLiteral.value});
                }
                try writer.writeByte('}');
            } else {
                const has_null = ort.items[ort.items.len - 1] == .base and ort.items[ort.items.len - 1].base.name == .null;
                const items = ort.items[0..if (has_null) ort.items.len - 1 else ort.items.len];
                if (has_null) try writer.writeByte('?');
                const alias_name = ctx.aliaser.getOrCreateUnionAlias(ctx.meta_model, items);
                try writer.print("{s}", .{alias_name});
                if (ctx.current_path.len != 0) ctx.aliaser.registerPathAlias(ctx.current_path, alias_name);
            }
        },
        .tuple => |tup| {
            try writer.writeAll("struct {");
            for (tup.items, 0..) |ty, i| {
                if (i != 0) try writer.writeByte(',');
                try writer.print(" {f}", .{fmtType(ty, ctx.meta_model, ctx.aliaser, ctx.current_path)});
            }
            try writer.writeAll(" }");
        },
        .literal => |lit| {
            try writer.writeAll("struct {");
            if (lit.value.properties.len != 0) {
                for (lit.value.properties) |property| {
                    const sub_path = pathJoin(ctx.aliaser.allocator, ctx.current_path, property.name) catch std.debug.panic("OOM join path", .{});
                    try writer.print("\n{f}", .{fmtPropertyWithPath(property, ctx.meta_model, ctx.aliaser, sub_path)});
                    ctx.aliaser.allocator.free(sub_path);
                }
                try writer.writeByte('\n');
            }
            try writer.writeByte('}');
        },
        .stringLiteral => |lit| try writer.print("[]const u8 = \"{f}\"", .{std.zig.fmtString(lit.value)}),
        .integerLiteral => |lit| try writer.print("i32 = {d}", .{lit.value}),
        .booleanLiteral => |lit| try writer.print("bool = {}", .{lit.value}),
    }
}

fn fmtType(ty: MetaModel.Type, meta_model: *const MetaModel, aliaser: *AliasCollector, current_path: []const u8) std.fmt.Formatter(FormatType, renderType) {
    return .{ .data = .{ .meta_model = meta_model, .ty = ty, .aliaser = aliaser, .current_path = current_path } };
}

const FormatProperty = struct {
    meta_model: *const MetaModel,
    property: MetaModel.Property,
    aliaser: *AliasCollector,
    current_path: []const u8,
};

fn renderProperty(ctx: FormatProperty, writer: *std.io.Writer) std.io.Writer.Error!void {
    const isUndefinedable = ctx.property.optional orelse false;
    const isNull = isTypeNull(ctx.property.type);
    // WORKAROUND: recursive SelectionRange
    const isSelectionRange = ctx.property.type == .reference and std.mem.eql(u8, ctx.property.type.reference.name, "SelectionRange");

    if (ctx.property.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .doc)});

    try writer.print("{f}: {s}{f}{s},", .{
        std.zig.fmtIdPU(ctx.property.name),
        if (isSelectionRange) "?*" else if (isUndefinedable and !isNull) "?" else "",
        fmtType(ctx.property.type, ctx.meta_model, ctx.aliaser, ctx.current_path),
        if (isNull or isUndefinedable) " = null" else "",
    });
}

fn fmtPropertyWithPath(property: MetaModel.Property, meta_model: *const MetaModel, aliaser: *AliasCollector, current_path: []const u8) std.fmt.Formatter(FormatProperty, renderProperty) {
    return .{ .data = .{ .meta_model = meta_model, .property = property, .aliaser = aliaser, .current_path = current_path } };
}

fn fmtProperty(property: MetaModel.Property, meta_model: *const MetaModel, aliaser: *AliasCollector, base_path: []const u8) std.fmt.Formatter(FormatProperty, renderProperty) {
    const this_path = pathJoin(aliaser.arena.allocator(), base_path, property.name) catch std.debug.panic("OOM joining base path", .{});
    return fmtPropertyWithPath(property, meta_model, aliaser, this_path);
}

const FormatProperties = struct {
    meta_model: *const MetaModel,
    structure: MetaModel.Structure,
    maybe_extender: ?MetaModel.Structure,
    aliaser: *AliasCollector,
    base_path: []const u8,
};

fn renderProperties(ctx: FormatProperties, writer: *std.io.Writer) std.io.Writer.Error!void {
    const properties: []MetaModel.Property = ctx.structure.properties;
    const extends: []MetaModel.Type = ctx.structure.extends orelse &.{};
    const mixins: []MetaModel.Type = ctx.structure.mixins orelse &.{};

    skip: for (properties) |property| {
        if (ctx.maybe_extender) |ext| {
            for (ext.properties) |ext_property| {
                if (std.mem.eql(u8, property.name, ext_property.name)) {
                    // std.log.info("Skipping implemented field emission: {s}", .{property.name});
                    continue :skip;
                }
            }
        }
        try writer.print("\n{f}", .{fmtProperty(property, ctx.meta_model, ctx.aliaser, ctx.base_path)});
    }

    for (extends) |ext| {
        if (ext != .reference) @panic("Expected reference for extends!");
        try writer.print("\n\n// Extends `{s}`{f}", .{
            ext.reference.name,
            fmtReference(ext.reference, ctx.structure, ctx.meta_model, ctx.aliaser, ctx.base_path),
        });
    }

    for (mixins) |ext| {
        if (ext != .reference) @panic("Expected reference for mixin!");
        try writer.print("\n\n// Uses mixin `{s}`{f}", .{
            ext.reference.name,
            fmtReference(ext.reference, ctx.structure, ctx.meta_model, ctx.aliaser, ctx.base_path),
        });
    }
}

fn fmtProperties(
    structure: MetaModel.Structure,
    maybe_extender: ?MetaModel.Structure,
    meta_model: *const MetaModel,
    aliaser: *AliasCollector,
    base_path: []const u8,
) std.fmt.Formatter(FormatProperties, renderProperties) {
    return .{ .data = .{ .meta_model = meta_model, .structure = structure, .maybe_extender = maybe_extender, .aliaser = aliaser, .base_path = base_path } };
}

const FormatReference = struct {
    meta_model: *const MetaModel,
    reference: MetaModel.ReferenceType,
    maybe_extender: ?MetaModel.Structure,
    aliaser: *AliasCollector,
    base_path: []const u8,
};

fn renderReference(ctx: FormatReference, writer: *std.io.Writer) std.io.Writer.Error!void {
    for (ctx.meta_model.structures) |s| {
        if (std.mem.eql(u8, s.name, ctx.reference.name)) {
            try writer.print("{f}", .{fmtProperties(s, ctx.maybe_extender, ctx.meta_model, ctx.aliaser, ctx.base_path)});
            return;
        }
    }
}

fn fmtReference(
    reference: MetaModel.ReferenceType,
    maybe_extender: ?MetaModel.Structure,
    meta_model: *const MetaModel,
    aliaser: *AliasCollector,
    base_path: []const u8,
) std.fmt.Formatter(FormatReference, renderReference) {
    return .{ .data = .{ .meta_model = meta_model, .reference = reference, .maybe_extender = maybe_extender, .aliaser = aliaser, .base_path = base_path } };
}

fn writeRequest(writer: *std.io.Writer, meta_model: MetaModel, request: MetaModel.Request, aliaser: *AliasCollector) std.io.Writer.Error!void {
    if (request.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .normal)});

    try writer.print(
        \\.{{
        \\  .method = "{s}",
        \\  .documentation = {?f},
        \\  .direction = .{s},
        \\  .Params = {?f},
        \\  .Result = {f},
        \\  .PartialResult = {?f},
        \\  .ErrorData = {?f},
        \\  .registration = .{{ .method = {?f}, .Options = {?f} }},
        \\}},
        \\
    , .{
        request.method,
        if (request.documentation) |documentation| std.json.fmt(documentation, .{}) else null,
        messageDirectionName(request.messageDirection),
        // NOTE: Multiparams not used here, so we dont have to implement them :)
        if (request.params) |params| fmtType(params.Type, &meta_model, aliaser, request.method) else null,
        fmtType(request.result, &meta_model, aliaser, request.method),
        if (request.partialResult) |ty| fmtType(ty, &meta_model, aliaser, request.method) else null,
        if (request.errorData) |ty| fmtType(ty, &meta_model, aliaser, request.method) else null,
        if (request.registrationMethod) |method| std.json.fmt(method, .{}) else null,
        if (request.registrationOptions) |ty| fmtType(ty, &meta_model, aliaser, request.method) else null,
    });
}

fn writeNotification(writer: *std.io.Writer, meta_model: MetaModel, notification: MetaModel.Notification, aliaser: *AliasCollector) std.io.Writer.Error!void {
    if (notification.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .normal)});

    try writer.print(
        \\.{{
        \\  .method = "{s}",
        \\  .documentation = {?f},
        \\  .direction = .{s},
        \\  .Params = {?f},
        \\  .registration = .{{ .method = {?f}, .Options = {?f} }},
        \\}},
        \\
    , .{
        notification.method,
        if (notification.documentation) |documentation| std.json.fmt(documentation, .{}) else null,
        messageDirectionName(notification.messageDirection),
        // NOTE: Multiparams not used here, so we dont have to implement them :)
        if (notification.params) |params| fmtType(params.Type, &meta_model, aliaser, notification.method) else null,
        if (notification.registrationMethod) |method| std.json.fmt(method, .{}) else null,
        if (notification.registrationOptions) |ty| fmtType(ty, &meta_model, aliaser, notification.method) else null,
    });
}

fn writeStructure(writer: *std.io.Writer, meta_model: MetaModel, structure: MetaModel.Structure, aliaser: *AliasCollector) std.io.Writer.Error!void {
    if (std.mem.eql(u8, structure.name, "LSPObject")) return;

    if (structure.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .doc)});
    try writer.print("pub const {f} = struct {{{f}\n}};\n\n", .{
        std.zig.fmtId(structure.name),
        fmtProperties(structure, null, &meta_model, aliaser, structure.name),
    });
}

fn writeEnumeration(writer: *std.io.Writer, meta_model: MetaModel, enumeration: MetaModel.Enumeration) std.io.Writer.Error!void {
    _ = meta_model;

    if (enumeration.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .doc)});

    const container_kind = switch (enumeration.type.name) {
        .string => "union(enum)",
        .integer => "enum(i32)",
        .uinteger => "enum(u32)",
    };
    try writer.print("pub const {f} = {s} {{\n", .{ std.zig.fmtId(enumeration.name), container_kind });

    // WORKAROUND: the enumeration value `pascal` appears twice in LanguageKind
    var found_pascal = false;

    var contains_empty_enum = false;
    for (enumeration.values) |entry| {
        if (entry.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .doc)});
        switch (entry.value) {
            .string => |value| {
                if (std.mem.eql(u8, value, "pascal")) {
                    if (found_pascal) continue;
                    found_pascal = true;
                }
                if (value.len == 0) contains_empty_enum = true;
                const name = if (value.len == 0) "empty" else value;
                try writer.print("{f},\n", .{std.zig.fmtIdP(name)});
            },
            .number => |value| try writer.print("{f} = {d},\n", .{ std.zig.fmtIdP(entry.name), value }),
        }
    }

    const supportsCustomValues = enumeration.supportsCustomValues orelse false;

    const field_name, const docs = if (supportsCustomValues) .{ "custom_value", "Custom Value" } else .{ "unknown_value", "Unknown Value" };
    switch (enumeration.type.name) {
        .string => {
            try writer.print(
                \\{s}: []const u8,
                \\pub const eql = parser.EnumCustomStringValues(@This(), {1}).eql;
                \\pub const jsonParse = parser.EnumCustomStringValues(@This(), {1}).jsonParse;
                \\pub const jsonParseFromValue = parser.EnumCustomStringValues(@This(), {1}).jsonParseFromValue;
                \\pub const jsonStringify = parser.EnumCustomStringValues(@This(), {1}).jsonStringify;
                \\
            , .{ field_name, contains_empty_enum });
        },
        .integer, .uinteger => {
            try writer.print(
                \\/// {s}
                \\_,
                \\pub const jsonStringify = parser.EnumStringifyAsInt(@This()).jsonStringify;
                \\
            , .{docs});
        },
    }

    try writer.writeAll("};\n\n");
}

fn writeTypeAlias(writer: *std.io.Writer, meta_model: MetaModel, type_alias: MetaModel.TypeAlias, aliaser: *AliasCollector) std.io.Writer.Error!void {
    if (std.mem.startsWith(u8, type_alias.name, "LSP")) return;

    if (type_alias.documentation) |docs| try writer.print("{f}", .{fmtDocs(docs, .doc)});
    try writer.print("pub const {f} = {f};\n\n", .{ std.zig.fmtId(type_alias.name), fmtType(type_alias.type, &meta_model, aliaser, type_alias.name) });
}

fn writeMetaModel(writer: *std.io.Writer, meta_model: MetaModel, allocator: std.mem.Allocator, arena: *std.heap.ArenaAllocator) std.io.Writer.Error!void {
    var aliaser: AliasCollector = AliasCollector.init(allocator, arena);
    defer aliaser.deinit();
    try writer.writeAll(@embedFile("lsp_types_base.zig") ++ "\n");

    try writer.writeAll("// Type Aliases\n\n");
    for (meta_model.typeAliases) |type_alias| {
        try writeTypeAlias(writer, meta_model, type_alias, &aliaser);
    }

    try writer.writeAll("// Enumerations\n\n");
    for (meta_model.enumerations) |enumeration| {
        try writeEnumeration(writer, meta_model, enumeration);
    }

    try writer.writeAll("// Structures\n\n");
    for (meta_model.structures) |structure| {
        try writeStructure(writer, meta_model, structure, &aliaser);
    }

    try writer.writeAll("const notification_metadata_generated = [_]NotificationMetadata{\n");
    for (meta_model.notifications) |notification| {
        try writeNotification(writer, meta_model, notification, &aliaser);
    }
    try writer.writeAll("\n};");

    try writer.writeAll("const request_metadata_generated = [_]RequestMetadata{\n");
    for (meta_model.requests) |request| {
        try writeRequest(writer, meta_model, request, &aliaser);
    }
    try writer.writeAll("};\n");

    try aliaser.writeAliases(writer);
}

fn pathJoin(allocator: std.mem.Allocator, base: []const u8, tail: []const u8) ![]const u8 {
    if (base.len == 0) return allocator.dupe(u8, tail);
    var buf = try allocator.alloc(u8, base.len + 1 + tail.len);
    std.mem.copyForwards(u8, buf[0..base.len], base);
    buf[base.len] = '/';
    std.mem.copyForwards(u8, buf[base.len + 1 ..], tail);
    return buf;
}
