const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;
const util = @import("util.zig");
const opts_mod = @import("options.zig");

const outPrint = util.outPrint;
pub const SymbolsOptions = opts_mod.SymbolsOptions;

pub fn analyzeSymbolsWithZLS(allocator: std.mem.Allocator, server: *zls.Server, handle: *zls.DocumentStore.Handle, opts: SymbolsOptions) !void {
    if (opts.show_imports) {
        var imports = try zls.Analyser.collectImports(allocator, handle.tree);
        defer imports.deinit(allocator);
        if (imports.items.len > 0) {
            outPrint("Imports:\n", .{});
            for (imports.items) |import_path| outPrint("  {s}\n", .{import_path});
            outPrint("\n", .{});
        }
    }

    const symbols = try zls.document_symbol.getDocumentSymbols(
        allocator,
        handle.tree,
        server.offset_encoding,
    );
    try displaySymbolsHierarchically(symbols, handle, opts);
}

fn displaySymbolsHierarchically(symbols: []const types.DocumentSymbol, handle: *zls.DocumentStore.Handle, opts: SymbolsOptions) !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var containers: std.ArrayList(types.DocumentSymbol) = .empty;
    var functions: std.ArrayList(types.DocumentSymbol) = .empty;
    var constants: std.ArrayList(types.DocumentSymbol) = .empty;

    for (symbols) |symbol| {
        if (symbol.kind == .Constant and symbol.children != null and symbol.children.?.len > 0) {
            try containers.append(allocator, symbol);
        } else switch (symbol.kind) {
            .Struct, .Class, .Interface, .Enum, .Namespace => try containers.append(allocator, symbol),
            .Function, .Method, .Constructor => try functions.append(allocator, symbol),
            .Constant, .Variable => try constants.append(allocator, symbol),
            else => {},
        }
    }

    if (containers.items.len > 0) {
        outPrint("Types:\n", .{});
        for (containers.items) |container| try printContainerWithStructure(container, handle);
        outPrint("\n", .{});
    }
    if (functions.items.len > 0) {
        outPrint("Functions:\n", .{});
        for (functions.items) |func| try printStructuredFunction(func, handle);
        outPrint("\n", .{});
    }
    if (!opts.api_only and !opts.minimal and constants.items.len > 0) {
        outPrint("Constants:\n", .{});
        for (constants.items) |constant| {
            if (std.mem.eql(u8, constant.name, "std") or std.mem.eql(u8, constant.name, "builtin") or std.mem.endsWith(u8, constant.name, ".zig")) continue;
            outPrint("  {s}\n", .{constant.name});
        }
    }
}

fn printContainerWithStructure(container: types.DocumentSymbol, handle: *zls.DocumentStore.Handle) !void {
    const container_type = if (container.kind == .Struct) "struct"
        else if (container.kind == .Enum) "enum"
        else if (container.kind == .Class or container.kind == .Interface) "interface"
        else "struct";
    outPrint("  {s} ({s})\n", .{ container.name, container_type });
    if (container.children) |children| {
        var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
        defer arena.deinit();
        const allocator = arena.allocator();
        var fields: std.ArrayList(types.DocumentSymbol) = .empty;
        var methods: std.ArrayList(types.DocumentSymbol) = .empty;
        var enum_values: std.ArrayList(types.DocumentSymbol) = .empty;
        for (children) |child| switch (child.kind) {
            .Field, .Property => try fields.append(allocator, child),
            .Function, .Method, .Constructor => try methods.append(allocator, child),
            .EnumMember => try enum_values.append(allocator, child),
            else => {},
        };
        if (fields.items.len > 0) {
            outPrint("    Fields:\n", .{});
            for (fields.items) |field| outPrint("      {s}\n", .{field.name});
        }
        if (enum_values.items.len > 0) {
            outPrint("    Values:\n", .{});
            for (enum_values.items) |value| outPrint("      {s}\n", .{value.name});
        }
        if (methods.items.len > 0) {
            outPrint("    Methods:\n", .{});
            for (methods.items) |method| try printStructuredMethod(method, handle);
        }
    }
}

fn printStructuredFunction(sym: types.DocumentSymbol, handle: *zls.DocumentStore.Handle) !void {
    _ = handle;
    if (sym.detail) |d| outPrint("  {s}: {s}\n", .{ sym.name, d }) else outPrint("  {s}\n", .{ sym.name });
}

fn printStructuredMethod(sym: types.DocumentSymbol, handle: *zls.DocumentStore.Handle) !void {
    _ = handle;
    if (sym.detail) |d| outPrint("      {s}: {s}\n", .{ sym.name, d }) else outPrint("      {s}\n", .{ sym.name });
}

fn printSymbolsEnhanced(allocator: std.mem.Allocator, server: *zls.Server, handle: *zls.DocumentStore.Handle, root: []const types.DocumentSymbol, opts: SymbolsOptions) void {
    analyzeSymbolsWithZLS(allocator, server, handle, opts) catch |err| {
        std.debug.print("Error analyzing symbols: {any}\n", .{err});
        printSymbolsFallback(root, opts);
    };
}

fn printSymbolsFallback(root: []const types.DocumentSymbol, opts: SymbolsOptions) void {
    for (root) |sym| switch (sym.kind) {
        .Function, .Method, .Constructor => if (opts.show_public or opts.show_private) outPrint("  {s} (fn)\n", .{sym.name}),
        .Struct, .Class, .Interface, .Enum => if (opts.show_public or opts.show_private) outPrint("  {s} (type)\n", .{sym.name}),
        .Constant => if (!opts.api_only and !opts.minimal) outPrint("  {s} (const)\n", .{sym.name}),
        else => {},
    };
}

pub fn printSymbols(allocator: std.mem.Allocator, server: *zls.Server, handle: *zls.DocumentStore.Handle, root: []const types.DocumentSymbol, opts: SymbolsOptions) void {
    printSymbolsEnhanced(allocator, server, handle, root, opts);
}

pub fn printSymbolInformation(infos: []const types.SymbolInformation) void {
    var structs_count: u32 = 0;
    var functions_count: u32 = 0;
    var constants_count: u32 = 0;
    for (infos) |sym| switch (sym.kind) {
        .Struct, .Class, .Interface => structs_count += 1,
        .Function, .Method, .Constructor => functions_count += 1,
        .Constant => constants_count += 1,
        else => {},
    };
    if (structs_count > 0) outPrint("\n📦 Structs & Types:\n", .{});
    for (infos) |sym| if (sym.kind == .Struct or sym.kind == .Class or sym.kind == .Interface) printSymbolInfoWithLocation(sym);
    if (functions_count > 0) outPrint("\n🔧 Functions & Methods:\n", .{});
    for (infos) |sym| if (sym.kind == .Function or sym.kind == .Method or sym.kind == .Constructor) printSymbolInfoWithLocation(sym);
    if (constants_count > 0) outPrint("\n📌 Constants:\n", .{});
    for (infos) |sym| if (sym.kind == .Constant) printSymbolInfoWithLocation(sym);
    outPrint("\n📝 Other:\n", .{});
    for (infos) |sym| switch (sym.kind) {
        .Struct, .Class, .Interface, .Function, .Method, .Constructor, .Constant => {},
        else => printSymbolInfoWithLocation(sym),
    };
}

fn printSymbolInfoWithLocation(sym: types.SymbolInformation) void {
    const line = sym.location.range.start.line + 1;
    const col = sym.location.range.start.character + 1;
    const kind_icon = switch (sym.kind) {
        .Function, .Method, .Constructor => "fn",
        .Struct => "struct",
        .Class => "class",
        .Interface => "interface",
        .Enum => "enum",
        .EnumMember => "•",
        .Constant => "const",
        .Variable => "var",
        .Field => "field",
        .Property => "prop",
        else => "?",
    };
    outPrint("[{d:>3}:{d:<2}] {s:<8} {s}\n", .{ line, col, kind_icon, sym.name });
}
