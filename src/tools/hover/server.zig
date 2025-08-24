const std = @import("std");
const zls = @import("zls");
const types = zls.lsp.types;

pub fn initServer(allocator: std.mem.Allocator, markdown: bool) !*zls.Server {
    const cfg_manager = zls.configuration.Manager.init(allocator);
    const server = try zls.Server.create(.{
        .allocator = allocator,
        .transport = null,
        .config = null,
        .config_manager = cfg_manager,
    });
    errdefer server.destroy();

    var init_params: types.InitializeParams = .{ .capabilities = .{} };
    if (markdown) {
        init_params.capabilities.textDocument = .{ .hover = .{ .contentFormat = &[_]types.MarkupKind{ .markdown } } };
    }
    _ = try server.sendRequestSync(allocator, "initialize", init_params);
    _ = try server.sendNotificationSync(allocator, "initialized", .{});
    return server;
}

pub fn openDocument(server: *zls.Server, arena: std.mem.Allocator, file_path: []const u8, content: []const u8) !*zls.DocumentStore.Handle {
    const abs = try std.fs.cwd().realpathAlloc(arena, file_path);
    const uri = try zls.URI.fromPath(arena, abs);
    const params: types.DidOpenTextDocumentParams = .{
        .textDocument = .{ .uri = uri, .languageId = "zig", .version = 0, .text = content },
    };
    try server.sendNotificationSync(arena, "textDocument/didOpen", params);
    return server.document_store.getHandle(uri).?;
}

