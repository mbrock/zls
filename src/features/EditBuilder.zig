const std = @import("std");

const types = @import("lsp").types;

const DocumentChange = types.TypePaths.@"WorkspaceEdit/documentChanges";
const TextEdit = types.TypePaths.@"TextDocumentEdit/edits";

pub const EditBuilder = struct {
    pub const Edit = TextEdit;

    alloc: std.mem.Allocator,
    // Non-edit document changes (e.g. CreateFile) that should be emitted as-is
    dcs: std.ArrayList(DocumentChange) = .{},
    // Accumulated text edits per document URI; linearized into TextDocumentEdit on build
    edits_by_uri: std.StringArrayHashMapUnmanaged(std.ArrayList(TextEdit)) = .{},

    pub fn init(a: std.mem.Allocator) EditBuilder {
        return .{
            .alloc = a,
        };
    }

    pub fn deinit(self: *EditBuilder) void {
        // Note: memory is typically from an arena; explicit frees are unnecessary.
        // Still deinit containers to release bookkeeping allocations.
        var it = self.edits_by_uri.iterator();
        while (it.next()) |entry| {
            entry.value_ptr.*.deinit();
        }
        self.edits_by_uri.deinit();
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

    pub fn textDocumentEdit(self: *EditBuilder, tde: types.TextDocumentEdit) !void {
        // Allow callers to inject a ready-made TextDocumentEdit if needed
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
        // Build the new edit once and stash it by URI
        const new_text = try self.alloc.dupe(u8, text);
        const new_edit: TextEdit = .{ .TextEdit = types.TextEdit{
            .range = range,
            .newText = new_text,
        } };

        const gop = try self.edits_by_uri.getOrPut(self.alloc, uri);
        if (!gop.found_existing) {
            gop.value_ptr.* = .{};
        }
        try gop.value_ptr.append(self.alloc, new_edit);
    }

    pub fn build(self: *EditBuilder) !types.WorkspaceEdit {
        // Linearize edits per URI into TextDocumentEdit changes
        var it = self.edits_by_uri.iterator();
        while (it.next()) |entry| {
            const uri = entry.key_ptr.*;
            const edits_list = entry.value_ptr.*;
            const edits_slice = try self.alloc.dupe(TextEdit, edits_list.items);
            const tde = types.TextDocumentEdit{
                .textDocument = .{ .uri = uri, .version = 100 },
                .edits = edits_slice,
            };
            try self.dcs.append(self.alloc, .{ .TextDocumentEdit = tde });
        }

        return types.WorkspaceEdit{
            .documentChanges = try self.dcs.toOwnedSlice(self.alloc),
        };
    }
};
