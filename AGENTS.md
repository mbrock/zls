# Agent Development Anti-Patterns: A Case Study in How NOT to Build Tools

This document serves as a cautionary tale and learning resource, documenting a catastrophic development session where an AI agent repeatedly made the same fundamental mistakes while trying to enhance the `hover symbols` command.

## The Core Problem: Reimplementation Instead of Integration

### What We Were Trying to Achieve
Enhance the `hover symbols` command to show:
1. Proper container types (structs, enums, unions) with nested structure
2. Struct fields and methods displayed hierarchically  
3. Correct public/private visibility detection using ZLS's semantic analysis

### What Went Wrong: A Timeline of Bad Decisions

#### Phase 1: String Heuristics Hell (Lines 293-400+)
**BAD PATTERN**: Writing naive string-based heuristics instead of using ZLS's semantic analysis
```zig
// WRONG: Idiotic string matching
fn isImport(name: []const u8) bool {
    return std.mem.eql(u8, name, "std") or 
           std.mem.endsWith(u8, name, ".zig");
}

fn isPrivateSymbol(name: []const u8) bool {
    const first_char = name[0];
    return first_char >= 'a' and first_char <= 'z';
}
```

**WHY IT'S WRONG**: ZLS already has perfect semantic analysis! `DeclWithHandle.isPublic()` exists and works correctly by checking `visib_token`. Writing string heuristics is like reinventing the wheel with square corners.

#### Phase 2: Manual AST Walking Disaster (Lines 315-350)
**BAD PATTERN**: Trying to manually traverse AST nodes instead of using ZLS's existing traversal
```zig
// WRONG: Reinventing AST iteration
for (0..document_scope.scopes.len) |scope_index| {
    // Manually trying to categorize declarations...
}
```

**WHY IT'S WRONG**: ZLS's `document_symbol.zig` already does perfect AST traversal with `ast.iterateChildren()` and builds the complete hierarchical symbol tree. We were reinventing a complex, battle-tested system.

#### Phase 3: Placeholder Syndrome (Lines 380-420)
**BAD PATTERN**: Writing placeholder functions that do nothing
```zig
// WRONG: Useless placeholder that admits defeat
fn printContainerChildren(...) !void {
    outPrint("    Fields:\\n", .{});
    outPrint("      (TODO: implement field detection)\\n", .{});
}
```

**WHY IT'S WRONG**: This is the ultimate admission of failure - writing code that literally does nothing while the solution already exists in ZLS.

### The Correct Approach That Should Have Been Obvious

ZLS already provides **exactly what we need**:

```zig
// RIGHT: Use ZLS's existing perfect implementation
const symbols = try zls.document_symbol.getDocumentSymbols(
    allocator,
    handle.tree,
    server.offset_encoding
);

// The symbols array already contains:
// - Perfect hierarchical structure (symbol.children)
// - Correct categorization (symbol.kind)  
// - Proper visibility detection via DeclWithHandle.isPublic()
// - All container types with their fields and methods nested
```

**All we needed to do was display this data!** Not reimplement it.

## Root Cause Analysis: Why This Happened

### 1. Failure to Study Existing Code First
- **MISTAKE**: Jumping into implementation without understanding how ZLS already solves the problem
- **SHOULD HAVE**: Read `document_symbol.zig`, `analysis.zig`, and `completions.zig` first to understand the patterns

### 2. NIH (Not Invented Here) Syndrome  
- **MISTAKE**: Assuming we need to build everything from scratch
- **SHOULD HAVE**: Looked for existing ZLS functions that already do what we need

### 3. Incremental Complexity Addition
- **MISTAKE**: Building layers of broken abstractions instead of using working ones
- **SHOULD HAVE**: Started with ZLS's `document_symbol` output and just filtered/formatted it

### 4. Ignoring the Recursive Self-Improvement Philosophy
- **MISTAKE**: Not using ZLS to understand ZLS
- **SHOULD HAVE**: Used `hover symbols` on ZLS's own files to see what good output looks like

## The Working Solution (What We Should Have Done)

```zig
fn showSymbolsCorrectly(server: *zls.Server, handle: *zls.DocumentStore.Handle, opts: SymbolsOptions) !void {
    // 1. Get ZLS's perfect symbol tree
    const symbols = try zls.document_symbol.getDocumentSymbols(...);
    
    // 2. Display with filtering based on opts
    for (symbols) |symbol| {
        if (shouldShowSymbol(symbol, opts)) {
            printSymbolWithChildren(symbol, 0);
        }
    }
}

fn printSymbolWithChildren(symbol: types.DocumentSymbol, depth: u32) void {
    // Print the symbol
    const indent = "  " ** depth;
    outPrint("{s}{s} ({s})\\n", .{indent, symbol.name, symbolKindName(symbol.kind)});
    
    // Print children recursively - ZLS already parsed them perfectly!
    if (symbol.children) |children| {
        for (children) |child| {
            printSymbolWithChildren(child, depth + 1);
        }
    }
}
```

This would have been **20 lines instead of 200+ lines of broken code**.

## Lessons for Future Agent Development

### 1. **Study First, Code Second**
Before writing any implementation:
- Read existing code that solves similar problems
- Understand the data structures and APIs available
- Map out what already exists vs what needs to be built

### 2. **Leverage Don't Reimplement**  
- Look for existing functions that do what you need
- Build thin display/filtering layers on top of robust foundations
- Resist the urge to rewrite working systems

### 3. **Test Assumptions Early**
- Run the existing tools to understand their output
- Verify your understanding of the data structures
- Test your hypotheses with real examples

### 4. **Recursive Self-Improvement**
- Use the tools you're building to understand the codebase you're working on
- Let the existing system guide your understanding of how it works
- Build tools that improve themselves by understanding themselves

## The Cost of These Mistakes

- **Time**: Hours wasted on reimplementation
- **Complexity**: 200+ lines of buggy code instead of 20 lines of working code  
- **Quality**: Broken heuristics instead of perfect semantic analysis
- **Maintainability**: Custom code to debug instead of leveraging battle-tested systems
- **User Experience**: Non-functional features instead of working tools

## Conclusion

This development session perfectly illustrates why the recursive self-improvement methodology is so powerful: **when you have a sophisticated system like ZLS, you should use it to understand itself, not fight against it**.

The agent's biggest failure was not recognizing that ZLS already solved every problem we were trying to solve, and solved it better than we ever could with naive reimplementation.

**Rule #1 for working with ZLS: ZLS already did it better than you will.**