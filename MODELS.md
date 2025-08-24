# Models: A ZLS Fork for Interactive Code Intelligence

This project is a fork of [ZLS (Zig Language Server)](https://github.com/zigtools/zls) that extends the traditional LSP architecture with two key enhancements:

1. **Enhanced Code Actions**: Advanced refactoring capabilities including local constant hoisting, function parameter encapsulation, and top-level struct extraction
2. **Hover CLI Tool**: A standalone command-line interface that exposes ZLS's language intelligence as composable Unix tools

## The Hover Tool: Language Server as Agent Interface

The `hover` CLI tool (`src/tools/hover_cli.zig`) represents a novel approach to code intelligence: **using language server capabilities as composable agent tools**. Rather than confining LSP features within editor boundaries, `hover` exposes them as scriptable commands that can be chained, automated, and integrated into larger workflows.

### Available Commands

```bash
hover info <file> <line> <column> [--markdown|--plaintext]  # Get hover information
hover symbols <file>                                       # List document symbols  
hover actions <file> <line> <column> [range] [--kind]     # List available code actions
hover apply <file> <line> <column> [range] <index>        # Apply a specific code action
hover refactor <file> <line> <column> [range] [--apply N] # List/apply refactorings
hover pagerank [path]                                      # Analyze codebase importance
hover xref <file> <line> <column>                         # Find references
hover [path]                                              # Project overview report
```

### Recursive Agent Methodology

The design philosophy centers on **recursive self-improvement**: using `hover` to understand and enhance `hover` itself. This creates a feedback loop where:

1. **Exploration**: Use `hover` to analyze the ZLS codebase and understand its patterns
2. **Enhancement**: Identify opportunities to improve `hover`'s capabilities  
3. **Application**: Apply those improvements using `hover`'s own refactoring tools
4. **Iteration**: Repeat the cycle with enhanced capabilities

#### Example: Self-Improving Workflow

```bash
# Understand the current hover implementation
hover symbols src/tools/hover_cli.zig

# Find all references to a key function
hover xref src/tools/hover_cli.zig 245 initServer

# Discover available refactorings for a code section
hover refactor src/tools/hover_cli.zig 867 1127

# Apply a refactoring to improve the code
hover refactor src/tools/hover_cli.zig 245 255 --apply 0

# Analyze the impact across the codebase
hover pagerank src/
```

### Immediate Enhancement Opportunities

Several areas where `hover` can accelerate its own development:

#### 1. **Enhanced Symbol Navigation**
- Add cross-reference visualization showing function call graphs
- Implement semantic search beyond simple text matching
- Create dependency analysis to understand module relationships

#### 2. **Intelligent Code Generation**
- Template-based code expansion using existing patterns
- Auto-generation of boilerplate based on surrounding context
- Smart import resolution and organization

#### 3. **Refactoring Intelligence**
- Context-aware refactoring suggestions based on code patterns
- Batch refactoring operations across multiple files
- Safe renaming that understands semantic boundaries

#### 4. **Codebase Analytics** 
- Technical debt identification through pattern analysis
- Performance hotspot detection via static analysis
- Architecture quality metrics and recommendations

### The Agent Amplification Effect

By treating language server capabilities as agent tools, `hover` enables several multiplicative benefits:

1. **Composability**: Chain language operations in ways impossible within traditional editors
2. **Automation**: Script complex code transformations and analyses
3. **Integration**: Embed code intelligence into larger toolchains and workflows
4. **Scalability**: Process entire codebases programmatically rather than file-by-file

### Design Principles

1. **Unix Philosophy**: Small, focused tools that do one thing well and compose naturally
2. **Language-Agnostic Interface**: While built for Zig, the CLI patterns could apply to any LSP
3. **Self-Hosting**: The tool should be maximally useful for improving itself
4. **Interactive and Scriptable**: Work equally well for human exploration and automated processing

## Enhanced Code Actions

The fork extends ZLS's code action system with several new refactoring capabilities:

### Local Constant Hoisting
Automatically extracts repeated literal values into named constants at the appropriate scope level.

### Function Parameter Encapsulation  
Refactors functions with many parameters into struct-based parameter objects for better maintainability.

### Top-Level Struct Extraction
Moves struct definitions to new files with proper module structure and import management.

## Future Directions

The long-term vision is to create a **self-improving code intelligence system** where:

- Language servers become composable building blocks for larger AI systems
- Code analysis and transformation capabilities bootstrap their own enhancement  
- The boundary between "tool" and "agent" becomes increasingly fluid
- Human developers work in partnership with intelligent code understanding systems

This approach represents a shift from passive language servers that respond to editor requests toward active code intelligence agents that can autonomously explore, understand, and improve codebases.

## Getting Started

```bash
# Build the hover tool
zig build

# Get project overview
./zig-out/bin/hover

# Explore a specific file
./zig-out/bin/hover symbols src/tools/hover_cli.zig

# Find refactoring opportunities
./zig-out/bin/hover refactor src/tools/hover_cli.zig 100 200
```

The tool is designed for immediate productivity while serving as a foundation for more sophisticated code intelligence workflows.