"""
Add explicit _caller tags to all invokeLLM() calls that are missing them.
The _caller is derived from the filename + the enclosing function name.
"""
import re, os

def derive_caller(filepath, context_before):
    """Derive a meaningful _caller string from the file path and surrounding code."""
    # Get base module name from file path
    # e.g., server/lib/hunt-engine.ts -> hunt-engine
    # e.g., server/routers/detection-rules.ts -> detection-rules
    base = os.path.basename(filepath).replace('.ts', '')
    
    # Try to find the enclosing function name from context
    # Look for the last function/method declaration before the invokeLLM call
    patterns = [
        r'(?:async\s+)?function\s+(\w+)',
        r'(\w+)\s*(?::\s*\w+)?\s*=\s*async\s*\(',
        r'(\w+)\s*(?::\s*\w+)?\s*=\s*\(',
        r'\.(\w+)\s*=\s*async\s*\(',
        r'(?:async\s+)?(\w+)\s*\([^)]*\)\s*(?::\s*\w+)?\s*\{',
    ]
    
    func_name = None
    for pattern in patterns:
        matches = list(re.finditer(pattern, context_before))
        if matches:
            candidate = matches[-1].group(1)
            # Skip common non-function names
            if candidate not in ('if', 'for', 'while', 'catch', 'try', 'else', 'return', 'const', 'let', 'var', 'function', 'async', 'await', 'new', 'throw'):
                func_name = candidate
                break
    
    if func_name:
        return f"{base}.{func_name}"
    return base

def add_caller_to_file(filepath):
    """Add _caller to all invokeLLM({ calls missing it in a file."""
    with open(filepath, 'r') as f:
        content = f.read()
    
    # Find all invokeLLM({ positions
    pattern = re.compile(r'invokeLLM\(\{')
    matches = list(pattern.finditer(content))
    
    if not matches:
        return 0
    
    fixes = 0
    offset = 0  # Track offset as we insert text
    
    for m in matches:
        pos = m.start() + offset
        # Check if _caller already exists within the call (next ~800 chars)
        snippet = content[pos:pos+800]
        if '_caller' in snippet.split('}')[0] if '}' in snippet else snippet:
            continue
        
        # Get context before the call (last 2000 chars) for function name detection
        context_before = content[max(0, pos-2000):pos]
        caller_name = derive_caller(filepath, context_before)
        
        # Insert _caller right after the opening {
        insert_pos = pos + len('invokeLLM({')
        # Check if there's a newline after {
        next_char = content[insert_pos:insert_pos+1]
        if next_char == '\n':
            # Find the indentation of the next line
            next_line_start = insert_pos + 1
            indent_match = re.match(r'(\s+)', content[next_line_start:])
            indent = indent_match.group(1) if indent_match else '    '
            insertion = f"\n{indent}_caller: \"{caller_name}\","
        else:
            insertion = f" _caller: \"{caller_name}\","
        
        content = content[:insert_pos] + insertion + content[insert_pos:]
        offset += len(insertion)
        fixes += 1
    
    if fixes > 0:
        with open(filepath, 'w') as f:
            f.write(content)
    
    return fixes

# Process all files
total_fixes = 0
for root, dirs, files in os.walk("server"):
    dirs[:] = [d for d in dirs if d != "node_modules" and d != "_core"]
    for f in files:
        if not f.endswith(".ts"):
            continue
        path = os.path.join(root, f)
        fixes = add_caller_to_file(path)
        if fixes > 0:
            print(f"  Fixed {fixes} calls in {path}")
            total_fixes += fixes

print(f"\nTotal: {total_fixes} _caller tags added across all files")
