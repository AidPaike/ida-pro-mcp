---
name: idapython
description: IDA Pro Python scripting for reverse engineering. Use when writing IDAPython scripts, analyzing binaries, working with IDA's API for disassembly, decompilation (Hex-Rays), type systems, cross-references, functions, segments, or any IDA database manipulation. Covers ida_* modules (50+), idautils iterators, and common patterns.
---

# IDAPython

Use modern `ida_*` modules. Avoid legacy `idc` module.

## Module Router

| Task | Module | Key Items |
|------|--------|-----------|
| Bytes/memory | `ida_bytes` | `get_bytes`, `patch_bytes`, `get_flags`, `create_*` |
| Functions | `ida_funcs` | `func_t`, `get_func`, `add_func`, `get_func_name` |
| Names | `ida_name` | `set_name`, `get_name`, `demangle_name` |
| Types | `ida_typeinf` | `tinfo_t`, `apply_tinfo`, `parse_decl` |
| Decompiler | `ida_hexrays` | `decompile`, `cfunc_t`, `lvar_t`, ctree visitor |
| Segments | `ida_segment` | `segment_t`, `getseg`, `add_segm` |
| Xrefs | `ida_xref` | `xrefblk_t`, `add_cref`, `add_dref` |
| Instructions | `ida_ua` | `insn_t`, `op_t`, `decode_insn` |
| Stack frames | `ida_frame` | `get_frame`, `define_stkvar` |
| Iteration | `idautils` | `Functions()`, `Heads()`, `XrefsTo()`, `Strings()` |
| UI/dialogs | `ida_kernwin` | `msg`, `ask_*`, `jumpto`, `Choose` |
| Database info | `ida_ida` | `inf_get_*`, `inf_is_64bit()` |
| Analysis | `ida_auto` | `auto_wait`, `plan_and_wait` |
| Flow graphs | `ida_gdl` | `FlowChart`, `BasicBlock` |
| Register tracking | `ida_regfinder` | `find_reg_value`, `reg_value_info_t` |

## Core Patterns

## MCP Dynamic Debugging

When debugger tools are available through the `dbg` MCP extension, prefer using
them to drive a live IDA debug session instead of only writing IDAPython scripts.
The event-loop debugger tools are MCP polling calls built around IDA debugger
actions and `wait_for_next_event`; do not install debugger hooks or rely on an
out-of-band controller for dynamic execution.

Recommended loop for agent-driven debugging:

1. Call `dbg_diagnose()` to confirm the selected debugger, process options, and
   remote debugger reachability.
2. Start or attach with `dbg_start_process_until_event(...)`,
   `dbg_start_current_file_until_event(...)`, or
   `dbg_attach_process_until_event(pid)`.
3. Use `dbg_get_snapshot()` after every stop to inspect IP, nearby disassembly,
   registers, stack trace, and active breakpoints.
4. Use `dbg_add_temp_bp_and_continue(addr)` or
   `dbg_continue_until_event(timeout_ms)` to drive execution to the next
   relevant state.
5. Use `dbg_read`, `dbg_write`, and `dbg_read_around` for live process memory.

For interactive CLI targets, use `dbg_pty_start`, `dbg_pty_send`, and
`dbg_pty_read` to capture stdin/stdout/stderr, then attach IDA to the returned
PID when instruction-level debugging is needed.

Use IDAPython snippets for analysis helpers, type fixes, and batch edits. Use
MCP debugger tools for live execution, waits, breakpoints, and runtime state.

### Iterate functions
```python
for ea in idautils.Functions():
    name = ida_funcs.get_func_name(ea)
    func = ida_funcs.get_func(ea)
```

### Iterate instructions in function
```python
for head in idautils.FuncItems(func_ea):
    insn = ida_ua.insn_t()
    if ida_ua.decode_insn(insn, head):
        print(f"{head:#x}: {insn.itype}")
```

### Cross-references
```python
for xref in idautils.XrefsTo(ea):
    print(f"{xref.frm:#x} -> {xref.to:#x} type={xref.type}")
```

### Read/write bytes
```python
data = ida_bytes.get_bytes(ea, size)
ida_bytes.patch_bytes(ea, b"\x90\x90")
```

### Names
```python
name = ida_name.get_name(ea)
ida_name.set_name(ea, "new_name", ida_name.SN_NOCHECK)
```

### Decompile function
```python
cfunc = ida_hexrays.decompile(ea)
if cfunc:
    print(cfunc)  # pseudocode
    for lvar in cfunc.lvars:
        print(f"{lvar.name}: {lvar.type()}")
```

### Walk ctree (decompiled AST)
```python
class MyVisitor(ida_hexrays.ctree_visitor_t):
    def visit_expr(self, e):
        if e.op == ida_hexrays.cot_call:
            print(f"Call at {e.ea:#x}")
        return 0

cfunc = ida_hexrays.decompile(ea)
MyVisitor().apply_to(cfunc.body, None)
```

### Apply type
```python
tif = ida_typeinf.tinfo_t()
if ida_typeinf.parse_decl(tif, None, "int (*)(char *, int)", 0):
    ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE)
```

### Create structure
```python
udt = ida_typeinf.udt_type_data_t()
m = ida_typeinf.udm_t()
m.name = "field1"
m.type = ida_typeinf.tinfo_t(ida_typeinf.BTF_INT32)
m.offset = 0
m.size = 4
udt.push_back(m)
tif = ida_typeinf.tinfo_t()
tif.create_udt(udt, ida_typeinf.BTF_STRUCT)
tif.set_named_type(ida_typeinf.get_idati(), "MyStruct")
```

### Strings list
```python
for s in idautils.Strings():
    print(f"{s.ea:#x}: {str(s)}")
```

### Wait for analysis
```python
ida_auto.auto_wait()  # Block until autoanalysis completes
```

## Key Constants

| Constant | Value/Use |
|----------|-----------|
| `BADADDR` | Invalid address sentinel |
| `ida_name.SN_NOCHECK` | Skip name validation |
| `ida_typeinf.TINFO_DEFINITE` | Force type application |
| `o_reg`, `o_mem`, `o_imm`, `o_displ`, `o_near` | Operand types |
| `dt_byte`, `dt_word`, `dt_dword`, `dt_qword` | Data types |
| `fl_CF`, `fl_CN`, `fl_JF`, `fl_JN`, `fl_F` | Code xref types |
| `dr_R`, `dr_W`, `dr_O` | Data xref types |

## Critical Rules

1. **NEVER convert hex/decimal manually** - use `int_convert` MCP tool
2. **Wait for analysis**: Call `ida_auto.auto_wait()` before reading results
3. **Thread safety**: IDA SDK calls must run on main thread (use `@idasync`)
4. **64-bit addresses**: Always assume `ea_t` can be 64-bit
5. **Live debugging**: Prefer MCP `dbg_*_until_event` and `dbg_pty_*` tools for
   dynamic execution instead of generating scripts that cannot observe runtime
   state.

## Anti-Patterns

| Avoid | Do Instead |
|-------|------------|
| `idc.*` functions | Use `ida_*` modules |
| Hardcoded addresses | Use names, patterns, or xrefs |
| Manual hex conversion | Use `int_convert` tool |
| Blocking main thread | Use `execute_sync()` for long ops |
| Guessing at types | Derive from disassembly/decompilation |

## Detailed API Reference

For comprehensive documentation on any module, read `docs/<module>.md`:
- **High-use**: `ida_bytes`, `ida_funcs`, `ida_hexrays`, `ida_typeinf`, `ida_name`, `idautils`
- **Medium-use**: `ida_segment`, `ida_xref`, `ida_ua`, `ida_frame`, `ida_kernwin`
- **Specialized**: `ida_dbg` (debugger), `ida_nalt` (netnode storage), `ida_regfinder` (register tracking)

Full RST sources from hex-rays.com available at `docs/<module>.rst`.
