use owo_colors::OwoColorize;

use crate::backend::MemoryOps;
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::memory::AddressSpace;
use crate::target::Target;
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{
    FrameSource, ThreadTraceContext, build_stacktrace, format_symbol, preferred_code_dtb,
};

pub fn print_section(title: &str) {
    println!("\n{}", ui::label(title));
}

/// Begin a stop block: a blank line. The single seam marking every
/// stop-output entry point, in case a heavier delimiter is ever wanted.
pub fn print_stop_separator() {
    println!();
}

/// Print the detail lines attached to an event banner: muted `├─` for middle
/// children, `╰─` for the last. `indent` is 1 space below a badge banner,
/// 4 spaces for a nested level; it is never derived from the badge width.
///
/// Children may contain `\n` (see [`wrap_prose`]): continuation lines get a
/// `│` gutter while the branch continues, bare spaces after the last child.
pub fn print_event_children(indent: &str, children: &[String]) {
    for (idx, child) in children.iter().enumerate() {
        let last = idx + 1 == children.len();
        let glyph = if last { "╰─" } else { "├─" };
        let mut lines = child.lines();
        if let Some(first) = lines.next() {
            println!("{indent}{} {}", ui::muted(glyph), first);
        }
        for continuation in lines {
            if last {
                println!("{indent}   {continuation}");
            } else {
                println!("{indent}{}  {continuation}", ui::muted("│"));
            }
        }
    }
}

/// Wrap plain prose for display starting at terminal column `col`, capped at
/// 100 columns of prose. Returns a single line when stdout is not a terminal
/// (piped output wants one line per field) or the terminal is too narrow.
/// Wrap before styling; width math over ANSI escapes miscounts.
pub fn wrap_prose(text: &str, col: usize) -> Vec<String> {
    let Some((terminal_size::Width(w), _)) = terminal_size::terminal_size() else {
        return vec![text.to_string()];
    };
    let width = (w as usize).saturating_sub(col).min(100);
    if width < 20 {
        return vec![text.to_string()];
    }
    textwrap::wrap(text, width)
        .into_iter()
        .map(|line| line.into_owned())
        .collect()
}

pub fn format_rflags(flags: u64) -> String {
    const FLAGS: &[(u64, &str)] = &[
        (0, "CF"),
        (2, "PF"),
        (4, "AF"),
        (6, "ZF"),
        (7, "SF"),
        (8, "TF"),
        (9, "IF"),
        (10, "DF"),
        (11, "OF"),
        (14, "NT"),
        (16, "RF"),
        (17, "VM"),
        (18, "AC"),
        (19, "VIF"),
        (20, "VIP"),
        (21, "ID"),
    ];

    let mut names = FLAGS
        .iter()
        .filter_map(|(bit, name)| ((flags & (1u64 << bit)) != 0).then_some(*name))
        .collect::<Vec<_>>();

    let iopl = (flags >> 12) & 0x3;
    if iopl != 0 {
        names.push(match iopl {
            1 => "IOPL1",
            2 => "IOPL2",
            _ => "IOPL3",
        });
    }

    if names.is_empty() {
        String::new()
    } else {
        format!(" [{}]", names.join(" "))
    }
}

/// Print the general-purpose register grid. `embedded` is true inside the
/// break/status dump (`registers` section header, 2-space indent); standalone
/// `registers` passes false so it reads flush-left with no header, matching
/// `disasm`.
pub fn print_registers(register_map: &RegisterMap, regs: &[u8], embedded: bool) {
    let read_reg_value = |name: &str| register_map.read_u64(name, regs);
    let styled_value = |name: &str| -> String {
        match read_reg_value(name) {
            Ok(value) => ui::addr(value),
            Err(_) => ui::muted(&format!("{:<16}", "N/A")),
        }
    };
    let cell = |name: &str| {
        format!(
            "{} {}",
            ui::muted(&format!("{name:<3}")),
            styled_value(name)
        )
    };
    let rflags = read_reg_value("eflags").unwrap_or(0);

    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("registers");
    }
    for row in [
        ["rax", "rbx", "rcx"],
        ["rdx", "rsi", "rdi"],
        ["rsp", "rbp", "rip"],
        ["r8", "r9", "r10"],
        ["r11", "r12", "r13"],
    ] {
        println!(
            "{indent}{}   {}   {}",
            cell(row[0]),
            cell(row[1]),
            cell(row[2])
        );
    }
    println!(
        "{indent}{}   {}   {} {}{}",
        cell("r14"),
        cell("r15"),
        ui::muted("rfl"),
        styled_value("eflags"),
        format_rflags(rflags)
    );
}

// Decoding lives in core; the REPL owns the *rendering*
// (`format_disasm_line`/`render_rows` below).
pub use crate::disasm::{AsmToken, DisasmRow, decode_rows, disasm_formatter};

/// Width of the byte column for a listing: the longest hex string among the
/// rows about to be printed, so the asm column always aligns and never gets
/// pushed right by a long (up to 15-byte) instruction.
pub fn hex_column_width<'a>(hexes: impl Iterator<Item = &'a str>) -> usize {
    hexes.map(str::len).max().unwrap_or(0)
}

/// Render one disassembly line: yellow `>` cursor on the current
/// instruction, dim bytes, dim `;` comment with symbol. The single source of
/// truth for a disassembled instruction, shared by both call sites.
///
/// `hex_width` is the byte column width, computed per listing via
/// [`hex_column_width`] so the asm column stays aligned without overfilling.
pub fn format_disasm_line(
    ip: u64,
    hex: &str,
    tokens: &[AsmToken],
    comment: Option<&str>,
    marker: Option<bool>,
    hex_width: usize,
) -> String {
    // `marker` is None for a plain listing (no cursor column); Some(current) for
    // the break/status view, where the current instruction gets a yellow `>`
    let prefix = match marker {
        Some(true) => format!(" {} ", ">".yellow().bold()),
        Some(false) => "   ".to_string(),
        None => String::new(),
    };
    let bytes = format!("{hex:<hex_width$}").bright_black().to_string();
    let asm = ui::disasm_asm(tokens);
    let comment = comment
        .map(|sym| format!(" {} {}", ui::muted(";"), ui::symbol(sym)))
        .unwrap_or_default();
    format!("{}{}  {}  {}{}", prefix, ui::addr(ip), bytes, asm, comment)
}

/// Print decoded rows in the house style, sizing the byte column once across
/// all rows so the asm column aligns. `marker_for` gives each row its cursor
/// state: `None` for a plain listing (`disasm`), `Some(current)` for the
/// break/status view where the current instruction gets a `>`.
pub fn render_rows(rows: &[DisasmRow], marker_for: impl Fn(u64) -> Option<bool>) {
    let width = hex_column_width(rows.iter().map(|row| row.hex.as_str()));
    for row in rows {
        println!(
            "{}",
            format_disasm_line(
                row.ip,
                &row.hex,
                &row.tokens,
                row.comment.as_deref(),
                marker_for(row.ip),
                width,
            )
        );
    }
}

pub fn print_disasm_context(
    debugger: &Target,
    breakpoints: &BreakpointManager,
    trace: &ThreadTraceContext,
    rip: u64,
) {
    print_section("disasm");

    let pre_bytes: u64 = 64;
    let post_bytes: u64 = 64;
    let start_addr = rip.saturating_sub(pre_bytes);
    let total_len = (pre_bytes + post_bytes) as usize;
    let active_memory = AddressSpace::new(&debugger.phys, trace.active_dtb);
    let code_dtb = preferred_code_dtb(trace, rip);
    let code_memory = AddressSpace::new(&debugger.phys, code_dtb);

    let mut bytes = vec![0u8; total_len];
    if active_memory
        .read_bytes(VirtAddr(start_addr), &mut bytes)
        .is_err()
        && (code_dtb == trace.active_dtb
            || code_memory
                .read_bytes(VirtAddr(start_addr), &mut bytes)
                .is_err())
    {
        println!("{}", "  (could not read memory at RIP)".bright_black());
        return;
    }
    breakpoints.mask_breakpoint_bytes(VirtAddr(start_addr), &mut bytes, trace.active_dtb);

    let resolve = |target: u64| format_symbol(debugger, trace, target);
    let mut formatter = disasm_formatter();
    let instructions = decode_rows(&bytes, start_addr, None, &mut formatter, resolve);

    // find which instruction corresponds to RIP
    let rip_idx = instructions.iter().position(|row| row.ip == rip);

    if let Some(idx) = rip_idx {
        let context_before = 3;
        let context_after = 3;
        let start = idx.saturating_sub(context_before);
        let end = (idx + context_after + 1).min(instructions.len());
        render_rows(&instructions[start..end], |ip| Some(ip == rip));
    } else {
        let mut forward_buf = vec![0u8; post_bytes as usize];
        if active_memory
            .read_bytes(VirtAddr(rip), &mut forward_buf)
            .is_ok()
            || (code_dtb != trace.active_dtb
                && code_memory
                    .read_bytes(VirtAddr(rip), &mut forward_buf)
                    .is_ok())
        {
            breakpoints.mask_breakpoint_bytes(VirtAddr(rip), &mut forward_buf, trace.active_dtb);
            let rows = decode_rows(&forward_buf, rip, Some(7), &mut formatter, resolve);
            render_rows(&rows, |ip| Some(ip == rip));
        } else {
            println!("{}", "  (could not read memory at RIP)".bright_black());
        }
    }
}

/// Print the stack frames. `embedded` is true inside the break/status dump:
/// bold `stack` header, 2-space indent, and no child-SP column (the return
/// address is the token you act on). Standalone `k` passes false:
/// flush-left, full child-SP + retaddr columns.
pub fn print_stacktrace(
    debugger: &Target,
    register_map: &RegisterMap,
    regs: &[u8],
    build_limit: usize,
    display_limit: usize,
    embedded: bool,
) {
    let indent = if embedded { "  " } else { "" };
    if embedded {
        print_section("stack");
    }

    let stacktrace = build_stacktrace(debugger, register_map, regs, build_limit);
    let shown = stacktrace.frames.len().min(display_limit);

    for (num, frame) in stacktrace.frames.iter().take(shown).enumerate() {
        let suffix = if frame.source == FrameSource::Scan {
            format!(" {}", "[scan]".bright_black())
        } else {
            String::new()
        };
        let symbol = if frame.symbol.starts_with("0x") {
            String::new()
        } else {
            format!("  {}{}", ui::symbol(&frame.symbol), suffix)
        };
        if embedded {
            println!(
                "{indent}{} {}{}",
                ui::muted(&format!("#{num:<2}")),
                ui::addr(frame.ip),
                symbol
            );
        } else {
            println!(
                "{indent}{} {}  {}{}",
                ui::muted(&format!("#{num:<2}")),
                ui::addr(frame.sp),
                ui::addr(frame.ip),
                symbol
            );
        }
    }

    let hidden = stacktrace.frames.len().saturating_sub(display_limit) + stacktrace.truncated;
    if hidden > 0 {
        println!(
            "{indent}{}",
            format!("... {} more frames", hidden).bright_black()
        );
    }
}
