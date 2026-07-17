use owo_colors::OwoColorize;

use crate::bugchecks::{
    BUGCHECK_DATA_SLOTS, BugcheckFault, CurrentBugcheckFailure, CurrentBugcheckResolution,
    resolve_current_bugcheck,
};
use crate::dbg_backend::BugcheckInfo;
use crate::target::Target;
use crate::ui;

// Bugcheck *analysis* (descriptor lookup, fault site, KiBugCheckData decode)
// lives in core, shared with the SDK/MCP; the REPL adds presentation.
pub use crate::bugchecks::{
    BugcheckAnalysis, BugcheckTrapFrame, CURRENT_KERNEL_RELOAD_WINDOW, analyze_bugcheck,
    bugcheck_fault_ip, bugcheck_site, current_bugcheck, looks_like_kernel_pointer,
    plausible_bugcheck_code,
};
pub use crate::trapframe::KtrapFrame;

use super::disasm::format_rflags;

fn print_unresolved_bugcheck_data(failure: &CurrentBugcheckFailure) {
    fn print_slots(label: &str, data: &[u64; BUGCHECK_DATA_SLOTS]) {
        println!(
            "{} {label} = [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
            "bugcheck:".bold(),
            data[0],
            data[1],
            data[2],
            data[3],
            data[4]
        );
    }

    println!(
        "{} unable to resolve nt!KiBugCheckData at {:#x}: {}",
        "bugcheck:".bold(),
        failure.address,
        failure.reason
    );
    if let Some(data) = &failure.slots {
        print_slots("raw slots", data);
    }
    if let Some(data) = &failure.dereferenced_slots {
        print_slots("dereferenced slots", data);
    }
}

pub fn format_arg_value(value: u64) -> String {
    ui::addr(value)
}

/// Render a [`BugcheckInfo`] using the shared core analysis
/// ([`analyze_bugcheck`]), so the REPL and the SDK/MCP never disagree on the
/// name/arguments/responsible driver of a bugcheck.
pub fn print_bugcheck_info(debugger: &Target, info: &BugcheckInfo) {
    print_bugcheck_analysis(&analyze_bugcheck(debugger, info));
}

fn format_bugcheck_fault(fault: &BugcheckFault) -> String {
    let address = ui::addr(fault.ip);
    if fault.symbol.starts_with("0x") {
        address
    } else {
        format!("{address}  {}", ui::symbol(&fault.symbol))
    }
}

/// Render an already-decoded [`BugcheckAnalysis`]: banner, responsible module,
/// fault site, args (with their documented meanings), data provenance, and any
/// trap frames the parameters point at.
pub fn print_bugcheck_analysis(analysis: &BugcheckAnalysis) {
    println!();
    println!(
        "{}",
        format!("{} ({:#010x})", analysis.name, analysis.code)
            .red()
            .bold()
    );
    if let Some(driver) = &analysis.driver {
        println!("  module: {}", driver.green());
    }
    if let Some(fault) = &analysis.fault {
        println!("  fault: {}", format_bugcheck_fault(fault));
    }
    if let Some(description) = &analysis.description {
        println!("  reason: {description}");
    }
    println!();
    println!("{}", "args".bold());
    for (idx, arg) in analysis.args.iter().enumerate() {
        if arg.description.is_empty() {
            println!("  arg{} {}", idx + 1, format_arg_value(arg.value));
        } else {
            println!(
                "  arg{} {}  {}",
                idx + 1,
                format_arg_value(arg.value),
                arg.description
            );
        }
    }
    if let Some(source) = &analysis.source {
        println!("  source: {}", source.bright_black());
    }
    for trap_frame in &analysis.trap_frames {
        println!();
        print_bugcheck_trap_frame(trap_frame);
    }
}

/// Render a trap frame named by a bugcheck parameter: always the address,
/// plus either the decoded contents or the precise decode failure.
pub fn print_bugcheck_trap_frame(trap_frame: &BugcheckTrapFrame) {
    match &trap_frame.frame {
        Some(frame) => print_ktrap_frame(frame, trap_frame.rip_symbol.as_deref()),
        None => println!(
            "{} @ {} (unable to decode: {})",
            "trap frame".bold(),
            ui::addr(trap_frame.address),
            trap_frame.error.as_deref().unwrap_or("unknown error")
        ),
    }
}

/// Render a decoded [`KtrapFrame`] in the register-grid house style
/// ([`super::disasm::print_registers`]). r12-r15 are absent by design: the
/// kernel saves them in the exception frame, not the trap frame.
pub fn print_ktrap_frame(frame: &KtrapFrame, rip_symbol: Option<&str>) {
    println!("{} @ {}", "trap frame".bold(), ui::addr(frame.address));
    println!(
        "  rax {}   rbx {}   rcx {}",
        ui::addr(frame.rax),
        ui::addr(frame.rbx),
        ui::addr(frame.rcx)
    );
    println!(
        "  rdx {}   rsi {}   rdi {}",
        ui::addr(frame.rdx),
        ui::addr(frame.rsi),
        ui::addr(frame.rdi)
    );
    println!(
        "  rsp {}   rbp {}   rip {}",
        ui::addr(frame.rsp),
        ui::addr(frame.rbp),
        ui::addr(frame.rip)
    );
    println!(
        "  r8  {}   r9  {}   r10 {}",
        ui::addr(frame.r8),
        ui::addr(frame.r9),
        ui::addr(frame.r10)
    );
    println!(
        "  r11 {}   rfl {}{}",
        ui::addr(frame.r11),
        ui::addr(frame.eflags as u64),
        format_rflags(frame.eflags as u64)
    );
    println!(
        "  cs  {}  ss  {}  error code {:#x}  irql {}  previous mode {}",
        format!("{:04x}", frame.cs).bright_white().bold(),
        format!("{:04x}", frame.ss).bright_white().bold(),
        frame.error_code,
        frame.previous_irql,
        if frame.previous_mode == 0 {
            "kernel"
        } else {
            "user"
        }
    );
    if let Some(symbol) = rip_symbol {
        println!("  rip => {}", ui::symbol(symbol));
    }
}

pub fn print_bugcheck_summary(debugger: &Target, info: Option<&BugcheckInfo>) {
    if let Some(info) = info {
        print_bugcheck_info(debugger, info);
        return;
    }

    // KD normally sends the bugcheck code and parameters as debug I/O before
    // the stop packet. If that stream is missing, the same values can be read
    // from nt!KiBugCheckData while the guest is frozen mid-bugcheck.
    print_bugcheck_summary_from_memory(debugger);
}

/// Read and display `nt!KiBugCheckData` (BugCheckCode + 4 parameters). The
/// guest is frozen mid-bugcheck, so this is readable over `/dev/kvm`.
pub fn print_bugcheck_summary_from_memory(debugger: &Target) {
    match resolve_current_bugcheck(debugger) {
        CurrentBugcheckResolution::Resolved(analysis) => print_bugcheck_analysis(&analysis),
        CurrentBugcheckResolution::SymbolUnavailable => println!(
            "{} guest is bugchecking (symbol nt!KiBugCheckData unavailable)",
            "bugcheck:".bold()
        ),
        CurrentBugcheckResolution::Unresolved(failure) => {
            print_unresolved_bugcheck_data(&failure);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_resolved_bugcheck_fault_site() {
        let line = format_bugcheck_fault(&BugcheckFault {
            ip: 0xffff_f805_f339_1730,
            symbol: "myfault+0x1730".to_string(),
            driver: Some("myfault.sys".to_string()),
        });

        assert!(line.contains("fffff805f3391730"));
        assert!(line.contains("myfault"));
        assert!(line.contains("+0x1730"));
    }

    #[test]
    fn raw_bugcheck_fault_site_is_not_repeated() {
        let line = format_bugcheck_fault(&BugcheckFault {
            ip: 0xffff_f805_f339_1730,
            symbol: "0xfffff805f3391730".to_string(),
            driver: None,
        });

        assert_eq!(line.matches("fffff805f3391730").count(), 1);
    }
}
