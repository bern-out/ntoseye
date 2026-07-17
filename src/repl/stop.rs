use std::time::Duration;

use owo_colors::OwoColorize;

use crate::dbg_backend::{BugcheckInfo, DebugBackend, StopEvent};
use crate::error::{Error, Result};
use crate::gdb::{BreakpointManager, RegisterMap};
use crate::target::{ReloadReport, Target, ThreadInfo, kthread_state_name};
use crate::types::VirtAddr;
use crate::ui;
use crate::unwind::{format_symbol, resolve_thread_trace_context};

use crate::repl::*;

/// Returns whether new kernel modules appeared (their symbols were just loaded),
/// which the caller uses as a "module set changed" signal for backends without a
/// load event.
pub fn refresh_kernel_module_symbols_on_stop(debugger: &Target, caches: &ReplCaches) -> bool {
    let Ok(report) = debugger.refresh_kernel_module_symbols() else {
        return false;
    };
    if report.total == 0 || report.loaded == 0 {
        return false;
    }

    print_module_symbol_report(&report);
    caches.refresh_symbol_context(debugger);
    true
}

pub fn print_target_reload_report(report: &ReloadReport) {
    if let Some(startup) = &report.startup {
        println!(
            "{} kernel reloaded: {} -> {}, psmods {}",
            "target:".bright_black(),
            ui::addr(report.previous_base_address.0),
            ui::addr(startup.base_address.0),
            ui::addr_opt(startup.loaded_module_list)
        );
    } else {
        println!(
            "{} kernel reloaded: previous base {}",
            "target:".bright_black(),
            ui::addr(report.previous_base_address.0)
        );
    }

    if let Some(symbol_report) = &report.symbol_report {
        print_module_symbol_report(symbol_report);
    }
    if let Some(err) = &report.symbol_error {
        error!(
            "failed to refresh kernel module symbols after reload: {}",
            err
        );
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetReloadStatus {
    Unchanged,
    Reloaded { loaded_module_list_available: bool },
    PendingRediscovery { kernel_base_hint: Option<VirtAddr> },
}

impl TargetReloadStatus {
    pub fn target_reloaded(self) -> bool {
        matches!(self, Self::Reloaded { .. })
    }

    pub fn pending_rediscovery(self) -> bool {
        matches!(self, Self::PendingRediscovery { .. })
    }

    fn loaded_module_list_available(self) -> bool {
        match self {
            Self::Reloaded {
                loaded_module_list_available,
            } => loaded_module_list_available,
            Self::Unchanged | Self::PendingRediscovery { .. } => false,
        }
    }

    fn kernel_base_hint(self) -> Option<VirtAddr> {
        match self {
            Self::PendingRediscovery { kernel_base_hint } => kernel_base_hint,
            _ => None,
        }
    }
}

// In core; re-exported for the REPL.
pub use crate::session::reload_report_has_loaded_module_list;

pub fn update_reload_module_list_pending(pending: &mut bool, reload_status: TargetReloadStatus) {
    match reload_status {
        TargetReloadStatus::Reloaded {
            loaded_module_list_available,
        } => *pending = !loaded_module_list_available,
        TargetReloadStatus::PendingRediscovery { .. } => *pending = true,
        TargetReloadStatus::Unchanged => {}
    }
}

pub fn try_complete_pending_module_list_reload(
    client: &mut dyn DebugBackend,
    debugger: &mut Target,
    caches: &ReplCaches,
    pending: &mut bool,
) -> bool {
    if !*pending {
        return false;
    }

    let Ok(startup) = debugger.startup_message_data() else {
        return false;
    };
    if startup.loaded_module_list.is_zero() {
        return false;
    }

    println!(
        "{} module list available: {}",
        "target:".bright_black(),
        ui::addr(startup.loaded_module_list.0)
    );
    refresh_kernel_module_symbols_on_stop(debugger, caches);
    caches.refresh_symbol_context(debugger);
    if let Err(e) = caches.refresh_processes(debugger) {
        error!(
            "failed to refresh process cache after module-list recovery: {}",
            e
        );
    }
    caches.clear_threads();
    caches.refresh_drivers(debugger);
    caches.refresh_vcpus(client);
    caches.refresh_expression_context(debugger);
    client.note_target_rediscovery_complete();
    *pending = false;
    true
}

/// Detect whether `event` reflects a guest reboot and, if so, rebuild debugger
/// state for the new kernel image, marking `event.target_reloaded`.
pub fn apply_target_reload_if_needed(
    client: &mut dyn DebugBackend,
    debugger: &mut Target,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
    event: &mut StopEvent,
) -> TargetReloadStatus {
    if !stop_event_requires_target_reload(debugger, event) {
        return TargetReloadStatus::Unchanged;
    }
    event.target_reloaded = true;

    let dropped_breakpoints = breakpoints.list().len();
    // The reload action (drop breakpoints, resolve the hint, reload the guest,
    // note rediscovery status) is shared with the SDK/MCP in core; the REPL
    // layers its cache refresh + output on top.
    let TargetReloadOutcome {
        report,
        hint: kernel_base_hint,
    } = perform_target_reload(client, debugger, breakpoints, event.target_kernel_base_hint);
    *caches.breakpoints.write().unwrap() = Vec::new();

    match report {
        Ok(report) => {
            let loaded_module_list_available = reload_report_has_loaded_module_list(&report);
            print_target_reload_report(&report);
            caches.refresh_symbol_context(debugger);
            *caches.vcpus.write().unwrap() = client.thread_list().unwrap_or_default();
            if let Err(e) = caches.refresh_processes(debugger) {
                *caches.processes.write().unwrap() = Vec::new();
                error!("failed to refresh process cache after reload: {}", e);
            }
            caches.clear_threads();
            *caches.drivers.write().unwrap() =
                debugger.enumerate_driver_objects().unwrap_or_default();
            caches.refresh_expression_context(debugger);
            if dropped_breakpoints > 0 {
                println!(
                    "{} dropped {} stale breakpoint(s)",
                    "target:".bright_black(),
                    dropped_breakpoints
                );
            }
            TargetReloadStatus::Reloaded {
                loaded_module_list_available,
            }
        }
        Err(e) => {
            // Rediscovery state was already noted as pending by
            // `perform_target_reload`; here we only surface the reason.
            match e {
                Error::NtoskrnlNotFound => {
                    println!(
                        "{} reboot observed; Windows kernel is not discoverable yet",
                        "target:".bright_black()
                    );
                }
                other => {
                    error!("target reloaded, but guest rediscovery failed: {}", other);
                }
            }
            *caches.processes.write().unwrap() = Vec::new();
            *caches.vcpus.write().unwrap() = client.thread_list().unwrap_or_default();
            *caches.drivers.write().unwrap() = Vec::new();
            caches.refresh_expression_context(debugger);
            if dropped_breakpoints > 0 {
                println!(
                    "{} dropped {} stale breakpoint(s)",
                    "target:".bright_black(),
                    dropped_breakpoints
                );
            }
            TargetReloadStatus::PendingRediscovery { kernel_base_hint }
        }
    }
}

pub const REPL_STOP_POLL: Duration = Duration::from_millis(100);

pub const STATUS_BREAKPOINT: u32 = 0x8000_0003;

pub use crate::session::processor_index_from_backend_thread_id;

pub fn refresh_windows_thread_context_for_backend_thread(
    debugger: &mut Target,
    thread_id: &str,
) -> Option<ThreadInfo> {
    let thread = processor_index_from_backend_thread_id(thread_id).and_then(|processor| {
        debugger
            .current_windows_thread_for_processor(processor)
            .ok()
    });
    if let Some(thread) = thread.clone() {
        debugger.set_current_windows_thread_context(thread);
    } else {
        debugger.clear_current_windows_thread_context();
    }
    thread
}

/// One-line summary: `thread Idle  state Running  ethread <addr>  pid 0  tid 0`.
/// The leading `thread` label distinguishes it from the break line above,
/// which names the process context (via CR3), not the thread's owner.
fn format_windows_thread(thread: &ThreadInfo) -> String {
    let process = thread.process_name.as_deref().unwrap_or("unknown");
    let mut line = format!("{} {}", ui::muted("thread"), process);
    if let Some(state) = thread.state {
        line.push_str(&format!(
            "  {} {}",
            ui::muted("state"),
            kthread_state_name(state)
        ));
    }
    line.push_str(&format!(
        "  {} {}",
        ui::muted("ethread"),
        ui::addr(thread.ethread.0)
    ));
    if let Some(pid) = thread.pid {
        line.push_str(&format!("  {} {pid}", ui::muted("pid")));
    }
    if let Some(tid) = thread.tid {
        line.push_str(&format!("  {} {tid}", ui::muted("tid")));
    }
    line
}

/// The exception cause child for a BREAK banner, e.g. `exception 0x80000003
/// at fffff807c0c5a0d0`. `None` when the stop carried no exception code.
pub fn stop_exception_cause(
    exception_code: Option<u32>,
    program_counter: Option<u64>,
) -> Option<String> {
    let code = exception_code?;
    Some(match program_counter {
        Some(pc) => format!("{} {:#x} at {}", ui::muted("exception"), code, ui::addr(pc)),
        None => format!("{} {:#x}", ui::muted("exception"), code),
    })
}

// In core (the reload state machine owns them); re-exported for the REPL.
pub use crate::session::{
    TargetReloadOutcome, clear_trap_flag, perform_target_reload, stop_event_requires_target_reload,
    stop_is_assisted_refresh_breakin, stop_is_stray_single_step,
};

pub use crate::session::set_current_thread_from_stop;

/// Refresh the caches the stop output depends on (vcpus, kernel module symbols),
/// done before any stop notice prints so it reflects the current kernel image.
/// Returns whether the kernel module set changed (a driver/module loaded or
/// unloaded), so the caller can refresh module-dependent caches. Both signals are
/// consulted/cleared: the backend load event (KD) and the per-stop module-list
/// diff (any backend).
pub fn refresh_stop_caches_pre(
    client: &mut dyn DebugBackend,
    debugger: &Target,
    caches: &ReplCaches,
) -> bool {
    caches.refresh_vcpus(client);
    let symbols_changed = refresh_kernel_module_symbols_on_stop(debugger, caches);
    let event_changed = client.take_modules_changed();
    symbols_changed || event_changed
}

/// Refresh the guest-state completion caches after a stop. Both the async and
/// synchronous stop paths call this, so the set can't drift. Drivers are a
/// near-static but expensive cache, so they re-enumerate only when the module set
/// actually changed (`modules_changed`) rather than on every stop.
pub fn refresh_stop_caches_post(
    debugger: &Target,
    caches: &ReplCaches,
    target_reloaded: bool,
    modules_changed: bool,
) {
    // on reload the rediscovery path already refreshed processes
    if !target_reloaded && let Err(e) = caches.refresh_processes(debugger) {
        error!("failed to refresh process cache: {}", e);
    }
    if modules_changed {
        caches.refresh_drivers(debugger);
    }
    caches.refresh_expression_context(debugger);
}

/// A classified stop: the raw event plus the target-reload status derived from
/// it. The two are produced together (`apply_target_reload_if_needed` sets the
/// status while mutating the event) and consumed together by the async printer,
/// so they travel as one.
pub struct StopOutcome {
    pub event: StopEvent,
    pub reload_status: TargetReloadStatus,
}

pub fn print_async_stop_context(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    caches: &ReplCaches,
    current_thread: &mut String,
    outcome: StopOutcome,
) {
    print_stop_separator();
    let StopOutcome {
        event,
        reload_status,
    } = outcome;
    let target_reloaded = reload_status.target_reloaded();
    let reload_load_symbols_stop = is_target_reload_load_symbols_stop(&event, reload_status);
    set_current_thread_from_stop(client, &event, current_thread);
    let modules_changed = refresh_stop_caches_pre(client, debugger, caches);
    // The trailing blank pairs with the seam the bugcheck pane owns; other
    // stops carry their exception as a cause child on the BREAK banner.
    if event.is_bugcheck && !target_reloaded {
        print_bugcheck_summary(debugger, event.bugcheck.as_ref());
        println!();
    }
    refresh_stop_caches_post(debugger, caches, target_reloaded, modules_changed);
    if reload_load_symbols_stop {
        print_target_reload_notification_context(debugger, current_thread, &event, reload_status);
        return;
    }
    if event.is_bugcheck && !target_reloaded {
        print_break_context_for_bugcheck(
            client,
            register_map,
            debugger,
            breakpoints,
            current_thread,
            event.bugcheck.as_ref(),
        );
    } else {
        let cause = if target_reloaded {
            None
        } else {
            stop_exception_cause(event.exception_code, event.program_counter)
        };
        print_break_context_at(
            client,
            register_map,
            debugger,
            breakpoints,
            current_thread,
            None,
            cause,
        );
    }
}

pub fn is_target_reload_load_symbols_stop(
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) -> bool {
    reload_status.target_reloaded()
        && event.exception_code.is_none()
        && event.target_kernel_base_hint.is_some()
}

pub fn print_target_reload_notification_context(
    debugger: &Target,
    current_thread: &str,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) {
    let pending_status = TargetReloadStatus::PendingRediscovery {
        kernel_base_hint: event.target_kernel_base_hint,
    };
    println!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} early boot at {} ",
            ui::thread_id(current_thread),
            pending_reload_location(debugger, event, pending_status, None)
        ))
    );
    let message = if reload_status.loaded_module_list_available() {
        "kernel reloaded; context is limited, continue to resume boot"
    } else {
        "kernel reloaded; module list is not available yet, continue to retry full reload"
    };
    print_event_children(" ", &[ui::muted(message)]);
    println!();
}

pub fn rebase_kernel_symbol_for_pending_reload(
    debugger: &Target,
    pc: u64,
    kernel_base_hint: Option<VirtAddr>,
) -> Option<String> {
    let new_base = kernel_base_hint?;
    let rva = pc.checked_sub(new_base.0)?;
    let old_addr = debugger.guest.ntoskrnl.base_address.0.checked_add(rva)?;
    let (module, symbol, offset) = debugger
        .symbols
        .find_closest_symbol_for_address(debugger.guest.ntoskrnl.dtb(), VirtAddr(old_addr))?;
    if offset > 0x1000 {
        return None;
    }
    Some(if offset == 0 {
        format!("{module}!{symbol}")
    } else {
        format!("{module}!{symbol}+{offset:#x}")
    })
}

pub fn pending_reload_location(
    debugger: &Target,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
    register_kernel_base_hint: Option<VirtAddr>,
) -> String {
    let Some(pc) = event.program_counter else {
        return "unknown".bright_black().to_string();
    };
    let kernel_base_hint = reload_status
        .kernel_base_hint()
        .or(register_kernel_base_hint);
    rebase_kernel_symbol_for_pending_reload(debugger, pc, kernel_base_hint)
        .map(|symbol| ui::symbol(&symbol))
        .unwrap_or_else(|| ui::addr(pc))
}

pub fn pending_reload_register_kernel_base_hint(
    register_map: &RegisterMap,
    regs: &[u8],
    pc: u64,
) -> Option<VirtAddr> {
    let base = register_map.read_u64("r9", regs).ok()?;
    if !looks_like_kernel_pointer(base) {
        return None;
    }
    let rva = pc.checked_sub(base)?;
    (rva < CURRENT_KERNEL_RELOAD_WINDOW).then_some(VirtAddr(base))
}

pub fn print_pending_rediscovery_stop_context(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &Target,
    current_thread: &mut String,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) {
    print_stop_separator();
    set_current_thread_from_stop(client, event, current_thread);
    let regs = client.read_registers();
    let register_kernel_base_hint = match (&regs, event.program_counter) {
        (Ok(regs), Some(pc)) => pending_reload_register_kernel_base_hint(register_map, regs, pc),
        _ => None,
    };
    println!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} early boot at {} ",
            ui::thread_id(current_thread),
            pending_reload_location(debugger, event, reload_status, register_kernel_base_hint)
        ))
    );
    print_event_children(
        " ",
        &[ui::muted(
            "kernel is not discoverable yet; context is limited, continue to retry",
        )],
    );
    println!();

    match regs {
        Ok(regs) => print_registers(register_map, &regs, true),
        Err(e) => println!("{} {}", "registers unavailable:".bold(), e),
    }
    println!();
}

pub fn should_resume_assisted_refresh_stop(
    debugger: &Target,
    breakpoints: &BreakpointManager,
    event: &StopEvent,
    reload_status: TargetReloadStatus,
) -> bool {
    matches!(reload_status, TargetReloadStatus::Unchanged)
        && stop_is_assisted_refresh_breakin(debugger, breakpoints, event)
}

pub fn resume_assisted_refresh_stop(client: &mut dyn DebugBackend) -> Result<()> {
    client.continue_execution()
}

pub fn surface_pending_stop(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
    current_thread: &mut String,
    reload_module_list_pending: &mut bool,
) -> Result<bool> {
    match client.try_wait_for_stop(REPL_STOP_POLL)? {
        Some(mut event) => {
            let reload_status =
                apply_target_reload_if_needed(client, debugger, breakpoints, caches, &mut event);
            update_reload_module_list_pending(reload_module_list_pending, reload_status);
            if reload_status.pending_rediscovery() {
                print_pending_rediscovery_stop_context(
                    client,
                    register_map,
                    debugger,
                    current_thread,
                    &event,
                    reload_status,
                );
                return Ok(true);
            }
            caches.refresh_vcpus(client);
            let _ = try_complete_pending_module_list_reload(
                client,
                debugger,
                caches,
                reload_module_list_pending,
            );
            if !*reload_module_list_pending
                && should_resume_assisted_refresh_stop(debugger, breakpoints, &event, reload_status)
            {
                resume_assisted_refresh_stop(client)?;
                return Ok(true);
            }
            print_async_stop_context(
                client,
                register_map,
                debugger,
                breakpoints,
                caches,
                current_thread,
                StopOutcome {
                    event,
                    reload_status,
                },
            );
            Ok(true)
        }
        None => Ok(false),
    }
}

pub fn surface_interrupt_stop(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &mut BreakpointManager,
    caches: &ReplCaches,
    current_thread: &mut String,
    reload_module_list_pending: &mut bool,
) -> Result<()> {
    let mut event = client.interrupt()?;
    let reload_status =
        apply_target_reload_if_needed(client, debugger, breakpoints, caches, &mut event);
    update_reload_module_list_pending(reload_module_list_pending, reload_status);
    if reload_status.pending_rediscovery() {
        print_pending_rediscovery_stop_context(
            client,
            register_map,
            debugger,
            current_thread,
            &event,
            reload_status,
        );
        return Ok(());
    }
    caches.refresh_vcpus(client);
    let _ = try_complete_pending_module_list_reload(
        client,
        debugger,
        caches,
        reload_module_list_pending,
    );
    print_async_stop_context(
        client,
        register_map,
        debugger,
        breakpoints,
        caches,
        current_thread,
        StopOutcome {
            event,
            reload_status,
        },
    );
    Ok(())
}

// In core so the REPL and Python SDK share identical step semantics.
pub use crate::session::step_one_and_clear_tf;
pub use crate::session::step_over_current_breakpoint;

// RIP-rewind for threads parked past a breakpoint int3; in core, shared with
// `Session::continue_until_break`.
pub use crate::session::rewind_threads_off_breakpoints;

pub fn print_break_context(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
) {
    print_break_context_at(
        client,
        register_map,
        debugger,
        breakpoints,
        thread_id,
        None,
        None,
    );
}

pub fn print_break_context_for_bugcheck(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
    info: Option<&BugcheckInfo>,
) {
    print_break_context_at(
        client,
        register_map,
        debugger,
        breakpoints,
        thread_id,
        info.and_then(bugcheck_fault_ip),
        None,
    );
}

/// `cause` is an optional pre-styled tree child naming why execution stopped
/// (e.g. `breakpoint #3`), rendered first.
pub fn print_break_context_at(
    client: &mut dyn DebugBackend,
    register_map: &RegisterMap,
    debugger: &mut Target,
    breakpoints: &BreakpointManager,
    thread_id: &str,
    display_rip: Option<u64>,
    cause: Option<String>,
) {
    let _ = client.set_current_thread(thread_id);

    let regs = match client.read_registers() {
        Ok(r) => r,
        Err(e) => {
            debugger.registers = None;
            println!(
                "{}{}\n",
                ui::badge("BREAK"),
                ui::plate(&format!(
                    " {} (read_registers failed: {}) ",
                    ui::thread_id(thread_id),
                    e
                ))
            );
            return;
        }
    };
    debugger.registers = Some(register_map.to_hashmap(&regs));

    let cr3 = register_map.read_u64("cr3", &regs).unwrap_or(0);
    let rip = register_map.read_u64("rip", &regs).unwrap_or(0);
    let windows_thread = refresh_windows_thread_context_for_backend_thread(debugger, thread_id);
    let trace = resolve_thread_trace_context(debugger, cr3);
    let context_rip = display_rip.unwrap_or(rip);
    let symbol = format_symbol(debugger, &trace, context_rip);

    println!(
        "{}{}",
        ui::badge("BREAK"),
        ui::plate(&format!(
            " {} {} at {} ",
            ui::thread_id(thread_id),
            trace.description,
            ui::symbol(&symbol)
        ))
    );

    let mut children: Vec<String> = Vec::new();
    if let Some(cause) = cause {
        children.push(cause);
    }
    // Bugcheck stops park at the break inside KeBugCheck, not at the fault
    // site the banner names.
    if display_rip.is_some_and(|display_rip| display_rip != rip) {
        let stop_symbol = format_symbol(debugger, &trace, rip);
        children.push(format!(
            "{} {}",
            ui::muted("stopped at"),
            ui::symbol(&stop_symbol)
        ));
    }
    if let Some(thread) = windows_thread {
        children.push(format_windows_thread(&thread));
    }
    print_event_children(" ", &children);

    print_registers(register_map, &regs, true);
    print_disasm_context(debugger, breakpoints, &trace, context_rip);
    print_stacktrace(
        debugger,
        register_map,
        &regs,
        BREAK_STACKTRACE_PROBE_LIMIT,
        BREAK_STACKTRACE_DISPLAY_LIMIT,
        true,
    );
    println!();
}

#[cfg(test)]
mod tests {
    use super::processor_index_from_backend_thread_id;

    #[test]
    fn backend_thread_ids_parse_as_zero_based_processors() {
        assert_eq!(processor_index_from_backend_thread_id("p1.1"), Some(0));
        assert_eq!(processor_index_from_backend_thread_id("p1.a"), Some(9));
        assert_eq!(processor_index_from_backend_thread_id("p1.0"), None);
        assert_eq!(processor_index_from_backend_thread_id("bad"), None);
    }
}
