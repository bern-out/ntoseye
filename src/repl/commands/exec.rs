use std::sync::atomic::Ordering;

use owo_colors::OwoColorize;

use crate::error::Result;
use crate::gdb::breakpoints::Breakpoint;
use crate::session::{
    BreakpointStopAction, StepKind, WatchpointStopAction, resolve_watchpoint_stop,
};
use crate::types::VirtAddr;
use crate::ui;

use crate::repl::*;

repl_command! {
    continue_vm();
    names: ["continue", "g"],
    usage: "continue",
    summary: "Resume VM execution.",
}

repl_command! {
    interrupt_running_vm();
    names: ["break"],
    usage: "break",
    summary: "Break/pause VM execution.",
    run_state: Running,
}

repl_command! {
    single_step();
    names: ["si", "t"],
    usage: "si",
    summary: "Single step (step into).",
    run_state: Halted,
}

repl_command! {
    cmd_p();
    names: ["p", "ni"],
    usage: "p or ni",
    summary: "Step over the current instruction.",
    run_state: Halted,
}

repl_command! {
    cmd_gu();
    names: ["gu", "finish"],
    usage: "gu or finish",
    summary: "Run until the current function returns.",
    run_state: Halted,
}

impl ReplState<'_> {
    pub fn interrupt_running_vm(&mut self) -> Result<()> {
        match surface_pending_stop(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &mut self.ctx.breakpoints,
            &self.caches,
            &mut self.ctx.current_thread,
            &mut self.ctx.reload_module_list_pending,
        ) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => {
                error!("error checking running VM: {:?}", e);
                return Ok(());
            }
        }

        if let Err(e) = surface_interrupt_stop(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &mut self.ctx.breakpoints,
            &self.caches,
            &mut self.ctx.current_thread,
            &mut self.ctx.reload_module_list_pending,
        ) {
            error!("failed to interrupt: {:?}", e);
        }

        Ok(())
    }

    fn continue_vm(&mut self) -> Result<()> {
        if self.ctx.backend.is_running() {
            match surface_pending_stop(
                &mut *self.ctx.backend,
                &self.ctx.register_map,
                &mut self.ctx.target,
                &mut self.ctx.breakpoints,
                &self.caches,
                &mut self.ctx.current_thread,
                &mut self.ctx.reload_module_list_pending,
            ) {
                Ok(true) => {}
                Ok(false) => error!("VM is running"),
                Err(e) => error!("error checking running VM: {:?}", e),
            }
            return Ok(());
        }

        // Step past a breakpoint at RIP, re-arm breakpoints, continue, and drop
        // stale inspection caches; the canonical resume prologue lives in core.
        if let Err(e) = self.ctx.resume() {
            error!("failed to continue: {:?}", e);
            return Ok(());
        }

        println!(
            "{}",
            "VM running, waiting for stop (Ctrl+C to pause)...".bright_black()
        );

        INTERRUPT_REQUESTED.store(false, Ordering::SeqCst);

        loop {
            let interrupt_requested = INTERRUPT_REQUESTED.swap(false, Ordering::SeqCst);
            let stop_result = if interrupt_requested {
                println!();
                match self.ctx.backend.try_wait_for_stop(REPL_STOP_POLL) {
                    Ok(Some(event)) => Ok(Some(event)),
                    Ok(None) => self.ctx.backend.interrupt().map(Some),
                    Err(e) => Err(e),
                }
            } else {
                self.ctx.backend.try_wait_for_stop(REPL_STOP_POLL)
            };

            match stop_result {
                Ok(Some(mut event)) => {
                    let reload_status = apply_target_reload_if_needed(
                        &mut *self.ctx.backend,
                        &mut self.ctx.target,
                        &mut self.ctx.breakpoints,
                        &self.caches,
                        &mut event,
                    );
                    update_reload_module_list_pending(
                        &mut self.ctx.reload_module_list_pending,
                        reload_status,
                    );
                    if reload_status.pending_rediscovery() {
                        print_pending_rediscovery_stop_context(
                            &mut *self.ctx.backend,
                            &self.ctx.register_map,
                            &self.ctx.target,
                            &mut self.ctx.current_thread,
                            &event,
                            reload_status,
                        );
                        break;
                    }
                    let _ = try_complete_pending_module_list_reload(
                        &mut *self.ctx.backend,
                        &mut self.ctx.target,
                        &self.caches,
                        &mut self.ctx.reload_module_list_pending,
                    );
                    if !interrupt_requested
                        && !self.ctx.reload_module_list_pending
                        && should_resume_assisted_refresh_stop(
                            &self.ctx.target,
                            &self.ctx.breakpoints,
                            &event,
                            reload_status,
                        )
                    {
                        if let Err(e) = resume_assisted_refresh_stop(&mut *self.ctx.backend) {
                            error!("failed to resume after assisted refresh break: {:?}", e);
                            break;
                        }
                        continue;
                    }
                    // Claim watchpoint stops before the stray-single-step
                    // absorber. Core owns backend acknowledgement, context
                    // refresh, condition evaluation, and false-hit resume.
                    let watchpoint_action = match resolve_watchpoint_stop(
                        &mut *self.ctx.backend,
                        &self.ctx.register_map,
                        &self.ctx.breakpoints,
                        &mut self.ctx.target,
                        &mut self.ctx.current_thread,
                        &event,
                    ) {
                        Ok(action) => action,
                        Err(e) => {
                            error!("failed to handle watchpoint hit: {e}");
                            break;
                        }
                    };
                    match watchpoint_action {
                        WatchpointStopAction::Hit {
                            breakpoint: bp,
                            condition_error,
                        } => {
                            self.caches.refresh_symbol_context(&self.ctx.target);
                            refresh_windows_thread_context_for_backend_thread(
                                &mut self.ctx.target,
                                &self.ctx.current_thread,
                            );
                            if let Some(error) = condition_error {
                                error!("watchpoint condition failed: {error}");
                            }
                            self.surface_hardware_breakpoint_hit(&bp);
                            break;
                        }
                        WatchpointStopAction::Resumed => continue,
                        WatchpointStopAction::NotBreakpoint => {}
                    }
                    // A stray single-step (STATUS_SINGLE_STEP, not at a user
                    // breakpoint) is a debugger artifact from a managed step-over
                    // on SMP KD, not a stop to surface; clear TF on its processor
                    // and resume. Shared classification with continue_until_break.
                    if stop_is_stray_single_step(&event, &self.ctx.breakpoints) {
                        set_current_thread_from_stop(
                            &mut *self.ctx.backend,
                            &event,
                            &mut self.ctx.current_thread,
                        );
                        let _ = clear_trap_flag(&mut *self.ctx.backend, &self.ctx.register_map);
                        if let Err(e) = self.ctx.backend.continue_execution() {
                            error!("failed to resume after stray single-step: {:?}", e);
                            break;
                        }
                        continue;
                    }
                    let target_reloaded = reload_status.target_reloaded();
                    let reload_load_symbols_stop =
                        is_target_reload_load_symbols_stop(&event, reload_status);
                    let is_bugcheck = event.is_bugcheck && !target_reloaded;
                    set_current_thread_from_stop(
                        &mut *self.ctx.backend,
                        &event,
                        &mut self.ctx.current_thread,
                    );
                    let modules_changed = refresh_stop_caches_pre(
                        &mut *self.ctx.backend,
                        &self.ctx.target,
                        &self.caches,
                    );
                    if is_bugcheck {
                        print_bugcheck_summary(&self.ctx.target, event.bugcheck.as_ref());
                        println!();
                    }
                    let stop_exception_code = event.exception_code;
                    let stop_pc = event.program_counter;
                    let early_non_breakpoint_stop = !target_reloaded
                        && !is_bugcheck
                        && stop_exception_code.zip(stop_pc).is_some_and(|(_, pc)| {
                            self.ctx.breakpoints.breakpoint_id_at_address(pc).is_none()
                        });
                    if early_non_breakpoint_stop {
                        print_stop_notice_parts(stop_exception_code, stop_pc);
                        println!();
                    }

                    refresh_stop_caches_post(
                        &self.ctx.target,
                        &self.caches,
                        target_reloaded,
                        modules_changed,
                    );

                    if self.ctx.breakpoints.has_enabled_breakpoints() && !is_bugcheck {
                        // Done before reading the current thread's regs so
                        // the BP-hit check below sees the post-rewind RIP
                        rewind_threads_off_breakpoints(
                            &mut *self.ctx.backend,
                            &self.ctx.register_map,
                            &self.ctx.breakpoints,
                            &self.ctx.current_thread,
                        );
                    }

                    let hit_result =
                        if early_non_breakpoint_stop || is_bugcheck || reload_load_symbols_stop {
                            BreakpointStopAction::NotBreakpoint
                        } else {
                            let regs = match self.ctx.backend.read_registers() {
                                Ok(r) => r,
                                Err(e) => {
                                    error!("failed to read registers: {:?}", e);
                                    break;
                                }
                            };

                            self.ctx.target.registers =
                                Some(self.ctx.register_map.to_hashmap(&regs));
                            let rip = self.ctx.register_map.read_u64("rip", &regs).unwrap_or(0);
                            let cr3 = self.ctx.register_map.read_u64("cr3", &regs).unwrap_or(0);
                            if cr3 != 0 {
                                self.ctx.target.set_context_dtb_override(cr3);
                                self.caches.refresh_symbol_context(&self.ctx.target);
                            }
                            refresh_windows_thread_context_for_backend_thread(
                                &mut self.ctx.target,
                                &self.ctx.current_thread,
                            );

                            // Shared core resolver so the REPL and `continue_until_break`
                            // can't drift on breakpoint-hit disposition; absorbed cases
                            // (Resumed) step over and resume internally, so we keep waiting.
                            match self.ctx.resolve_breakpoint_stop(rip, cr3) {
                                Ok(BreakpointStopAction::Resumed) => continue,
                                Ok(action) => action,
                                Err(e) => {
                                    error!("failed to handle breakpoint stop: {:?}", e);
                                    break;
                                }
                            }
                        };

                    match hit_result {
                        BreakpointStopAction::Hit {
                            id,
                            symbol,
                            temporary,
                            condition_error,
                            ..
                        } => {
                            if let Some(error) = condition_error {
                                error!("breakpoint condition failed: {error}");
                            }
                            println!();
                            if !temporary {
                                println!(
                                    "{} {} {}",
                                    ui::label("breakpoint:"),
                                    ui::bp_id(id),
                                    symbol
                                        .as_ref()
                                        .map(|s| format!("({})", ui::symbol(s)))
                                        .unwrap_or_default()
                                );
                            }
                            print_break_context(
                                &mut *self.ctx.backend,
                                &self.ctx.register_map,
                                &mut self.ctx.target,
                                &self.ctx.breakpoints,
                                &self.ctx.current_thread,
                            );

                            break;
                        }
                        // Absorbed inline in the resolver above; defensively keep
                        // waiting if one ever reaches here.
                        BreakpointStopAction::Resumed => continue,
                        BreakpointStopAction::NotBreakpoint => {
                            if !target_reloaded && !early_non_breakpoint_stop && !is_bugcheck {
                                print_stop_notice_parts(stop_exception_code, stop_pc);
                                println!();
                            }
                            if reload_load_symbols_stop {
                                print_target_reload_notification_context(
                                    &self.ctx.target,
                                    &self.ctx.current_thread,
                                    &event,
                                    reload_status,
                                );
                            } else if is_bugcheck {
                                print_break_context_for_bugcheck(
                                    &mut *self.ctx.backend,
                                    &self.ctx.register_map,
                                    &mut self.ctx.target,
                                    &self.ctx.breakpoints,
                                    &self.ctx.current_thread,
                                    event.bugcheck.as_ref(),
                                );
                            } else {
                                print_break_context(
                                    &mut *self.ctx.backend,
                                    &self.ctx.register_map,
                                    &mut self.ctx.target,
                                    &self.ctx.breakpoints,
                                    &self.ctx.current_thread,
                                );
                            }
                            break;
                        }
                    }
                }
                Ok(None) => {
                    // timeout
                }
                Err(e) => {
                    error!("error waiting for stop: {:?}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Print a hardware (DR) breakpoint hit, mirroring the software-breakpoint
    /// `Hit` rendering. The address the breakpoint watches is unrelated to
    /// `rip` for data watches, so the banner names the breakpoint while the
    /// break context shows where execution actually stopped.
    fn surface_hardware_breakpoint_hit(&mut self, bp: &Breakpoint) {
        println!();
        let access = bp
            .hardware
            .map(|hw| format!(" {}{}", hw.access.letter(), hw.len))
            .unwrap_or_default();
        println!(
            "{} {}{} {}",
            ui::label("hardware breakpoint:"),
            ui::bp_id(bp.id),
            access.bright_black(),
            bp.symbol
                .as_ref()
                .map(|s| format!("({})", ui::symbol(s)))
                .unwrap_or_default()
        );
        print_break_context(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &self.ctx.breakpoints,
            &self.ctx.current_thread,
        );
    }

    fn single_step(&mut self) -> Result<()> {
        // The step itself (over-breakpoint dance, trap-flag clear, breakpoint
        // re-arm, thread re-select) is the canonical `Session::step`;
        // the REPL only adds the break-context display.
        if let Err(e) = self.ctx.step() {
            error!("failed to step: {:?}", e);
            return Ok(());
        }

        println!();
        print_break_context(
            &mut *self.ctx.backend,
            &self.ctx.register_map,
            &mut self.ctx.target,
            &self.ctx.breakpoints,
            &self.ctx.current_thread,
        );

        Ok(())
    }

    fn run_to_temporary_code_breakpoint(&mut self, address: VirtAddr) -> Result<()> {
        if self
            .ctx
            .breakpoints
            .enabled_breakpoint_id_for_current_context(&self.ctx.target, address)
            .is_some()
        {
            return self.continue_vm();
        }

        let temp_id = match self.ctx.breakpoints.add_temporary_code(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
        ) {
            Ok(id) => id,
            Err(e) => {
                error!(
                    "failed to set temporary breakpoint at {}: {}",
                    ui::addr(address.0),
                    e
                );
                return Ok(());
            }
        };
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        let result = self.continue_vm();

        let _ = self
            .ctx
            .breakpoints
            .remove(&mut *self.ctx.backend, &self.ctx.target, temp_id);
        self.caches.refresh_breakpoints(&self.ctx.breakpoints);

        result
    }

    fn cmd_p(&mut self) -> Result<()> {
        // The step-over decision (is the current insn a call? where does it
        // return?) is shared with the SDKs; the REPL only differs in *how* it
        // runs to the target, via its rich-display continue loop.
        match self.ctx.step_over_target() {
            Ok(StepKind::Single) => self.single_step(),
            Ok(StepKind::RunTo(target)) => self.run_to_temporary_code_breakpoint(target),
            Err(e) => {
                error!("failed to decode current instruction: {}", e);
                Ok(())
            }
        }
    }

    fn cmd_gu(&mut self) -> Result<()> {
        match self.ctx.step_out_target() {
            Ok(target) => self.run_to_temporary_code_breakpoint(target),
            Err(e) => {
                error!("{}", e);
                Ok(())
            }
        }
    }
}
