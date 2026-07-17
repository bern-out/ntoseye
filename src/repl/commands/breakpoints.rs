use tabled::builder::Builder;
use tabled::settings::Padding;

use owo_colors::OwoColorize;

use crate::dbg_backend::HwBreakpointAccess;
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::ui;

use crate::repl::*;

repl_command! {
    cmd_bp;
    names: ["bp"],
    usage: "bp <address> [<expr>]",
    summary: "Set a breakpoint.",
    completion: Expression,
    run_state: Halted,
}

repl_command! {
    cmd_ba;
    names: ["ba"],
    usage: "ba <access><size> <address> [<expr>]",
    summary: "Set a hardware (debug-register) breakpoint (KD backend only).",
    details: "access: e=execute, r=read/write, w=write; size: 1,2,4,8 bytes (execute is 1). e.g. ba w4 nt!MyGlobal",
    completion: [None, Expression],
    run_state: Halted,
}

repl_command! {
    cmd_bl();
    names: ["bl"],
    usage: "bl",
    summary: "List all breakpoints.",
}

repl_command! {
    cmd_bc;
    names: ["bc"],
    usage: "bc <id>",
    summary: "Clear a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_bd;
    names: ["bd"],
    usage: "bd <id>",
    summary: "Disable a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

repl_command! {
    cmd_be;
    names: ["be"],
    usage: "be <id>",
    summary: "Enable a breakpoint by ID.",
    completion: Breakpoint,
    run_state: Halted,
}

fn breakpoint_condition(invocation: &CommandInvocation<'_>, start: usize) -> Option<String> {
    (invocation.argv.len() > start).then(|| invocation.join_args(start))
}

/// Parse a WinDbg-style `ba` access/size token like `w4`, `r1`, `e1`: a leading
/// access letter (`e`/`r`/`w`) followed by the watch width in bytes.
fn parse_hw_breakpoint_spec(spec: &str) -> Result<(HwBreakpointAccess, u8)> {
    let mut chars = spec.chars();
    let access = match chars.next().map(|c| c.to_ascii_lowercase()) {
        Some('e') => HwBreakpointAccess::Execute,
        Some('w') => HwBreakpointAccess::Write,
        Some('r') => HwBreakpointAccess::ReadWrite,
        _ => {
            return Err(Error::Rsp(format!(
                "invalid access in '{spec}' (use e=execute, r=read/write, w=write)"
            )));
        }
    };
    let size: String = chars.collect();
    let len = match size.as_str() {
        // Execute watches are always a single byte; allow the bare `e`.
        "" if matches!(access, HwBreakpointAccess::Execute) => 1,
        "" => {
            return Err(Error::Rsp(format!(
                "missing size in '{spec}' (e.g. ba w4 <address>)"
            )));
        }
        other => other
            .parse()
            .map_err(|_| Error::Rsp(format!("invalid size '{other}' (use 1, 2, 4, or 8)")))?,
    };
    Ok((access, len))
}

impl ReplState<'_> {
    fn breakpoint_id_arg(invocation: &CommandInvocation<'_>, command: &str) -> Option<u32> {
        let Some(id_str) = invocation.arg(0) else {
            println!("{}\n", command_help(command));
            return None;
        };

        match id_str.parse() {
            Ok(id) => Some(id),
            Err(_) => {
                error!("invalid breakpoint ID: {}", id_str);
                None
            }
        }
    }

    fn cmd_ba(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let spec_str = require_arg!(invocation, 0, "ba");
        let addr_str = require_arg!(invocation, 1, "ba");

        let (access, len) = match parse_hw_breakpoint_spec(spec_str) {
            Ok(parsed) => parsed,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let address = match Expr::eval(addr_str, &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };
        let condition = breakpoint_condition(&invocation, 2);

        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);

        match self.ctx.breakpoints.add_hardware(
            &mut *self.ctx.backend,
            address,
            access,
            len,
            symbol.clone(),
            condition.clone(),
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                println!(
                    "hardware breakpoint {} ({} {}b) set at {}{}{}\n",
                    ui::bp_id(id),
                    access.label(),
                    len,
                    ui::addr(address.0),
                    symbol
                        .map(|s| format!(" ({})", ui::symbol(&s)))
                        .unwrap_or_default(),
                    condition_label.bright_black(),
                );
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bp(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        // Process-scope BP support is per-backend; the
        // manager returns `Error::NotSupported` for
        // backends that can't honour them.

        let addr_str = require_arg!(invocation, 0, "bp");
        let condition = breakpoint_condition(&invocation, 1);
        let address = match Expr::eval(addr_str, &self.ctx.target) {
            Ok(a) => a,
            Err(e) => {
                error!("{}", e);
                return Ok(());
            }
        };

        let symbol = self
            .ctx
            .target
            .symbols
            .format_closest_symbol_for_address(self.ctx.target.current_dtb(), address);

        match self.ctx.breakpoints.add(
            &mut *self.ctx.backend,
            &self.ctx.target,
            address,
            symbol.clone(),
            condition.clone(),
        ) {
            Ok(id) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                let condition_label = condition
                    .as_ref()
                    .map(|condition| format!(" if {condition}"))
                    .unwrap_or_default();
                println!(
                    "breakpoint {} set at {}{}{}{}\n",
                    ui::bp_id(id),
                    ui::addr(address.0),
                    symbol
                        .map(|s| format!(" ({})", ui::symbol(&s)))
                        .unwrap_or_default(),
                    condition_label.bright_black(),
                    format!(
                        " ({})",
                        self.ctx
                            .breakpoints
                            .list()
                            .into_iter()
                            .find(|bp| bp.id == id)
                            .map(|bp| bp.scope.label())
                            .unwrap_or_else(|| "global".to_string())
                    )
                    .bright_black()
                );
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bl(&mut self) -> Result<()> {
        let bps = self.ctx.breakpoints.list();
        if bps.is_empty() {
            println!("no breakpoints set\n");
        } else {
            let mut builder = Builder::default();
            builder.push_record(vec![
                "ID".to_string(),
                "Status".to_string(),
                "Type".to_string(),
                "Address".to_string(),
                "Symbol".to_string(),
                "Condition".to_string(),
                "Scope".to_string(),
            ]);

            for bp in bps {
                let status = if bp.enabled { "enabled" } else { "disabled" };
                let scope = bp.scope.label();
                let kind = match bp.hardware {
                    Some(hw) => format!("hw {}{}", hw.access.letter(), hw.len),
                    None => "sw".to_string(),
                };

                builder.push_record(vec![
                    bp.id.to_string(),
                    status.to_string(),
                    kind,
                    ui::addr(bp.address.0),
                    bp.symbol.as_deref().unwrap_or("-").to_string(),
                    bp.condition.as_deref().unwrap_or("-").to_string(),
                    scope,
                ]);
            }

            let mut table = builder.build();
            table
                .with(tabled::settings::Style::empty())
                .with(Padding::new(0, 2, 0, 0));
            println!("{table}\n");
        }

        Ok(())
    }

    fn cmd_bc(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bc") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .remove(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} cleared\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_bd(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "bd") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .disable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} disabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }

    fn cmd_be(&mut self, invocation: CommandInvocation<'_>) -> Result<()> {
        let Some(id) = Self::breakpoint_id_arg(&invocation, "be") else {
            return Ok(());
        };

        match self
            .ctx
            .breakpoints
            .enable(&mut *self.ctx.backend, &self.ctx.target, id)
        {
            Ok(()) => {
                self.caches.refresh_breakpoints(&self.ctx.breakpoints);
                println!("breakpoint {} enabled\n", ui::bp_id(id));
            }
            Err(e) => {
                error!("{}", e);
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::*;

    fn bp_invocation<'a>(argv: &'a [&'a str]) -> CommandInvocation<'a> {
        CommandInvocation {
            name: "bp",
            argv: argv.iter().copied().map(Cow::Borrowed).collect(),
            raw_tail: "",
        }
    }

    #[test]
    fn breakpoint_condition_accepts_comparison_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "==", "1"]);

        assert_eq!(
            breakpoint_condition(&invocation, 1).as_deref(),
            Some("$rax == 1")
        );
    }

    #[test]
    fn breakpoint_condition_preserves_chained_expression_tail() {
        let invocation = bp_invocation(&["nt!Foo", "$rax", "==", "1", "&&", "$rcx", "!=", "0"]);

        assert_eq!(
            breakpoint_condition(&invocation, 1).as_deref(),
            Some("$rax == 1 && $rcx != 0")
        );
    }
}
