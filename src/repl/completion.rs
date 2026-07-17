use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::RwLock;

use crate::dbg_backend::DebugBackend;
use crate::error::Result;
use crate::gdb::BreakpointManager;
use crate::symbols::{SymbolIndex, SymbolStore};
use crate::target::{DriverObjectInfo, Target, ThreadInfo};
use crate::types::{Dtb, VirtAddr};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CompletionStrategy {
    None,
    Symbol,
    Expression,
    Type,
    Process,
    Thread,
    Vcpu,
    Breakpoint,
    Driver,
    Alias,
}

impl CompletionStrategy {
    pub fn from_kebab(s: &str) -> Option<Self> {
        Some(match s {
            "none" | "" => Self::None,
            "symbol" => Self::Symbol,
            "expression" => Self::Expression,
            "type" => Self::Type,
            "process" => Self::Process,
            "thread" => Self::Thread,
            "vcpu" => Self::Vcpu,
            "breakpoint" => Self::Breakpoint,
            "driver" => Self::Driver,
            "alias" => Self::Alias,
            _ => return None,
        })
    }
}

/// Cached process info for completion (name, PID)
pub type ProcessCache = Vec<(String, u64)>;

/// Cached execution-context IDs for completion
pub type VcpuCache = Vec<String>;

/// Cached Windows thread info for completion
pub type ThreadCache = Vec<ThreadInfo>;

/// Cached breakpoint info for completion (id, enabled, address, symbol)
pub type BreakpointCache = Vec<(u32, bool, VirtAddr, Option<String>)>;

/// Cached driver object info for completion
pub type DriverObjectCache = Vec<DriverObjectInfo>;

/// Cached expression variable name and display kind
pub type ExpressionVariableCache = Vec<(String, &'static str)>;

/// Cached (name, help, per-arg strategies) for script-registered commands
pub type UserCommandCache = Vec<(String, String, Vec<CompletionStrategy>)>;

/// Cached user alias definitions for completion
pub type AliasCache = Vec<(String, String)>;

/// Completion-facing state shared between the REPL loop (which rewrites the
/// caches as the target's state changes) and the tab completer. Every field is
/// a cheap-to-clone handle, so the loop and the completer each hold a clone.
#[derive(Clone)]
pub struct ReplCaches {
    pub symbols: Arc<RwLock<SymbolIndex>>,
    pub types: Arc<RwLock<SymbolIndex>>,
    pub symbol_store: Arc<SymbolStore>,
    pub dtb: Arc<RwLock<Dtb>>,
    pub processes: Arc<RwLock<ProcessCache>>,
    pub threads: Arc<RwLock<ThreadCache>>,
    pub vcpus: Arc<RwLock<VcpuCache>>,
    pub breakpoints: Arc<RwLock<BreakpointCache>>,
    pub drivers: Arc<RwLock<DriverObjectCache>>,
    pub registers: Arc<Vec<String>>,
    pub expression_variables: Arc<RwLock<ExpressionVariableCache>>,
    pub user_commands: Arc<RwLock<UserCommandCache>>,
    pub aliases: Arc<RwLock<AliasCache>>,
}

impl ReplCaches {
    /// Re-enumerate the guest's process list into the completion cache
    pub fn refresh_processes(&self, debugger: &Target) -> Result<()> {
        let processes = debugger.guest()?.enumerate_processes()?;
        *self.processes.write().unwrap() = processes.into_iter().map(|p| (p.name, p.pid)).collect();
        Ok(())
    }

    pub fn refresh_vcpus(&self, client: &mut dyn DebugBackend) {
        if let Ok(vcpus) = client.thread_list() {
            *self.vcpus.write().unwrap() = vcpus;
        }
    }

    /// The thread cache is only populated on demand (threads/thread commands);
    /// a full thread walk is far too expensive to run on every stop, especially
    /// over serial KD. Reloads just drop the now-stale entries.
    pub fn clear_threads(&self) {
        self.threads.write().unwrap().clear();
    }

    /// Snapshot the current breakpoint set into the completion cache
    pub fn refresh_breakpoints(&self, breakpoints: &BreakpointManager) {
        *self.breakpoints.write().unwrap() = breakpoints
            .list()
            .iter()
            .map(|bp| (bp.id, bp.enabled, bp.address, bp.symbol.clone()))
            .collect();
    }

    /// Rebuild the symbol/type/DTB completion caches after the active context
    /// changes (kernel reload, process attach/detach).
    ///
    /// The merged symbol/type indexes are a function of the active DTB (the caches
    /// are built coherently with `dtb` at init and on every change), and
    /// rebuilding+sorting them is expensive. The continue loop calls this on every
    /// stop, so a breakpoint on a hot function; e.g. `PeekMessageW`, hammered by
    /// every message pump, would otherwise re-sort the whole index per hit. Skip
    /// the rebuild when the context DTB hasn't moved.
    pub fn refresh_symbol_context(&self, debugger: &Target) {
        let new_dtb = debugger.current_dtb();
        if *self.dtb.read().unwrap() == new_dtb {
            return;
        }
        *self.symbols.write().unwrap() = debugger.current_symbol_index();
        *self.types.write().unwrap() = debugger.current_types_index();
        *self.dtb.write().unwrap() = new_dtb;
    }

    /// Best-effort re-enumeration of driver objects into the completion cache,
    /// leaving the previous entries in place if enumeration fails
    pub fn refresh_drivers(&self, debugger: &Target) {
        if let Ok(drivers) = debugger.enumerate_driver_objects() {
            *self.drivers.write().unwrap() = drivers;
        }
    }

    pub fn refresh_expression_context(&self, debugger: &Target) {
        let mut variables = BTreeMap::new();
        for name in debugger.user_vars.keys() {
            if !self.registers.contains(name) {
                variables.insert(name.clone(), "Variable");
            }
        }
        for index in 0..debugger.results.len() {
            variables.insert(index.to_string(), "Result");
        }
        for var in debugger.builtin_variables() {
            variables.entry(var.name.to_string()).or_insert("Builtin");
        }
        *self.expression_variables.write().unwrap() = variables.into_iter().collect();
    }
}
