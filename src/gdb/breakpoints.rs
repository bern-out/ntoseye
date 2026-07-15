use std::{collections::HashMap, sync::Arc};

use pelite::pe64::{Pe, PeView, image::IMAGE_SCN_MEM_EXECUTE};

use crate::backend::MemoryOps;
use crate::dbg_backend::{
    DebugBackend, DebugCapability, HW_BREAKPOINT_SLOTS, HwBreakpointAccess, WatchpointAccess,
    validate_hw_breakpoint,
};
use crate::error::{Error, Result};
use crate::expr::Expr;
use crate::guest::{ModuleInfo, ProcessInfo, read_pe_image};
use crate::memory::AddressSpace;
use crate::target::Target;
use crate::types::{Dtb, VirtAddr};

/// A hardware (debug-register) breakpoint's parameters: the access it traps on,
/// the watch width in bytes, and which DR slot (0-3) it occupies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HardwareBreakpoint {
    pub(crate) access: HwBreakpointAccess,
    pub(crate) len: u8,
    pub(crate) slot: u8,
}

#[derive(Debug, Clone)]
pub struct Breakpoint {
    pub id: u32,
    pub address: VirtAddr,
    pub enabled: bool,
    pub symbol: Option<String>,
    pub scope: BreakpointScope,
    pub condition: Option<String>,
    pub(crate) condition_expr: Option<Arc<Expr>>,
    pub temporary: bool,
    /// Transport-specific breakpoint state; hosts use [`Self::watchpoint`] for
    /// the semantic data-watch metadata.
    pub(crate) hardware: Option<HardwareBreakpoint>,
    backend: BreakpointBackend,
}

impl Breakpoint {
    /// Data-watch semantics for this stop point. Execute-only debug-register
    /// breakpoints remain code breakpoints and deliberately return `None`.
    pub fn watchpoint(&self) -> Option<(WatchpointAccess, u8)> {
        let hardware = self.hardware?;
        let access = match hardware.access {
            HwBreakpointAccess::Write => WatchpointAccess::Write,
            HwBreakpointAccess::ReadWrite => WatchpointAccess::ReadWrite,
            HwBreakpointAccess::Execute => return None,
        };
        Some((access, hardware.len))
    }

    /// The watched access name (`"write"`/`"read_write"`), or `None` for a
    /// code breakpoint. Presentation surfaces share this instead of
    /// destructuring [`Self::watchpoint`] themselves.
    pub fn watch_access_name(&self) -> Option<&'static str> {
        self.watchpoint().map(|(access, _)| access.name())
    }

    /// The watched byte width, or `None` for a code breakpoint.
    pub fn watch_length(&self) -> Option<u8> {
        self.watchpoint().map(|(_, length)| length)
    }

    /// Evaluate the condition compiled when this breakpoint was installed.
    /// Unconditional breakpoints always hold.
    pub(crate) fn evaluate_condition(&self, target: &Target) -> Result<bool> {
        match &self.condition_expr {
            Some(expr) => Ok(expr.resolve(target)?.0 != 0),
            None => Ok(true),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BreakpointScope {
    Kernel,
    Process { pid: u64, dtb: Dtb, name: String },
}

impl BreakpointScope {
    fn matches_cr3(&self, cr3: u64) -> bool {
        // Mask out the PCID (bits 0..11) and reserved/canonical bits
        // (52..63), leaving only the page-directory base physical frame.
        const CR3_PAGE_MASK: u64 = 0x000F_FFFF_FFFF_F000;
        match self {
            Self::Kernel => true,
            Self::Process { dtb, .. } => (cr3 & CR3_PAGE_MASK) == (*dtb & CR3_PAGE_MASK),
        }
    }

    pub fn label(&self) -> String {
        match self {
            Self::Kernel => "global".to_string(),
            Self::Process { pid, name, .. } => format!("{name} ({pid})"),
        }
    }
}

/// Who owns the int3 byte for a breakpoint.
///
/// * `Kernel`: written via the target's kernel debugger API
///   (`DbgKdWriteBreakPointApi` / gdb `Z0`). The kernel tracks the original
///   byte and handles step-over.
///
/// * `GuestMemoryPatch`: we write 0xCC ourselves through `/dev/kvm` against a
///   specific process's page table. No Kdp primitive supports per-process BPs
///   (KD's BP APIs all route through `MmDbgCopyMemory`, which uses the current
///   CR3), so this is the only way to scope a user-mode BP to one process.
///   Writing at the physical-frame level bypasses copy-on-write, so the int3
///   is visible to every process mapping that frame. `check_breakpoint_hit`'s
///   CR3 filter discards wrong-process hits, but the kernel still pays for
///   the trap.
/// * `Hardware`: an x86 debug-register watch (`ba`). No memory is modified —
///   the CPU traps on the linear address — so there is no displaced byte and no
///   step-over dance. The DR slot and watch parameters live on
///   [`Breakpoint::hardware`]; hits are identified by DR6, not by RIP, so
///   hardware breakpoints stay out of the int3-hit predicates.
#[derive(Debug, Clone)]
enum BreakpointBackend {
    Kernel { original_byte: u8 },
    GuestMemoryPatch { original_byte: u8 },
    Hardware,
}

impl BreakpointBackend {
    /// The instruction byte we displaced with the int3, so display paths can
    /// overlay it and never show our own breakpoint. Hardware breakpoints
    /// displace nothing (they never reach the masking path).
    fn original_byte(&self) -> u8 {
        match self {
            Self::Kernel { original_byte } | Self::GuestMemoryPatch { original_byte } => {
                *original_byte
            }
            Self::Hardware => 0,
        }
    }
}

#[derive(Default)]
pub struct BreakpointManager {
    breakpoints: HashMap<u32, Breakpoint>,
    next_id: u32,
}

impl BreakpointManager {
    pub fn new() -> Self {
        Self {
            breakpoints: HashMap::new(),
            next_id: 0,
        }
    }

    /// Test-only: register a breakpoint directly, bypassing backend
    /// installation. `hardware: Some(..)` makes a DR breakpoint; `None` a
    /// kernel int3 with a dummy displaced byte. Lets tests outside this
    /// module (session run-control) stage manager state without a live
    /// target.
    #[cfg(test)]
    pub(crate) fn insert_for_test(
        &mut self,
        id: u32,
        address: VirtAddr,
        enabled: bool,
        hardware: Option<HardwareBreakpoint>,
    ) {
        let backend = match hardware {
            Some(_) => BreakpointBackend::Hardware,
            None => BreakpointBackend::Kernel {
                original_byte: 0x90,
            },
        };
        self.breakpoints.insert(
            id,
            Breakpoint {
                id,
                address,
                enabled,
                symbol: None,
                scope: BreakpointScope::Kernel,
                condition: None,
                condition_expr: None,
                temporary: false,
                hardware,
                backend,
            },
        );
    }

    pub fn add(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        self.add_code(client, debugger, address, symbol, condition, false)
    }

    pub fn add_temporary_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
    ) -> Result<u32> {
        self.add_code(client, debugger, address, None, None, true)
    }

    fn add_code(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        symbol: Option<String>,
        condition: Option<String>,
        temporary: bool,
    ) -> Result<u32> {
        let condition_expr = Self::compile_condition(condition.as_deref())?;
        let scope = Self::scope_for_current_context(debugger);
        let caps = client.capabilities();
        if matches!(scope, BreakpointScope::Process { .. })
            && !caps.iter().any(|c| c.capability == DebugCapability::UserModeBreakpoints && c.supported)
        {
            return Err(Error::NotSupported);
        }
        if matches!(scope, BreakpointScope::Kernel)
            && !caps.iter().any(|c| c.capability == DebugCapability::KernelBreakpoints && c.supported)
        {
            return Err(Error::NotSupported);
        }

        Self::validate_breakpoint_target(debugger, address)?;
        let backend = Self::install_breakpoint(client, debugger, address, &scope)?;
        let id = self.next_id;
        self.next_id += 1;

        let bp = Breakpoint {
            id,
            address,
            enabled: true,
            symbol,
            scope,
            condition,
            condition_expr,
            temporary,
            hardware: None,
            backend,
        };

        self.breakpoints.insert(id, bp);
        Ok(id)
    }

    /// Set a hardware (debug-register) breakpoint: a global watch on `address`
    /// for `access` over `len` bytes. Backends without DR support (everything
    /// but KD) reject this with [`Error::NotSupported`]. Unlike software
    /// breakpoints these are always global (DR matches a linear address in any
    /// process) and modify no guest memory, so validation is alignment/width
    /// only, not page executability.
    pub(crate) fn add_hardware(
        &mut self,
        client: &mut dyn DebugBackend,
        address: VirtAddr,
        access: HwBreakpointAccess,
        len: u8,
        symbol: Option<String>,
        condition: Option<String>,
    ) -> Result<u32> {
        let condition_expr = Self::compile_condition(condition.as_deref())?;
        if !client.supports_watchpoints() {
            return Err(Error::NotSupported);
        }
        validate_hw_breakpoint(access, len, address.0)?;

        let slot = self.free_hardware_slot()?;
        client.set_hardware_breakpoint(slot, address.0, access, len)?;

        let id = self.next_id;
        self.next_id += 1;
        let bp = Breakpoint {
            id,
            address,
            enabled: true,
            symbol,
            scope: BreakpointScope::Kernel,
            condition,
            condition_expr,
            temporary: false,
            hardware: Some(HardwareBreakpoint { access, len, slot }),
            backend: BreakpointBackend::Hardware,
        };
        self.breakpoints.insert(id, bp);
        Ok(id)
    }

    fn compile_condition(condition: Option<&str>) -> Result<Option<Arc<Expr>>> {
        condition
            .map(Expr::parse)
            .transpose()
            .map(|expr| expr.map(Arc::new))
    }

    /// The lowest DR slot (0-3) not already claimed by a hardware breakpoint,
    /// or an error when all four are in use. Disabled hardware breakpoints keep
    /// their slot reserved (matching WinDbg's fixed four).
    fn free_hardware_slot(&self) -> Result<u8> {
        (0..HW_BREAKPOINT_SLOTS)
            .find(|slot| {
                !self
                    .breakpoints
                    .values()
                    .any(|bp| bp.hardware.is_some_and(|hw| hw.slot == *slot))
            })
            .ok_or_else(|| {
                Error::Rsp(format!(
                    "all {HW_BREAKPOINT_SLOTS} hardware breakpoint slots are in use"
                ))
            })
    }

    pub fn remove(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        self.remove_if_uninstalled(id, |bp| Self::uninstall_breakpoint(client, debugger, bp))
    }

    fn remove_if_uninstalled(
        &mut self,
        id: u32,
        uninstall: impl FnOnce(&Breakpoint) -> Result<()>,
    ) -> Result<()> {
        let bp = self
            .breakpoints
            .get(&id)
            .cloned()
            .ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            uninstall(&bp)?;
        }
        self.breakpoints.remove(&id);

        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }

        Ok(())
    }

    pub fn discard(&mut self, id: u32) -> Result<Breakpoint> {
        let bp = self.breakpoints.remove(&id).ok_or(Error::BPNotFound(id))?;
        if self.breakpoints.is_empty() {
            self.next_id = 0;
        }
        Ok(bp)
    }

    pub fn enable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if bp.enabled {
            return Ok(());
        }

        Self::install_existing_breakpoint(client, debugger, bp)?;
        bp.enabled = true;
        Ok(())
    }

    pub fn disable(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        Self::uninstall_breakpoint(client, debugger, bp)?;
        bp.enabled = false;
        Ok(())
    }

    pub fn disable_guest_memory_patch_in_address_space(
        &mut self,
        client: &mut dyn DebugBackend,
        debugger: &Target,
        id: u32,
        dtb: Dtb,
    ) -> Result<()> {
        let bp = self.breakpoints.get_mut(&id).ok_or(Error::BPNotFound(id))?;

        if !bp.enabled {
            return Ok(());
        }

        match bp.backend {
            BreakpointBackend::GuestMemoryPatch { original_byte } => {
                let memory = AddressSpace::new(&debugger.phys, dtb);
                memory.write_bytes(bp.address, &[original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                bp.enabled = false;
                Ok(())
            }
            BreakpointBackend::Kernel { .. } => Err(Error::Rsp(
                "cannot address-space-disable a kernel breakpoint".into(),
            )),
            BreakpointBackend::Hardware => Err(Error::Rsp(
                "cannot address-space-disable a hardware breakpoint".into(),
            )),
        }
    }

    pub fn list(&self) -> Vec<&Breakpoint> {
        let mut bps: Vec<_> = self.breakpoints.values().collect();
        bps.sort_by_key(|bp| bp.id);
        bps
    }

    pub fn has_enabled_breakpoints(&self) -> bool {
        self.breakpoints.values().any(|bp| bp.enabled)
    }

    /// Whether any enabled hardware (DR) breakpoint exists — the cheap gate the
    /// stop path checks before reading DR6 on a single-step.
    pub(crate) fn has_enabled_hardware_breakpoints(&self) -> bool {
        self.breakpoints
            .values()
            .any(|bp| bp.enabled && bp.hardware.is_some())
    }

    /// The enabled hardware breakpoint occupying DR slot `slot`, if any — used
    /// to map a DR6 status bit back to the breakpoint that fired.
    pub(crate) fn hardware_breakpoint_for_slot(&self, slot: u8) -> Option<Breakpoint> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.hardware.is_some_and(|hw| hw.slot == slot))
            .cloned()
    }

    /// Best-effort release of every DR slot held by a hardware breakpoint
    /// (enabled or not — disabled ones still reserve their slot). Used by the
    /// target-reload path before it drops the manager: after a real reboot the
    /// debug registers are reset anyway, but a reload without a machine reset
    /// (kernel rediscovery) would otherwise leave orphaned watches raising
    /// `#DB`s no manager entry can claim.
    pub(crate) fn clear_hardware_slots(&self, client: &mut dyn DebugBackend) {
        for bp in self.breakpoints.values() {
            if let Some(hw) = bp.hardware {
                let _ = client.clear_hardware_breakpoint(hw.slot);
            }
        }
    }

    // NOTE refreshing ensures local breakpoint state matches target state in case they were cleared,
    // this should fix single stepping breaking every breakpoint proceeding the step..
    pub fn refresh_enabled(&self, client: &mut dyn DebugBackend, debugger: &Target) -> Result<()> {
        let mut enabled: Vec<_> = self
            .breakpoints
            .values()
            .filter(|bp| bp.enabled && bp.hardware.is_none())
            .collect();
        enabled.sort_by_key(|bp| bp.id);

        for bp in enabled {
            let _ = Self::uninstall_breakpoint(client, debugger, bp);
            Self::install_existing_breakpoint(client, debugger, bp)?;
        }

        Ok(())
    }

    pub fn check_breakpoint_hit(&self, rip: u64, cr3: u64) -> BreakpointHitResult {
        for bp in self.breakpoints.values() {
            if bp.hardware.is_none()
                && bp.address.0 == rip
                && bp.enabled
                && bp.scope.matches_cr3(cr3)
            {
                return BreakpointHitResult::Hit(bp.clone());
            }
        }

        BreakpointHitResult::NotBreakpoint
    }

    pub fn enabled_breakpoint_id_for_current_context(
        &self,
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<u32> {
        let scope = Self::scope_for_current_context(debugger);
        self.enabled_software_breakpoint_id(&scope, address)
    }

    fn enabled_software_breakpoint_id(
        &self,
        scope: &BreakpointScope,
        address: VirtAddr,
    ) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| {
                bp.enabled && bp.hardware.is_none() && bp.address == address && &bp.scope == scope
            })
            .map(|bp| bp.id)
    }

    /// Overlay our breakpoints' original bytes onto a buffer read for display,
    /// so no view ever shows the int3 we injected. `start` is the buffer's
    /// guest VA; `cr3` scopes process breakpoints to the address space the
    /// bytes were read from (kernel breakpoints are global).
    pub fn mask_breakpoint_bytes(&self, start: VirtAddr, buf: &mut [u8], cr3: u64) {
        let end = start.0.wrapping_add(buf.len() as u64);
        for bp in self.breakpoints.values() {
            if !bp.enabled || bp.hardware.is_some() || !bp.scope.matches_cr3(cr3) {
                continue;
            }
            if bp.address.0 < start.0 || bp.address.0 >= end {
                continue;
            }
            buf[(bp.address.0 - start.0) as usize] = bp.backend.original_byte();
        }
    }

    /// Find a BP at `rip` regardless of its scope; "is this int3 owned by us?"
    pub fn breakpoint_id_at_address(&self, rip: u64) -> Option<u32> {
        self.breakpoints
            .values()
            .find(|bp| bp.enabled && bp.hardware.is_none() && bp.address.0 == rip)
            .map(|bp| bp.id)
    }

    fn scope_for_current_context(debugger: &Target) -> BreakpointScope {
        match &debugger.current_process_info {
            Some(ProcessInfo { pid, name, dtb, .. }) => BreakpointScope::Process {
                pid: *pid,
                dtb: *dtb,
                name: name.clone(),
            },
            None => BreakpointScope::Kernel,
        }
    }

    fn install_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        address: VirtAddr,
        scope: &BreakpointScope,
    ) -> Result<BreakpointBackend> {
        match scope {
            BreakpointScope::Kernel => {
                // Capture the displaced byte before the kernel writes the int3,
                // so display paths can mask it back out (the kernel owns the
                // original byte but never hands it to us)
                let memory = AddressSpace::new(&debugger.phys, debugger.current_dtb());
                let mut original = [0u8; 1];
                memory.read_bytes(address, &mut original)?;
                client.set_breakpoint(address.0)?;
                Ok(BreakpointBackend::Kernel {
                    original_byte: original[0],
                })
            }
            BreakpointScope::Process { dtb, .. } => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                let mut original = [0u8; 1];
                memory.read_bytes(address, &mut original)?;
                memory.write_bytes(address, &[0xcc])?;
                // The kernel doesn't know about this BP (we patched it
                // directly via /dev/kvm), so the backend needs to be told
                // separately for managed-BP bookkeeping at stop time.
                client.note_breakpoint_installed(address.0);
                Ok(BreakpointBackend::GuestMemoryPatch {
                    original_byte: original[0],
                })
            }
        }
    }

    fn install_existing_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.set_breakpoint(bp.address.0)
            }
            (BreakpointScope::Process { dtb, .. }, BreakpointBackend::GuestMemoryPatch { .. }) => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                memory.write_bytes(bp.address, &[0xcc])?;
                client.note_breakpoint_installed(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => {
                    client.set_hardware_breakpoint(hw.slot, bp.address.0, hw.access, hw.len)
                }
                None => Err(Error::Rsp("hardware breakpoint missing parameters".into())),
            },
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn uninstall_breakpoint(
        client: &mut dyn DebugBackend,
        debugger: &Target,
        bp: &Breakpoint,
    ) -> Result<()> {
        match (&bp.scope, &bp.backend) {
            (BreakpointScope::Kernel, BreakpointBackend::Kernel { .. }) => {
                client.remove_breakpoint(bp.address.0)
            }
            (
                BreakpointScope::Process { dtb, .. },
                BreakpointBackend::GuestMemoryPatch { original_byte },
            ) => {
                let memory = AddressSpace::new(&debugger.phys, *dtb);
                memory.write_bytes(bp.address, &[*original_byte])?;
                client.note_breakpoint_uninstalled(bp.address.0);
                Ok(())
            }
            (_, BreakpointBackend::Hardware) => match bp.hardware {
                Some(hw) => client.clear_hardware_breakpoint(hw.slot),
                None => Err(Error::Rsp("hardware breakpoint missing parameters".into())),
            },
            _ => Err(Error::Rsp("breakpoint backend/scope mismatch".into())),
        }
    }

    fn validate_breakpoint_target(debugger: &Target, address: VirtAddr) -> Result<()> {
        let module = Self::find_kernel_module_containing_address(debugger, address);
        let memory = AddressSpace::new(&debugger.phys, debugger.current_dtb());
        let translation = memory
            .virt_to_phys(address)?
            .ok_or(Error::BadVirtualAddress(address))?;

        if translation.nx {
            let context = module
                .as_ref()
                .map(|module| module.short_name.as_str())
                .unwrap_or("unknown");
            return Err(Error::Rsp(format!(
                "refusing breakpoint at {:#x}: target page is non-executable ({})",
                address.0, context
            )));
        }

        if let Some(module) = module {
            let image = read_pe_image(module.base_address, &memory)?;
            let view = PeView::from_bytes(image.as_slice())?;
            let rva = address.0.saturating_sub(module.base_address.0) as u32;
            let in_executable_section = view.section_headers().iter().any(|section| {
                let size = section.VirtualSize.max(section.SizeOfRawData);
                size != 0
                    && section.Characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                    && rva >= section.VirtualAddress
                    && rva < section.VirtualAddress.saturating_add(size)
            });

            if !in_executable_section {
                return Err(Error::Rsp(format!(
                    "refusing breakpoint at {:#x}: address falls in non-executable section of {}",
                    address.0, module.short_name
                )));
            }
        }

        Ok(())
    }

    fn find_kernel_module_containing_address(
        debugger: &Target,
        address: VirtAddr,
    ) -> Option<ModuleInfo> {
        debugger
            .kernel_modules()
            .ok()?
            .into_iter()
            .find(|module| module.contains_address(address))
    }
}

#[derive(Debug)]
pub enum BreakpointHitResult {
    /// Breakpoint hit
    Hit(Breakpoint),
    /// RIP doesn't match any breakpoint
    NotBreakpoint,
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        Breakpoint, BreakpointBackend, BreakpointHitResult, BreakpointManager, BreakpointScope,
        HardwareBreakpoint,
    };
    use crate::dbg_backend::{DebugBackend, HwBreakpointAccess, StopEvent, WatchpointAccess};
    use crate::error::{Error, Result};
    use crate::expr::{Expr, ExprBinaryOp};
    use crate::gdb::RegisterMap;
    use crate::types::VirtAddr;

    #[test]
    fn failed_uninstall_keeps_breakpoint_managed_for_retry() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x1000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot: 0,
            }),
        );

        let result = manager.remove_if_uninstalled(7, |_| {
            Err(Error::Kd("injected hardware clear failure".into()))
        });
        assert!(result.is_err());
        assert_eq!(manager.list().len(), 1);
        assert_eq!(manager.list()[0].id, 7);
        assert!(manager.has_enabled_hardware_breakpoints());
    }

    #[test]
    fn exposes_data_watches_without_transport_metadata() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::ReadWrite,
                len: 8,
                slot: 2,
            }),
        );

        let breakpoint = manager.list().into_iter().find(|bp| bp.id == 7).unwrap();
        assert_eq!(
            breakpoint.watchpoint(),
            Some((WatchpointAccess::ReadWrite, 8))
        );
    }

    #[test]
    fn detects_breakpoint_hit_at_exact_rip() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x1000),
                enabled: true,
                symbol: None,
                scope: BreakpointScope::Kernel,
                condition: None,
                condition_expr: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::Kernel {
                    original_byte: 0x90,
                },
            },
        );

        match manager.check_breakpoint_hit(0x1000, 0) {
            BreakpointHitResult::Hit(bp) => assert_eq!(bp.id, 0),
            other => panic!("unexpected result: {:?}", other),
        }
    }

    #[test]
    fn process_breakpoint_hit_requires_matching_cr3() {
        let mut manager = BreakpointManager::new();
        manager.breakpoints.insert(
            0,
            Breakpoint {
                id: 0,
                address: VirtAddr(0x7ff7_1234_1000),
                enabled: true,
                symbol: None,
                scope: BreakpointScope::Process {
                    pid: 42,
                    dtb: 0x1234_5000,
                    name: "user.exe".to_string(),
                },
                condition: None,
                condition_expr: None,
                temporary: false,
                hardware: None,
                backend: BreakpointBackend::GuestMemoryPatch {
                    original_byte: 0x90,
                },
            },
        );

        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5000),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_5fff),
            BreakpointHitResult::Hit(_)
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x9999_9000),
            BreakpointHitResult::NotBreakpoint
        ));
        assert!(matches!(
            manager.check_breakpoint_hit(0x7ff7_1234_1000, 0x1234_4000),
            BreakpointHitResult::NotBreakpoint
        ));
    }

    #[test]
    fn hardware_breakpoint_is_ignored_by_int3_hit_predicates() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            0,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        // A DR watch traps via DR6, not RIP, so it must never register as an
        // int3 hit even when the faulting RIP equals its address.
        assert!(matches!(
            manager.check_breakpoint_hit(0x2000, 0),
            BreakpointHitResult::NotBreakpoint
        ));
        assert_eq!(manager.breakpoint_id_at_address(0x2000), None);
    }

    #[test]
    fn has_enabled_hardware_breakpoints_tracks_enabled_hw_bps() {
        let mut manager = BreakpointManager::new();

        // Software breakpoints do not count toward the DR6 gate.
        manager.insert_for_test(0, VirtAddr(0x1000), true, None);
        assert!(!manager.has_enabled_hardware_breakpoints());

        // An enabled hardware breakpoint opens the gate.
        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );
        assert!(manager.has_enabled_hardware_breakpoints());

        // Disabling that same hardware breakpoint closes it again.
        manager.breakpoints.get_mut(&1).unwrap().enabled = false;
        assert!(!manager.has_enabled_hardware_breakpoints());
    }

    #[test]
    fn hardware_breakpoint_for_slot_resolves_enabled_slot_only() {
        let mut manager = BreakpointManager::new();
        manager.insert_for_test(
            7,
            VirtAddr(0x3000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::ReadWrite,
                len: 8,
                slot: 1,
            }),
        );

        let found = manager
            .hardware_breakpoint_for_slot(1)
            .expect("slot 1 hw bp");
        assert_eq!(found.id, 7);
        assert_eq!(found.hardware.expect("hw params").slot, 1);

        // Nothing occupies slot 0.
        assert!(manager.hardware_breakpoint_for_slot(0).is_none());

        // A disabled hw bp in slot 0 must not be resolved either.
        manager.insert_for_test(
            8,
            VirtAddr(0x4000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 2,
                slot: 0,
            }),
        );
        assert!(manager.hardware_breakpoint_for_slot(0).is_none());
    }

    #[test]
    fn software_and_hardware_breakpoint_coexist_at_same_address() {
        let mut manager = BreakpointManager::new();
        let addr = 0x5000;

        // Software int3 and a DR watch pinned to the same linear address.
        manager.insert_for_test(0, VirtAddr(addr), true, None);
        manager.insert_for_test(
            1,
            VirtAddr(addr),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 1,
            }),
        );

        // The int3 predicate resolves the software bp; the DR watch is skipped
        // regardless of HashMap iteration order.
        match manager.check_breakpoint_hit(addr, 0) {
            BreakpointHitResult::Hit(bp) => {
                assert_eq!(bp.id, 0);
                assert!(bp.hardware.is_none());
            }
            other => panic!("expected software hit, got {:?}", other),
        }
        assert_eq!(manager.breakpoint_id_at_address(addr), Some(0));
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            Some(0)
        );

        // A data watch alone cannot satisfy run-to-address: it fires on a data
        // access, not when execution reaches the watched linear address.
        manager.breakpoints.remove(&0);
        assert_eq!(
            manager.enabled_software_breakpoint_id(&BreakpointScope::Kernel, VirtAddr(addr)),
            None
        );
    }

    #[test]
    fn condition_compiler_accepts_the_full_expression_grammar() {
        let source = "$rax == 1 && ($rcx & 0xff) != 0";
        let compiled = BreakpointManager::compile_condition(Some(source))
            .unwrap()
            .expect("compiled condition");
        assert!(matches!(
            compiled.as_ref(),
            Expr::Binary(_, ExprBinaryOp::LogicalAnd, _)
        ));

        assert!(
            BreakpointManager::compile_condition(None)
                .unwrap()
                .is_none()
        );
        assert!(BreakpointManager::compile_condition(Some("$rax == ")).is_err());
    }

    /// Backend stub that records which DR slots `clear_hardware_breakpoint`
    /// releases; every other operation is out of scope for these tests.
    struct SlotRecorder {
        register_map: RegisterMap,
        cleared: Vec<u8>,
    }

    impl SlotRecorder {
        fn new() -> Self {
            Self {
                register_map: RegisterMap::default(),
                cleared: Vec::new(),
            }
        }
    }

    impl DebugBackend for SlotRecorder {
        fn register_map(&self) -> &RegisterMap {
            &self.register_map
        }
        fn read_registers(&mut self) -> Result<Vec<u8>> {
            Err(Error::NotSupported)
        }
        fn write_registers(&mut self, _data: &[u8]) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn set_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn remove_breakpoint(&mut self, _addr: u64) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn clear_hardware_breakpoint(&mut self, slot: u8) -> Result<()> {
            self.cleared.push(slot);
            Ok(())
        }
        fn continue_execution(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn step(&mut self) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn interrupt(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn wait_for_stop(&mut self) -> Result<StopEvent> {
            Err(Error::NotSupported)
        }
        fn try_wait_for_stop(&mut self, _timeout: Duration) -> Result<Option<StopEvent>> {
            Ok(None)
        }
        fn thread_list(&mut self) -> Result<Vec<String>> {
            Err(Error::NotSupported)
        }
        fn set_current_thread(&mut self, _thread_id: &str) -> Result<()> {
            Err(Error::NotSupported)
        }
        fn stopped_thread_id(&mut self) -> Result<String> {
            Err(Error::NotSupported)
        }
        fn is_running(&self) -> bool {
            false
        }
    }

    #[test]
    fn clear_hardware_slots_releases_every_hw_slot_and_skips_software() {
        let mut manager = BreakpointManager::new();
        // Enabled DR watch occupying slot 2.
        manager.insert_for_test(
            0,
            VirtAddr(0x1000),
            true,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Write,
                len: 4,
                slot: 2,
            }),
        );
        // A disabled DR watch still reserves slot 0 and must be released too.
        manager.insert_for_test(
            1,
            VirtAddr(0x2000),
            false,
            Some(HardwareBreakpoint {
                access: HwBreakpointAccess::Execute,
                len: 1,
                slot: 0,
            }),
        );
        // Software int3: no DR slot, must never reach the backend.
        manager.insert_for_test(2, VirtAddr(0x3000), true, None);

        let mut backend = SlotRecorder::new();
        manager.clear_hardware_slots(&mut backend);

        // Exactly the two hardware slots, nothing for the software bp.
        let mut cleared = backend.cleared.clone();
        cleared.sort_unstable();
        assert_eq!(cleared, vec![0, 2]);
    }
}
