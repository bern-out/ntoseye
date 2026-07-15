//! x64 `_KTRAP_FRAME` decoding.
//!
//! Windows builds a `_KTRAP_FRAME` on every kernel-mode trap (interrupt,
//! exception, syscall); several bugchecks carry a pointer to one in their
//! parameters. The layout is taken from the PDB rather than hardcoded, so
//! decoding tracks whatever build the guest is running.

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::symbols::{TypeInfo, le_uint};
use crate::target::Target;
use crate::types::VirtAddr;

pub const KTRAP_FRAME_TYPE: &str = "_KTRAP_FRAME";

/// A decoded x64 `_KTRAP_FRAME`. Only the state the kernel actually saves in
/// the frame is here: the volatile registers plus rbx/rdi/rsi/rbp and the
/// trap's iretq block (rip/cs/rsp/ss/eflags). The nonvolatile r12-r15 live in
/// the accompanying `_KEXCEPTION_FRAME`, not the trap frame.
#[derive(Clone, Debug)]
pub struct KtrapFrame {
    /// Guest-virtual address the frame was decoded from.
    pub address: u64,
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub rsp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub rip: u64,
    pub cs: u16,
    pub ss: u16,
    pub eflags: u32,
    /// Hardware error code pushed by the CPU for faults that carry one
    /// (page fault, GP fault, ...); otherwise whatever the trap handler wrote.
    pub error_code: u64,
    /// `KPROCESSOR_MODE` the trap came from (0 = kernel, 1 = user).
    pub previous_mode: u8,
    pub previous_irql: u8,
}

impl KtrapFrame {
    /// Decode a frame at `address` out of `buf` (which must cover the whole
    /// struct) using the PDB-described `layout`.
    pub fn decode(layout: &TypeInfo, address: u64, buf: &[u8]) -> Result<Self> {
        let field = |name: &str| -> Result<u64> {
            let f = layout
                .fields
                .get(name)
                .ok_or_else(|| Error::FieldNotFound(name.to_string()))?;
            let off = f.offset as usize;
            let size = (f.size as usize).min(8);
            if size == 0 || off + size > buf.len() {
                return Err(Error::FieldNotFound(name.to_string()));
            }
            Ok(le_uint(&buf[off..off + size]))
        };
        Ok(Self {
            address,
            rax: field("Rax")?,
            rbx: field("Rbx")?,
            rcx: field("Rcx")?,
            rdx: field("Rdx")?,
            rsi: field("Rsi")?,
            rdi: field("Rdi")?,
            rbp: field("Rbp")?,
            rsp: field("Rsp")?,
            r8: field("R8")?,
            r9: field("R9")?,
            r10: field("R10")?,
            r11: field("R11")?,
            rip: field("Rip")?,
            cs: field("SegCs")? as u16,
            ss: field("SegSs")? as u16,
            eflags: field("EFlags")? as u32,
            error_code: field("ErrorCode")?,
            previous_mode: field("PreviousMode")? as u8,
            previous_irql: field("PreviousIrql")? as u8,
        })
    }
}

/// Read and decode an `_KTRAP_FRAME` at a kernel address. Fails when the
/// type is not in the loaded symbols or the memory is unreadable.
pub fn read_ktrap_frame(debugger: &Target, addr: VirtAddr) -> Result<KtrapFrame> {
    let process = debugger.current_process()?;
    let dtb = process.dtb();
    let layout = debugger
        .symbols
        .find_type_across_modules(dtb, KTRAP_FRAME_TYPE)
        .ok_or_else(|| Error::StructNotFound(KTRAP_FRAME_TYPE.to_string()))?;
    let mut buf = vec![0u8; layout.size];
    process.memory().read_bytes(addr, &mut buf)?;
    KtrapFrame::decode(&layout, addr.0, &buf)
}

/// Read an explicitly addressed trap frame, or the current Windows thread's
/// saved `KTHREAD.TrapFrame` when `addr` is `None`.
pub fn read_ktrap_frame_at_or_current(
    debugger: &Target,
    addr: Option<VirtAddr>,
) -> Result<KtrapFrame> {
    let addr = match addr {
        Some(addr) => addr,
        None => debugger
            .current_thread_pseudo_register("trapframe")
            .map(VirtAddr)
            .ok_or_else(|| {
                Error::DebugInfo(
                    "current thread has no saved trap frame (or no Windows thread context)".into(),
                )
            })?,
    };
    read_ktrap_frame(debugger, addr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::symbols::{FieldInfo, ParsedType};
    use std::collections::HashMap;

    /// A miniature `_KTRAP_FRAME` layout: enough fields, PDB-shaped, with the
    /// sub-8-byte sizes the real type uses for segments/flags/mode/irql.
    fn test_layout() -> TypeInfo {
        let mut fields = HashMap::new();
        let mut add = |name: &str, offset: u32, size: u64| {
            fields.insert(
                name.to_string(),
                FieldInfo {
                    offset,
                    size,
                    type_data: ParsedType::Primitive("test".into()),
                },
            );
        };
        add("PreviousMode", 0x00, 1);
        add("PreviousIrql", 0x01, 1);
        add("Rax", 0x08, 8);
        add("Rcx", 0x10, 8);
        add("Rdx", 0x18, 8);
        add("R8", 0x20, 8);
        add("R9", 0x28, 8);
        add("R10", 0x30, 8);
        add("R11", 0x38, 8);
        add("Rbx", 0x40, 8);
        add("Rdi", 0x48, 8);
        add("Rsi", 0x50, 8);
        add("Rbp", 0x58, 8);
        add("ErrorCode", 0x60, 8);
        add("Rip", 0x68, 8);
        add("SegCs", 0x70, 2);
        add("EFlags", 0x74, 4);
        add("Rsp", 0x78, 8);
        add("SegSs", 0x80, 2);
        TypeInfo {
            name: KTRAP_FRAME_TYPE.to_string(),
            size: 0x88,
            fields,
        }
    }

    #[test]
    fn decodes_fields_at_pdb_offsets() {
        let layout = test_layout();
        let mut buf = vec![0u8; layout.size];
        buf[0x00] = 1; // PreviousMode = user
        buf[0x01] = 2; // PreviousIrql
        buf[0x08..0x10].copy_from_slice(&0x1111u64.to_le_bytes()); // Rax
        buf[0x60..0x68].copy_from_slice(&0x2u64.to_le_bytes()); // ErrorCode
        buf[0x68..0x70].copy_from_slice(&0xffff_f800_1234_5678u64.to_le_bytes()); // Rip
        buf[0x70..0x72].copy_from_slice(&0x10u16.to_le_bytes()); // SegCs
        buf[0x74..0x78].copy_from_slice(&0x0004_0246u32.to_le_bytes()); // EFlags
        buf[0x78..0x80].copy_from_slice(&0xffff_b001_0000_0000u64.to_le_bytes()); // Rsp
        buf[0x80..0x82].copy_from_slice(&0x18u16.to_le_bytes()); // SegSs

        let frame = KtrapFrame::decode(&layout, 0xffff_b000_dead_0000, &buf).unwrap();
        assert_eq!(frame.address, 0xffff_b000_dead_0000);
        assert_eq!(frame.rax, 0x1111);
        assert_eq!(frame.rip, 0xffff_f800_1234_5678);
        assert_eq!(frame.rsp, 0xffff_b001_0000_0000);
        assert_eq!(frame.cs, 0x10);
        assert_eq!(frame.ss, 0x18);
        assert_eq!(frame.eflags, 0x0004_0246);
        assert_eq!(frame.error_code, 2);
        assert_eq!(frame.previous_mode, 1);
        assert_eq!(frame.previous_irql, 2);
    }

    #[test]
    fn missing_field_is_an_error_not_a_zero() {
        let mut layout = test_layout();
        layout.fields.remove("Rip");
        let buf = vec![0u8; layout.size];
        assert!(matches!(
            KtrapFrame::decode(&layout, 0, &buf),
            Err(Error::FieldNotFound(name)) if name == "Rip"
        ));
    }

    #[test]
    fn short_buffer_is_an_error() {
        let layout = test_layout();
        // Buffer ends before Rsp/SegSs.
        let buf = vec![0u8; 0x70];
        assert!(KtrapFrame::decode(&layout, 0, &buf).is_err());
    }
}
