use crate::bugchecks::{BugcheckAnalysis, BugcheckTrapFrame};
use crate::gdb::breakpoints::Breakpoint;
use crate::target::{
    AddressDescription, AddressModule, DeviceObjectDetail, DriverObjectDetail, IoStackLocationInfo,
    IrpHit, IrpInfo, MemoryRegionInfo, MemorySearchMatch, NotifyCallback, ObjectHeaderDetail,
    PteLevel, SsdtTable, Target, irp_major_function_name, kthread_state_name, wait_reason_name,
};
use crate::trapframe::KtrapFrame;

// Shared shape for SDK/MCP structure rendering; surfaces disagree only on how
// address-like values are encoded.
/// A node in a neutral value tree.
pub enum View {
    /// An address/pointer/status: hex string for MCP, int for Python.
    Hex(u64),
    OptHex(Option<u64>),
    /// A plain count: a number on both surfaces.
    Num(u64),
    OptNum(Option<u64>),
    /// A signed count.
    Int(i64),
    Bool(bool),
    OptBool(Option<bool>),
    Str(String),
    OptStr(Option<String>),
    Null,
    List(Vec<View>),
    /// An ordered key/value object (insertion order is preserved on render).
    Object(Vec<(&'static str, View)>),
}

/// Render a [`View`] to JSON (MCP): addresses become `0x` hex strings.
#[cfg(feature = "mcp")]
pub fn to_json(v: &View) -> serde_json::Value {
    use serde_json::Value;
    match v {
        View::Hex(n) => Value::from(format!("{n:#x}")),
        View::OptHex(o) => o.map_or(Value::Null, |n| Value::from(format!("{n:#x}"))),
        View::Num(n) => Value::from(*n),
        View::OptNum(o) => o.map_or(Value::Null, Value::from),
        View::Int(n) => Value::from(*n),
        View::Bool(b) => Value::from(*b),
        View::OptBool(o) => o.map_or(Value::Null, Value::from),
        View::Str(s) => Value::from(s.clone()),
        View::OptStr(o) => o.clone().map_or(Value::Null, Value::from),
        View::Null => Value::Null,
        View::List(items) => Value::Array(items.iter().map(to_json).collect()),
        View::Object(fields) => {
            let mut map = serde_json::Map::new();
            for (key, val) in fields {
                map.insert((*key).to_string(), to_json(val));
            }
            Value::Object(map)
        }
    }
}

/// Render a [`View`] to a Python object (the SDK): addresses become plain ints.
#[cfg(feature = "python")]
pub fn to_py<'py>(
    py: pyo3::Python<'py>,
    v: &View,
) -> pyo3::PyResult<pyo3::Bound<'py, pyo3::PyAny>> {
    use pyo3::IntoPyObjectExt;
    use pyo3::prelude::*;
    use pyo3::types::{PyDict, PyList};
    Ok(match v {
        View::Hex(n) | View::Num(n) => n.into_bound_py_any(py)?,
        View::OptHex(o) | View::OptNum(o) => match o {
            Some(n) => n.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Int(n) => n.into_bound_py_any(py)?,
        View::Bool(b) => b.into_bound_py_any(py)?,
        View::OptBool(o) => match o {
            Some(b) => b.into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Str(s) => s.as_str().into_bound_py_any(py)?,
        View::OptStr(o) => match o {
            Some(s) => s.as_str().into_bound_py_any(py)?,
            None => py.None().into_bound(py),
        },
        View::Null => py.None().into_bound(py),
        View::List(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(to_py(py, item)?)?;
            }
            list.into_any()
        }
        View::Object(fields) => {
            let dict = PyDict::new(py);
            for (key, val) in fields {
                dict.set_item(key, to_py(py, val)?)?;
            }
            dict.into_any()
        }
    })
}

// --- builders: one decoded struct → its neutral shape ---

fn io_stack(s: &IoStackLocationInfo) -> View {
    View::Object(vec![
        ("address", View::Hex(s.address.0)),
        ("major_function", View::Num(s.major_function as u64)),
        (
            "major_function_name",
            View::Str(format!(
                "IRP_MJ_{}",
                irp_major_function_name(s.major_function)
            )),
        ),
        ("minor_function", View::Num(s.minor_function as u64)),
        ("device_object", View::Hex(s.device_object.0)),
        ("file_object", View::Hex(s.file_object.0)),
        ("completion_routine", View::Hex(s.completion_routine.0)),
        ("context", View::Hex(s.context.0)),
    ])
}

/// `_IRP` plus its current `_IO_STACK_LOCATION` (`current_stack` is null when the
/// stack slot is out of range or unreadable).
pub fn irp(irp: &IrpInfo) -> View {
    View::Object(vec![
        ("address", View::Hex(irp.address.0)),
        ("type", View::Num(irp.irp_type as u64)),
        ("size", View::Num(irp.size as u64)),
        ("stack_count", View::Num(irp.stack_count as u64)),
        ("current_location", View::Num(irp.current_location as u64)),
        ("pending_returned", View::Bool(irp.pending_returned)),
        ("requestor_mode", View::Num(irp.requestor_mode as u64)),
        ("io_status", View::OptHex(irp.io_status.map(|s| s as u64))),
        ("user_event", View::Hex(irp.user_event.0)),
        ("user_buffer", View::Hex(irp.user_buffer.0)),
        ("mdl_address", View::Hex(irp.mdl_address.0)),
        ("thread", View::Hex(irp.thread.0)),
        (
            "current_stack",
            irp.current_stack.as_ref().map_or(View::Null, io_stack),
        ),
    ])
}

/// `_DRIVER_OBJECT`: header fields, device chain, and the 28-entry `IRP_MJ_*`
/// dispatch table (each routine resolved to its nearest symbol).
pub fn driver_object(target: &Target, d: &DriverObjectDetail) -> View {
    let dtb = target.kernel_dtb();
    let devices = d
        .device_chain
        .iter()
        .map(|x| {
            View::Object(vec![
                ("device", View::Hex(x.device.0)),
                ("device_type", View::Num(x.device_type as u64)),
                ("flags", View::Num(x.flags as u64)),
                ("characteristics", View::Num(x.characteristics as u64)),
                ("attached", View::Hex(x.attached.0)),
                ("next", View::Hex(x.next.0)),
            ])
        })
        .collect();
    let dispatch = d
        .dispatch
        .iter()
        .enumerate()
        .map(|(i, f)| {
            View::Object(vec![
                ("index", View::Num(i as u64)),
                (
                    "name",
                    View::Str(format!("IRP_MJ_{}", irp_major_function_name(i as u8))),
                ),
                ("routine", View::Hex(f.0)),
                (
                    "symbol",
                    View::OptStr(target.symbols.format_closest_symbol_for_address(dtb, *f)),
                ),
            ])
        })
        .collect();
    View::Object(vec![
        ("object", View::Hex(d.object.0)),
        ("via_pointer", View::Bool(d.via_pointer)),
        ("name", View::OptStr(d.name.clone())),
        ("driver_start", View::Hex(d.driver_start.0)),
        ("driver_size", View::Num(d.driver_size)),
        ("driver_section", View::Hex(d.driver_section.0)),
        ("driver_unload", View::Hex(d.driver_unload.0)),
        ("devices", View::List(devices)),
        ("dispatch", View::List(dispatch)),
    ])
}

/// `_DEVICE_OBJECT` plus its `AttachedDevice` stack.
pub fn device_object(d: &DeviceObjectDetail) -> View {
    let stack = d
        .attached_stack
        .iter()
        .map(|x| {
            View::Object(vec![
                ("device", View::Hex(x.device.0)),
                ("driver_object", View::Hex(x.driver_object.0)),
                ("device_type", View::Num(x.device_type as u64)),
                ("flags", View::Num(x.flags as u64)),
            ])
        })
        .collect();
    View::Object(vec![
        ("object", View::Hex(d.object.0)),
        ("via_pointer", View::Bool(d.via_pointer)),
        ("device_type", View::Num(d.device_type as u64)),
        ("flags", View::Num(d.flags as u64)),
        ("characteristics", View::Num(d.characteristics as u64)),
        ("driver_object", View::Hex(d.driver_object.0)),
        ("attached_device", View::Hex(d.attached_device.0)),
        ("next_device", View::Hex(d.next_device.0)),
        ("current_irp", View::Hex(d.current_irp.0)),
        ("device_extension", View::Hex(d.device_extension.0)),
        ("attached_stack", View::List(stack)),
    ])
}

/// Executive `_OBJECT_HEADER` and the body it precedes.
pub fn object_header(o: &ObjectHeaderDetail) -> View {
    View::Object(vec![
        ("input", View::Hex(o.input.0)),
        ("mode", View::Str(o.mode.to_string())),
        ("header", View::Hex(o.header.0)),
        ("body", View::Hex(o.body.0)),
        ("pointer_count", View::Int(o.pointer_count)),
        ("handle_count", View::Int(o.handle_count)),
        ("type_index", View::OptNum(o.type_index)),
        ("type_object", View::OptHex(o.type_object.map(|t| t.0))),
        ("type_name", View::OptStr(o.type_name.clone())),
        ("info_mask", View::OptNum(o.info_mask.map(u64::from))),
        ("name_info", View::OptHex(o.name_info.map(|n| n.0))),
        ("name", View::OptStr(o.name.clone())),
    ])
}

/// One notification-callback row; `symbol` is resolved by the surface (it also
/// drives MCP's symbol filter) and passed in.
pub fn notify_callback(c: &NotifyCallback, symbol: Option<String>) -> View {
    View::Object(vec![
        ("kind", View::Str(c.kind.to_string())),
        ("index", View::Num(c.index as u64)),
        ("function", View::Hex(c.function.0)),
        ("symbol", View::OptStr(symbol)),
        ("block", View::Hex(c.block.0)),
        ("raw", View::Hex(c.raw.0)),
        ("context", View::Hex(c.context.0)),
    ])
}

/// One system-service table (the kernel SSDT or the win32k shadow).
pub fn ssdt_table(t: &SsdtTable) -> View {
    let entries = t
        .entries
        .iter()
        .map(|e| {
            View::Object(vec![
                ("index", View::Num(e.index as u64)),
                ("target", View::Hex(e.target.0)),
                ("symbol", View::OptStr(e.symbol.clone())),
                ("module", View::OptStr(e.module.clone())),
            ])
        })
        .collect();
    View::Object(vec![
        ("label", View::Str(t.label.clone())),
        ("base", View::Hex(t.base.0)),
        ("limit", View::Num(t.limit as u64)),
        ("entries", View::List(entries)),
    ])
}

/// One discovered in-flight IRP plus the context it was found in.
pub fn irp_hit(h: &IrpHit) -> View {
    View::Object(vec![
        ("irp", View::Hex(h.irp.0)),
        ("source", View::Str(h.source.to_string())),
        ("stack_count", View::Num(h.stack_count as u64)),
        ("current_location", View::Num(h.current_location as u64)),
        ("pid", View::OptNum(h.pid)),
        ("tid", View::OptNum(h.tid)),
        ("ethread", View::OptHex(h.ethread.map(|e| e.0))),
        (
            "state",
            View::OptStr(h.state.map(|s| kthread_state_name(s).to_string())),
        ),
        (
            "wait_reason",
            View::OptStr(h.wait_reason.map(|r| wait_reason_name(r).to_string())),
        ),
        ("driver", View::OptStr(h.driver.clone())),
        ("device", View::OptHex(h.device.map(|d| d.0))),
    ])
}

/// What an address belongs to (the loaded module/section, the process VAD
/// region, or nothing recognized).
fn address_module(m: &AddressModule) -> View {
    View::Object(vec![
        ("name", View::Str(m.name.clone())),
        ("base", View::Hex(m.base.0)),
        ("size", View::Num(m.size as u64)),
        ("offset", View::Hex(m.offset)),
    ])
}

fn memory_region(r: &MemoryRegionInfo) -> View {
    View::Object(vec![
        ("start", View::Hex(r.start.0)),
        ("end", View::Hex(r.end.0)),
        ("protection", View::OptNum(r.protection)),
        ("vad_type", View::OptNum(r.vad_type)),
        ("private_memory", View::OptBool(r.private_memory)),
        ("commit_charge", View::OptNum(r.commit_charge)),
        ("details", View::OptStr(r.details.clone())),
    ])
}

pub fn address_description(d: &AddressDescription) -> View {
    let module = d.module.as_ref().map_or(View::Null, address_module);
    let region = d.region.as_ref().map_or(View::Null, memory_region);
    View::Object(vec![
        ("address", View::Hex(d.address.0)),
        ("dtb", View::Hex(d.dtb)),
        ("kind", View::Str(d.kind.to_string())),
        ("module", module),
        ("section", View::OptStr(d.section.clone())),
        ("va_type", View::OptStr(d.va_type.clone())),
        ("region", region),
    ])
}

/// One structured memory-search hit.
pub fn memory_search_match(m: &MemorySearchMatch) -> View {
    let d = &m.description;
    View::Object(vec![
        ("address", View::Hex(m.address.0)),
        ("offset", View::Hex(m.offset)),
        ("symbol", View::OptStr(m.symbol.clone())),
        ("kind", View::Str(d.kind.to_string())),
        (
            "module",
            d.module.as_ref().map_or(View::Null, address_module),
        ),
        ("section", View::OptStr(d.section.clone())),
        ("va_type", View::OptStr(d.va_type.clone())),
        (
            "region",
            d.region.as_ref().map_or(View::Null, memory_region),
        ),
    ])
}

/// One page-table level (WinDbg-style flags).
pub fn pte_level(pte: &PteLevel) -> View {
    View::Object(vec![
        ("level", View::Str(pte.name.clone())),
        ("address", View::Hex(pte.address.0)),
        ("value", View::Hex(pte.value.0)),
        ("pfn", View::Hex(pte.value.pfn())),
        ("present", View::Bool(pte.value.is_present())),
        ("large_page", View::Bool(pte.value.is_large_page())),
        ("writable", View::Bool(pte.value.is_writable())),
        ("user", View::Bool(pte.value.is_user())),
        ("nx", View::Bool(pte.value.is_nx())),
        ("flags", View::Str(pte.value.flags())),
    ])
}

/// A decoded bugcheck (BSOD): code/name/description, its four parameters, and the
/// faulting instruction when one was identified.
pub fn bugcheck(a: &BugcheckAnalysis) -> View {
    let args = a
        .args
        .iter()
        .enumerate()
        .map(|(i, arg)| {
            View::Object(vec![
                ("index", View::Num((i + 1) as u64)),
                ("value", View::Hex(arg.value)),
                ("description", View::Str(arg.description.clone())),
            ])
        })
        .collect();
    let fault = a.fault.as_ref().map_or(View::Null, |f| {
        View::Object(vec![
            ("ip", View::Hex(f.ip)),
            ("symbol", View::Str(f.symbol.clone())),
            ("driver", View::OptStr(f.driver.clone())),
        ])
    });
    let trap_frames = a.trap_frames.iter().map(bugcheck_trap_frame).collect();
    View::Object(vec![
        ("code", View::Num(a.code as u64)),
        ("code_hex", View::Str(format!("{:#010x}", a.code))),
        ("name", View::Str(a.name.clone())),
        ("description", View::OptStr(a.description.clone())),
        ("driver", View::OptStr(a.driver.clone())),
        ("source", View::OptStr(a.source.clone())),
        ("args", View::List(args)),
        ("fault", fault),
        ("trap_frames", View::List(trap_frames)),
    ])
}

fn ktrap_frame_registers(frame: &KtrapFrame) -> View {
    View::Object(vec![
        ("rax", View::Hex(frame.rax)),
        ("rbx", View::Hex(frame.rbx)),
        ("rcx", View::Hex(frame.rcx)),
        ("rdx", View::Hex(frame.rdx)),
        ("rsi", View::Hex(frame.rsi)),
        ("rdi", View::Hex(frame.rdi)),
        ("rbp", View::Hex(frame.rbp)),
        ("rsp", View::Hex(frame.rsp)),
        ("r8", View::Hex(frame.r8)),
        ("r9", View::Hex(frame.r9)),
        ("r10", View::Hex(frame.r10)),
        ("r11", View::Hex(frame.r11)),
        ("rip", View::Hex(frame.rip)),
        ("cs", View::Hex(frame.cs as u64)),
        ("ss", View::Hex(frame.ss as u64)),
        ("eflags", View::Hex(frame.eflags as u64)),
        ("error_code", View::Hex(frame.error_code)),
        ("previous_mode", View::Num(frame.previous_mode as u64)),
        ("previous_irql", View::Num(frame.previous_irql as u64)),
    ])
}

/// A decoded `_KTRAP_FRAME` shared by structured host APIs.
pub fn trap_frame(frame: &KtrapFrame, rip_symbol: Option<String>) -> View {
    View::Object(vec![
        ("address", View::Hex(frame.address)),
        ("rip_symbol", View::OptStr(rip_symbol)),
        ("frame", ktrap_frame_registers(frame)),
    ])
}

/// A trap frame carried by a bugcheck parameter: its address, the symbol at
/// the interrupted `rip`, and either the decoded `_KTRAP_FRAME` registers or
/// the reason decoding failed.
pub fn bugcheck_trap_frame(tf: &BugcheckTrapFrame) -> View {
    View::Object(vec![
        ("address", View::Hex(tf.address)),
        ("rip_symbol", View::OptStr(tf.rip_symbol.clone())),
        (
            "frame",
            tf.frame.as_ref().map_or(View::Null, ktrap_frame_registers),
        ),
        ("error", View::OptStr(tf.error.clone())),
    ])
}

/// One code-breakpoint/data-watchpoint row (MCP `list_breakpoints`); the
/// `watch_*` fields are null for code breakpoints, and the Python handle keeps
/// the same field set in its cached snapshot.
pub fn breakpoint(bp: &Breakpoint) -> View {
    View::Object(vec![
        ("id", View::Num(bp.id.into())),
        ("address", View::Hex(bp.address.0)),
        ("enabled", View::Bool(bp.enabled)),
        ("symbol", View::OptStr(bp.symbol.clone())),
        ("scope", View::Str(bp.scope.label())),
        ("condition", View::OptStr(bp.condition.clone())),
        ("temporary", View::Bool(bp.temporary)),
        (
            "watch_access",
            View::OptStr(bp.watch_access_name().map(str::to_string)),
        ),
        (
            "watch_length",
            View::OptNum(bp.watch_length().map(u64::from)),
        ),
    ])
}

#[cfg(all(test, feature = "mcp"))]
mod tests {
    use super::{bugcheck_trap_frame, to_json, trap_frame};
    use crate::bugchecks::BugcheckTrapFrame;
    use crate::trapframe::KtrapFrame;

    #[test]
    fn bugcheck_trap_frame_exposes_decode_failure() {
        let view = bugcheck_trap_frame(&BugcheckTrapFrame {
            address: 0xffff_8000_1234_5000,
            frame: None,
            rip_symbol: None,
            error: Some("type `_KTRAP_FRAME` not found".to_string()),
        });
        let json = to_json(&view);
        assert!(json["frame"].is_null());
        assert_eq!(json["error"], "type `_KTRAP_FRAME` not found");
    }

    #[test]
    fn standalone_trap_frame_has_shared_structured_shape() {
        let frame = KtrapFrame {
            address: 0xffff_f800_1234_5000,
            rax: 1,
            rbx: 2,
            rcx: 3,
            rdx: 4,
            rsi: 5,
            rdi: 6,
            rbp: 7,
            rsp: 8,
            r8: 9,
            r9: 10,
            r10: 11,
            r11: 12,
            rip: 0xffff_f800_4321_1000,
            cs: 0x10,
            ss: 0x18,
            eflags: 0x202,
            error_code: 0,
            previous_mode: 0,
            previous_irql: 2,
        };
        let json = to_json(&trap_frame(&frame, Some("nt!KiDispatchException".into())));
        assert_eq!(json["address"], "0xfffff80012345000");
        assert_eq!(json["rip_symbol"], "nt!KiDispatchException");
        assert_eq!(json["frame"]["rip"], "0xfffff80043211000");
        assert_eq!(json["frame"]["previous_irql"], 2);
    }
}
