use nix::sys::uio::{RemoteIoVec, process_vm_readv, process_vm_writev};
use nix::unistd::Pid;
use std::fs;
use std::io::{IoSlice, IoSliceMut};
use std::path::Path;

use crate::backend::MemoryOps;
use crate::error::{Error, Result};
use crate::types::PhysAddr;

const FOUR_GIB: u64 = 0x1_0000_0000;
const VMWARE_MIN_MEMORY: u64 = 0x0100_0000;
const VMWARE_MAX_MEMORY: u64 = 0x0100_0000_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MemoryRegion {
    start: u64,
    end: u64,
}

impl MemoryRegion {
    fn len(self) -> u64 {
        self.end - self.start
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Hypervisor {
    Kvm,
    Vmware,
}

impl Hypervisor {
    fn label(self) -> &'static str {
        match self {
            Self::Kvm => "KVM/QEMU",
            Self::Vmware => "VMware",
        }
    }

    fn low_memory_limit(self) -> u64 {
        match self {
            Self::Kvm => 0x8000_0000,
            Self::Vmware => 0xC000_0000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct VmProcess {
    pid: i32,
    hypervisor: Hypervisor,
}

#[derive(Debug)]
struct ProcMapRegion<'a> {
    memory: MemoryRegion,
    permissions: &'a str,
    offset: u64,
    path: Option<&'a str>,
}

pub struct LiveVmHandle {
    memory: MemoryRegion,
    pid: Pid,
    hypervisor: Hypervisor,
}

fn read_comm(proc_root: &Path, pid: i32) -> Option<String> {
    fs::read_to_string(proc_root.join(pid.to_string()).join("comm"))
        .ok()
        .map(|value| value.trim().to_string())
}

fn process_has_fd(process_path: &Path, target: &Path) -> bool {
    fs::read_dir(process_path.join("fd"))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|entry| fs::read_link(entry.path()).is_ok_and(|path| path == target))
}

fn discover_vm_processes(proc_root: &Path) -> Result<Vec<VmProcess>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir(proc_root)?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|value| value.parse::<i32>().ok())
        else {
            continue;
        };
        let process_path = entry.path();
        if !process_path.is_dir() {
            continue;
        }

        if process_has_fd(&process_path, Path::new("/dev/kvm")) {
            processes.push(VmProcess {
                pid,
                hypervisor: Hypervisor::Kvm,
            });
        } else if read_comm(proc_root, pid).as_deref() == Some("vmware-vmx") {
            processes.push(VmProcess {
                pid,
                hypervisor: Hypervisor::Vmware,
            });
        }
    }
    processes.sort_unstable_by_key(|process| process.pid);
    Ok(processes)
}

fn select_vm_process(processes: Vec<VmProcess>) -> Result<VmProcess> {
    match processes.as_slice() {
        [] => Err(Error::VmNotFound),
        [process] => Ok(*process),
        _ => {
            let choices = processes
                .iter()
                .map(|process| format!("{} PID {}", process.hypervisor.label(), process.pid))
                .collect::<Vec<_>>()
                .join(", ");
            Err(Error::MultipleVmProcesses(choices))
        }
    }
}

fn find_vm_process() -> Result<VmProcess> {
    select_vm_process(discover_vm_processes(Path::new("/proc"))?)
}

fn take_proc_map_field<'a>(input: &mut &'a str) -> Option<&'a str> {
    let trimmed = input.trim_start();
    if trimmed.is_empty() {
        return None;
    }
    let end = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    *input = &trimmed[end..];
    Some(&trimmed[..end])
}

fn parse_proc_map_region(line: &str) -> Option<ProcMapRegion<'_>> {
    let mut remaining = line;
    let address_range = take_proc_map_field(&mut remaining)?;
    let permissions = take_proc_map_field(&mut remaining)?;
    let offset = u64::from_str_radix(take_proc_map_field(&mut remaining)?, 16).ok()?;
    let _device = take_proc_map_field(&mut remaining)?;
    let _inode = take_proc_map_field(&mut remaining)?;
    let (start, end) = address_range.split_once('-')?;
    let start = u64::from_str_radix(start, 16).ok()?;
    let end = u64::from_str_radix(end, 16).ok()?;
    if end <= start {
        return None;
    }
    let path = remaining.trim_start();
    Some(ProcMapRegion {
        memory: MemoryRegion { start, end },
        permissions,
        offset,
        path: (!path.is_empty()).then_some(path),
    })
}

fn is_read_write(region: &ProcMapRegion<'_>) -> bool {
    region.permissions.as_bytes().starts_with(b"rw")
}

fn is_vmem_path(path: &str) -> bool {
    path.strip_suffix(" (deleted)")
        .unwrap_or(path)
        .ends_with(".vmem")
}

fn select_memory_region(hypervisor: Hypervisor, pid: i32, maps: &str) -> Result<MemoryRegion> {
    let regions = maps.lines().filter_map(parse_proc_map_region);
    match hypervisor {
        Hypervisor::Kvm => regions
            .filter(is_read_write)
            .map(|region| region.memory)
            .max_by_key(|region| region.len())
            .ok_or(Error::VmMemoryRegionNotFound {
                pid,
                hypervisor: hypervisor.label(),
            }),
        Hypervisor::Vmware => {
            // VMware backs guest RAM with one writable, offset-zero .vmem mapping.
            // Stay strict: the largest anonymous VMA is not evidence of GPA layout.
            let candidates = regions
                .filter(|region| {
                    is_read_write(region)
                        && region.offset == 0
                        && (VMWARE_MIN_MEMORY..=VMWARE_MAX_MEMORY).contains(&region.memory.len())
                        && region.path.is_some_and(is_vmem_path)
                })
                .map(|region| region.memory)
                .collect::<Vec<_>>();
            match candidates.as_slice() {
                [] => Err(Error::VmMemoryRegionNotFound {
                    pid,
                    hypervisor: hypervisor.label(),
                }),
                [region] => Ok(*region),
                _ => Err(Error::MultipleVmMemoryRegions {
                    pid,
                    count: candidates.len(),
                }),
            }
        }
    }
}

fn primary_memory_region(process: VmProcess) -> Result<MemoryRegion> {
    let path = Path::new("/proc")
        .join(process.pid.to_string())
        .join("maps");
    let maps = fs::read_to_string(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::PermissionDenied {
            Error::PtraceDenied {
                pid: process.pid,
                scope: read_ptrace_scope(),
            }
        } else {
            Error::Io(error)
        }
    })?;
    select_memory_region(process.hypervisor, process.pid, &maps)
}

fn gpa_to_offset(hypervisor: Hypervisor, gpa: PhysAddr, len: usize) -> Result<u64> {
    let len = u64::try_from(len).map_err(|_| Error::BadPhysicalAddress(gpa))?;
    let end = gpa.checked_add(len).ok_or(Error::BadPhysicalAddress(gpa))?;
    let low_memory_limit = hypervisor.low_memory_limit();
    if gpa < low_memory_limit && end <= low_memory_limit {
        return Ok(gpa);
    }
    if gpa >= FOUR_GIB {
        return Ok(gpa - (FOUR_GIB - low_memory_limit));
    }
    Err(Error::BadPhysicalAddress(gpa))
}

fn read_ptrace_scope() -> String {
    fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn probe_ptrace_access(pid: Pid, addr: u64) -> Result<()> {
    let mut probe = [0u8; 1];
    let remote_iov = RemoteIoVec {
        base: addr as usize,
        len: 1,
    };
    match process_vm_readv(pid, &mut [IoSliceMut::new(&mut probe)], &[remote_iov]) {
        Err(nix::Error::EPERM) => Err(Error::PtraceDenied {
            pid: pid.as_raw(),
            scope: read_ptrace_scope(),
        }),
        Err(error) => Err(error.into()),
        Ok(1) => Ok(()),
        Ok(bytes_read) => Err(Error::PartialRead(bytes_read)),
    }
}

impl LiveVmHandle {
    pub fn new() -> Result<Self> {
        let process = find_vm_process()?;
        let memory = primary_memory_region(process)?;
        let pid = Pid::from_raw(process.pid);
        probe_ptrace_access(pid, memory.start)?;
        Ok(Self {
            memory,
            pid,
            hypervisor: process.hypervisor,
        })
    }

    fn host_address(&self, gpa: PhysAddr, len: usize) -> Result<u64> {
        let offset = gpa_to_offset(self.hypervisor, gpa, len)?;
        let end_offset = offset
            .checked_add(len as u64)
            .ok_or(Error::BadPhysicalAddress(gpa))?;
        if end_offset > self.memory.len() {
            return Err(Error::BadPhysicalAddress(gpa));
        }
        self.memory
            .start
            .checked_add(offset)
            .ok_or(Error::BadPhysicalAddress(gpa))
    }
}

impl MemoryOps<PhysAddr> for LiveVmHandle {
    fn read_bytes(&self, addr: PhysAddr, buf: &mut [u8]) -> Result<()> {
        let hva = self.host_address(addr, buf.len())?;
        let remote_iov = RemoteIoVec {
            base: hva as usize,
            len: buf.len(),
        };
        let bytes_read = process_vm_readv(self.pid, &mut [IoSliceMut::new(buf)], &[remote_iov])?;
        if bytes_read != buf.len() {
            return Err(Error::PartialRead(bytes_read));
        }
        Ok(())
    }

    fn write_bytes(&self, addr: PhysAddr, buf: &[u8]) -> Result<()> {
        let hva = self.host_address(addr, buf.len())?;
        let remote_iov = RemoteIoVec {
            base: hva as usize,
            len: buf.len(),
        };
        let bytes_written = process_vm_writev(self.pid, &[IoSlice::new(buf)], &[remote_iov])?;
        if bytes_written != buf.len() {
            return Err(Error::PartialWrite(bytes_written));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_TEMP_DIR: AtomicU64 = AtomicU64::new(0);

    struct TempProcRoot(PathBuf);

    impl TempProcRoot {
        fn new() -> Self {
            let sequence = NEXT_TEMP_DIR.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "ntoseye-host-test-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempProcRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn discovery_skips_non_pid_entries_and_finds_each_hypervisor() {
        let proc_root = TempProcRoot::new();
        fs::create_dir(proc_root.0.join("fb")).unwrap();

        let kvm = proc_root.0.join("42");
        fs::create_dir_all(kvm.join("fd")).unwrap();
        symlink("/dev/kvm", kvm.join("fd/7")).unwrap();

        let vmware = proc_root.0.join("99");
        fs::create_dir(&vmware).unwrap();
        fs::write(vmware.join("comm"), "vmware-vmx\n").unwrap();

        assert_eq!(
            discover_vm_processes(&proc_root.0).unwrap(),
            vec![
                VmProcess {
                    pid: 42,
                    hypervisor: Hypervisor::Kvm,
                },
                VmProcess {
                    pid: 99,
                    hypervisor: Hypervisor::Vmware,
                },
            ]
        );
    }

    #[test]
    fn process_selection_requires_exactly_one_live_vm() {
        assert!(matches!(
            select_vm_process(Vec::new()),
            Err(Error::VmNotFound)
        ));
        let process = VmProcess {
            pid: 42,
            hypervisor: Hypervisor::Kvm,
        };
        assert_eq!(select_vm_process(vec![process]).unwrap(), process);
        assert!(matches!(
            select_vm_process(vec![
                process,
                VmProcess {
                    pid: 99,
                    hypervisor: Hypervisor::Vmware,
                },
            ]),
            Err(Error::MultipleVmProcesses(_))
        ));
    }

    #[test]
    fn vmware_region_is_a_unique_writable_vmem_mapping() {
        let maps = "\
10000000-12000000 rw-s 00000000 00:01 1 /tmp/Windows 11/Windows 11.vmem
20000000-40000000 rw-p 00000000 00:00 0
50000000-54000000 r--s 00000000 00:01 2 /tmp/read-only.vmem
";
        assert_eq!(
            select_memory_region(Hypervisor::Vmware, 99, maps).unwrap(),
            MemoryRegion {
                start: 0x1000_0000,
                end: 0x1200_0000,
            }
        );
    }

    #[test]
    fn vmware_region_accepts_deleted_vmem_path() {
        let maps = "10000000-12000000 rw-s 00000000 00:01 1 /tmp/Windows.vmem (deleted)\n";
        assert!(select_memory_region(Hypervisor::Vmware, 99, maps).is_ok());
    }

    #[test]
    fn vmware_region_rejects_missing_or_ambiguous_mappings() {
        let missing = "10000000-20000000 rw-p 00000000 00:00 0\n";
        assert!(matches!(
            select_memory_region(Hypervisor::Vmware, 99, missing),
            Err(Error::VmMemoryRegionNotFound {
                pid: 99,
                hypervisor: "VMware",
            })
        ));

        let ambiguous = "\
10000000-12000000 rw-s 00000000 00:01 1 /tmp/first.vmem
20000000-22000000 rw-s 00000000 00:01 2 /tmp/second.vmem
";
        assert!(matches!(
            select_memory_region(Hypervisor::Vmware, 99, ambiguous),
            Err(Error::MultipleVmMemoryRegions { pid: 99, count: 2 })
        ));
    }

    #[test]
    fn kvm_region_is_the_largest_read_write_mapping() {
        let maps = "\
10000000-50000000 ---p 00000000 00:00 0
60000000-62000000 rw-p 00000000 00:00 0
70000000-74000000 rw-s 00000000 00:01 1 /memfd:pc.ram
";
        assert_eq!(
            select_memory_region(Hypervisor::Kvm, 42, maps).unwrap(),
            MemoryRegion {
                start: 0x7000_0000,
                end: 0x7400_0000,
            }
        );
    }

    #[test]
    fn gpa_translation_rejects_mmio_holes_and_crossing_ranges() {
        for (hypervisor, low_memory_limit) in [
            (Hypervisor::Kvm, 0x8000_0000),
            (Hypervisor::Vmware, 0xC000_0000),
        ] {
            assert_eq!(
                gpa_to_offset(hypervisor, low_memory_limit - 1, 1).unwrap(),
                low_memory_limit - 1
            );
            assert!(matches!(
                gpa_to_offset(hypervisor, low_memory_limit - 1, 2),
                Err(Error::BadPhysicalAddress(address)) if address == low_memory_limit - 1
            ));
            assert!(matches!(
                gpa_to_offset(hypervisor, low_memory_limit, 1),
                Err(Error::BadPhysicalAddress(address)) if address == low_memory_limit
            ));
            assert!(matches!(
                gpa_to_offset(hypervisor, FOUR_GIB - 1, 1),
                Err(Error::BadPhysicalAddress(address)) if address == FOUR_GIB - 1
            ));
            assert_eq!(
                gpa_to_offset(hypervisor, FOUR_GIB, 1).unwrap(),
                low_memory_limit
            );
        }
        assert!(matches!(
            gpa_to_offset(Hypervisor::Vmware, u64::MAX, 2),
            Err(Error::BadPhysicalAddress(u64::MAX))
        ));
    }
}
