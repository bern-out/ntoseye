//! x86-64 debug-register (DR7/DR6) bit encoding for hardware breakpoints.
//!
//! DR0-DR3 hold up to four linear breakpoint addresses; DR7 enables each slot
//! and selects its trigger condition (R/W) and width (LEN); DR6 reports which
//! slots fired (status bits B0-B3). These helpers are pure so the wire-level
//! per-processor read-modify-write in [`crate::kd`] stays trivial and the bit
//! math is unit-testable.

use crate::dbg_backend::HwBreakpointAccess;

/// DR7 R/W field for an access type (2 bits): 00 execute, 01 write, 11 r/w.
fn rw_field(access: HwBreakpointAccess) -> u64 {
    match access {
        HwBreakpointAccess::Execute => 0b00,
        HwBreakpointAccess::Write => 0b01,
        HwBreakpointAccess::ReadWrite => 0b11,
    }
}

/// DR7 LEN field for a watch width in bytes (2 bits). x86 uses a quirky
/// ordering: 1→00, 2→01, 8→10, 4→11. Falls back to 0 (1 byte) for widths the
/// caller should have rejected via [`crate::dbg_backend::validate_hw_breakpoint`].
fn len_field(len: u8) -> u64 {
    match len {
        2 => 0b01,
        8 => 0b10,
        4 => 0b11,
        _ => 0b00,
    }
}

/// Global-enable slot `slot` in `dr7` and write its R/W+LEN condition, clearing
/// any prior state for that slot. Uses the global-enable bit (Gn) so the watch
/// survives task switches — the right choice for kernel-wide breakpoints.
/// `(access, len)` must have passed [`crate::dbg_backend::validate_hw_breakpoint`].
pub fn dr7_set_slot(dr7: u64, slot: u8, access: HwBreakpointAccess, len: u8) -> u64 {
    let slot = slot as u64;
    let rw = rw_field(access);
    let len_bits = len_field(len);
    let enable_mask = 0b11u64 << (slot * 2); // Ln | Gn
    let control_mask = 0b1111u64 << (16 + slot * 4); // R/Wn | LENn
    let mut out = dr7 & !enable_mask & !control_mask;
    out |= 1u64 << (slot * 2 + 1); // Gn: global enable
    out |= (rw | (len_bits << 2)) << (16 + slot * 4);
    out |= 1u64 << 10; // reserved, read-as-one on x86
    out
}

/// Disable slot `slot` in `dr7` and zero its R/W+LEN fields, leaving the other
/// slots untouched.
pub fn dr7_clear_slot(dr7: u64, slot: u8) -> u64 {
    let slot = slot as u64;
    let enable_mask = 0b11u64 << (slot * 2);
    let control_mask = 0b1111u64 << (16 + slot * 4);
    dr7 & !enable_mask & !control_mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dbg_backend::HwBreakpointAccess;

    // --- Field extractors mirroring the x86 DR7 layout, so each test asserts
    // hardware-observable bit positions rather than restating dr7_set_slot's
    // arithmetic. Ln = bit 2n, Gn = bit 2n+1, R/W = bits 16+4n (width 2),
    // LEN = bits 18+4n (width 2).
    fn ln(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (2 * slot as u64)) & 1
    }
    fn gn(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (2 * slot as u64 + 1)) & 1
    }
    fn rw(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (16 + 4 * slot as u64)) & 0b11
    }
    fn len(dr7: u64, slot: u8) -> u64 {
        (dr7 >> (18 + 4 * slot as u64)) & 0b11
    }
    fn reserved10(dr7: u64) -> u64 {
        (dr7 >> 10) & 1
    }

    #[test]
    fn set_slot0_write_4_encodes_global_enable_rw_len_and_reserved() {
        let dr7 = dr7_set_slot(0, 0, HwBreakpointAccess::Write, 4);
        // Global enable, not local: kernel-wide watches must survive task switch.
        assert_eq!(gn(dr7, 0), 1, "Gn (bit 1) must be set");
        assert_eq!(ln(dr7, 0), 0, "Ln (bit 0) must stay clear");
        // Write => R/W 0b01; 4 bytes => LEN 0b11 (the quirky x86 ordering).
        assert_eq!(rw(dr7, 0), 0b01, "R/W field (bits 16-17) for Write");
        assert_eq!(len(dr7, 0), 0b11, "LEN field (bits 18-19) for 4 bytes");
        assert_eq!(reserved10(dr7), 1, "reserved bit 10 reads-as-one");
    }

    #[test]
    fn set_slot2_execute_1_encodes_zero_rw_zero_len() {
        let dr7 = dr7_set_slot(0, 2, HwBreakpointAccess::Execute, 1);
        // Execute => R/W 0b00; 1 byte => LEN 0b00. Both fields land in slot 2's
        // nibble at bits 24-27, not slot 0's.
        assert_eq!(rw(dr7, 2), 0b00, "R/W field (bits 24-25) for Execute");
        assert_eq!(len(dr7, 2), 0b00, "LEN field (bits 26-27) for 1 byte");
        assert_eq!(gn(dr7, 2), 1, "Gn for slot 2 (bit 5) must be set");
    }

    #[test]
    fn set_slot1_readwrite_8_encodes_the_len_quirk() {
        let dr7 = dr7_set_slot(0, 1, HwBreakpointAccess::ReadWrite, 8);
        // ReadWrite => R/W 0b11; 8 bytes => LEN 0b10, the value that would be
        // "2" under a naive linear encoding. This pins the x86 quirk.
        assert_eq!(rw(dr7, 1), 0b11, "R/W field (bits 20-21) for ReadWrite");
        assert_eq!(len(dr7, 1), 0b10, "LEN field (bits 22-23) for 8 bytes");
    }

    #[test]
    fn each_slot_uses_its_own_gn_bit_and_control_nibble() {
        // Set the same condition (Write, 2 bytes) in each slot in isolation and
        // assert the whole word: Gn at 2n+1, R/W 0b01 + LEN 0b01 at nibble
        // 16+4n, reserved bit 10, and nothing else. A misplaced shift reddens.
        for slot in 0u8..4 {
            let dr7 = dr7_set_slot(0, slot, HwBreakpointAccess::Write, 2);
            let expected = (1u64 << (2 * slot as u64 + 1))
                | (0b0101u64 << (16 + 4 * slot as u64))
                | (1u64 << 10);
            assert_eq!(dr7, expected, "slot {slot} must own exactly its bits");
        }
    }

    #[test]
    fn setting_a_slot_leaves_another_set_slot_intact() {
        let dr7 = dr7_set_slot(0, 0, HwBreakpointAccess::Write, 4);
        let dr7 = dr7_set_slot(dr7, 3, HwBreakpointAccess::ReadWrite, 8);
        // Slot 0 conditions untouched by the slot-3 write.
        assert_eq!(gn(dr7, 0), 1, "slot 0 Gn preserved");
        assert_eq!(ln(dr7, 0), 0, "slot 0 Ln preserved");
        assert_eq!(rw(dr7, 0), 0b01, "slot 0 R/W preserved");
        assert_eq!(len(dr7, 0), 0b11, "slot 0 LEN preserved");
        // Slot 3 conditions written correctly.
        assert_eq!(gn(dr7, 3), 1, "slot 3 Gn set");
        assert_eq!(rw(dr7, 3), 0b11, "slot 3 R/W ReadWrite");
        assert_eq!(len(dr7, 3), 0b10, "slot 3 LEN 8 bytes");
    }

    #[test]
    fn clear_slot_removes_its_bits_and_spares_others() {
        let dr7 = dr7_set_slot(0, 1, HwBreakpointAccess::Write, 2);
        let dr7 = dr7_set_slot(dr7, 0, HwBreakpointAccess::ReadWrite, 8);
        let cleared = dr7_clear_slot(dr7, 0);
        // Slot 0 enable + control fully gone.
        assert_eq!(gn(cleared, 0), 0, "slot 0 Gn cleared");
        assert_eq!(ln(cleared, 0), 0, "slot 0 Ln cleared");
        assert_eq!(rw(cleared, 0), 0b00, "slot 0 R/W cleared");
        assert_eq!(len(cleared, 0), 0b00, "slot 0 LEN cleared");
        // Slot 1 completely undisturbed.
        assert_eq!(gn(cleared, 1), 1, "slot 1 Gn preserved");
        assert_eq!(rw(cleared, 1), 0b01, "slot 1 R/W preserved");
        assert_eq!(len(cleared, 1), 0b01, "slot 1 LEN preserved");
    }

    #[test]
    fn clear_is_the_inverse_of_set_for_enable_and_control_fields() {
        // Starting from a dr7 with slot 1 already armed, arming then clearing
        // slot 0 must restore the word exactly (clear does not touch bit 10,
        // and set already set it, so `before` and the result coincide).
        let before = dr7_set_slot(0, 1, HwBreakpointAccess::Write, 2);
        let armed = dr7_set_slot(before, 0, HwBreakpointAccess::ReadWrite, 8);
        assert_eq!(
            dr7_clear_slot(armed, 0),
            before,
            "clearing slot 0 must undo exactly the slot-0 set"
        );
    }
}
