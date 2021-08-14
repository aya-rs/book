#![no_std]

// ANCHOR: struct
#[repr(C)]
pub struct PacketLog {
    pub ipv4_address: u32,
    pub action: u32,
}
// ANCHOR_END: struct

// ANCHOR: pod
#[cfg(feature = "user")]
unsafe impl aya::Pod for PacketLog {}
// ANCHOR_END: pod