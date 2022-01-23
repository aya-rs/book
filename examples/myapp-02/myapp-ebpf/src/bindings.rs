/* automatically generated by rust-bindgen 0.59.1 */

#[repr(C)]
#[derive(Copy, Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct __BindgenBitfieldUnit<Storage> {
    storage: Storage,
}
impl<Storage> __BindgenBitfieldUnit<Storage> {
    #[inline]
    pub const fn new(storage: Storage) -> Self {
        Self { storage }
    }
}
impl<Storage> __BindgenBitfieldUnit<Storage>
where
    Storage: AsRef<[u8]> + AsMut<[u8]>,
{
    #[inline]
    pub fn get_bit(&self, index: usize) -> bool {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = self.storage.as_ref()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        byte & mask == mask
    }
    #[inline]
    pub fn set_bit(&mut self, index: usize, val: bool) {
        debug_assert!(index / 8 < self.storage.as_ref().len());
        let byte_index = index / 8;
        let byte = &mut self.storage.as_mut()[byte_index];
        let bit_index = if cfg!(target_endian = "big") {
            7 - (index % 8)
        } else {
            index % 8
        };
        let mask = 1 << bit_index;
        if val {
            *byte |= mask;
        } else {
            *byte &= !mask;
        }
    }
    #[inline]
    pub fn get(&self, bit_offset: usize, bit_width: u8) -> u64 {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        let mut val = 0;
        for i in 0..(bit_width as usize) {
            if self.get_bit(i + bit_offset) {
                let index = if cfg!(target_endian = "big") {
                    bit_width as usize - 1 - i
                } else {
                    i
                };
                val |= 1 << index;
            }
        }
        val
    }
    #[inline]
    pub fn set(&mut self, bit_offset: usize, bit_width: u8, val: u64) {
        debug_assert!(bit_width <= 64);
        debug_assert!(bit_offset / 8 < self.storage.as_ref().len());
        debug_assert!((bit_offset + (bit_width as usize)) / 8 <= self.storage.as_ref().len());
        for i in 0..(bit_width as usize) {
            let mask = 1 << i;
            let val_bit_is_set = val & mask == mask;
            let index = if cfg!(target_endian = "big") {
                bit_width as usize - 1 - i
            } else {
                i
            };
            self.set_bit(index + bit_offset, val_bit_is_set);
        }
    }
}
pub type __u8 = ::aya_bpf::cty::c_uchar;
pub type __u16 = ::aya_bpf::cty::c_ushort;
pub type __u32 = ::aya_bpf::cty::c_uint;
pub type __be16 = __u16;
pub type __be32 = __u32;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct ethhdr {
    pub h_dest: [::aya_bpf::cty::c_uchar; 6usize],
    pub h_source: [::aya_bpf::cty::c_uchar; 6usize],
    pub h_proto: __be16,
}
pub type __sum16 = __u16;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct iphdr {
    pub _bitfield_align_1: [u8; 0],
    pub _bitfield_1: __BindgenBitfieldUnit<[u8; 1usize]>,
    pub tos: __u8,
    pub tot_len: __be16,
    pub id: __be16,
    pub frag_off: __be16,
    pub ttl: __u8,
    pub protocol: __u8,
    pub check: __sum16,
    pub saddr: __be32,
    pub daddr: __be32,
}
impl iphdr {
    #[inline]
    pub fn ihl(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(0usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_ihl(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(0usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn version(&self) -> __u8 {
        unsafe { ::core::mem::transmute(self._bitfield_1.get(4usize, 4u8) as u8) }
    }
    #[inline]
    pub fn set_version(&mut self, val: __u8) {
        unsafe {
            let val: u8 = ::core::mem::transmute(val);
            self._bitfield_1.set(4usize, 4u8, val as u64)
        }
    }
    #[inline]
    pub fn new_bitfield_1(ihl: __u8, version: __u8) -> __BindgenBitfieldUnit<[u8; 1usize]> {
        let mut __bindgen_bitfield_unit: __BindgenBitfieldUnit<[u8; 1usize]> = Default::default();
        __bindgen_bitfield_unit.set(0usize, 4u8, {
            let ihl: u8 = unsafe { ::core::mem::transmute(ihl) };
            ihl as u64
        });
        __bindgen_bitfield_unit.set(4usize, 4u8, {
            let version: u8 = unsafe { ::core::mem::transmute(version) };
            version as u64
        });
        __bindgen_bitfield_unit
    }
}

impl<Storage> __BindgenBitfieldUnit<Storage> {}
impl ethhdr {
    pub fn h_dest(&self) -> Option<[::aya_bpf::cty::c_uchar; 6usize]> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_dest) }.ok()
    }
    pub fn h_source(&self) -> Option<[::aya_bpf::cty::c_uchar; 6usize]> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_source) }.ok()
    }
    pub fn h_proto(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.h_proto) }.ok()
    }
}
impl iphdr {
    pub fn tos(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.tos) }.ok()
    }
    pub fn tot_len(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.tot_len) }.ok()
    }
    pub fn id(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.id) }.ok()
    }
    pub fn frag_off(&self) -> Option<__be16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.frag_off) }.ok()
    }
    pub fn ttl(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.ttl) }.ok()
    }
    pub fn protocol(&self) -> Option<__u8> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.protocol) }.ok()
    }
    pub fn check(&self) -> Option<__sum16> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.check) }.ok()
    }
    pub fn saddr(&self) -> Option<__be32> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.saddr) }.ok()
    }
    pub fn daddr(&self) -> Option<__be32> {
        unsafe { ::aya_bpf::helpers::bpf_probe_read(&self.daddr) }.ok()
    }
}