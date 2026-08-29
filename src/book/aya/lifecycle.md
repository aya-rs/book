# Program Lifecycle

In Aya, an instance of the `Ebpf` type manages the lifetime of all the eBPF
objects created through it.

Consider the following example:

```rust,ignore
use aya::Ebpf;
use aya::programs::{Xdp, XdpMode};

fn main() {
    {
        // (1)
        let mut bpf = Ebpf::load_file("bpf.o")?;

        let program: &mut Xdp = bpf.program_mut("xdp").unwrap().try_into().unwrap();
        // (2)
        program.load()?;
        // (3)
        program.attach("eth0", XdpMode::default()).unwrap();
    }
    // (4)

}
```

1. When you call `load` or `load_file`, all the maps referenced by the eBPF
   code are created and stored inside the returned `Ebpf` instance.
1. Similarly when you load a program to the kernel, it's stored inside the
   `Ebpf` instance.
1. When you attach a program, it stays attached until the parent `Ebpf` instance
   gets dropped.
1. At this point the `bpf` variable has been dropped. Our program and maps are
   detached/unloaded.
