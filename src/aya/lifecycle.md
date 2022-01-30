# Program Lifecycle

## BPF Object Lifecycle

BPF object lifecycle is tied to File Descriptors (FDs) returned from the `bpf` syscall.
Every time you create a program or map, retrieve a reference to a program/map, or attach
a program, you are given an FD and the Kernel increments its internal reference counter.
When the FD is closed, the reference count is decreased.
When it reaches 0, the kernel will unload/detach the BPF object.

There are some expections to the above, for example, when attachments are handled using another API (e.g netlink)

If you wish for your BPF object to outlive the program that creates it, you may
pin a BBPF object to BPFFS `/sys/fs/bpf`.

## Aya Object Lifecycle

When you call `load` or `load_file`, the FDs returned by map and program creation are
stored in the `Bpf` struct. Essentially these BPF objects are bound to the lifetime of the
`Bpf` struct.

When the `Bpf` struct goes out of scope (either because your program terminated or the variable
itself has gone out of scope), the `Drop` trait ensures that these file descriptors will be closed.

Ownership of `LinkRef`, returned from a call to `prog.attach()`, is **shared** with between your
program and the `Bpf` struct using a smart pointer. As such, your program link will stay alive
so long as either you, or the Bpf struct hold on to it. In other words:

1. When the `Bpf` struct goes out of scope, your `LinkRef` will also go out of scope and detach is triggered.
1. If your code lets the `LinkRef` go out of scope, then detach is triggered.

This can be illustrated in the following example:

```rust,ignore
use std::fs::File;
use std::convert::TryInto;
use aya::Bpf;
use aya::programs::{CgroupSkb, CgroupSkbAttachType};

fn main() {
    // load the BPF code
    let mut bpf = Bpf::load_file("bpf.o")?;
    load_program(&bpf);
    println!("my program is detached :(");
}

fn load_program(&mut Bpf) {
    // get the `ingress_filter` program compiled into `bpf.o`
    let ingress: &mut CgroupSkb = bpf.program_mut("ingress_filter")?.try_into()?;

    // load the program into the kernel
    ingress.load()?;

    // attach th program to the root cgroup. `ingress_filter` will be called for all
    // incoming packets.
    let cgroup = File::open("/sys/fs/cgroup/unified")?;

    ingress.attach(cgroup, CgroupSkbAttachType::Ingress)?;
}
```

When `load_program` is finished, the `Drop` trait of `LinkRef` - returned from `ingress.attach()` - closes the FD and the program is detached.
However, as the `Bpf` struct is still in scope, the program is still loaded in the kernel.

To avoid issues like this there are 2 recommendations:

1. Never ignore the return value of `attach()` - always use a `let` binding
2. Explicitly `std::mem::forget(link)`, which will effecitvely bind the lifecycle of the link to that of the `Bpf` struct