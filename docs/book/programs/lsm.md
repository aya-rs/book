# LSM

> [!EXAMPLE] Source Code
> Full code for the example in this chapter is available [on GitHub][source-code].

## What is LSM

LSM stands for [Linux Security Modules][lsm-wikipedia] which is a framework
which allows developers to write security systems on top of the Linux kernel.
It's also briefly described in
[the Linux kernel documentation][lsm-kernel-docs].

LSM is used by kernel modules or (since kernel 5.7) by eBPF programs. The most
popular modules that make use of LSM are AppArmor, SELinux, Smack and TOMOYO.
eBPF LSM programs allow developers to implement the same functionality
implemented by the modules just mentioned, using eBPF APIs.

The central concept behind LSM is **LSM hooks**. LSM hooks are exposed in key
locations in the kernel, and eBPF programs can attach to them to implement
custom security policies. Examples of operations that can be policied via hooks
include:

- filesystem operations
  - opening, creating, moving and removing files
  - mounting and unmounting filesystems
- task/process operations
  - allocating and freeing tasks, changing user and group identify for a task
- socket operations
  - creating and binding sockets
  - receiving and sending messages

Each of those actions has a corresponding LSM hook. Each hook takes a number of
arguments, which provides context about the program and it's operation in order
to implement policy decisions. The list of hooks with their arguments can be
found in the [lsm_hook_defs.h][lsm-hook-defs] header.

For example, consider the `task_setnice` hook, which has the following
definition:

```c
LSM_HOOK(int, 0, task_setnice, struct task_struct *p, int nice)
```

The hook is triggered when a nice value is set for any process in the system.
If you are not familiar with the concept of process niceness, check out
[this article][nice-wikipedia]. As you can see from the definition, this hook
takes the following arguments:

- `p` is the instance of `task_struct` which represents the process on which
  the nice value is set
- `nice` is the nice value

By attaching to the hook, an eBPF program can decide whether to accept or
reject the given nice value.

In addition to the arguments found in the hook definition, eBPF programs have
access to one extra argument - `ret` - which is a return value of potential
previous eBPF LSM programs.

## Ensure that BPF LSM is enabled

Before proceeding further and trying to write a BPF LSM program, please make
sure that:

- Your kernel version is at least 5.7.
- BPF LSM is enabled.

The second point can be checked with:

```console
$ cat /sys/kernel/security/lsm
capability,lockdown,landlock,yama,apparmor,bpf
```

The correct output should contain `bpf`. If it doesn't, BPF LSM has to be
manually enabled by adding it to kernel config parameters. It can be achieved
by editing the GRUB config in `/etc/default/grub` and adding the following to
the kernel parameters:

```console
GRUB_CMDLINE_LINUX="lsm=[YOUR CURRENTLY ENABLED LSMs],bpf"
```

Then rebuilding the GRUB configuration with any of the commands listed below
(each of them might be available or not in different Linux distributions):

```console
update-grub2
```

```console
grub2-mkconfig -o /boot/grub2/grub.cfg
```

```console
grub-mkconfig -o /boot/grub/grub.cfg
```

And finally, rebooting the system.

## Writing LSM BPF program

Let's try to create an LSM eBPF program which which is triggered by
`task_setnice` hook. The purpose of this program will be denying setting the
nice value lower than 0 (which means higher priority), for a particular process.

The `renice` tool can be used to change niceness values:

```console
renice [value] -p [pid]
```

With our eBPF program, we want to make it impossible to call `renice` for a
given `pid` with a negative `[value]`.

eBPF projects come with two parts: eBPF program(s) and the userspace program.
To make our example simple, we can try to deny a change of a nice value of
the userspace process which loads the eBPF program.

The first step is to create a new project:

```console
cargo generate --name lsm-nice -d program_type=lsm \
    -d lsm_hook=task_setnice https://github.com/aya-rs/aya-template
```

That command should create a new Aya project with an empty program attaching to
the `task_setnice` hook. Let's go to its directory:

```console
cd lsm-nice
```

One of the arguments passed to the `task_setnice` hook is a pointer to a
[task_struct type](https://elixir.bootlin.com/linux/v5.15.3/source/include/linux/sched.h#L723).
Therefore we need to generate a binding to `task_struct` with aya-tool.

> If you are not familiar with aya-tool, please refer to
> [this section](../aya/aya-tool.md).

```console
aya-tool generate task_struct > lsm-nice-ebpf/src/vmlinux.rs
```

Now it's time to modify the `lsm-nice-ebpf` project and write an actual program
there. The full program code should look like this:

```rust linenums="1" title="lsm-nice-ebpf/src/main.rs"
--8<-- "examples/lsm-nice/lsm-nice-ebpf/src/main.rs"
```

1. We include the autogenerated binding to `task_struct`:
1. Then we define a global variable `PID`. We initialize the value to 0, but at
runtime the userspace side will patch the value with the actual pid we're
interested in.
1. Finally we have the program and the logic what to do with nice values.

After that we also need to modify the userspace part. We don't need as much
work as with the eBPF part, but we need to:

1. Get the PID.
1. Log it.
1. Write it to the global variable in the eBPF object.

The final result should look like:

```rust linenums="1" title="lsm-nice/src/main.rs"
--8<-- "examples/lsm-nice/lsm-nice/src/main.rs"
```

1. Where we start with getting and logging a PID:
1. And then we set the global variable:

After that, we can build and run our project with:

```console
RUST_LOG=info cargo run --config 'target."cfg(all())".runner="sudo -E"'
```

The output should contain our log line showing the PID of the userspace
process, i.e.:

```console
16:32:30 [INFO] lsm_nice: [lsm-nice/src/main.rs:22] PID: 573354
```

Now we can try to change the nice value for that process. Setting a positive
value (lowering the priority) should still work:

```console
$ renice 10 -p 587184
587184 (process ID) old priority 0, new priority 10
```

But setting a negative value should not be allowed:

```console
$ renice -10 -p 587184
renice: failed to set priority for 587184 (process ID): Operation not permitted
```

If doing that resulted in `Operation not permitted`, congratulations, your LSM
eBPF program works!

[source-code]: https://github.com/aya-rs/book/tree/main/examples/lsm-nice
[lsm-wikipedia]: https://en.wikipedia.org/wiki/Linux_Security_Modules
[lsm-kernel-docs]: https://www.kernel.org/doc/html/latest/security/lsm.html
[lsm-hook-defs]: https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h
[nice-wikipedia]: https://en.wikipedia.org/wiki/Nice_(Unix)
