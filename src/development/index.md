# Development

## Requirements

Aya eBPF and user-space programs **require a Linux distribution and kernel that
supports eBPF**.

To verify that your kernel was compiled with the necessary flags, check the
kernel configuration file (typically under `/boot/config-$(uname -r)` or
`/proc/config.gz`) and verify that the following flags are set:


```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
# [optional, for tc filters]
CONFIG_NET_CLS_BPF=m
# [optional, for tc actions]
CONFIG_NET_ACT_BPF=m
CONFIG_BPF_JIT=y
CONFIG_HAVE_BPF_JIT=y
# [optional, for kprobes]
CONFIG_BPF_EVENTS=y
```

## Additional requirements

### For BTF / CO-RE support (aya-gen)

If you are developing Aya programs that leverage CO-RE support (using
**aya-gen**), you need will need kernel headers & a BTF file present in your
development environment so that aya-gen can generate the necessary bindings for
your project:

- Ensure that kernel headers are present in your environment (see [special
instructions](./docker.md#mac-os-x-docker-for-mac) for Docker for Mac)
- Ensure that that your kernel is built with the `CONFIG_DEBUG_INFO_BTF` enabled
& that a btf file exists under the default path of `sys/kernel/btf/vmlinux`) for
aya-gen to use **OR**
- If your development machine does not come with embdedded BTF information, you 
can download the type information from a respository such as [BTFHub-archive](https://github.com/aquasecurity/btfhub-archive/) or generate the type
information yourself by recompiling the linux kernel w/ `CONFIG_DEBUG_INFO_BTF` 
enabled.