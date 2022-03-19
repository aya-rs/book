# Developing on Docker

## Setup

### Mac OS X (Docker for Mac)

#### Dockerfile

On Mac environments, Docker uses a fork of the Linux kernel called linuxkit, and
**necessary kernel headers are not available by default**. To look up your
kernel version, run `uname -r` in the linux VM. Then, you can install the
headers by adding the following to your Dockerfile:

```dockerfile
COPY --from=docker/for-desktop-kernel:desktop-<your-kernel-version> /kernel-dev.tar /
RUN tar xf kernel-dev.tar && rm kernel-dev.tar
```


#### Running the container:


```bash
docker run --rm --privileged -it -v /lib/modules:/lib/modules:ro -v /etc/localtime:/etc/localtime:ro -v /var/run/docker.sock:/var/run/docker.sock --pid=host <your-img>
```

### Linux


#### Running the container:

For Linux environments, you should additionally mount the kernel headers from `/usr/src`.

```bash
docker run --rm --privileged -it -v /lib/modules:/lib/modules:ro -v /usr/src:/usr/src:ro -v /etc/localtime:/etc/localtime:ro -v /var/run/docker.sock:/var/run/docker.sock <your-img>
```

## Troubleshooting

1. `BPF_PROG_LOAD syscall failed ... Operation not permitted (os error)`
	- On certain kernel versions (<= 5.10), you may run this an error due to
	insufficient memory available to the BPF process. **This can be fixed by
	running `ulimit -l unlimited`** or mounting the container with the `--ulimit
	<args>` option.