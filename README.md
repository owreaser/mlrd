# mlrd / mallard 🦆

Handles ssh keys and hostnames, and lets you switch between hosts automatically
based on the current network (ex. public-facing and lan ip addresses depending
on wheither or not you're on the same network as your ssh-able server).

mlrd is made for Linux-based systems. There is no promise of success or support
on Windows/MacOS systems. The SSID detection feature is reliant on the `iw`
command.

mlrd saves your configuration to `~/.local/share/mallard`.

## How to Build mlrd

```bash
gcc ./src/mlrd.c -o mlrd -O3
```

If you want to install mlrd, you can move the executable to `/usr/bin/` or
something. I'm not responsible if something goes wrong when doing this.
