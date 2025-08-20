# MIPS toolchain Install

## Download toolchain
the musl toolchian can be downloaded from https://toolchains.bootlin.com/releases_mips32.html 
```
wget https://toolchains.bootlin.com/downloads/releases/toolchains/mips32/tarballs/mips32--musl--stable-2025.08-1.tar.xz

tar xvf mips32--musl--stable-2025.08-1.tar.xz -C ~/.zkm-toolchain/

```

## Create mipsel-zkm-zkvm-elf-gcc
Create mipsel-zkm-zkvm-elf-gcc file in the same directory with rustc
the file contents is as follows：
```
#!/bin/sh

exec ~/.zkm-toolchain/mips32--musl--stable-2025.08-1/bin/mips-buildroot-linux-musl-gcc -EL -msoft-float -fno-stack-protector $@
```
Add execution permission for this file
```
chmod +x mipsel-zkm-zkvm-elf-gcc
```
