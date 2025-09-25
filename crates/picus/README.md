# Usage Instructions
This document describes how to use the Picus translator
## Build
From the `picus/` directory just run:

```
cargo build
```

## Run
To extract the AddSub chip run the following command from the top level directory:

```
./target/debug/zkm-picus --chip AddSub
```

This will produce a file called `AddSub.picus` inside of the directory `picus_output`. The directory can be overriden by setting the environment variable `PICUS_OUT_DIR`