# [WIP] nodemap-core
Core library for nodemap

## Build and generate c++ code
```
cargo build --release
cxxbridge src/lib.rs --header > bridge/bridge.rs.h
cxxbridge src/lib.rs > bridge/bridge.rs.cc
```
