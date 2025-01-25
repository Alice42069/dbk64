# dbk64
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/dbk64.svg)](https://crates.io/crates/dbk64)

A simple library that uses cheat engines dbk64 driver to read/write process memory.

## Usage
This library is available on [crates.io](https://crates.io/crates/dbk64).

```text
[dependencies]
dbk64 = "0.0.1"
```

## Example
```rust
use dbk64::DBK64;

fn main() {
    let process_id = 12345_u64;

    let dbk64 = DBK64::open(None).unwrap();

    let process = dbk64.open_process(process_id as u32).unwrap();
    dbg!(&process);

    dbk64
        .write_raw(process_id, 0xDEADBEEF, b"Hello World")
        .unwrap();
}

```

## License
Licensed under [MIT License](https://opensource.org/licenses/MIT), see [LICENSE](LICENSE).