# dbk64
[![MIT License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![crates.io](https://img.shields.io/crates/v/dbk64.svg)](https://crates.io/crates/dbk64)

A simple library that uses cheat engines dbk64 driver to read/write process memory.

## Usage
This library is available on [crates.io](https://crates.io/crates/dbk64).

```text
[dependencies]
dbk64 = "0.0.3"
```

## Example
```rust
use dbk64::DBK64;

fn main() {
    let dbk64 = DBK64::open(None, 1234).unwrap(); // process id

    let base_addrses = dbk64.get_base_address().unwrap();

    dbk64
        .write_raw(
            base_addrses + 0xD976C9,
            &[0x48, 0x31, 0xc0, 0xFF, 0x86, 0x30, 0x08],
        )
        .unwrap();
    
}

```

## License
Licensed under [MIT License](https://opensource.org/licenses/MIT), see [LICENSE](LICENSE).
