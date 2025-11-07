# crypto-ratio

[![Crates.io](https://img.shields.io/crates/v/crypto-ratio.svg)](https://crates.io/crates/crypto-ratio)
[![Documentation](https://docs.rs/crypto-ratio/badge.svg)](https://docs.rs/crypto-ratio)
[![License](https://img.shields.io/crates/l/crypto-ratio.svg)](LICENSE)

Rational number arithmetic using crypto-bigint [crypto-bigint](https://github.com/RustCrypto/crypto-bigint).

Built for use in [RISC Zero](https://risczero.com) zkVM applications to leverage accelerated crypto-bigint precompiles with rational number operations.

## Features

- **Generic over integer width**: Works with U64, U256, U512, U1024, U2048, and all crypto-bigint types up to U16384 
- **RISC Zero optimized**: Designed to work with [RISC Zero's accelerated crypto-bigint precompiles](https://dev.risczero.com/api/zkvm/accelerators)
- **Performance-focused**: Deferred reduction and smart heuristics minimize expensive GCD operations
- **Overflow handling**: Automatic fallback to wider types when operations overflow 
- **no_std compatible**: Works in embedded, constrained, and zkVM environments

## Why RISC Zero?

This library was built to enable efficient rational number arithmetic in RISC Zero's zkVM, where [crypto-bigint operations are hardware-accelerated](https://dev.risczero.com/api/zkvm/precompiles) through precompiles. By building on crypto-bigint rather than num-bigint, this crate can leverage:

- **Hardware acceleration** for big integer operations in zkVM
- **Reduced cycle counts** for cryptographic workloads (U256 and U512 extrem fast)

Special thanks to the [RISC Zero team](https://risczero.com) for building an incredible zkVM platform and for their excellent documentation on accelerator usage.

## Installation

Add to your `Cargo.toml`:
```toml
[dependencies]
crypto-ratio = "0.1"
crypto-bigint = "0.5"
```

For RISC Zero zkVM guests:
```toml
[dependencies]
crypto-ratio = "0.1"
crypto-bigint = "0.5"
risc0-zkvm = { version = "3.0.3" }
```

## Quick Start
```rust
use crypto_ratio::{Ratio, RatioU512};
use crypto_bigint::U512;

// Create rationals
let a = RatioU512::from_u64(1, 2);  // 1/2
let b = RatioU512::from_u64(1, 3);  // 1/3

// Arithmetic operations
let sum = &a + &b;  // 5/6
let product = &a * &b;  // 1/6

// Explicit reduction when needed
let mut result = product;
result.normalize();

// Comparison
assert!(a > b);

// Float conversion
let r = RatioU512::from_float(0.75).unwrap();
assert_eq!(r.to_f64_approx(), 0.75);
```

## RISC Zero zkVM Example
```rust
use crypto_ratio::RatioU512;
use risc0_zkvm::guest::env;

pub fn main() {
    // Read inputs from host
    let a_numer: u64 = env::read();
    let a_denom: u64 = env::read();
    let b_numer: u64 = env::read();
    let b_denom: u64 = env::read();
    
    // Perform rational arithmetic (leverages crypto-bigint precompiles)
    let a = RatioU512::from_u64(a_numer, a_denom);
    let b = RatioU512::from_u64(b_numer, b_denom);
    
    let mut result = a.mul(&b);
    result.normalize();
    
    // Commit result
    env::commit(&result.numer.to_le_bytes());
    env::commit(&result.denom.to_le_bytes());
}
```

## Design Philosophy

### Unreduced Operations by Default

Operations like multiplication and addition return **unreduced** results for performance. Call `normalize()` explicitly when reduction is needed:
```rust
use crypto_ratio::RatioU256;

let a = RatioU256::from_u64(2, 3);
let b = RatioU256::from_u64(3, 4);

// Unreduced: 6/12
let product = &a * &b;

// Reduced: 1/2
let mut reduced = product;
reduced.normalize();
```

**Why?** In loops and chained operations, automatic reduction uses too much cycles:
```rust
// Bad: Reduces 100 times (expensive!)
let mut sum = RatioU512::zero();
for i in 0..100 {
    let term = RatioU512::from_u64(i, 1000);
    sum = sum + term;  // Auto-reduce would GCD here
}

// Good: Reduces once at the end
let mut sum = RatioU512::zero();
for i in 0..100 {
    let term = RatioU512::from_u64(i, 1000);
    sum = sum.add(&term);  // Unreduced
}
sum.normalize();  // Single GCD at the end
```

### Smart Reduction Heuristics

`mul_reduced()` provides automatic reduction using fast heuristics:
```rust
let a = RatioU512::from_u64(2, 3);
let b = RatioU512::from_u64(3, 4);

// Smart reduction uses:
// 1. Bit shifts for power-of-2 factors (~10ns)
// 2. Fast u64 GCD for small values (~50ns)
// 3. Skips GCD for large coprime values (~0ns)
let product = a.mul_reduced(&b);  // 1/2 (reduced)
```

### Generic Over Integer Width

Choose the size that fits your precision and performance needs:
Headsup: Perfromance decreases from U2048 onwards due to automatic wide types on overflow, fix coming soon. 
```rust
use crypto_ratio::{Ratio, RatioU256, RatioU512, RatioU1024};
use crypto_bigint::{U256, U512, U1024};

// Small: Fast operations, limited range
let small = RatioU256::from_u64(1, 2);

// Medium: Good balance (recommended)
let medium = RatioU512::from_u64(1, 2);

// Large: Maximum precision
let large = RatioU1024::from_u64(1, 2);

// Custom size
let custom = Ratio::<U256>::from_u64(1, 2);
```

### Overflow Handling

Operations automatically use wider types when needed:
```rust
use crypto_ratio::RatioU256;

// U256 operations may internally use U512
let a = RatioU256::from_u64(u64::MAX, 1);
let b = RatioU256::from_u64(u64::MAX, 1);

// This works! Uses U512 internally, reduces back to U256
let sum = a.add(&b);
```

## Real-World Example: Taylor Series

Computing e^x using Taylor series expansion demonstrates the performance benefits:
```rust
use crypto_ratio::RatioU512;
use crypto_bigint::U512;

fn exp_approx(x: RatioU512, terms: usize) -> RatioU512 {
    let mut result = RatioU512::one();
    let mut term = RatioU512::one();
    let mut factorial = U512::ONE;
    
    for n in 1..terms {
        factorial = factorial.wrapping_mul(&U512::from_u64(n as u64));
        term = term.mul(&x);
        
        let next_term = term.div_by_uint(&factorial);
        result = result.add(&next_term);
        
        // Only reduce when needed (heuristic-based)
        if result.needs_reduction() {
            result.normalize();
        }
    }
    
    result.normalize();
    result
}

let x = RatioU512::from_float(0.5).unwrap();
let e_to_half = exp_approx(x, 10);
println!("e^0.5 ≈ {}", e_to_half.to_f64_approx());
```

## Trade-offs

### Performance vs Automatic Reduction

| Approach | Pros | Cons | Best For |
|----------|------|------|----------|
| Unreduced (default) | 10-100x faster in loops | Manual `normalize()` calls | High-performance code, loops, zkVM |
| `mul_reduced()` | Smart, usually fast | Some overhead | General use, single operations |
| Always reduce | Simple API | Much slower | Prototyping |

### Integer Size Selection

| Size | Range | Speed | Memory | Use Case |
|------|-------|-------|--------|----------|
| U256 | ~77 decimal digits | Fastest | 32 bytes | Embedded, simple fractions, zkVM-optimized |
| U512 | ~154 decimal digits | Fast | 64 bytes | Embedded, zkVM-optimized **Recommended default** |
| U1024 | ~308 decimal digits | Moderate | 128 bytes | High precision |
| U2048+ | ~600+ decimal digits | Slower | 256+ bytes | Specialized applications (performance drops, num-bigint might be faster) |

## Performance

### Benchmark Overview

Typical performance on modern hardware (U512):

| Operation | Time | Speedup vs num-rational |
|-----------|------|-------------------------|
| Construction | ~15ns | 2-3x faster |
| Addition | ~30ns | 5-10x faster |
| Multiplication (unreduced) | ~25ns | 10-20x faster |
| Multiplication (reduced) | ~80ns | 3-5x faster |
| Comparison | ~35ns | 3-5x faster |
| GCD | ~200ns | 2-3x faster |
| Taylor Series (5 terms) | ~800ns | 8-12x faster |

## Running Tests
```bash
# Run all tests (2,300+ tests across 9 integer sizes)
cargo test

# Run tests for specific size
cargo test u256_tests
cargo test u512_tests

# Run specific test
cargo test test_addition_compatibility

# Run with output
cargo test -- --nocapture

# Run tests with all features
cargo test --all-features
```

## Running Benchmarks
```bash
# Run all benchmarks
cargo bench

# Run benchmarks for specific size
cargo bench U256
cargo bench U512

# Run specific operation
cargo bench multiplication
cargo bench taylor_series

# Run specific size + operation
cargo bench U512/multiplication

# Generate detailed report with violin plots
cargo bench -- --save-baseline main

# Compare against baseline
cargo bench -- --baseline main
```

Benchmark results are saved in `target/criterion/` with detailed HTML reports including:
- Violin plots showing distribution
- Regression analysis
- Historical comparison
- Statistical significance tests

### Viewing Benchmark Reports

After running benchmarks, open the HTML report:
```bash
# On macOS
open target/criterion/report/index.html

# On Linux
xdg-open target/criterion/report/index.html

# On Windows
start target/criterion/report/index.html
```

## API Overview

### Construction
```rust
// From u64 (with reduction)
let r = RatioU512::from_u64(2, 3);

// From float
let r = RatioU512::from_float(0.5).unwrap();

// Without reduction
let r = RatioU512::new_raw(numer, denom, false);

// With reduction
let r = RatioU512::new(numer, denom);
```

### Arithmetic
```rust
let a = RatioU512::from_u64(1, 2);
let b = RatioU512::from_u64(1, 3);

// Basic operations (unreduced)
let sum = &a + &b;
let diff = &a - &b;
let prod = &a * &b;
let quot = &a / &b;

// Negation
let neg = -a;

// Reciprocal
let recip = a.recip();
```

### Reduction
```rust
let mut r = RatioU512::from_u64(6, 8);

// Explicit reduction
r.normalize();  // Now 3/4

// Conditional reduction
if r.needs_reduction() {
    r.normalize();
}

// Smart multiplication
let a = RatioU512::from_u64(2, 3);
let b = RatioU512::from_u64(3, 4);
let prod = a.mul_reduced(&b);  // 1/2 (reduced)
```

### Comparison
```rust
let a = RatioU512::from_u64(1, 2);
let b = RatioU512::from_u64(1, 3);

assert!(a > b);
assert!(a >= b);
assert!(b < a);
assert!(a != b);
```

## no_std Support

This crate is `no_std` compatible (requires `alloc` for GCD operations):
```toml
[dependencies]
crypto-ratio = { version = "0.1", default-features = false }
```

Perfect for:
- Embedded systems
- RISC Zero zkVM guests
- WebAssembly
- Constrained environments

## Minimum Supported Rust Version (MSRV)

Rust 1.65 or later.

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run `cargo test` and `cargo bench`
5. Ensure `cargo clippy` passes
6. Submit a pull request

## Comparison with Alternatives

| Feature | crypto-ratio | num-rational | rug |
|---------|--------------|--------------|-----|
| Pure Rust | ✅ | ✅ | ❌ (GMP) |
| no_std | ✅ | ❌ | ❌ |
| RISC Zero zkVM | ✅ | ❌ | ❌ |
| Generic width | ✅ | ❌ | ✅ |
| Deferred reduction | ✅ | ❌ | ❌ |
| Compile-time size | ✅ | ❌ | ❌ |
| Accelerated precompiles | ✅ | ❌ | ❌ |
| Performance | High | Medium | Very High* |

*GMP performance only available in native code, not in zkVM environments.

**Choose crypto-ratio if you need**: RISC Zero zkVM support, pure Rust, no_std support, control over reduction, or compile-time size selection.

**Choose num-rational if you need**: Simple API with automatic reduction, dynamic sizing, don't need zkVM support.

**Choose rug if you need**: Maximum performance in native environments, don't mind GMP dependency.

## Acknowledgments

Built on [crypto-bigint](https://github.com/RustCrypto/crypto-bigint) by RustCrypto.

Designed for [RISC Zero](https://risczero.com) zkVM with support for hardware-accelerated big integer operations.

Inspired by [num-rational](https://github.com/rust-num/num-rational) with focus on stable performance and flexibility.

## Resources

- [RISC Zero Documentation](https://dev.risczero.com)
- [crypto-bigint Accelerators in RISC Zero](https://dev.risczero.com/api/zkvm/precompiles)
- [API Documentation](https://docs.rs/crypto-ratio)

---

**Questions?** Open an issue or discussion on [GitHub](https://github.com/sbcdn/crypto-ratio).