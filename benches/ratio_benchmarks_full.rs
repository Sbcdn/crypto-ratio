//! Benchmarks comparing Ratio<T> performance across multiple integer sizes
//!
//! Run with: cargo bench --bench ratio_benchmarks
//!
//! This benchmark suite tests Ratio<T> implementations for multiple integer sizes:
//! - U256: Common cryptographic size (256-bit)
//! - U512: Standard size, baseline for comparison (512-bit)
//! - U1024: Large cryptographic operations (1024-bit)
//! - U2048: Very large computations (2048-bit)
//!
//! Each size is benchmarked against num-bigint/num-rational to measure
//! performance improvements in lottery verification and similar workloads.
//!
//! Key Performance Metrics:
//! - Construction (from_u64, from_float)
//! - Arithmetic operations (add, mul, div)
//! - Comparison operations
//! - GCD computation
//! - Real-world workloads (Taylor series, lottery computation)

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_bigint::{Encoding, U1024, U2048, U256, U512};
use crypto_ratio::WideInteger;
use num_bigint::BigInt;
use num_rational::Ratio as NumRatio;

type NumRational = NumRatio<BigInt>;

const LN_ONE_MINUS_PHI: f64 = -0.22314355131420976; // ln(1-0.8)

/// Macro to generate complete benchmark suite for a given integer type
macro_rules! generate_ratio_benchmarks {
    ($mod_name:ident, $uint_type:ty, $ratio_type:ty, $size_name:expr) => {
        mod $mod_name {
            use super::*;

            type TestUint = $uint_type;
            type TestRatio = $ratio_type;

            // ====================================================================
            // BASIC OPERATIONS
            // ====================================================================

            /// Benchmark creating rationals from u64 pairs
            pub fn bench_from_u64(c: &mut Criterion) {
                let bench_name = format!("{}/from_u64", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                group.bench_function("Ratio", |b| {
                    b.iter(|| {
                        let r = TestRatio::from_u64(black_box(12345), black_box(67890));
                        black_box(r);
                    })
                });

                group.bench_function("num-rational", |b| {
                    b.iter(|| {
                        let r = NumRational::new(
                            black_box(BigInt::from(12345)),
                            black_box(BigInt::from(67890)),
                        );
                        black_box(r);
                    })
                });

                group.finish();
            }

            /// Benchmark creating rationals from floating point
            pub fn bench_from_float(c: &mut Criterion) {
                let bench_name = format!("{}/from_float", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("small", 0.5),
                    ("medium", 0.22314355131420976),
                    ("tiny", 0.00001),
                ];

                for (name, value) in test_cases {
                    group.bench_with_input(BenchmarkId::new("Ratio", name), &value, |b, &val| {
                        b.iter(|| {
                            let r = TestRatio::from_float(black_box(val)).unwrap();
                            black_box(r);
                        })
                    });

                    group.bench_with_input(
                        BenchmarkId::new("num-rational", name),
                        &value,
                        |b, &val| {
                            b.iter(|| {
                                let r = NumRational::from_float(black_box(val)).unwrap();
                                black_box(r);
                            })
                        },
                    );
                }

                group.finish();
            }

            /// Benchmark addition: tests same denominator (fast path) and different denominators
            pub fn bench_addition(c: &mut Criterion) {
                let bench_name = format!("{}/addition", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("same_denom", (1u64, 6u64), (2u64, 6u64)),
                    ("diff_denom", (1u64, 2u64), (1u64, 3u64)),
                    ("large", (999999u64, 1000000u64), (999998u64, 1000001u64)),
                ];

                for (name, (n1, d1), (n2, d2)) in test_cases {
                    let r1 = TestRatio::from_u64(n1, d1);
                    let r2 = TestRatio::from_u64(n2, d2);

                    group.bench_with_input(
                        BenchmarkId::new("Ratio", name),
                        &(r1.clone(), r2.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1.add(black_box(r2));
                                black_box(result);
                            })
                        },
                    );

                    let r1_num = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                    let r2_num = NumRational::new(BigInt::from(n2), BigInt::from(d2));

                    group.bench_with_input(
                        BenchmarkId::new("num-rational", name),
                        &(r1_num.clone(), r2_num.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1 + black_box(r2);
                                black_box(result);
                            })
                        },
                    );
                }

                group.finish();
            }

            /// Benchmark multiplication: unreduced vs smart reduction vs always-reduced
            pub fn bench_multiplication(c: &mut Criterion) {
                let bench_name = format!("{}/multiplication", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("small", (2u64, 3u64), (3u64, 4u64)),
                    ("medium", (12345u64, 67890u64), (98765u64, 43210u64)),
                    ("large", (999999u64, 1000000u64), (1000000u64, 999999u64)),
                ];

                for (name, (n1, d1), (n2, d2)) in test_cases {
                    let r1 = TestRatio::from_u64(n1, d1);
                    let r2 = TestRatio::from_u64(n2, d2);

                    // Unreduced multiplication (fastest)
                    group.bench_with_input(
                        BenchmarkId::new("Ratio_unreduced", name),
                        &(r1.clone(), r2.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1.mul(black_box(r2));
                                black_box(result);
                            })
                        },
                    );

                    // Smart reduction (heuristic-based)
                    group.bench_with_input(
                        BenchmarkId::new("Ratio_reduced", name),
                        &(r1.clone(), r2.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1.mul_reduced(black_box(r2));
                                black_box(result);
                            })
                        },
                    );

                    // num-rational (always reduces)
                    let r1_num = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                    let r2_num = NumRational::new(BigInt::from(n2), BigInt::from(d2));

                    group.bench_with_input(
                        BenchmarkId::new("num-rational", name),
                        &(r1_num.clone(), r2_num.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1 * black_box(r2);
                                black_box(result);
                            })
                        },
                    );
                }

                group.finish();
            }

            /// Benchmark comparison operations (uses cross-multiplication)
            pub fn bench_comparison(c: &mut Criterion) {
                let bench_name = format!("{}/comparison", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("similar", (1u64, 2u64), (1u64, 3u64)),
                    ("large_diff", (1u64, 1000000u64), (999999u64, 1000000u64)),
                ];

                for (name, (n1, d1), (n2, d2)) in test_cases {
                    let r1 = TestRatio::from_u64(n1, d1);
                    let r2 = TestRatio::from_u64(n2, d2);

                    group.bench_with_input(
                        BenchmarkId::new("Ratio", name),
                        &(r1.clone(), r2.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1.gt(black_box(r2));
                                black_box(result);
                            })
                        },
                    );

                    let r1_num = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                    let r2_num = NumRational::new(BigInt::from(n2), BigInt::from(d2));

                    group.bench_with_input(
                        BenchmarkId::new("num-rational", name),
                        &(r1_num.clone(), r2_num.clone()),
                        |b, (r1, r2)| {
                            b.iter(|| {
                                let result = r1 > black_box(r2);
                                black_box(result);
                            })
                        },
                    );
                }

                group.finish();
            }

            /// Benchmark GCD computation (critical for reduction)
            pub fn bench_gcd(c: &mut Criterion) {
                let bench_name = format!("{}/gcd", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("small", 48u64, 18u64),
                    ("medium", 123456u64, 789012u64),
                    ("large", u64::MAX / 7, u64::MAX / 11),
                    ("coprime", 999983u64, 999979u64), // Two large primes
                ];

                for (name, a, b) in test_cases {
                    group.bench_with_input(
                        BenchmarkId::new("Ratio", name),
                        &(a, b),
                        |bench, &(a, b)| {
                            bench.iter(|| {
                                let result = TestUint::gcd(
                                    black_box(TestUint::from_u64(a)),
                                    black_box(TestUint::from_u64(b)),
                                );
                                black_box(result);
                            })
                        },
                    );

                    group.bench_with_input(
                        BenchmarkId::new("num-bigint", name),
                        &(a, b),
                        |bench, &(a, b)| {
                            bench.iter(|| {
                                use num_integer::Integer;
                                let result =
                                    BigInt::from(black_box(a)).gcd(&BigInt::from(black_box(b)));
                                black_box(result);
                            })
                        },
                    );
                }

                group.finish();
            }

            /// Benchmark explicit normalization/reduction
            pub fn bench_reduction(c: &mut Criterion) {
                let bench_name = format!("{}/reduction", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                let test_cases = vec![
                    ("small", (6u64, 8u64)),
                    ("medium", (123456u64, 789012u64)),
                    ("coprime", (999983u64, 999979u64)), // Two large primes - no reduction
                ];

                for (name, (n, d)) in test_cases {
                    group.bench_with_input(
                        BenchmarkId::new("Ratio", name),
                        &(n, d),
                        |b, &(n, d)| {
                            b.iter(|| {
                                let mut r = TestRatio::new_raw(
                                    TestUint::from_u64(n),
                                    TestUint::from_u64(d),
                                    false,
                                );
                                r.normalize();
                                black_box(r);
                            })
                        },
                    );

                    group.bench_with_input(
                        BenchmarkId::new("num-rational", name),
                        &(n, d),
                        |b, &(n, d)| {
                            b.iter(|| {
                                let r = NumRational::new(
                                    black_box(BigInt::from(n)),
                                    black_box(BigInt::from(d)),
                                );
                                black_box(r);
                            })
                        },
                    );
                }

                group.finish();
            }

            // ====================================================================
            // REAL-WORLD WORKLOADS
            // ====================================================================

            /// Benchmark Taylor series computation (e^x approximation)
            /// Pattern: φ = 1 + x + x²/2! + x³/3! + ...
            /// This simulates lottery verification workload
            pub fn bench_taylor_series(c: &mut Criterion) {
                let bench_name = format!("{}/taylor_series", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                // Adjust iterations based on integer size to avoid overflow
                let iterations = if TestUint::BITS <= 256 { 3 } else { 5 };

                group.bench_function("Ratio", |b| {
                    let x = TestRatio::from_u64(1, 10);

                    b.iter(|| {
                        let mut phi = TestRatio::one();
                        let mut new_x = x.clone();
                        let mut divisor = TestUint::ONE;

                        for _ in 0..iterations {
                            phi = phi.add(&new_x);
                            divisor = divisor.wrapping_add(&TestUint::ONE);
                            new_x = new_x.mul(&x).div_by_uint(&divisor);

                            if phi.needs_reduction() {
                                phi.normalize();
                            }
                        }

                        black_box(phi);
                    })
                });

                group.bench_function("num-rational", |b| {
                    let x = NumRational::new(BigInt::from(1), BigInt::from(10));

                    b.iter(|| {
                        let mut phi = NumRational::new(BigInt::from(1), BigInt::from(1));
                        let mut new_x = x.clone();
                        let mut divisor = BigInt::from(1);

                        for _ in 0..iterations {
                            phi = phi + &new_x;
                            divisor = divisor + 1;
                            new_x = &new_x * &x / &divisor;
                        }

                        black_box(phi);
                    })
                });

                group.finish();
            }

            /// Benchmark complete lottery verification computation
            /// This is the primary use case for this library
            pub fn bench_lottery_computation(c: &mut Criterion) {
                let bench_name = format!("{}/lottery_computation", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                group.bench_function("Ratio", |b| {
                    b.iter(|| {
                        let ev = TestUint::from_u128(12345678901234567890);
                        let ev_max = TestUint::MAX;
                        let denominator = ev_max.wrapping_sub(&ev);
                        let q = TestRatio::new_raw(ev_max, denominator, false);

                        let c = TestRatio::from_float(LN_ONE_MINUS_PHI).unwrap();
                        let w = TestRatio::from_u64(1000, 10000);
                        let x = w.mul(&c).neg();
                        let phi = TestRatio::one().add(&x);
                        let result = q.lt(&phi);

                        black_box(result);
                    })
                });

                group.bench_function("num-rational", |b| {
                    b.iter(|| {
                        let ev_bytes = TestUint::from_u128(12345678901234567890).to_be_bytes();
                        let ev = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ev_bytes);

                        let ev_max_bytes = TestUint::MAX.to_be_bytes();
                        let ev_max = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ev_max_bytes);

                        let denominator = &ev_max - &ev;
                        let q = NumRational::new(ev_max, denominator);

                        let c = NumRational::from_float(LN_ONE_MINUS_PHI).unwrap();
                        let w = NumRational::new(BigInt::from(1000), BigInt::from(10000));
                        let x = -(&w * &c);
                        let phi = NumRational::new(BigInt::from(1), BigInt::from(1)) + &x;
                        let result = q < phi;

                        black_box(result);
                    })
                });

                group.finish();
            }

            /// Benchmark repeated operations (stress test for allocation/performance)
            pub fn bench_repeated_operations(c: &mut Criterion) {
                let bench_name = format!("{}/repeated_operations", $size_name);
                let mut group = c.benchmark_group(&bench_name);

                group.bench_function("Ratio_100_adds", |b| {
                    b.iter(|| {
                        let mut acc = TestRatio::one();
                        let increment = TestRatio::from_u64(1, 1000);

                        for _ in 0..100 {
                            acc = acc.add(&increment);
                        }

                        black_box(acc);
                    })
                });

                group.bench_function("num-rational_100_adds", |b| {
                    b.iter(|| {
                        let mut acc = NumRational::new(BigInt::from(1), BigInt::from(1));
                        let increment = NumRational::new(BigInt::from(1), BigInt::from(1000));

                        for _ in 0..100 {
                            acc = acc + &increment;
                        }

                        black_box(acc);
                    })
                });

                group.finish();
            }

            // ====================================================================
            // OVERVIEW BENCHMARK (Single consolidated view)
            // ====================================================================

            /// Overview benchmark showing all key operations in one report
            pub fn bench_overview(c: &mut Criterion) {
                let bench_name = format!("{}/overview", $size_name);
                let mut group = c.benchmark_group(&bench_name);
                group.measurement_time(std::time::Duration::from_secs(10));

                // 1. Construction
                group.bench_function("1_construction/Ratio", |b| {
                    b.iter(|| {
                        let r = TestRatio::from_u64(black_box(12345), black_box(67890));
                        black_box(r);
                    })
                });

                group.bench_function("1_construction/num-rational", |b| {
                    b.iter(|| {
                        let r = NumRational::new(
                            black_box(BigInt::from(12345)),
                            black_box(BigInt::from(67890)),
                        );
                        black_box(r);
                    })
                });

                // 2. Addition
                let r1_add = TestRatio::from_u64(1, 2);
                let r2_add = TestRatio::from_u64(1, 3);
                let n1_add = NumRational::new(BigInt::from(1), BigInt::from(2));
                let n2_add = NumRational::new(BigInt::from(1), BigInt::from(3));

                group.bench_function("2_addition/Ratio", |b| {
                    b.iter(|| {
                        let result = r1_add.add(black_box(&r2_add));
                        black_box(result);
                    })
                });

                group.bench_function("2_addition/num-rational", |b| {
                    b.iter(|| {
                        let result = &n1_add + black_box(&n2_add);
                        black_box(result);
                    })
                });

                // 3. Multiplication (unreduced)
                let r1_mul = TestRatio::from_u64(2, 3);
                let r2_mul = TestRatio::from_u64(3, 4);
                let n1_mul = NumRational::new(BigInt::from(2), BigInt::from(3));
                let n2_mul = NumRational::new(BigInt::from(3), BigInt::from(4));

                group.bench_function("3_mul_unreduced/Ratio", |b| {
                    b.iter(|| {
                        let result = r1_mul.mul(black_box(&r2_mul));
                        black_box(result);
                    })
                });

                group.bench_function("3_mul_unreduced/num-rational", |b| {
                    b.iter(|| {
                        let result = &n1_mul * black_box(&n2_mul);
                        black_box(result);
                    })
                });

                // 4. Multiplication (with reduction)
                group.bench_function("4_mul_reduced/Ratio", |b| {
                    b.iter(|| {
                        let result = r1_mul.mul_reduced(black_box(&r2_mul));
                        black_box(result);
                    })
                });

                // 5. Comparison
                let r1_cmp = TestRatio::from_u64(1, 2);
                let r2_cmp = TestRatio::from_u64(1, 3);
                let n1_cmp = NumRational::new(BigInt::from(1), BigInt::from(2));
                let n2_cmp = NumRational::new(BigInt::from(1), BigInt::from(3));

                group.bench_function("5_comparison/Ratio", |b| {
                    b.iter(|| {
                        let result = r1_cmp.gt(black_box(&r2_cmp));
                        black_box(result);
                    })
                });

                group.bench_function("5_comparison/num-rational", |b| {
                    b.iter(|| {
                        let result = &n1_cmp > black_box(&n2_cmp);
                        black_box(result);
                    })
                });

                // 6. GCD
                group.bench_function("6_gcd/Ratio", |b| {
                    b.iter(|| {
                        let result = TestUint::gcd(
                            black_box(TestUint::from_u64(123456)),
                            black_box(TestUint::from_u64(789012)),
                        );
                        black_box(result);
                    })
                });

                group.bench_function("6_gcd/num-bigint", |b| {
                    b.iter(|| {
                        use num_integer::Integer;
                        let result =
                            BigInt::from(black_box(123456)).gcd(&BigInt::from(black_box(789012)));
                        black_box(result);
                    })
                });

                // 7. Taylor Series (adjust iterations for size)
                let iterations = if TestUint::BITS <= 256 { 3 } else { 5 };
                let x_taylor = TestRatio::from_u64(1, 10);
                let x_num = NumRational::new(BigInt::from(1), BigInt::from(10));

                group.bench_function("7_taylor_series/Ratio", |b| {
                    b.iter(|| {
                        let mut phi = TestRatio::one();
                        let mut new_x = x_taylor.clone();
                        let mut divisor = TestUint::ONE;

                        for _ in 0..iterations {
                            phi = phi.add(&new_x);
                            divisor = divisor.wrapping_add(&TestUint::ONE);
                            new_x = new_x.mul(&x_taylor).div_by_uint(&divisor);
                            if phi.needs_reduction() {
                                phi.normalize();
                            }
                        }
                        black_box(phi);
                    })
                });

                group.bench_function("7_taylor_series/num-rational", |b| {
                    b.iter(|| {
                        let mut phi = NumRational::new(BigInt::from(1), BigInt::from(1));
                        let mut new_x = x_num.clone();
                        let mut divisor = BigInt::from(1);

                        for _ in 0..iterations {
                            phi = phi + &new_x;
                            divisor = divisor + 1;
                            new_x = &new_x * &x_num / &divisor;
                        }
                        black_box(phi);
                    })
                });

                group.finish();
            }

            /// Export all benchmark functions for this size
            pub fn register_all(c: &mut Criterion) {
                bench_overview(c);
                bench_from_u64(c);
                bench_from_float(c);
                bench_addition(c);
                bench_multiplication(c);
                bench_comparison(c);
                bench_gcd(c);
                bench_reduction(c);
                bench_taylor_series(c);
                bench_lottery_computation(c);
                bench_repeated_operations(c);
            }
        }
    };
}

// ============================================================================
// INSTANTIATE BENCHMARK SUITES FOR EACH INTEGER SIZE
// ============================================================================

generate_ratio_benchmarks!(u256_benches, U256, crypto_ratio::Ratio<U256>, "U256");
generate_ratio_benchmarks!(u512_benches, U512, crypto_ratio::RatioU512, "U512");
generate_ratio_benchmarks!(u1024_benches, U1024, crypto_ratio::Ratio<U1024>, "U1024");
generate_ratio_benchmarks!(u2048_benches, U2048, crypto_ratio::Ratio<U2048>, "U2048");

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

criterion_group!(u256_benchmarks, u256_benches::register_all);

criterion_group!(u512_benchmarks, u512_benches::register_all);

criterion_group!(u1024_benchmarks, u1024_benches::register_all);

criterion_group!(u2048_benchmarks, u2048_benches::register_all);

// Run all sizes
criterion_main!(
    u256_benchmarks,
    u512_benchmarks,
    u1024_benchmarks,
    u2048_benchmarks
);
