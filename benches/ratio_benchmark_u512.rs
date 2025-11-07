//! Benchmarks comparing Ratio512 vs num-bigint/num-rational
//!
//! Run with: cargo bench --bench ratio_benchmarks
//!
//! These benchmarks measure the performance improvement of Ratio512
//! over the baseline num-bigint implementation for lottery verification workloads.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use crypto_bigint::{Encoding, U512};
use crypto_ratio::{RatioU512, WideInteger}; // Import WideInteger for gcd
use num_bigint::BigInt;
use num_rational::Ratio as NumRatio;

type NumRational = NumRatio<BigInt>;

const LN_ONE_MINUS_PHI: f64 = -0.22314355131420976; // ln(1-0.8)

// ============================================================================
// BASIC OPERATIONS BENCHMARKS
// ============================================================================

fn bench_from_u64(c: &mut Criterion) {
    let mut group = c.benchmark_group("from_u64");

    group.bench_function("Ratio512", |b| {
        b.iter(|| {
            let r = RatioU512::from_u64(black_box(12345), black_box(67890));
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

fn bench_from_float(c: &mut Criterion) {
    let mut group = c.benchmark_group("from_float");

    // Test both small values (u64 fast path) and large values
    let test_cases = vec![
        ("small", 0.5),
        ("medium", 0.22314355131420976),
        ("tiny", 0.00001),
    ];

    for (name, value) in test_cases {
        group.bench_with_input(BenchmarkId::new("Ratio512", name), &value, |b, &val| {
            b.iter(|| {
                let r = RatioU512::from_float(black_box(val)).unwrap();
                black_box(r);
            })
        });

        group.bench_with_input(BenchmarkId::new("num-rational", name), &value, |b, &val| {
            b.iter(|| {
                let r = NumRational::from_float(black_box(val)).unwrap();
                black_box(r);
            })
        });
    }

    group.finish();
}

fn bench_addition(c: &mut Criterion) {
    let mut group = c.benchmark_group("addition");

    // Test same denominator (fast path) and different denominators
    let test_cases = vec![
        ("same_denom", (1u64, 6u64), (2u64, 6u64)),
        ("diff_denom", (1u64, 2u64), (1u64, 3u64)),
        ("large", (999999u64, 1000000u64), (999998u64, 1000001u64)),
    ];

    for (name, (n1, d1), (n2, d2)) in test_cases {
        // Ratio512
        let r1_512 = RatioU512::from_u64(n1, d1);
        let r2_512 = RatioU512::from_u64(n2, d2);

        group.bench_with_input(
            BenchmarkId::new("RatioU512", name),
            &(r1_512.clone(), r2_512.clone()),
            |b, (r1, r2)| {
                b.iter(|| {
                    let result = r1.add(black_box(r2));
                    black_box(result);
                })
            },
        );

        // num-rational
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

fn bench_multiplication(c: &mut Criterion) {
    let mut group = c.benchmark_group("multiplication");

    let test_cases = vec![
        ("small", (2u64, 3u64), (3u64, 4u64)),
        ("medium", (12345u64, 67890u64), (98765u64, 43210u64)),
        ("large", (999999u64, 1000000u64), (1000000u64, 999999u64)),
    ];

    for (name, (n1, d1), (n2, d2)) in test_cases {
        // Ratio512 (unreduced)
        let r1_512 = RatioU512::from_u64(n1, d1);
        let r2_512 = RatioU512::from_u64(n2, d2);

        group.bench_with_input(
            BenchmarkId::new("RatioU512", name),
            &(r1_512.clone(), r2_512.clone()),
            |b, (r1, r2)| {
                b.iter(|| {
                    let result = r1.mul(black_box(r2));
                    black_box(result);
                })
            },
        );

        // Ratio512 (with smart reduction)
        group.bench_with_input(
            BenchmarkId::new("RatioU512_reduced", name),
            &(r1_512.clone(), r2_512.clone()),
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

fn bench_comparison(c: &mut Criterion) {
    let mut group = c.benchmark_group("comparison");

    let test_cases = vec![
        ("similar", (1u64, 2u64), (1u64, 3u64)),
        ("large_diff", (1u64, 1000000u64), (999999u64, 1000000u64)),
    ];

    for (name, (n1, d1), (n2, d2)) in test_cases {
        // Ratio512
        let r1_512 = RatioU512::from_u64(n1, d1);
        let r2_512 = RatioU512::from_u64(n2, d2);

        group.bench_with_input(
            BenchmarkId::new("RatioU512", name),
            &(r1_512.clone(), r2_512.clone()),
            |b, (r1, r2)| {
                b.iter(|| {
                    let result = r1.gt(black_box(r2));
                    black_box(result);
                })
            },
        );

        // num-rational
        let r1_num = NumRational::new(BigInt::from(n1), BigInt::from(d1));
        let r2_num = NumRational::new(BigInt::from(n2), BigInt::from(d2));

        group.bench_with_input(
            BenchmarkId::new("num-rational_gt", name),
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

fn bench_reduction(c: &mut Criterion) {
    let mut group = c.benchmark_group("reduction");

    let test_cases = vec![
        ("small", (6u64, 8u64)),
        ("medium", (123456u64, 789012u64)),
        ("coprime", (999983u64, 999979u64)), // Two large primes
    ];

    for (name, (n, d)) in test_cases {
        // Ratio512
        group.bench_with_input(BenchmarkId::new("Ratio512", name), &(n, d), |b, &(n, d)| {
            b.iter(|| {
                let mut r = RatioU512::new_raw(U512::from_u64(n), U512::from_u64(d), false);
                r.normalize();
                black_box(r);
            })
        });

        // num-rational (automatically reduces in constructor)
        group.bench_with_input(
            BenchmarkId::new("num-rational", name),
            &(n, d),
            |b, &(n, d)| {
                b.iter(|| {
                    let r =
                        NumRational::new(black_box(BigInt::from(n)), black_box(BigInt::from(d)));
                    black_box(r);
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// TAYLOR SERIES SIMULATION (Real-world workload)
// ============================================================================

fn bench_taylor_series(c: &mut Criterion) {
    let mut group = c.benchmark_group("taylor_series");

    // Simulate 5 iterations of Taylor series (typical for lottery)
    group.bench_function("Ratio512", |b| {
        let x = RatioU512::from_u64(1, 10);

        b.iter(|| {
            let mut phi = RatioU512::one();
            let mut new_x = x.clone();
            let mut divisor = U512::ONE;

            for _ in 0..5 {
                phi = phi.add(&new_x);
                divisor = divisor.wrapping_add(&U512::ONE);
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

            for _ in 0..5 {
                phi = phi + &new_x;
                divisor = divisor + 1;
                new_x = &new_x * &x / &divisor;
            }

            black_box(phi);
        })
    });

    group.finish();
}

// ============================================================================
// LOTTERY COMPUTATION SIMULATION
// ============================================================================

fn bench_lottery_computation(c: &mut Criterion) {
    let mut group = c.benchmark_group("lottery_computation");

    group.bench_function("Ratio512", |b| {
        b.iter(|| {
            let ev = U512::from_u128(12345678901234567890);
            let ev_max = U512::MAX;
            let denominator = ev_max.wrapping_sub(&ev);
            let q = RatioU512::new_raw(ev_max, denominator, false);

            let c = RatioU512::from_float(LN_ONE_MINUS_PHI).unwrap(); // Fixed!
            let w = RatioU512::from_u64(1000, 10000);
            let x = w.mul(&c).neg();
            let phi = RatioU512::one().add(&x);
            let result = q.lt(&phi);

            black_box(result);
        })
    });

    group.bench_function("num-rational", |b| {
        b.iter(|| {
            let ev_bytes = U512::from_u128(12345678901234567890).to_be_bytes();
            let ev = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ev_bytes);

            let ev_max_bytes = U512::MAX.to_be_bytes();
            let ev_max = BigInt::from_bytes_be(num_bigint::Sign::Plus, &ev_max_bytes);

            let denominator = &ev_max - &ev;
            let q = NumRational::new(ev_max, denominator);

            let c = NumRational::from_float(LN_ONE_MINUS_PHI).unwrap(); // Fixed!
            let w = NumRational::new(BigInt::from(1000), BigInt::from(10000));
            let x = -(&w * &c);
            let phi = NumRational::new(BigInt::from(1), BigInt::from(1)) + &x;
            let result = q < phi;

            black_box(result);
        })
    });

    group.finish();
}

// ============================================================================
// GCD BENCHMARKS
// ============================================================================

fn bench_gcd(c: &mut Criterion) {
    let mut group = c.benchmark_group("gcd");

    let test_cases = vec![
        ("small", 48u64, 18u64),
        ("medium", 123456u64, 789012u64),
        ("large", u64::MAX / 7, u64::MAX / 11),
        ("coprime", 999983u64, 999979u64), // Two large primes
    ];

    for (name, a, b) in test_cases {
        // Ratio512 (crypto_bigint)
        group.bench_with_input(
            BenchmarkId::new("Ratio512", name),
            &(a, b),
            |bench, &(a, b)| {
                bench.iter(|| {
                    let result =
                        U512::gcd(black_box(U512::from_u64(a)), black_box(U512::from_u64(b)));
                    black_box(result);
                })
            },
        );

        // num-bigint
        group.bench_with_input(
            BenchmarkId::new("num-bigint", name),
            &(a, b),
            |bench, &(a, b)| {
                bench.iter(|| {
                    use num_integer::Integer;
                    let result = BigInt::from(black_box(a)).gcd(&BigInt::from(black_box(b)));
                    black_box(result);
                })
            },
        );
    }

    group.finish();
}

// ============================================================================
// MEMORY/ALLOCATION BENCHMARKS
// ============================================================================

fn bench_repeated_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("repeated_operations");

    // Simulate many repeated operations (stress test)
    group.bench_function("Ratio512_100_adds", |b| {
        b.iter(|| {
            let mut acc = RatioU512::one();
            let increment = RatioU512::from_u64(1, 1000);

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

// ============================================================================
// OVERVIEW/SUMMARY BENCHMARK (Shows in single report page)
// ============================================================================

fn bench_overview(c: &mut Criterion) {
    let mut group = c.benchmark_group("overview");

    // Set measurement time for consistent results
    group.measurement_time(std::time::Duration::from_secs(10));

    // 1. Construction
    group.bench_function("1_construction/Ratio512", |b| {
        b.iter(|| {
            let r = RatioU512::from_u64(black_box(12345), black_box(67890));
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
    let r1_add = RatioU512::from_u64(1, 2);
    let r2_add = RatioU512::from_u64(1, 3);
    let n1_add = NumRational::new(BigInt::from(1), BigInt::from(2));
    let n2_add = NumRational::new(BigInt::from(1), BigInt::from(3));

    group.bench_function("2_addition/Ratio512", |b| {
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
    let r1_mul = RatioU512::from_u64(2, 3);
    let r2_mul = RatioU512::from_u64(3, 4);
    let n1_mul = NumRational::new(BigInt::from(2), BigInt::from(3));
    let n2_mul = NumRational::new(BigInt::from(3), BigInt::from(4));

    group.bench_function("3_multiplication/Ratio512", |b| {
        b.iter(|| {
            let result = r1_mul.mul(black_box(&r2_mul));
            black_box(result);
        })
    });

    group.bench_function("3_multiplication/num-rational", |b| {
        b.iter(|| {
            let result = &n1_mul * black_box(&n2_mul);
            black_box(result);
        })
    });

    // 4. Multiplication (with reduction)
    group.bench_function("4_multiplication_reduced/Ratio512", |b| {
        b.iter(|| {
            let result = r1_mul.mul_reduced(black_box(&r2_mul));
            black_box(result);
        })
    });

    group.bench_function("4_multiplication_reduced/num-rational", |b| {
        b.iter(|| {
            let result = &n1_mul * black_box(&n2_mul);
            black_box(result);
        })
    });

    // 5. Comparison
    let r1_cmp = RatioU512::from_u64(1, 2);
    let r2_cmp = RatioU512::from_u64(1, 3);
    let n1_cmp = NumRational::new(BigInt::from(1), BigInt::from(2));
    let n2_cmp = NumRational::new(BigInt::from(1), BigInt::from(3));

    group.bench_function("5_comparison/Ratio512", |b| {
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
    group.bench_function("6_gcd/Ratio512", |b| {
        b.iter(|| {
            let result = U512::gcd(
                black_box(U512::from_u64(123456)),
                black_box(U512::from_u64(789012)),
            );
            black_box(result);
        })
    });

    group.bench_function("6_gcd/num-rational", |b| {
        b.iter(|| {
            use num_integer::Integer;
            let result = BigInt::from(black_box(123456)).gcd(&BigInt::from(black_box(789012)));
            black_box(result);
        })
    });

    // 7. Taylor Series (real-world)
    let x_taylor = RatioU512::from_u64(1, 10);
    let x_num = NumRational::new(BigInt::from(1), BigInt::from(10));

    group.bench_function("7_taylor_series/Ratio512", |b| {
        b.iter(|| {
            let mut phi = RatioU512::one();
            let mut new_x = x_taylor.clone();
            let mut divisor = U512::ONE;

            for _ in 0..5 {
                phi = phi.add(&new_x);
                divisor = divisor.wrapping_add(&U512::ONE);
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

            for _ in 0..5 {
                phi = phi + &new_x;
                divisor = divisor + 1;
                new_x = &new_x * &x_num / &divisor;
            }
            black_box(phi);
        })
    });

    group.finish();
}

// ============================================================================
// BENCHMARK GROUPS
// ============================================================================

criterion_group!(overview, bench_overview);

criterion_group!(
    basic_ops,
    bench_from_u64,
    bench_from_float,
    bench_addition,
    bench_multiplication,
    bench_comparison,
    bench_reduction,
    bench_gcd
);

criterion_group!(
    real_world,
    bench_taylor_series,
    bench_lottery_computation,
    bench_repeated_operations
);

criterion_main!(overview, basic_ops, real_world); // Run overview first!
