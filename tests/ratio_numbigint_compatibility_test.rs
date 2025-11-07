// ratio_compatibility_tests.rs
//
// Comprehensive test suite to verify Ratio<T> correctness and compatibility with num-bigint::Rational
// This suite is instantiated for multiple integer sizes using macros.
//
// This test suite serves multiple purposes:
// 1. Verify mathematical correctness of all operations
// 2. Ensure compatibility with num-rational behavior (where appropriate)
// 3. Test performance-critical design decisions (unreduced operations)
// 4. Verify edge cases and overflow handling
// 5. Test real-world usage patterns (Taylor series, repeated operations)
//
// Key Design Philosophy Being Tested:
// - Operations (mul, add) return UNREDUCED results for performance
// - User calls normalize() explicitly when needed
// - mul_reduced() available for convenience with smart heuristics
// - from_u64() DOES reduce (for ergonomics)

#[cfg(test)]
mod compatibility_tests {
    use crypto_bigint::{
        Encoding, U1024, U128, U1280, U1536, U16384, U1792, U192, U2048, U256, U3072, U320, U3584,
        U384, U4096, U4224, U4352, U448, U512, U576, U6144, U64, U640, U704, U768, U8192, U832,
        U896, U960,
    };
    use crypto_ratio::WideInteger;
    use num_bigint::BigInt;
    use num_rational::Ratio as NumRatio;
    use std::cmp::Ordering;

    type NumRational = NumRatio<BigInt>;

    /// Macro to generate complete test suite for a given integer type
    macro_rules! generate_ratio_tests {
        ($mod_name:ident, $uint_type:ty, $ratio_type:ty) => {
            mod $mod_name {
                use super::*;

                type TestUint = $uint_type;
                type TestRatio = $ratio_type;

                /// Convert Ratio to num-rational for compatibility testing
                fn ratio_to_num(r: &TestRatio) -> NumRational {
                    let numer_bytes = r.numer.to_be_bytes();
                    let denom_bytes = r.denom.to_be_bytes();

                    let mut numer = BigInt::from_bytes_be(num_bigint::Sign::Plus, &numer_bytes);
                    let denom = BigInt::from_bytes_be(num_bigint::Sign::Plus, &denom_bytes);

                    if r.negative {
                        numer = -numer;
                    }

                    NumRational::new(numer, denom)
                }

                /// Compare Ratio with num-rational for mathematical equality
                fn compare_ratios(r1: &TestRatio, r2: &NumRational) -> bool {
                    let r1_as_num = ratio_to_num(r1);
                    &r1_as_num == r2
                }

                /// Get a large value appropriate for this integer size
                fn get_large_value() -> TestUint {
                    if TestUint::BITS <= 64 {
                        TestUint::from_u64(u64::MAX / 4)
                    } else if TestUint::BITS <= 128 {
                        TestUint::from_u128(u128::MAX / 4)
                    } else {
                        TestUint::from_u128(u128::MAX / 2)
                    }
                }

                /// Get max value for u128 operations, or smaller value for tiny types
                fn get_huge_value() -> TestUint {
                    if TestUint::BITS <= 64 {
                        TestUint::from_u64(u64::MAX)
                    } else if TestUint::BITS <= 128 {
                        TestUint::from_u128(u128::MAX)
                    } else {
                        TestUint::from_u128(u128::MAX)
                    }
                }

                /// Skip test if integer type is too small for this test
                fn skip_if_too_small(min_bits: u32) -> bool {
                    if TestUint::BITS < min_bits as usize {
                        eprintln!(
                            "Skipping test - requires at least {} bits, have {}",
                            min_bits,
                            TestUint::BITS
                        );
                        return true;
                    }
                    false
                }

                // ========================================================================
                // MULTIPLICATION REDUCTION BEHAVIOR TESTS
                // ========================================================================
                // These tests verify the core design decision: mul() returns unreduced
                // results for performance, while mul_reduced() offers smart reduction.

                /// Verify that mul() does NOT automatically reduce for performance.
                /// This is a key design decision - operations are unreduced, user calls normalize().
                /// Example: 2/3 × 3/4 = 6/12 (unreduced), not 1/2
                #[test]
                fn test_mul_returns_unreduced() {
                    let r1 = TestRatio::from_u64(2, 3);
                    let r2 = TestRatio::from_u64(3, 4);
                    let result = &r1 * &r2;

                    // Should be 6/12, NOT 1/2
                    assert_eq!(
                        result.numer,
                        TestUint::from_u64(6),
                        "mul() should return unreduced numerator"
                    );
                    assert_eq!(
                        result.denom,
                        TestUint::from_u64(12),
                        "mul() should return unreduced denominator"
                    );

                    // But should be mathematically equal to 1/2
                    let expected = TestRatio::from_u64(1, 2);
                    assert_eq!(result, expected, "6/12 should equal 1/2 mathematically");
                }

                /// Verify that mul_reduced() DOES reduce using smart heuristics.
                /// This provides an alternative when reduced results are needed immediately.
                #[test]
                fn test_mul_reduced_returns_reduced() {
                    let r1 = TestRatio::from_u64(2, 3);
                    let r2 = TestRatio::from_u64(3, 4);
                    let result = r1.mul_reduced(&r2);

                    // Should be 1/2 (fully reduced)
                    assert_eq!(
                        result.numer,
                        TestUint::from_u64(1),
                        "mul_reduced() should return reduced numerator"
                    );
                    assert_eq!(
                        result.denom,
                        TestUint::from_u64(2),
                        "mul_reduced() should return reduced denominator"
                    );
                }

                /// Test the power-of-2 fast path in mul_reduced().
                /// Heuristic: Remove power-of-2 factors via bit shifts (very fast, ~10ns).
                /// Example: 4/8 × 2/6 = 8/48 → remove 2^3 → 1/6
                #[test]
                fn test_mul_reduced_power_of_2() {
                    let r1 = TestRatio::from_u64(4, 8);
                    let r2 = TestRatio::from_u64(2, 6);
                    let result = r1.mul_reduced(&r2);

                    assert_eq!(result.numer, TestUint::from_u64(1));
                    assert_eq!(result.denom, TestUint::from_u64(6));
                }

                /// Test the u64 GCD fast path in mul_reduced().
                /// Heuristic: If result fits in u64, use fast u64 GCD (~50ns vs ~10µs for full GCD).
                #[test]
                fn test_mul_reduced_small_values() {
                    let r1 = TestRatio::from_u64(15, 35);
                    let r2 = TestRatio::from_u64(21, 28);
                    let result = r1.mul_reduced(&r2);

                    assert_eq!(result.numer, TestUint::from_u64(9));
                    assert_eq!(result.denom, TestUint::from_u64(28));
                }

                /// Test that mul_reduced() skips expensive GCD for large coprime values.
                /// Heuristic: Values >128 bits skip GCD unless cheap reduction found.
                /// This prevents ~10µs GCD overhead on already-reduced fractions.
                #[test]
                fn test_mul_reduced_large_coprime() {
                    let r1 = TestRatio::from_u64(999983, 999979);
                    let r2 = TestRatio::from_u64(999961, 999953);
                    let result = r1.mul_reduced(&r2);

                    let g = TestUint::gcd(result.numer, result.denom);
                    assert_eq!(
                        g,
                        TestUint::ONE,
                        "Coprime multiplication should stay coprime"
                    );
                }

                /// Verify that chained mul() operations accumulate unreduced fractions.
                /// Important for performance in loops (e.g., Taylor series).
                /// Example: (2/3 × 3/4) × 4/5 = 24/60 (unreduced) = 2/5 (reduced)
                #[test]
                fn test_mul_chain_unreduced() {
                    let r1 = TestRatio::from_u64(2, 3);
                    let r2 = TestRatio::from_u64(3, 4);
                    let r3 = TestRatio::from_u64(4, 5);

                    let result = (&r1 * &r2) * r3;

                    // Should be 24/60, not 2/5
                    assert_eq!(result.numer, TestUint::from_u64(24));
                    assert_eq!(result.denom, TestUint::from_u64(60));

                    // But mathematically equal to 2/5
                    let mut normalized = result.clone();
                    normalized.normalize();
                    assert_eq!(normalized.numer, TestUint::from_u64(2));
                    assert_eq!(normalized.denom, TestUint::from_u64(5));
                }

                /// Ensure mul() doesn't reduce.
                #[test]
                fn test_regression_mul_should_not_reduce() {
                    let r1 = TestRatio::from_u64(2, 3);
                    let r2 = TestRatio::from_u64(3, 4);
                    let result = &r1 * &r2;

                    // MUST be unreduced
                    assert_ne!(
                        result.numer,
                        TestUint::from_u64(1),
                        "BUG: mul() is reducing when it shouldn't!"
                    );
                    assert_ne!(
                        result.denom,
                        TestUint::from_u64(2),
                        "BUG: mul() is reducing when it shouldn't!"
                    );
                }

                /// Ensure mul_reduced() fully reduces.
                #[test]
                fn test_regression_mul_reduced_should_reduce() {
                    let r1 = TestRatio::from_u64(2, 3);
                    let r2 = TestRatio::from_u64(3, 4);
                    let result = r1.mul_reduced(&r2);

                    // MUST be fully reduced (not just power-of-2 reduced)
                    assert_eq!(
                        result.numer,
                        TestUint::from_u64(1),
                        "BUG: mul_reduced() not fully reducing!"
                    );
                    assert_eq!(
                        result.denom,
                        TestUint::from_u64(2),
                        "BUG: mul_reduced() not fully reducing!"
                    );
                }

                // ========================================================================
                // ADDITION REDUCTION BEHAVIOR TESTS
                // ========================================================================
                // Verify that addition operations also return unreduced results.

                /// Test that same-denominator addition (fast path) returns unreduced result.
                /// Fast path: When denominators equal, just add numerators (skip LCM calculation).
                /// Note: Use new_raw() to avoid from_u64() auto-reduction.
                #[test]
                fn test_add_returns_unreduced_same_denom() {
                    let r1 =
                        TestRatio::new_raw(TestUint::from_u64(1), TestUint::from_u64(6), false);
                    let r2 =
                        TestRatio::new_raw(TestUint::from_u64(2), TestUint::from_u64(6), false);
                    let result = &r1 + &r2;

                    // Should be 3/6, NOT 1/2
                    assert_eq!(result.numer, TestUint::from_u64(3));
                    assert_eq!(result.denom, TestUint::from_u64(6));
                }

                /// Test that different-denominator addition returns unreduced result.
                /// Example: 1/2 + 1/4 = 2/4 + 1/4 = 3/4... wait, no: 1/2 + 1/4 = 4/8 + 2/8 = 6/8
                #[test]
                fn test_add_returns_unreduced_diff_denom() {
                    let r1 = TestRatio::from_u64(1, 2);
                    let r2 = TestRatio::from_u64(1, 4);
                    let result = &r1 + &r2;

                    // Should be 6/8, NOT 3/4
                    assert_eq!(result.numer, TestUint::from_u64(6));
                    assert_eq!(result.denom, TestUint::from_u64(8));
                }

                /// Verify deferred reduction pattern: operations don't reduce until normalize() called.
                /// This is the core pattern for performance-critical code.
                #[test]
                fn test_deferred_reduction() {
                    let r1 = TestRatio::from_u64(1, 2);
                    let r2 = TestRatio::from_u64(1, 2);

                    let result = &r1 + &r2; // Should be 2/2 (not normalized to 1/1)

                    assert_eq!(result.numer, TestUint::from_u64(2));
                    assert_eq!(result.denom, TestUint::from_u64(2));

                    // After explicit normalize(), should be 1/1
                    let mut normalized = result.clone();
                    normalized.normalize();
                    assert_eq!(normalized.numer, TestUint::from_u64(1));
                    assert_eq!(normalized.denom, TestUint::from_u64(1));
                }

                // ========================================================================
                // BASIC COMPATIBILITY TESTS
                // ========================================================================
                // Verify that operations produce mathematically correct results matching num-rational.

                /// Test addition operations match num-rational behavior after normalization.
                #[test]
                fn test_addition_compatibility() {
                    let test_cases = vec![
                        ((1u64, 2u64), (1u64, 3u64)), // 1/2 + 1/3 = 5/6
                        ((2u64, 5u64), (3u64, 7u64)), // 2/5 + 3/7
                        ((1u64, 4u64), (1u64, 4u64)), // 1/4 + 1/4 = 1/2
                        ((7u64, 8u64), (1u64, 8u64)), // 7/8 + 1/8 = 1
                    ];

                    for ((n1, d1), (n2, d2)) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);

                        let mut result = &r1 + &r2;
                        result.normalize();

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));
                        let expected = num1 + num2;

                        assert!(
                            compare_ratios(&result, &expected),
                            "{}/{} + {}/{} mismatch: got {}/{} (neg={})",
                            n1,
                            d1,
                            n2,
                            d2,
                            result.numer,
                            result.denom,
                            result.negative
                        );
                    }
                }

                /// Test multiplication operations match num-rational behavior after normalization.
                /// Covers: simple fractions, cross-cancellation opportunities, integer results
                #[test]
                fn test_multiplication_compatibility() {
                    let test_cases = vec![
                        ((2u64, 3u64), (3u64, 4u64)),  // 2/3 * 3/4 = 1/2
                        ((1u64, 2u64), (1u64, 2u64)),  // 1/2 * 1/2 = 1/4
                        ((5u64, 7u64), (7u64, 11u64)), // Cross-cancel test
                        ((12u64, 5u64), (5u64, 6u64)), // 12/5 * 5/6 = 2
                    ];

                    for ((n1, d1), (n2, d2)) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);
                        let mut result = &r1 * &r2;
                        result.normalize();

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));
                        let expected = num1 * num2;

                        assert!(
                            compare_ratios(&result, &expected),
                            "{}/{} * {}/{} mismatch",
                            n1,
                            d1,
                            n2,
                            d2
                        );
                    }
                }

                /// Test subtraction operations match num-rational behavior.
                #[test]
                fn test_subtraction_compatibility() {
                    let test_cases = vec![
                        ((1u64, 2u64), (1u64, 3u64)), // 1/2 - 1/3 = 1/6
                        ((3u64, 4u64), (1u64, 4u64)), // 3/4 - 1/4 = 1/2
                    ];

                    for ((n1, d1), (n2, d2)) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);
                        let mut result = &r1 - &r2;
                        result.normalize();

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));
                        let expected = num1 - num2;

                        assert!(compare_ratios(&result, &expected));
                    }
                }

                /// Test division operations match num-rational behavior.
                /// Division is multiplication by reciprocal: a/b ÷ c/d = a/b × d/c
                #[test]
                fn test_division_compatibility() {
                    let test_cases = vec![
                        ((1u64, 2u64), (1u64, 3u64)), // (1/2) / (1/3) = 3/2
                        ((2u64, 3u64), (4u64, 5u64)), // (2/3) / (4/5) = 10/12 = 5/6
                    ];

                    for ((n1, d1), (n2, d2)) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);
                        let mut result = &r1 / &r2;
                        result.normalize();

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));
                        let expected = num1 / num2;

                        assert!(compare_ratios(&result, &expected));
                    }
                }

                /// Test negation operation correctness.
                /// Negation flips the sign bit, handles zero specially.
                #[test]
                fn test_negation_compatibility() {
                    let test_cases = vec![
                        (1u64, 2u64),
                        (3u64, 4u64),
                        (0u64, 1u64), // Zero case: -0 = 0
                    ];

                    for (n, d) in test_cases {
                        let r = TestRatio::from_u64(n, d);
                        let neg_r = -r;

                        let num = NumRational::new(BigInt::from(n), BigInt::from(d));
                        let expected = -num;

                        assert!(compare_ratios(&neg_r, &expected), "-({}/{}) mismatch", n, d);
                    }
                }

                // ========================================================================
                // SIGNED ARITHMETIC TESTS
                // ========================================================================
                // Test operations involving negative numbers.

                /// Test all sign combinations in addition: pos+neg, neg+pos, neg+neg.
                /// Verifies correct sign handling and magnitude subtraction.
                #[test]
                fn test_signed_addition() {
                    // 1/2 + (-1/3) = 1/6
                    let r1 = TestRatio::from_u64(1, 2);
                    let r2 = -TestRatio::from_u64(1, 3);
                    let mut result = &r1 + &r2;
                    result.normalize();

                    let num1 = NumRational::new(BigInt::from(1), BigInt::from(2));
                    let num2 = -NumRational::new(BigInt::from(1), BigInt::from(3));
                    let expected = num1 + num2;

                    assert!(compare_ratios(&result, &expected));

                    // (-1/2) + 1/3 = -1/6
                    let r1 = -TestRatio::from_u64(1, 2);
                    let r2 = TestRatio::from_u64(1, 3);
                    let mut result = &r1 + &r2;
                    result.normalize();

                    let num1 = -NumRational::new(BigInt::from(1), BigInt::from(2));
                    let num2 = NumRational::new(BigInt::from(1), BigInt::from(3));
                    let expected = num1 + num2;

                    assert!(compare_ratios(&result, &expected));

                    // (-1/2) + (-1/3) = -5/6
                    let r1 = -TestRatio::from_u64(1, 2);
                    let r2 = -TestRatio::from_u64(1, 3);
                    let mut result = &r1 + &r2;
                    result.normalize();

                    let num1 = -NumRational::new(BigInt::from(1), BigInt::from(2));
                    let num2 = -NumRational::new(BigInt::from(1), BigInt::from(3));
                    let expected = num1 + num2;

                    assert!(compare_ratios(&result, &expected));
                }

                /// Test sign propagation laws in operations.
                /// Verifies: -(a+b) = (-a)+(-b), -(a*b) = (-a)*b = a*(-b), etc.
                #[test]
                fn test_sign_in_operations() {
                    let a = TestRatio::from_u64(2, 3);
                    let b = TestRatio::from_u64(3, 5);

                    // -(a+b) should equal (-a) + (-b)
                    let mut left = -(&a + &b);
                    left.normalize();
                    let mut right = &(-a.clone()) + &(-b.clone());
                    right.normalize();
                    assert_eq!(left, right, "-(a+b) = (-a)+(-b)");

                    // -(a*b) should equal (-a)*b and a*(-b)
                    let mut neg_product = -(&a * &b);
                    neg_product.normalize();
                    let mut left_neg = &(-a.clone()) * &b;
                    left_neg.normalize();
                    let mut right_neg = &a * &(-b.clone());
                    right_neg.normalize();
                    assert_eq!(neg_product, left_neg, "-(a*b) = (-a)*b");
                    assert_eq!(neg_product, right_neg, "-(a*b) = a*(-b)");

                    // (-a)/b should equal a/(-b) and -(a/b)
                    let mut div1 = &(-a.clone()) / &b;
                    div1.normalize();
                    let mut div2 = &a / &(-b.clone());
                    div2.normalize();
                    let mut div3 = -(&a / &b);
                    div3.normalize();
                    assert_eq!(div1, div2, "(-a)/b = a/(-b)");
                    assert_eq!(div1, div3, "(-a)/b = -(a/b)");
                }

                /// Test double negation: -(-x) = x.
                #[test]
                fn test_double_negation() {
                    let a = TestRatio::from_u64(7, 13);
                    let neg_a = -a.clone();
                    let double_neg = -neg_a;

                    assert_eq!(a, double_neg, "-(-a) = a");
                }

                /// Test signed operations with large numbers.
                /// Verifies sign handling doesn't break with overflow paths.
                #[test]
                fn test_signed_large_numbers() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let large = get_large_value();

                    let r1 = TestRatio::new_raw(large, TestUint::from_u64(1), true); // negative
                    let r2 = TestRatio::new_raw(large, TestUint::from_u64(2), false); // positive

                    let mut result = &r1 + &r2;
                    result.normalize();

                    // Just verify valid result
                    assert!(!result.denom.is_zero_bool());
                }

                // ========================================================================
                // COMPARISON TESTS
                // ========================================================================
                // Test <, >, ==, ≤, ≥ operations work correctly.

                /// Test comparison operations (>, <) match num-rational.
                /// Uses cross-multiplication: a/b < c/d ⟺ a*d < c*b
                #[test]
                fn test_comparison_compatibility() {
                    let test_cases = vec![
                        ((1u64, 2u64), (1u64, 3u64), true),  // 1/2 > 1/3
                        ((1u64, 3u64), (1u64, 2u64), false), // 1/3 < 1/2
                        ((2u64, 4u64), (1u64, 2u64), false), // 2/4 == 1/2
                        ((3u64, 5u64), (4u64, 7u64), true),  // 3/5 > 4/7
                    ];

                    for ((n1, d1), (n2, d2), _expect_gt) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));

                        assert_eq!(
                            r1.gt(&r2),
                            num1 > num2,
                            "{}/{} > {}/{} mismatch",
                            n1,
                            d1,
                            n2,
                            d2
                        );
                        assert_eq!(
                            r1.lt(&r2),
                            num1 < num2,
                            "{}/{} < {}/{} mismatch",
                            n1,
                            d1,
                            n2,
                            d2
                        );
                    }
                }

                /// Test equality comparison works with unreduced fractions.
                /// Mathematical equality: 1/2 == 2/4 even though representationally different.
                #[test]
                fn test_unreduced_equality() {
                    let reduced = TestRatio::from_u64(1, 2);
                    let unreduced =
                        TestRatio::new_raw(TestUint::from_u64(2), TestUint::from_u64(4), false);

                    assert_eq!(reduced, unreduced, "1/2 should equal 2/4");
                }

                /// Test comparison operations work with unreduced fractions.
                /// Verifies cross-multiplication handles unnormalized inputs correctly.
                #[test]
                fn test_unreduced_comparison() {
                    let r1 =
                        TestRatio::new_raw(TestUint::from_u64(4), TestUint::from_u64(8), false); // 4/8 = 1/2
                    let r2 =
                        TestRatio::new_raw(TestUint::from_u64(2), TestUint::from_u64(6), false); // 2/6 = 1/3

                    assert!(r1.gt(&r2), "4/8 (1/2) should be > 2/6 (1/3)");
                    assert!(r2.lt(&r1), "2/6 (1/3) should be < 4/8 (1/2)");
                }

                /// Test that unreduced fractions produce mathematically correct results.
                /// Example: 2/4 + 3/6 should equal 1, even though inputs are unreduced.
                #[test]
                fn test_unreduced_addition_correctness() {
                    let r1 =
                        TestRatio::new_raw(TestUint::from_u64(2), TestUint::from_u64(4), false); // 2/4
                    let r2 =
                        TestRatio::new_raw(TestUint::from_u64(3), TestUint::from_u64(6), false); // 3/6

                    let result = &r1 + &r2;

                    // Should equal 1 (even if unreduced internally)
                    let one = TestRatio::one();
                    assert_eq!(result, one, "2/4 + 3/6 should equal 1");
                }

                /// Test Eq trait implementation matches num-rational.
                #[test]
                fn test_equality_compatibility() {
                    let r1 = TestRatio::from_u64(1, 2);
                    let r2 = TestRatio::from_u64(2, 4);
                    let r3 = TestRatio::from_u64(1, 3);

                    assert_eq!(r1, r2);
                    assert_ne!(r1, r3);

                    let num1 = NumRational::new(BigInt::from(1), BigInt::from(2));
                    let num2 = NumRational::new(BigInt::from(2), BigInt::from(4));
                    let num3 = NumRational::new(BigInt::from(1), BigInt::from(3));

                    assert_eq!(r1 == r2, num1 == num2);
                    assert_eq!(r1 == r3, num1 == num3);
                }

                /// Test transitivity: if a<b and b<c, then a<c.
                #[test]
                fn test_comparison_transitivity() {
                    let a = TestRatio::from_u64(1, 4);
                    let b = TestRatio::from_u64(1, 3);
                    let c = TestRatio::from_u64(1, 2);

                    assert!(a.lt(&b) && b.lt(&c), "Setup: 1/4 < 1/3 < 1/2");
                    assert!(a.lt(&c), "Transitivity: if a<b and b<c then a<c");
                }

                /// Test comparison with large numbers requiring wide overflow handling.
                /// Verifies cross-multiplication doesn't panic when a*d overflows.
                #[test]
                fn test_comparison_with_large_numbers() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let large1 = get_large_value();
                    let large2 = get_large_value().shr_vartime(1);

                    let r1 = TestRatio::new_raw(large1, TestUint::from_u64(1), false);
                    let r2 = TestRatio::new_raw(large2, TestUint::from_u64(1), false);

                    assert!(r1.gt(&r2));
                    assert!(!r1.lt(&r2));

                    // Test with different denominators
                    let r3 = TestRatio::new_raw(large1, TestUint::from_u64(2), false);
                    let r4 = TestRatio::new_raw(large2, TestUint::from_u64(1), false);

                    let _result = r3.lt(&r4); // Just verify no panic
                }

                /// Test Ord trait implementation (full ordering).
                /// Verifies cmp() returns correct Ordering enum.
                #[test]
                fn test_ordering_comprehensive() {
                    let test_cases = vec![
                        (
                            TestRatio::from_u64(1, 2),
                            TestRatio::from_u64(1, 3),
                            Ordering::Greater,
                        ),
                        (
                            TestRatio::from_u64(1, 3),
                            TestRatio::from_u64(1, 2),
                            Ordering::Less,
                        ),
                        (
                            TestRatio::from_u64(2, 4),
                            TestRatio::from_u64(1, 2),
                            Ordering::Equal,
                        ),
                        (
                            -TestRatio::from_u64(1, 2),
                            TestRatio::from_u64(1, 2),
                            Ordering::Less,
                        ),
                        (TestRatio::zero(), TestRatio::from_u64(1, 2), Ordering::Less),
                    ];

                    for (a, b, expected) in test_cases {
                        assert_eq!(a.cmp(&b), expected, "{:?} cmp {:?}", a, b);
                    }
                }

                // ========================================================================
                // REDUCTION TESTS
                // ========================================================================
                // Test normalize() and reduction correctness.

                /// Test from_u64() automatically reduces to lowest terms.
                /// This is for ergonomics - users expect 6/8 to become 3/4.
                #[test]
                fn test_reduction() {
                    let test_cases = vec![
                        ((6u64, 8u64), (3u64, 4u64)),
                        ((10u64, 15u64), (2u64, 3u64)),
                        ((7u64, 7u64), (1u64, 1u64)),
                        ((0u64, 5u64), (0u64, 1u64)), // Zero normalization
                    ];

                    for ((n, d), (exp_n, exp_d)) in test_cases {
                        let r = TestRatio::from_u64(n, d);

                        assert_eq!(
                            r.numer,
                            TestUint::from_u64(exp_n),
                            "{}/{} numerator not normalized correctly",
                            n,
                            d
                        );
                        assert_eq!(
                            r.denom,
                            TestUint::from_u64(exp_d),
                            "{}/{} denominator not normalized correctly",
                            n,
                            d
                        );
                    }
                }

                /// Test that normalizing an already-reduced fraction is fast (no-op).
                /// Important for needs_reduction() heuristic effectiveness.
                #[test]
                fn test_normalize_already_reduced() {
                    let r = TestRatio::from_u64(7, 13); // Coprime
                    let before = r.clone();

                    let mut after = r.clone();
                    after.normalize();

                    // Should be identical (no change)
                    assert_eq!(before.numer, after.numer);
                    assert_eq!(before.denom, after.denom);
                }

                /// Test power-of-2 optimization in normalize().
                /// Fast path: Remove common power-of-2 factors via bit shifts before GCD.
                #[test]
                fn test_normalize_power_of_2_optimization() {
                    let mut r =
                        TestRatio::new_raw(TestUint::from_u64(16), TestUint::from_u64(64), false);
                    r.normalize();

                    // Should be 1/4 (removed 2^4)
                    assert_eq!(r.numer, TestUint::from_u64(1));
                    assert_eq!(r.denom, TestUint::from_u64(4));
                }

                /// Test idempotence: normalize(normalize(x)) = normalize(x).
                /// Calling normalize() multiple times should have no additional effect.
                #[test]
                fn test_reduction_idempotence() {
                    let mut r =
                        TestRatio::new_raw(TestUint::from_u64(6), TestUint::from_u64(8), false);
                    let first = r.clone();

                    r.normalize();
                    let second = r.clone();

                    r.normalize();
                    let third = r.clone();

                    // Normalization is idempotent
                    assert_eq!(second.numer, third.numer);
                    assert_eq!(second.denom, third.denom);

                    // First is mathematically equal but representationally different
                    assert_eq!(first, second, "6/8 should be mathematically equal to 3/4");
                    assert_ne!(
                        first.numer, second.numer,
                        "First (6/8) should have different numerator than normalized (3/4)"
                    );
                    assert_ne!(
                        first.denom, second.denom,
                        "First (6/8) should have different denominator than normalized (3/4)"
                    );

                    assert_eq!(second.numer, TestUint::from_u64(3));
                    assert_eq!(second.denom, TestUint::from_u64(4));
                    assert_eq!(first.numer, TestUint::from_u64(6));
                    assert_eq!(first.denom, TestUint::from_u64(8));
                }

                /// Test needs_reduction() threshold detection.
                /// Verifies the heuristic triggers at appropriate bit sizes (60% of max bits).
                #[test]
                fn test_needs_reduction_threshold() {
                    let threshold = <TestUint as crypto_ratio::RatioInteger>::REDUCTION_THRESHOLD;

                    // Just below threshold - should NOT need reduction
                    let small_bits = threshold - 1;
                    let small = TestUint::ONE.shl_vartime(small_bits as usize);
                    let r_small = TestRatio::new_raw(small, TestUint::from_u64(1), false);
                    assert!(
                        !r_small.needs_reduction(),
                        "Should not need reduction below threshold"
                    );

                    // Above threshold - SHOULD need reduction
                    let large_bits = threshold + 1;
                    let large = TestUint::ONE.shl_vartime(large_bits as usize);
                    let r_large = TestRatio::new_raw(large, TestUint::from_u64(1), false);
                    assert!(
                        r_large.needs_reduction(),
                        "Should need reduction above threshold"
                    );
                }

                // ========================================================================
                // OVERFLOW AND WIDE TYPE TESTS
                // ========================================================================
                // Test wide fallback paths when operations overflow.

                /// Test multiplication overflow triggers cross-cancellation.
                /// When a*c overflows, use GCD to reduce before multiplying.
                #[test]
                fn test_mul_overflow_triggers_cross_cancel() {
                    if skip_if_too_small(256) {
                        return;
                    } // Need 256+ bits

                    let large = get_large_value();

                    let r1 = TestRatio::new_raw(large, TestUint::from_u64(1), false);
                    let r2 = TestRatio::new_raw(large, TestUint::from_u64(1), false);

                    let result = &r1 * &r2;

                    assert!(!result.denom.is_zero_bool());
                }

                /// Test addition overflow triggers wide fallback.
                /// When b*d overflows, perform addition in wider type then reduce back.
                #[test]
                fn test_add_overflow_triggers_wide() {
                    if skip_if_too_small(256) {
                        return;
                    } // Need 256+ bits

                    let huge_denom = get_huge_value();

                    let r1 = TestRatio::new_raw(TestUint::from_u64(1), huge_denom, false);
                    let r2 = TestRatio::new_raw(TestUint::from_u64(1), huge_denom, false);

                    let mut result = &r1 + &r2;
                    result.normalize();

                    let bytes = huge_denom.to_be_bytes();
                    let big = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);
                    let num1 = NumRational::new(BigInt::from(1), big.clone());
                    let num2 = NumRational::new(BigInt::from(1), big);
                    let expected = num1 + num2;

                    assert!(compare_ratios(&result, &expected));
                }

                /// Test large number addition requiring wide type.
                /// Verifies the wide path produces correct results.
                #[test]
                fn test_large_number_addition() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let large1 = get_large_value();
                    let large2 = get_large_value().shr_vartime(1);

                    let r1 = TestRatio::new_raw(large1, large2, false);
                    let r2 = TestRatio::new_raw(large2, large1, false);

                    let mut result = &r1 + &r2;
                    result.normalize();

                    // Just verify it doesn't panic and produces valid result
                    assert!(!result.denom.is_zero_bool());
                }

                /// Test forced wide path with different denominators.
                #[test]
                fn test_overflow_to_wide_path() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let big_denom1 = get_huge_value();
                    let big_denom2 = get_huge_value().shr_vartime(1);

                    let r1 = TestRatio::new_raw(TestUint::from_u64(1), big_denom1, false);
                    let r2 = TestRatio::new_raw(TestUint::from_u64(1), big_denom2, false);

                    let mut result = &r1 + &r2;
                    result.normalize();

                    // Just verify it produces valid result
                    assert!(!result.denom.is_zero_bool());
                }

                /// Test operations near MAX don't panic.
                #[test]
                fn test_near_max_values() {
                    let near_max = TestUint::MAX.wrapping_sub(&TestUint::from_u64(1000));

                    let r1 = TestRatio::new_raw(near_max, TestUint::from_u64(1), false);
                    let r2 =
                        TestRatio::new_raw(TestUint::from_u64(1), TestUint::from_u64(2), false);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert!(!result.denom.is_zero_bool());
                    assert!(result.numer <= near_max);
                }

                // ========================================================================
                // COMPLEX OPERATIONS AND EDGE CASES
                // ========================================================================
                // Test combined operations and boundary conditions.

                /// Test complex expression: (1/2 + 1/3) * 2/5 = 1/3
                #[test]
                fn test_complex_operations() {
                    let r1 = TestRatio::from_u64(1, 2);
                    let r2 = TestRatio::from_u64(1, 3);
                    let r3 = TestRatio::from_u64(2, 5);

                    let mut result = (&r1 + &r2) * r3;
                    result.normalize();

                    let num1 = NumRational::new(BigInt::from(1), BigInt::from(2));
                    let num2 = NumRational::new(BigInt::from(1), BigInt::from(3));
                    let num3 = NumRational::new(BigInt::from(2), BigInt::from(5));
                    let expected = (num1 + num2) * num3;

                    assert!(compare_ratios(&result, &expected));
                }

                /// Test multiplication by zero: x * 0 = 0
                #[test]
                fn test_mul_by_zero() {
                    let r = TestRatio::from_u64(7, 13);
                    let zero = TestRatio::zero();

                    let result1 = &r * &zero;
                    let result2 = &zero * &r;

                    assert!(result1.is_zero(), "r * 0 = 0");
                    assert!(result2.is_zero(), "0 * r = 0");
                }

                /// Test multiplicative identity: x * 1 = x
                #[test]
                fn test_mul_by_one() {
                    let r = TestRatio::from_u64(7, 13);
                    let one = TestRatio::one();

                    let result = &r * &one;

                    assert_eq!(result, r, "r * 1 = r");
                }

                /// Test additive identity: x + 0 = x
                #[test]
                fn test_add_zero() {
                    let r = TestRatio::from_u64(7, 13);
                    let zero = TestRatio::zero();

                    let result = &r + &zero;

                    assert_eq!(result, r, "r + 0 = r");
                }

                /// Test extreme size difference: huge * tiny
                #[test]
                fn test_mul_large_with_small() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let large = TestRatio::new_raw(get_large_value(), TestUint::from_u64(1), false);
                    let small = TestRatio::from_u64(1, 1000000);

                    let mut result = &large * &small;
                    result.normalize();

                    assert!(!result.denom.is_zero_bool());
                }

                /// Test from_float produces reduced fractions that multiply correctly.
                #[test]
                fn test_from_float_then_mul() {
                    let r1 = TestRatio::from_float(0.5).unwrap();
                    let r2 = TestRatio::from_float(0.25).unwrap();

                    let result = &r1 * &r2;

                    let mut normalized = result.clone();
                    normalized.normalize();
                    assert_eq!(normalized.numer, TestUint::from_u64(1));
                    assert_eq!(normalized.denom, TestUint::from_u64(8));
                }

                /// Test zero edge cases.
                #[test]
                fn test_zero_edge_cases() {
                    let zero = TestRatio::zero();
                    let one = TestRatio::one();
                    let half = TestRatio::from_u64(1, 2);

                    assert_eq!(zero, &zero + &zero);
                    assert_eq!(zero, &zero - &zero);
                    assert_eq!(zero, &zero * &one);
                    assert_eq!(zero, &half * &zero);
                    assert_eq!(zero, -zero.clone());
                }

                /// Test division by zero panics with correct message.
                #[test]
                #[should_panic(expected = "division by zero")]
                fn test_divide_by_zero() {
                    let one = TestRatio::one();
                    let zero = TestRatio::zero();
                    let _ = &one / &zero;
                }

                /// Test reciprocal of zero panics with correct message.
                #[test]
                #[should_panic(expected = "reciprocal of zero")]
                fn test_reciprocal_of_zero() {
                    let zero = TestRatio::zero();
                    let _ = zero.recip();
                }

                // ========================================================================
                // GCD TESTS
                // ========================================================================
                // Test GCD algorithm correctness and properties.

                /// Test GCD produces correct results for known inputs.
                /// Uses Euclidean algorithm (binary GCD for performance).
                #[test]
                fn test_gcd_correctness() {
                    let test_cases = vec![
                        (48u64, 18u64, 6u64),
                        (1071u64, 462u64, 21u64),
                        (100u64, 35u64, 5u64),
                        (u64::MAX / 2, u64::MAX / 3, 1u64),
                    ];

                    for (a, b, expected_gcd) in test_cases {
                        let a_uint = TestUint::from_u64(a);
                        let b_uint = TestUint::from_u64(b);

                        let result = TestUint::gcd(a_uint, b_uint);

                        assert_eq!(
                            result,
                            TestUint::from_u64(expected_gcd),
                            "GCD({}, {}) should be {}, got {:?}",
                            a,
                            b,
                            expected_gcd,
                            result
                        );
                    }

                    // Test large numbers only if we have enough bits
                    if TestUint::BITS >= 128 {
                        let large1 = TestUint::from_u128(123456789012345u128 * 17);
                        let large2 = TestUint::from_u128(123456789012345u128 * 19);
                        let g = TestUint::gcd(large1, large2);
                        assert_eq!(g, TestUint::from_u128(123456789012345u128));
                    }
                }

                /// Test mathematical properties that GCD must satisfy.
                /// Property 1: GCD divides both inputs
                /// Property 2: After dividing by GCD, results are coprime
                #[test]
                fn test_gcd_properties() {
                    let test_pairs = if TestUint::BITS <= 64 {
                        vec![
                            (TestUint::from_u64(123456789), TestUint::from_u64(987654321)),
                            (
                                TestUint::from_u64(u64::MAX / 7),
                                TestUint::from_u64(u64::MAX / 11),
                            ),
                            (
                                TestUint::from_u64(u64::MAX / 3),
                                TestUint::from_u64(u64::MAX / 5),
                            ),
                            (
                                TestUint::from_u64(1_000_000_000_000),
                                TestUint::from_u64(999_999_999_999),
                            ),
                        ]
                    } else {
                        vec![
                            (
                                TestUint::from_u128(123456789012345u128),
                                TestUint::from_u128(987654321098765u128),
                            ),
                            (
                                TestUint::from_u128(u128::MAX / 7),
                                TestUint::from_u128(u128::MAX / 11),
                            ),
                            (
                                TestUint::from_u128(u128::MAX / 3),
                                TestUint::from_u128(u128::MAX / 5),
                            ),
                            (
                                TestUint::from_u64(1_000_000_000_000),
                                TestUint::from_u64(999_999_999_999),
                            ),
                        ]
                    };

                    for (a, b) in test_pairs {
                        let g = TestUint::gcd(a, b);
                        assert_eq!(a.wrapping_rem(&g), TestUint::ZERO, "GCD must divide a");
                        assert_eq!(b.wrapping_rem(&g), TestUint::ZERO, "GCD must divide b");

                        if !g.is_zero_bool() {
                            let a_normalized = a.wrapping_div(&g);
                            let b_normalized = b.wrapping_div(&g);
                            let g2 = TestUint::gcd(a_normalized, b_normalized);
                            assert_eq!(
                                g2,
                                TestUint::ONE,
                                "After dividing by GCD, values must be coprime"
                            );
                        }
                    }
                }

                /// Test GCD with large bit-size differences.
                #[test]
                fn test_gcd_with_large_bit_differences() {
                    let small = TestUint::from_u64(12345);
                    let large = if TestUint::BITS <= 64 {
                        TestUint::from_u64(u64::MAX / 100)
                    } else {
                        TestUint::from_u128(u128::MAX / 100)
                    };

                    let g1 = TestUint::gcd(small, large);
                    let g2 = TestUint::gcd(large, small);

                    assert_eq!(g1, g2, "GCD must be commutative");
                    assert_eq!(small.wrapping_rem(&g1), TestUint::ZERO);
                    assert_eq!(large.wrapping_rem(&g1), TestUint::ZERO);
                }

                /// Test consecutive numbers are coprime: gcd(n, n+1) = 1
                #[test]
                fn test_gcd_consecutive_numbers() {
                    let n = if TestUint::BITS <= 64 {
                        TestUint::from_u64(u64::MAX / 2)
                    } else {
                        TestUint::from_u128(u128::MAX / 2)
                    };
                    let n_plus_1 = n.wrapping_add(&TestUint::ONE);

                    let g = TestUint::gcd(n, n_plus_1);
                    assert_eq!(g, TestUint::ONE, "Consecutive numbers must be coprime");
                }

                /// Test GCD of powers of 2: gcd(2^a, 2^b) = 2^min(a,b)
                #[test]
                fn test_gcd_powers_of_two() {
                    let a = TestUint::ONE.shl_vartime(100);
                    let b = TestUint::ONE.shl_vartime(150);
                    let g = TestUint::gcd(a, b);

                    assert_eq!(g, a, "GCD of 2^100 and 2^150 should be 2^100");
                }

                /// Test GCD with known common factor.
                #[test]
                fn test_gcd_with_common_factors() {
                    let factor = if TestUint::BITS <= 64 {
                        TestUint::from_u64(123456789u64)
                    } else {
                        TestUint::from_u128(123456789u128)
                    };
                    let a = factor.wrapping_mul(&TestUint::from_u64(17));
                    let b = factor.wrapping_mul(&TestUint::from_u64(19));

                    let g = TestUint::gcd(a, b);
                    assert_eq!(g, factor, "GCD should be the common factor");
                }

                /// Test GCD with near-equal values (worst case for Euclidean algorithm).
                #[test]
                fn test_gcd_near_equal_values() {
                    let a = if TestUint::BITS <= 64 {
                        TestUint::from_u64(u64::MAX / 1000)
                    } else {
                        TestUint::from_u128(u128::MAX / 1000)
                    };
                    let b = a.wrapping_sub(&TestUint::from_u64(1));

                    let g = TestUint::gcd(a, b);

                    assert!(
                        g.bits_u32() < 64,
                        "GCD of near-equal values should be small"
                    );
                    assert_eq!(a.wrapping_rem(&g), TestUint::ZERO);
                    assert_eq!(b.wrapping_rem(&g), TestUint::ZERO);
                }

                /// Test GCD(x, 0) = x (mathematical definition).
                #[test]
                fn test_gcd_with_zero_and_nonzero() {
                    let nonzero = if TestUint::BITS <= 64 {
                        TestUint::from_u64(123456789)
                    } else {
                        TestUint::from_u128(123456789)
                    };
                    let zero = TestUint::ZERO;

                    assert_eq!(TestUint::gcd(nonzero, zero), nonzero);
                    assert_eq!(TestUint::gcd(zero, nonzero), nonzero);
                }

                /// Test consecutive Fibonacci numbers are coprime (classic GCD test).
                #[test]
                fn test_fibonacci_like_gcd() {
                    let fib_a_uint = if TestUint::BITS <= 64 {
                        TestUint::from_u64(1134903170u64)
                    } else {
                        TestUint::from_u128(1134903170u128)
                    };

                    let fib_b_uint = if TestUint::BITS <= 64 {
                        TestUint::from_u64(1836311903u64)
                    } else {
                        TestUint::from_u128(1836311903u128)
                    };

                    let g = TestUint::gcd(fib_a_uint, fib_b_uint);
                    assert_eq!(
                        g,
                        TestUint::ONE,
                        "Consecutive Fibonacci numbers must be coprime"
                    );
                }

                // ========================================================================
                // MULTIPLICATION SEQUENCE TESTS
                // ========================================================================
                // Test repeated multiplications.

                /// Test multiplication fast path (no overflow).
                #[test]
                fn test_mul_wide_fast_path() {
                    let r1 = TestRatio::from_u64(123, 456);
                    let r2 = TestRatio::from_u64(789, 321);

                    let result = &r1 * &r2;

                    let num1 = NumRational::new(BigInt::from(123), BigInt::from(456));
                    let num2 = NumRational::new(BigInt::from(789), BigInt::from(321));
                    let expected = num1 * num2;

                    let mut normalized_result = result.clone();
                    normalized_result.normalize();
                    assert!(compare_ratios(&normalized_result, &expected));
                }

                /// Test large multiplication requiring cross-cancellation.
                #[test]
                fn test_very_large_multiplication() {
                    // Use size-appropriate large values - be more conservative
                    let large = if TestUint::BITS <= 64 {
                        TestUint::from_u64(10_000) // Very small for U64
                    } else if TestUint::BITS <= 192 {
                        TestUint::from_u64(100_000) // Small for U192
                    } else if TestUint::BITS <= 256 {
                        TestUint::from_u64(u64::MAX / 1000)
                    } else {
                        get_large_value()
                    };

                    let r1 = TestRatio::new_raw(large, TestUint::from_u64(1000), false);
                    let r2 = TestRatio::new_raw(large, TestUint::from_u64(2000), false);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    // Verify against num-bigint for correctness
                    let bytes = large.to_be_bytes();
                    let big_val = BigInt::from_bytes_be(num_bigint::Sign::Plus, &bytes);

                    let num1 = NumRational::new(big_val.clone(), BigInt::from(1000u64));
                    let num2 = NumRational::new(big_val, BigInt::from(2000u64));
                    let expected = num1 * num2;

                    assert!(
                        compare_ratios(&result, &expected),
                        "Large multiplication failed"
                    );
                }

                /// Test multiplication with various sizes and GCD patterns.
                #[test]
                fn test_multiplication_with_reduction_verification() {
                    let test_cases = if TestUint::BITS <= 64 {
                        vec![
                            ((12u64, 35u64), (15u64, 28u64)),
                            ((123u64, 789u64), (456u64, 901u64)),
                        ]
                    } else {
                        vec![
                            ((12u64, 35u64), (15u64, 28u64)),
                            ((123456u64, 789012u64), (345678u64, 901234u64)),
                            (
                                (u64::MAX / 100, u64::MAX / 101),
                                (u64::MAX / 102, u64::MAX / 103),
                            ),
                        ]
                    };

                    for ((n1, d1), (n2, d2)) in test_cases {
                        let r1 = TestRatio::from_u64(n1, d1);
                        let r2 = TestRatio::from_u64(n2, d2);
                        let mut result = &r1 * &r2;
                        result.normalize();

                        let num1 = NumRational::new(BigInt::from(n1), BigInt::from(d1));
                        let num2 = NumRational::new(BigInt::from(n2), BigInt::from(d2));
                        let expected = num1 * num2;

                        assert!(
                            compare_ratios(&result, &expected),
                            "Multiplication {}/{} * {}/{} failed",
                            n1,
                            d1,
                            n2,
                            d2
                        );
                    }
                }

                /// Test extreme size differences in multiplication.
                #[test]
                fn test_multiplication_extreme_sizes() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let tiny_num = TestUint::ONE;
                    let huge_denom = get_huge_value();

                    let r1 = TestRatio::new_raw(tiny_num, huge_denom, false);
                    let r2 = TestRatio::new_raw(tiny_num, huge_denom, false);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert!(!result.denom.is_zero_bool());
                    assert!(result.numer.bits_u32() <= 10);
                }

                /// Test repeated multiplication (simulates power/exponentiation).
                /// Verifies (1/2)^20 calculated correctly.
                #[test]
                fn test_multiplication_many_iterations() {
                    let x = TestRatio::from_u64(1, 2);
                    let mut result = TestRatio::one();

                    for i in 0..20 {
                        result = &result * &x;

                        let mut expected_result = result.clone();
                        expected_result.normalize();

                        let expected =
                            NumRational::new(BigInt::from(1), BigInt::from(2u64.pow(i + 1)));

                        assert!(
                            compare_ratios(&expected_result, &expected),
                            "After {} multiplications, result incorrect",
                            i + 1
                        );
                    }
                }

                /// Test cross-cancellation effectiveness: (a/b) * (b/a) = 1
                #[test]
                fn test_cross_cancellation_effectiveness() {
                    let (a, b) = if TestUint::BITS <= 64 {
                        (
                            TestUint::from_u64(1_000_000_000_000),
                            TestUint::from_u64(2_000_000_000_000),
                        )
                    } else {
                        (
                            TestUint::from_u128(1000000000000000u128),
                            TestUint::from_u128(2000000000000000u128),
                        )
                    };

                    let r1 = TestRatio::new_raw(a, b, false);
                    let r2 = TestRatio::new_raw(b, a, false);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert_eq!(result.numer, TestUint::ONE);
                    assert_eq!(result.denom, TestUint::ONE);
                }

                /// Test multiplication of coprime fractions (no cancellation possible).
                #[test]
                fn test_mul_with_coprime_values() {
                    let r1 = TestRatio::from_u64(17, 19);
                    let r2 = TestRatio::from_u64(23, 29);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert_eq!(result.numer, TestUint::from_u64(17 * 23));
                    assert_eq!(result.denom, TestUint::from_u64(19 * 29));
                }

                /// Test multiplicative inverse: a/b * b/a = 1
                #[test]
                fn test_multiply_by_reciprocal() {
                    let test_values =
                        vec![(7u64, 13u64), (123u64, 456u64), (999999u64, 1000000u64)];

                    for (n, d) in test_values {
                        let r = TestRatio::from_u64(n, d);
                        let r_inv = TestRatio::from_u64(d, n);

                        let mut result = &r * &r_inv;
                        result.normalize();

                        assert_eq!(
                            result.numer,
                            TestUint::ONE,
                            "n={}, d={}: result should be 1",
                            n,
                            d
                        );
                        assert_eq!(
                            result.denom,
                            TestUint::ONE,
                            "n={}, d={}: result should be 1",
                            n,
                            d
                        );
                    }
                }

                /// Test telescoping product: (2/3) * (3/4) * (4/5) * (5/6) * (6/7) = 2/7
                #[test]
                fn test_multiply_sequence_with_verification() {
                    let mut acc = TestRatio::from_u64(1, 1);

                    let factors = vec![(2, 3), (3, 4), (4, 5), (5, 6), (6, 7)];

                    for (n, d) in factors {
                        let r = TestRatio::from_u64(n, d);
                        acc = &acc * &r;
                    }

                    acc.normalize();

                    // Result should be 720/2520 = 2/7
                    assert_eq!(acc.numer, TestUint::from_u64(2));
                    assert_eq!(acc.denom, TestUint::from_u64(7));
                }

                /// Test multiplication chain with common factors.
                #[test]
                fn test_multiply_chain_normalizes_correctly() {
                    let r1 = TestRatio::from_u64(2, 4);
                    let r2 = TestRatio::from_u64(4, 6);
                    let r3 = TestRatio::from_u64(6, 8);

                    let mut result = (&r1 * &r2) * r3;
                    result.normalize();

                    assert_eq!(result.numer, TestUint::ONE);
                    assert_eq!(result.denom, TestUint::from_u64(4));
                }

                /// Test large pre-normalized fractions multiply correctly.
                #[test]
                fn test_multiply_very_large_normalized_fractions() {
                    let r1 = TestRatio::from_u64(1000000, 2000000);
                    let r2 = TestRatio::from_u64(3000000, 6000000);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert_eq!(result.numer, TestUint::ONE);
                    assert_eq!(result.denom, TestUint::from_u64(4));
                }

                /// Test multiplication overflow requiring wide reduction.
                #[test]
                fn test_large_multiply_needs_wide_reduction() {
                    if skip_if_too_small(256) {
                        return;
                    }

                    let large = get_large_value();

                    let r1 = TestRatio::new_raw(large, TestUint::from_u64(100), false);
                    let r2 = TestRatio::new_raw(large, TestUint::from_u64(200), false);

                    let mut result = &r1 * &r2;
                    result.normalize();

                    assert!(!result.denom.is_zero_bool());
                }

                // ========================================================================
                // ADDITION TESTS
                // ========================================================================

                /// Test same-denominator addition optimization.
                /// When denominators equal, result = (a+b)/d (no LCM calculation needed).
                #[test]
                fn test_add_same_denominator() {
                    let r1 = TestRatio::from_u64(1, 6);
                    let r2 = TestRatio::from_u64(2, 6);

                    let mut result = &r1 + &r2;
                    result.normalize();

                    assert_eq!(result.numer, TestUint::from_u64(1));
                    assert_eq!(result.denom, TestUint::from_u64(2));
                }

                /// Test addition with large LCM (coprime denominators).
                /// lcm(999983, 999979) = 999983 * 999979 (huge!)
                #[test]
                fn test_addition_with_large_lcm() {
                    let r1 = TestRatio::from_u64(1, 999983);
                    let r2 = TestRatio::from_u64(1, 999979);

                    let mut result = &r1 + &r2;
                    result.normalize();

                    let num1 = NumRational::new(BigInt::from(1), BigInt::from(999983));
                    let num2 = NumRational::new(BigInt::from(1), BigInt::from(999979));
                    let expected = num1 + num2;

                    assert!(
                        compare_ratios(&result, &expected),
                        "Addition with large LCM failed"
                    );
                }

                // ========================================================================
                // TAYLOR SERIES AND REALISTIC WORKLOADS
                // ========================================================================
                // Test real-world usage patterns.

                /// Test Taylor series accumulation pattern (e^x approximation).
                /// Pattern: φ = 1 + x + x²/2! + x³/3! + ...
                /// Note: Uses smaller values for U256 to avoid overflow
                #[test]
                fn test_taylor_series_accumulation() {
                    let mut phi = TestRatio::one();

                    // Scale values and iterations to integer size
                    let (numer, denom, iterations) = if TestUint::BITS <= 64 {
                        (12345u64, 67890u64, 3)
                    } else if TestUint::BITS <= 128 {
                        (123456u64, 789012u64, 4)
                    } else if TestUint::BITS <= 256 {
                        (1234567u64, 8901234u64, 4)
                    } else {
                        (5089366576984891u64, 2552174939754843u64, 5)
                    };

                    let x = TestRatio::from_u64(numer, denom);
                    let mut new_x = x.clone();
                    let mut divisor = TestUint::ONE;

                    for _ in 0..iterations {
                        phi = phi.add(&new_x);
                        divisor = divisor.wrapping_add(&TestUint::ONE);
                        new_x = new_x.mul(&x).div_by_uint(&divisor);
                    }

                    let mut normalized = phi.clone();
                    normalized.normalize();

                    assert!(!normalized.denom.is_zero_bool());
                }

                /// Test realistic Taylor series with needs_reduction() heuristic.
                #[test]
                fn test_taylor_series_realistic() {
                    let x = TestRatio::from_u64(1, 10);
                    let mut phi = TestRatio::one();
                    let mut new_x = x.clone();
                    let mut divisor = TestUint::ONE;

                    // Reduce iterations for smaller types to avoid overflow
                    let max_iterations = if TestUint::BITS <= 64 {
                        10
                    } else if TestUint::BITS <= 128 {
                        15
                    } else {
                        20
                    };

                    for i in 0..max_iterations {
                        phi = phi.add(&new_x);

                        // Only reduce when heuristic triggers (performance optimization)
                        if phi.needs_reduction() {
                            phi.normalize();
                        }

                        divisor = divisor.wrapping_add(&TestUint::ONE);
                        new_x = new_x.mul(&x).div_by_uint(&divisor);

                        assert!(
                            !phi.denom.is_zero_bool(),
                            "Iteration {}: denominator became zero",
                            i
                        );
                    }

                    phi.normalize();
                    assert!(phi.is_positive());
                }

                /// Test many repeated additions (stress test).
                /// Simulates accumulating small increments (common pattern).
                #[test]
                fn test_repeated_operations() {
                    let mut acc = TestRatio::one();
                    let increment = TestRatio::from_u64(1, 1000);

                    for _ in 0..100 {
                        acc = acc.add(&increment);
                    }

                    let mut normalized = acc.clone();
                    normalized.normalize();

                    // Should be 1 + 100/1000 = 1.1 = 11/10
                    let expected = NumRational::new(BigInt::from(11), BigInt::from(10));

                    assert!(
                        compare_ratios(&normalized, &expected),
                        "Repeated operations failed"
                    );
                }

                // ========================================================================
                // MISCELLANEOUS TESTS
                // ========================================================================

                /// Test division by large integer.
                /// div_by_uint multiplies denominator: a/b ÷ n = a/(b*n)
                #[test]
                fn test_division_by_large_uint() {
                    if skip_if_too_small(128) {
                        return;
                    }

                    let r = TestRatio::from_u64(1, 2);
                    let large_divisor = if TestUint::BITS >= 128 {
                        TestUint::from_u128(u128::MAX / 1000)
                    } else {
                        TestUint::from_u64(u64::MAX / 1000)
                    };

                    let result = r.div_by_uint(&large_divisor);

                    assert!(!result.denom.is_zero_bool());
                }

                /// Test reciprocal operation: 1/(a/b) = b/a
                #[test]
                fn test_reciprocal_compatibility() {
                    let test_cases = vec![(2u64, 3u64), (5u64, 7u64), (1u64, 1u64)];

                    for (n, d) in test_cases {
                        let r = TestRatio::from_u64(n, d);
                        let recip = r.recip();

                        assert_eq!(recip.numer, TestUint::from_u64(d));
                        assert_eq!(recip.denom, TestUint::from_u64(n));
                    }
                }

                /// Test is_integer() predicate.
                #[test]
                fn test_is_integer_compatibility() {
                    assert!(TestRatio::from_u64(5, 1).is_integer());
                    assert!(!TestRatio::from_u64(5, 2).is_integer());
                    assert!(TestRatio::zero().is_integer());
                }

                /// Test sign predicates (is_positive, is_negative).
                #[test]
                fn test_sign_checks() {
                    let pos = TestRatio::from_u64(1, 2);
                    let neg = -TestRatio::from_u64(1, 2);
                    let zero = TestRatio::zero();

                    assert!(pos.is_positive());
                    assert!(!pos.is_negative());

                    assert!(!neg.is_positive());
                    assert!(neg.is_negative());

                    assert!(!zero.is_positive());
                    assert!(!zero.is_negative());
                }

                /// Test from_float edge cases and precision.
                #[test]
                fn test_from_float_edge_cases_comprehensive() {
                    // Very small positive - too small to represent
                    let tiny = TestRatio::from_float(f64::MIN_POSITIVE).unwrap();
                    assert!(tiny.is_zero());

                    // Small but representable
                    let small = TestRatio::from_float(1e-10).unwrap();
                    assert!(small.is_positive());

                    // Test large values only if type is big enough
                    if TestUint::BITS >= 128 {
                        let huge_value = if TestUint::BITS <= 128 { 1e30 } else { 1e100 };
                        let huge = TestRatio::from_float(huge_value).unwrap();
                        assert!(huge.is_positive());
                    }

                    // Negative zero becomes positive zero
                    let neg_zero = TestRatio::from_float(-0.0).unwrap();
                    assert!(neg_zero.is_zero());

                    // Powers of 2 are exact
                    let max_exp = if TestUint::BITS <= 64 { 5 } else { 10 };
                    for exp in 0..max_exp {
                        let val = 2.0_f64.powi(exp);
                        let r = TestRatio::from_float(val).unwrap();
                        assert!((r.to_f64_approx() - val).abs() < f64::EPSILON);
                    }

                    // Negative powers of 2
                    for exp in 1..10 {
                        let val = 2.0_f64.powi(-exp);
                        let r = TestRatio::from_float(val).unwrap();
                        assert!((r.to_f64_approx() - val).abs() < 1e-15);
                    }
                }

                // ========================================================================
                // MATHEMATICAL PROPERTIES
                // ========================================================================
                // Verify algebraic laws and field properties.

                /// Test commutativity: a+b = b+a, a*b = b*a
                #[test]
                fn test_commutativity() {
                    let a = TestRatio::from_u64(2, 3);
                    let b = TestRatio::from_u64(3, 5);

                    // Addition
                    let mut ab = &a + &b;
                    ab.normalize();
                    let mut ba = &b + &a;
                    ba.normalize();
                    assert_eq!(ab, ba, "Addition should be commutative");

                    // Multiplication
                    let mut ab_mul = &a * &b;
                    ab_mul.normalize();
                    let mut ba_mul = &b * &a;
                    ba_mul.normalize();
                    assert_eq!(ab_mul, ba_mul, "Multiplication should be commutative");
                }

                /// Test associativity: (a+b)+c = a+(b+c), (a*b)*c = a*(b*c)
                #[test]
                fn test_associativity() {
                    let a = TestRatio::from_u64(2, 3);
                    let b = TestRatio::from_u64(3, 5);
                    let c = TestRatio::from_u64(5, 7);

                    // Addition
                    let mut left = (&a + &b) + c.clone();
                    left.normalize();
                    let mut right = &a + &(&b + &c);
                    right.normalize();
                    assert_eq!(left, right, "Addition should be associative");

                    // Multiplication
                    let mut left_mul = (&a * &b) * c.clone();
                    left_mul.normalize();
                    let mut right_mul = &a * &(&b * &c);
                    right_mul.normalize();
                    assert_eq!(left_mul, right_mul, "Multiplication should be associative");
                }

                /// Test distributivity: a*(b+c) = a*b + a*c
                #[test]
                fn test_distributivity() {
                    let a = TestRatio::from_u64(2, 3);
                    let b = TestRatio::from_u64(3, 5);
                    let c = TestRatio::from_u64(5, 7);

                    let mut left = &a * &(&b + &c);
                    left.normalize();
                    let mut right = (&a * &b) + (&a * &c);
                    right.normalize();
                    assert_eq!(
                        left, right,
                        "Multiplication should distribute over addition"
                    );
                }

                /// Test identity elements: 0 for addition, 1 for multiplication
                #[test]
                fn test_identity_elements() {
                    let a = TestRatio::from_u64(7, 13);
                    let zero = TestRatio::zero();
                    let one = TestRatio::one();

                    // Additive identity: a + 0 = a
                    let mut a_plus_zero = &a + &zero;
                    a_plus_zero.normalize();
                    let mut a_normalized = a.clone();
                    a_normalized.normalize();
                    assert_eq!(a_plus_zero, a_normalized, "a + 0 = a");

                    // Multiplicative identity: a * 1 = a
                    let mut a_times_one = &a * &one;
                    a_times_one.normalize();
                    assert_eq!(a_times_one, a_normalized, "a * 1 = a");
                }

                /// Test inverse elements: a+(-a)=0, a*(1/a)=1
                #[test]
                fn test_inverse_elements() {
                    let a = TestRatio::from_u64(7, 13);
                    let zero = TestRatio::zero();
                    let one = TestRatio::one();

                    // Additive inverse
                    let mut a_minus_a = &a + &(-a.clone());
                    a_minus_a.normalize();
                    assert_eq!(a_minus_a, zero, "a + (-a) = 0");

                    // Multiplicative inverse
                    let mut a_times_recip = &a * &a.recip();
                    a_times_recip.normalize();
                    assert_eq!(a_times_recip, one, "a * (1/a) = 1");

                    // Subtraction inverse
                    let mut a_sub_a = &a - &a;
                    a_sub_a.normalize();
                    assert_eq!(a_sub_a, zero, "a - a = 0");

                    // Division inverse
                    let mut a_div_a = &a / &a;
                    a_div_a.normalize();
                    assert_eq!(a_div_a, one, "a / a = 1");
                }
            }
        };
    }

    // ============================================================================
    // INSTANTIATE TEST SUITE FOR EACH INTEGER SIZE
    // ============================================================================

    // Small sizes (64-960 bits)
    generate_ratio_tests!(u64_tests, U64, crypto_ratio::Ratio<U64>);
    generate_ratio_tests!(u128_tests, U128, crypto_ratio::Ratio<U128>);
    generate_ratio_tests!(u192_tests, U192, crypto_ratio::Ratio<U192>);
    generate_ratio_tests!(u256_tests, U256, crypto_ratio::Ratio<U256>);
    generate_ratio_tests!(u320_tests, U320, crypto_ratio::Ratio<U320>);
    generate_ratio_tests!(u384_tests, U384, crypto_ratio::Ratio<U384>);
    generate_ratio_tests!(u448_tests, U448, crypto_ratio::Ratio<U448>);
    generate_ratio_tests!(u512_tests, U512, crypto_ratio::RatioU512); // Type alias
    generate_ratio_tests!(u576_tests, U576, crypto_ratio::Ratio<U576>);
    generate_ratio_tests!(u640_tests, U640, crypto_ratio::Ratio<U640>);
    generate_ratio_tests!(u704_tests, U704, crypto_ratio::Ratio<U704>);
    generate_ratio_tests!(u768_tests, U768, crypto_ratio::Ratio<U768>);
    generate_ratio_tests!(u832_tests, U832, crypto_ratio::Ratio<U832>);
    generate_ratio_tests!(u896_tests, U896, crypto_ratio::Ratio<U896>);
    generate_ratio_tests!(u960_tests, U960, crypto_ratio::Ratio<U960>);

    // Medium sizes (1024-2048 bits)
    generate_ratio_tests!(u1024_tests, U1024, crypto_ratio::Ratio<U1024>);
    generate_ratio_tests!(u1280_tests, U1280, crypto_ratio::Ratio<U1280>);
    generate_ratio_tests!(u1536_tests, U1536, crypto_ratio::Ratio<U1536>);
    generate_ratio_tests!(u1792_tests, U1792, crypto_ratio::Ratio<U1792>);
    generate_ratio_tests!(u2048_tests, U2048, crypto_ratio::Ratio<U2048>);

    // Large sizes (3072-4352 bits)
    generate_ratio_tests!(u3072_tests, U3072, crypto_ratio::Ratio<U3072>);
    generate_ratio_tests!(u3584_tests, U3584, crypto_ratio::Ratio<U3584>);
    generate_ratio_tests!(u4096_tests, U4096, crypto_ratio::Ratio<U4096>);
    generate_ratio_tests!(u4224_tests, U4224, crypto_ratio::Ratio<U4224>);
    generate_ratio_tests!(u4352_tests, U4352, crypto_ratio::Ratio<U4352>);

    // Very large sizes (6144-32768 bits)
    generate_ratio_tests!(u6144_tests, U6144, crypto_ratio::Ratio<U6144>);
    generate_ratio_tests!(u8192_tests, U8192, crypto_ratio::Ratio<U8192>);
    generate_ratio_tests!(u16384_tests, U16384, crypto_ratio::Ratio<U16384>);
}
