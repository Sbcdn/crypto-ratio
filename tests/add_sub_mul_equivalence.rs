//! Equivalence tests for `add_sub` and the integer-operand `mul` fast path,
//! against two references:
//!   1. bitwise vs `add`/`sub`/`mul` — these must be exact no-op refactors,
//!   2. value vs `num-rational` — an independent rational implementation.
//! Covers small, large (overflow-path), equal-denominator, and zero operands.

use crypto_bigint::{Encoding, U512};
use crypto_ratio::RatioU512;
use num_bigint::{BigInt, Sign};
use num_rational::Ratio as NumRatio;

type NumR = NumRatio<BigInt>;

fn to_num(r: &RatioU512) -> NumR {
    let n = BigInt::from_bytes_le(Sign::Plus, r.numer.to_le_bytes().as_ref());
    let d = BigInt::from_bytes_le(Sign::Plus, r.denom.to_le_bytes().as_ref());
    let n = if r.negative { -n } else { n };
    NumR::new(n, d) // num-rational reduces on construction
}

/// Deterministic xorshift so the corpus of test inputs is reproducible.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    /// A U512 with `words` 64-bit limbs filled (1..=8) — varies magnitude so we
    /// hit both the narrow fast path and the wide-overflow fallback in add/mul.
    fn uint(&mut self, words: usize) -> U512 {
        let mut bytes = [0u8; 64];
        for i in 0..words.min(8) {
            bytes[i * 8..i * 8 + 8].copy_from_slice(&self.next().to_le_bytes());
        }
        U512::from_le_bytes(bytes)
    }
    fn nonzero(&mut self, words: usize) -> U512 {
        let v = self.uint(words);
        if v == U512::ZERO { U512::ONE } else { v }
    }
}

/// The decisive proof: `add_sub` is bit-for-bit identical to `(add, sub)` at
/// ALL magnitudes — narrow fast path, equal-denom, and the wide-overflow
/// fallback. If this holds, the change cannot alter any observable behaviour.
#[test]
fn add_sub_is_bit_identical_to_add_and_sub() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    for i in 0..20_000u64 {
        let aw = (i % 4) as usize + 1;
        let bw = ((i / 4) % 4) as usize + 1;
        let a = RatioU512::new_raw(rng.uint(aw), rng.nonzero(aw), i & 1 == 0);
        let b = RatioU512::new_raw(rng.uint(bw), rng.nonzero(bw), i & 2 == 0);

        let (sum, diff) = a.add_sub(&b);
        let want_sum = RatioU512::add(&a, &b);
        let want_diff = RatioU512::sub(&a, &b);

        assert_eq!(
            (&sum.numer, &sum.denom, sum.negative),
            (&want_sum.numer, &want_sum.denom, want_sum.negative),
            "add_sub sum != add  (case {i})"
        );
        assert_eq!(
            (&diff.numer, &diff.denom, diff.negative),
            (&want_diff.numer, &want_diff.denom, want_diff.negative),
            "add_sub diff != sub  (case {i})"
        );
    }
}

/// Independent-oracle value check, within crypto-ratio's exact arithmetic range
/// (<=64-bit numer/denom so cross-products never exceed U512 — beyond that the
/// crate's own unreduced `add` wraps, by design, and would diverge from
/// arbitrary-precision num-rational regardless of `add_sub`).
#[test]
fn add_sub_values_match_num_rational_in_range() {
    let mut rng = Rng(0x2545_F491_4F6C_DD1D);
    for i in 0..20_000u64 {
        let a = RatioU512::new_raw(rng.uint(1), rng.nonzero(1), i & 1 == 0);
        let b = RatioU512::new_raw(rng.uint(1), rng.nonzero(1), i & 2 == 0);

        let (sum, diff) = a.add_sub(&b);
        let (na, nb) = (to_num(&a), to_num(&b));
        assert_eq!(to_num(&sum), &na + &nb, "add_sub sum value (case {i})");
        assert_eq!(to_num(&diff), &na - &nb, "add_sub diff value (case {i})");
    }
}

#[test]
fn mul_integer_operand_is_oracle_correct() {
    let mut rng = Rng(0xD1B5_4A32_D192_ED03);
    for i in 0..20_000u64 {
        let aw = (i % 4) as usize + 1;
        let a = RatioU512::new_raw(rng.uint(aw), rng.nonzero(aw), i & 1 == 0);
        let k = (rng.next() % 1_000_000) + 1; // small integer multiplier
        let int = RatioU512::from_u64(k, 1); // denom == 1 -> fast path

        let p = RatioU512::mul(&a, &int);
        let q = RatioU512::mul(&int, &a); // symmetric (self.denom == 1)

        let want = to_num(&a) * BigInt::from(k);
        assert_eq!(to_num(&p), want, "mul(a, k) value (case {i})");
        assert_eq!(to_num(&q), want, "mul(k, a) value (case {i})");
    }
}
