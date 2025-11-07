//! Arbitrary-precision rational number arithmetic using crypto-bigint integers.
//!
//! This library provides `Ratio<T>`, a generic rational number type supporting
//! any crypto-bigint unsigned integer from U64 to U16384.
//!
//! # Features
//!
//! - **Generic over integer width**: Works with U256, U512, U1024, U2048, etc.
//! - **Performance-focused**: Deferred reduction and smart heuristics
//! - **Overflow handling**: Automatic fallback to wider types when needed
//! - **no_std compatible**: Works in embedded and constrained environments
//!
//! # Design Philosophy
//!
//! Operations like multiplication and addition return **unreduced** results by default.
//! Call [`Ratio::normalize`] explicitly when reduction is needed. This design
//! improves performance in loops and chained operations.
//!
//! For convenience, [`Ratio::mul_reduced`] provides smart reduction using fast
//! heuristics that avoid expensive GCD operations when possible.
//!
//! # Examples
//!
//! ## Basic Usage
//!
//! ```
//! use crypto_ratio::Ratio;
//! use crypto_bigint::U256;
//!
//! // Create rationals
//! let a = Ratio::<U256>::from_u64(1, 2);  // 1/2
//! let b = Ratio::<U256>::from_u64(1, 3);  // 1/3
//!
//! // Operations return unreduced results
//! let sum = &a + &b;  // 5/6
//! assert_eq!(sum.numer, U256::from_u64(5));
//! assert_eq!(sum.denom, U256::from_u64(6));
//!
//! // Explicit reduction when needed
//! let product = &a * &b;  // 1/6 (unreduced as 2/12)
//! let mut reduced = product.clone();
//! reduced.normalize();
//! assert_eq!(reduced.numer, U256::from_u64(1));
//! assert_eq!(reduced.denom, U256::from_u64(6));
//! ```
//!
//! ## Type Aliases
//!
//! ```
//! use crypto_ratio::RatioU512;
//!
//! let r = RatioU512::from_u64(3, 4);
//! assert_eq!(r.to_f64_approx(), 0.75);
//! ```
//!
//! ## Deferred Reduction Pattern
//!
//! ```
//! use crypto_ratio::RatioU512;
//!
//! // Accumulate without reduction
//! let mut sum = RatioU512::zero();
//! let increment = RatioU512::from_u64(1, 100);
//!
//! for _ in 0..10 {
//!     sum = sum.add(&increment);
//! }
//!
//! // Reduce once at the end
//! sum.normalize();
//! ```

pub mod ratio_trait;

pub use crate::ratio_trait::{RatioInteger, WideInteger};
use core::cmp::Ordering;

/// A rational number represented as numerator/denominator with explicit sign.
///
/// # Type Parameter
///
/// `T` must implement [`RatioInteger`], which includes all crypto-bigint types
/// from U64 through U16384.
///
/// # Invariants
///
/// - Denominator is never zero
/// - Values are not automatically reduced (call [`normalize`](Ratio::normalize) explicitly)
/// - Sign is stored separately in the `negative` field
/// - Zero is always represented with `negative = false`
///
/// # Examples
///
/// ```
/// use crypto_ratio::Ratio;
/// use crypto_bigint::U512;
///
/// let r = Ratio::<U512>::from_u64(2, 3);
/// assert_eq!(r.numer, U512::from_u64(2));
/// assert_eq!(r.denom, U512::from_u64(3));
/// assert!(!r.negative);
/// ```
#[derive(Clone, Debug)]
pub struct Ratio<T: RatioInteger> {
    /// The numerator.
    pub numer: T,
    /// The denominator.
    pub denom: T,
    /// Sign of the rational (true = negative).
    pub negative: bool,
}

impl<T: RatioInteger> Ratio<T> {
    // ========================================================================
    // CONSTRUCTORS
    // ========================================================================

    /// Create a ratio without reduction.
    ///
    /// The denominator must be non-zero. This method is fast but the caller
    /// is responsible for calling [`normalize`](Ratio::normalize) if needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::Ratio;
    /// use crypto_bigint::U256;
    ///
    /// let r = Ratio::new_raw(U256::from_u64(4), U256::from_u64(6), false);
    /// assert_eq!(r.numer, U256::from_u64(4)); // Not reduced
    /// assert_eq!(r.denom, U256::from_u64(6));
    /// ```
    #[inline(always)]
    pub fn new_raw(numer: T, denom: T, negative: bool) -> Self {
        Self {
            numer,
            denom,
            negative,
        }
    }

    /// Create a ratio with automatic GCD reduction.
    ///
    /// This is slower than [`new_raw`](Ratio::new_raw) but ensures the result
    /// is in lowest terms.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::Ratio;
    /// use crypto_bigint::U256;
    ///
    /// let r = Ratio::new(U256::from_u64(4), U256::from_u64(6));
    /// assert_eq!(r.numer, U256::from_u64(2)); // Reduced
    /// assert_eq!(r.denom, U256::from_u64(3));
    /// ```
    pub fn new(numer: T, denom: T) -> Self {
        if numer.is_zero_bool() {
            return Self::zero();
        }
        let g = T::gcd(numer.clone(), denom.clone());
        Self {
            numer: numer.wrapping_div(&g),
            denom: denom.wrapping_div(&g),
            negative: false,
        }
    }

    /// Create from u64 with automatic reduction.
    ///
    /// This is the most efficient constructor for small values.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let r = RatioU256::from_u64(6, 8);
    /// assert_eq!(r.to_f64_approx(), 0.75);
    /// ```
    #[inline]
    pub fn from_u64(numer: u64, denom: u64) -> Self {
        let g = gcd_u64(numer, denom);
        Self {
            numer: T::from_u64(numer / g),
            denom: T::from_u64(denom / g),
            negative: false,
        }
    }

    /// Create a ratio representing 1.
    #[inline(always)]
    pub fn one() -> Self {
        Self {
            numer: T::ONE,
            denom: T::ONE,
            negative: false,
        }
    }

    /// Create a ratio representing 0.
    #[inline(always)]
    pub fn zero() -> Self {
        Self {
            numer: T::ZERO,
            denom: T::ONE,
            negative: false,
        }
    }

    // ========================================================================
    // BASIC OPERATIONS
    // ========================================================================

    /// Negate the ratio, flipping its sign.
    #[allow(clippy::should_implement_trait)] // We do implement Neg trait, clippy doesn't detect it
    #[inline(always)]
    pub fn neg(mut self) -> Self {
        if !self.numer.is_zero_bool() {
            self.negative = !self.negative;
        }
        self
    }

    /// Get the absolute value.
    #[inline(always)]
    pub fn abs(&self) -> Self {
        Self {
            numer: self.numer.clone(),
            denom: self.denom.clone(),
            negative: false,
        }
    }

    /// Check if the ratio is zero.
    #[inline(always)]
    pub fn is_zero(&self) -> bool {
        self.numer.is_zero_bool()
    }

    /// Check if the ratio is positive.
    #[inline]
    pub fn is_positive(&self) -> bool {
        !self.negative && !self.numer.is_zero_bool()
    }

    /// Check if the ratio is negative.
    #[inline]
    pub fn is_negative(&self) -> bool {
        self.negative && !self.numer.is_zero_bool()
    }

    /// Check if the ratio represents an integer (denominator is 1).
    #[inline]
    pub fn is_integer(&self) -> bool {
        self.denom == T::ONE
    }

    // ========================================================================
    // REDUCTION
    // ========================================================================

    /// Check if the ratio should be reduced to prevent overflow.
    ///
    /// Returns true if either numerator or denominator exceeds the
    /// reduction threshold (typically 70% of the type's bit width).
    #[inline(always)]
    pub fn needs_reduction(&self) -> bool {
        self.numer.bits_u32() > T::REDUCTION_THRESHOLD
            || self.denom.bits_u32() > T::REDUCTION_THRESHOLD
    }

    /// Normalize only if [`needs_reduction`](Ratio::needs_reduction) returns true.
    ///
    /// This is useful in loops to avoid unnecessary GCD operations.
    #[inline]
    pub fn normalize_if_needed(&mut self) {
        if self.needs_reduction() {
            self.normalize();
        }
    }

    /// Reduce the ratio to lowest terms using GCD.
    ///
    /// This operation is optimized to:
    /// - Return immediately if already reduced (GCD = 1)
    /// - Use bit shifts for power-of-2 factors
    /// - Normalize zero to 0/1
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let mut r = RatioU256::new_raw(
    ///     crypto_bigint::U256::from_u64(6),
    ///     crypto_bigint::U256::from_u64(8),
    ///     false
    /// );
    /// r.normalize();
    /// assert_eq!(r.numer, crypto_bigint::U256::from_u64(3));
    /// assert_eq!(r.denom, crypto_bigint::U256::from_u64(4));
    /// ```
    #[inline]
    #[allow(clippy::should_implement_trait)]
    pub fn normalize(&mut self) {
        if self.numer.is_zero_bool() {
            self.denom = T::ONE;
            self.negative = false;
            return;
        }

        let g = T::gcd(self.numer.clone(), self.denom.clone());
        if g == T::ONE {
            return;
        }

        let trailing = g.trailing_zeros_u32();
        let bits = g.bits_u32();

        if trailing > 0 && bits == trailing + 1 {
            self.numer = self.numer.shr_vartime_u32(trailing);
            self.denom = self.denom.shr_vartime_u32(trailing);
        } else {
            self.numer = self.numer.wrapping_div(&g);
            self.denom = self.denom.wrapping_div(&g);
        }
    }

    // ========================================================================
    // FLOAT CONVERSION
    // ========================================================================

    /// Convert an f64 to a ratio with automatic reduction.
    ///
    /// Returns `None` if the input is infinite or NaN.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU512;
    ///
    /// let r = RatioU512::from_float(0.75).unwrap();
    /// assert_eq!(r.numer, crypto_bigint::U512::from_u64(3));
    /// assert_eq!(r.denom, crypto_bigint::U512::from_u64(4));
    /// ```
    pub fn from_float(f: f64) -> Option<Self> {
        if !f.is_finite() {
            return None;
        }
        let negative = f.is_sign_negative();
        let abs_f = f.abs();

        const SCALE_POWER: u32 = 52;
        let scale = 1u64 << SCALE_POWER;
        let scaled = (abs_f * scale as f64) as u128;

        if scaled == 0 {
            return Some(Self::zero());
        }

        if scaled <= u64::MAX as u128 {
            let n_u64 = scaled as u64;
            let g = gcd_u64(n_u64, scale);
            return Some(Self {
                numer: T::from_u64(n_u64 / g),
                denom: T::from_u64(scale / g),
                negative,
            });
        }

        let n = T::from_u128(scaled);
        let d = T::from_u64(scale);
        let g = T::gcd(n.clone(), d.clone());

        Some(Self {
            numer: n.wrapping_div(&g),
            denom: d.wrapping_div(&g),
            negative,
        })
    }

    /// Approximate conversion to f64.
    ///
    /// Large values are scaled to fit in f64 range, potentially losing precision.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let r = RatioU256::from_u64(1, 2);
    /// assert!((r.to_f64_approx() - 0.5).abs() < 1e-10);
    /// ```
    #[inline]
    pub fn to_f64_approx(&self) -> f64 {
        let n_bits = self.numer.bits_u32();
        let d_bits = self.denom.bits_u32();

        if n_bits == 0 {
            return 0.0;
        }

        let n_shift = n_bits.saturating_sub(64);
        let d_shift = d_bits.saturating_sub(64);

        let n_approx = self.numer.shr_vartime_u32(n_shift).first_word() as f64;
        let d_approx = self.denom.shr_vartime_u32(d_shift).first_word() as f64;

        let exp_diff = (n_shift as i32) - (d_shift as i32);
        let val = n_approx / d_approx * 2f64.powi(exp_diff);

        if self.negative {
            -val
        } else {
            val
        }
    }

    // ========================================================================
    // ARITHMETIC - ADDITION
    // ========================================================================

    /// Add two ratios.
    ///
    /// Returns an unreduced result. Call [`normalize`](Ratio::normalize) if needed.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let a = RatioU256::from_u64(1, 2);
    /// let b = RatioU256::from_u64(1, 3);
    /// let sum = a.add(&b);
    /// // Result is 5/6
    /// ```
    #[inline]
    pub fn add(&self, other: &Self) -> Self {
        if self.denom == other.denom {
            let (n, neg) = self.add_sub_numer(other);
            return Self {
                numer: n,
                denom: self.denom.clone(),
                negative: neg,
            };
        }

        let (ad, ad_hi) = self.numer.mul_wide(&other.denom);
        let (bc, bc_hi) = other.numer.mul_wide(&self.denom);
        let (bd, bd_hi) = self.denom.mul_wide(&other.denom);

        if ad_hi.is_zero_bool() && bc_hi.is_zero_bool() && bd_hi.is_zero_bool() {
            let (numer, negative) = match (self.negative, other.negative) {
                (false, false) => (ad.wrapping_add(&bc), false),
                (true, true) => (ad.wrapping_add(&bc), true),
                (false, true) if ad >= bc => (ad.wrapping_sub(&bc), false),
                (false, true) => (bc.wrapping_sub(&ad), true),
                (true, false) if bc >= ad => (bc.wrapping_sub(&ad), false),
                (true, false) => (ad.wrapping_sub(&bc), true),
            };

            return Self {
                numer,
                denom: bd,
                negative,
            };
        }

        self.add_wide(other)
    }

    #[inline(always)]
    fn add_sub_numer(&self, other: &Self) -> (T, bool) {
        match (self.negative, other.negative) {
            (false, false) => (self.numer.wrapping_add(&other.numer), false),
            (true, true) => (self.numer.wrapping_add(&other.numer), true),
            (false, true) if self.numer >= other.numer => {
                (self.numer.wrapping_sub(&other.numer), false)
            }
            (false, true) => (other.numer.wrapping_sub(&self.numer), true),
            (true, false) if other.numer >= self.numer => {
                (other.numer.wrapping_sub(&self.numer), false)
            }
            (true, false) => (self.numer.wrapping_sub(&other.numer), true),
        }
    }

    #[cold]
    #[inline(never)]
    fn add_wide(&self, other: &Self) -> Self {
        let a = self.numer.to_wide();
        let b = self.denom.to_wide();
        let c = other.numer.to_wide();
        let d = other.denom.to_wide();

        let ad = a.wrapping_mul(&d);
        let bc = b.wrapping_mul(&c);
        let bd = b.wrapping_mul(&d);

        let (numer_wide, negative) = match (self.negative, other.negative) {
            (false, false) => (ad.wrapping_add(&bc), false),
            (true, true) => (ad.wrapping_add(&bc), true),
            (false, true) => {
                if ad >= bc {
                    (ad.wrapping_sub(&bc), false)
                } else {
                    (bc.wrapping_sub(&ad), true)
                }
            }
            (true, false) => {
                if bc >= ad {
                    (bc.wrapping_sub(&ad), false)
                } else {
                    (ad.wrapping_sub(&bc), true)
                }
            }
        };

        let g = T::Wide::gcd(numer_wide.clone(), bd.clone());
        let normalized_numer = numer_wide.wrapping_div(&g);
        let normalized_denom = bd.wrapping_div(&g);

        let numer =
            T::from_wide_checked(&normalized_numer).expect("numerator overflow after reduction");
        let denom =
            T::from_wide_checked(&normalized_denom).expect("denominator overflow after reduction");

        Self {
            numer,
            denom,
            negative,
        }
    }

    // ========================================================================
    // ARITHMETIC - MULTIPLICATION
    // ========================================================================

    /// Multiply two ratios without automatic reduction.
    ///
    /// For reduced results, use [`mul_reduced`](Ratio::mul_reduced) or call
    /// [`normalize`](Ratio::normalize) afterward.
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let a = RatioU256::from_u64(2, 3);
    /// let b = RatioU256::from_u64(3, 4);
    /// let product = a.mul(&b);
    /// // Result is 6/12 (unreduced)
    /// ```
    #[inline]
    pub fn mul(&self, other: &Self) -> Self {
        let negative = self.negative ^ other.negative;

        let self_max_bits = self.numer.bits_u32().max(self.denom.bits_u32());
        let other_max_bits = other.numer.bits_u32().max(other.denom.bits_u32());
        let large_threshold = (T::BITS * 6) / 10;

        let (self_work, other_work) =
            if self_max_bits > large_threshold || other_max_bits > large_threshold {
                let mut s = self.clone();
                let mut o = other.clone();
                if self_max_bits > large_threshold {
                    s.normalize();
                }
                if other_max_bits > large_threshold {
                    o.normalize();
                }
                (s, o)
            } else {
                (self.clone(), other.clone())
            };

        let (ac, ac_hi) = self_work.numer.mul_wide(&other_work.numer);
        let (bd, bd_hi) = self_work.denom.mul_wide(&other_work.denom);

        if ac_hi.is_zero_bool() && bd_hi.is_zero_bool() {
            return Self {
                numer: ac,
                denom: bd,
                negative,
            };
        }

        let g_ad = T::gcd(self_work.numer.clone(), other_work.denom.clone());
        let g_bc = T::gcd(self_work.denom.clone(), other_work.numer.clone());

        let a = self_work.numer.wrapping_div(&g_ad);
        let c = other_work.numer.wrapping_div(&g_bc);
        let b = self_work.denom.wrapping_div(&g_bc);
        let d = other_work.denom.wrapping_div(&g_ad);

        let (ac, ac_hi) = a.mul_wide(&c);
        let (bd, bd_hi) = b.mul_wide(&d);

        if !ac_hi.is_zero_bool() || !bd_hi.is_zero_bool() {
            panic!("multiplication overflow after cross-cancellation");
        }

        Self {
            numer: ac,
            denom: bd,
            negative,
        }
    }

    /// Multiply with smart reduction using fast heuristics.
    ///
    /// This applies cheap reduction techniques:
    /// - Power-of-2 factors via bit shifts (~10ns)
    /// - Small value GCD using u64 (~50ns)
    /// - Skips expensive full GCD for large coprime values
    ///
    /// # Examples
    ///
    /// ```
    /// use crypto_ratio::RatioU256;
    ///
    /// let a = RatioU256::from_u64(2, 3);
    /// let b = RatioU256::from_u64(3, 4);
    /// let product = a.mul_reduced(&b);
    /// // Result is 1/2 (reduced)
    /// ```
    #[inline]
    pub fn mul_reduced(&self, other: &Self) -> Self {
        let self_max_bits = self.numer.bits_u32().max(self.denom.bits_u32());
        let other_max_bits = other.numer.bits_u32().max(other.denom.bits_u32());
        let large_threshold = (T::BITS * 6) / 10;

        let (self_work, other_work) =
            if self_max_bits > large_threshold || other_max_bits > large_threshold {
                let mut s = self.clone();
                let mut o = other.clone();
                if self_max_bits > large_threshold {
                    s.normalize();
                }
                if other_max_bits > large_threshold {
                    o.normalize();
                }
                (s, o)
            } else {
                (self.clone(), other.clone())
            };

        let negative = self.negative ^ other.negative;

        let (ac, ac_hi) = self_work.numer.mul_wide(&other_work.numer);
        let (bd, bd_hi) = self_work.denom.mul_wide(&other_work.denom);

        if ac_hi.is_zero_bool() && bd_hi.is_zero_bool() {
            let mut numer = ac;
            let mut denom = bd;

            let trailing_n = numer.trailing_zeros_u32();
            let trailing_d = denom.trailing_zeros_u32();
            let common_trailing = trailing_n.min(trailing_d);

            if common_trailing > 0 {
                numer = numer.shr_vartime_u32(common_trailing);
                denom = denom.shr_vartime_u32(common_trailing);
            }

            let numer_bits = numer.bits_u32();
            let denom_bits = denom.bits_u32();

            if numer_bits <= 64 && denom_bits <= 64 {
                if let (Some(n_u64), Some(d_u64)) = (numer.try_to_u64(), denom.try_to_u64()) {
                    let g = gcd_u64(n_u64, d_u64);
                    if g > 1 {
                        return Self {
                            numer: T::from_u64(n_u64 / g),
                            denom: T::from_u64(d_u64 / g),
                            negative,
                        };
                    }
                    return Self {
                        numer,
                        denom,
                        negative,
                    };
                }
            }

            if numer_bits <= 128 && denom_bits <= 128 {
                let g = T::gcd(numer.clone(), denom.clone());
                if g != T::ONE {
                    return Self {
                        numer: numer.wrapping_div(&g),
                        denom: denom.wrapping_div(&g),
                        negative,
                    };
                }
            }

            return Self {
                numer,
                denom,
                negative,
            };
        }

        let g_ad = T::gcd(self_work.numer.clone(), other_work.denom.clone());
        let g_bc = T::gcd(self_work.denom.clone(), other_work.numer.clone());

        let a = self_work.numer.wrapping_div(&g_ad);
        let c = other_work.numer.wrapping_div(&g_bc);
        let b = self_work.denom.wrapping_div(&g_bc);
        let d = other_work.denom.wrapping_div(&g_ad);

        let (ac, ac_hi) = a.mul_wide(&c);
        let (bd, bd_hi) = b.mul_wide(&d);

        if !ac_hi.is_zero_bool() || !bd_hi.is_zero_bool() {
            panic!("multiplication overflow after cross-cancellation");
        }

        Self {
            numer: ac,
            denom: bd,
            negative,
        }
    }

    /// Divide by an unsigned integer.
    ///
    /// Multiplies the denominator by the divisor.
    #[inline]
    pub fn div_by_uint(&self, divisor: &T) -> Self {
        let (bd, bd_hi) = self.denom.mul_wide(divisor);

        if !bd_hi.is_zero_bool() {
            panic!("denominator overflow in div_by_uint");
        }

        Self {
            numer: self.numer.clone(),
            denom: bd,
            negative: self.negative,
        }
    }

    /// Subtract another ratio.
    ///
    /// Equivalent to `self.add(&other.neg())`.
    #[inline]
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.clone().neg())
    }

    /// Divide by another ratio.
    ///
    /// # Panics
    ///
    /// Panics if `other` is zero.
    #[inline]
    pub fn div(&self, other: &Self) -> Self {
        if other.numer.is_zero_bool() {
            panic!("division by zero");
        }

        let reciprocal = Self {
            numer: other.denom.clone(),
            denom: other.numer.clone(),
            negative: other.negative,
        };
        self.mul(&reciprocal)
    }

    /// Get the reciprocal (1/x).
    ///
    /// # Panics
    ///
    /// Panics if the ratio is zero.
    #[inline]
    pub fn recip(&self) -> Self {
        if self.numer.is_zero_bool() {
            panic!("reciprocal of zero");
        }
        Self {
            numer: self.denom.clone(),
            denom: self.numer.clone(),
            negative: self.negative,
        }
    }

    // ========================================================================
    // COMPARISONS
    // ========================================================================

    /// Less-than comparison optimized for both small and large values.
    ///
    /// Uses fast paths for:
    /// - Sign differences
    /// - Large magnitude differences
    /// - Small values (≤64 bits)
    #[inline]
    pub fn lt(&self, other: &Self) -> bool {
        if self.negative != other.negative {
            return self.negative;
        }

        let self_numer_bits = self.numer.bits_u32();
        let self_denom_bits = self.denom.bits_u32();
        let other_numer_bits = other.numer.bits_u32();
        let other_denom_bits = other.denom.bits_u32();

        let self_mag = self_numer_bits as i32 - self_denom_bits as i32;
        let other_mag = other_numer_bits as i32 - other_denom_bits as i32;
        let mag_diff = self_mag - other_mag;

        if mag_diff < -2 {
            return !self.negative;
        }
        if mag_diff > 2 {
            return self.negative;
        }

        if self_numer_bits <= 64
            && self_denom_bits <= 64
            && other_numer_bits <= 64
            && other_denom_bits <= 64
        {
            if let (Some(self_n), Some(self_d), Some(other_n), Some(other_d)) = (
                self.numer.try_to_u64(),
                self.denom.try_to_u64(),
                other.numer.try_to_u64(),
                other.denom.try_to_u64(),
            ) {
                let ad = (self_n as u128) * (other_d as u128);
                let bc = (other_n as u128) * (self_d as u128);
                return if self.negative { ad > bc } else { ad < bc };
            }
        }

        let (ad, ad_hi) = self.numer.mul_wide(&other.denom);
        let (bc, bc_hi) = self.denom.mul_wide(&other.numer);

        match (ad_hi.cmp(&bc_hi), ad.cmp(&bc)) {
            (Ordering::Less, _) => !self.negative,
            (Ordering::Greater, _) => self.negative,
            (Ordering::Equal, ord) => {
                if self.negative {
                    ord == Ordering::Greater
                } else {
                    ord == Ordering::Less
                }
            }
        }
    }

    /// Greater-than comparison optimized for both small and large values.
    ///
    /// Uses fast paths for:
    /// - Sign differences
    /// - Large magnitude differences
    /// - Small values (≤64 bits)
    #[inline]
    pub fn gt(&self, other: &Self) -> bool {
        if self.negative != other.negative {
            return !self.negative && other.negative;
        }

        let self_numer_bits = self.numer.bits_u32();
        let self_denom_bits = self.denom.bits_u32();
        let other_numer_bits = other.numer.bits_u32();
        let other_denom_bits = other.denom.bits_u32();

        let self_mag = self_numer_bits as i32 - self_denom_bits as i32;
        let other_mag = other_numer_bits as i32 - other_denom_bits as i32;
        let mag_diff = self_mag - other_mag;

        if mag_diff > 2 {
            return !self.negative;
        }
        if mag_diff < -2 {
            return self.negative;
        }

        if self_numer_bits <= 64
            && self_denom_bits <= 64
            && other_numer_bits <= 64
            && other_denom_bits <= 64
        {
            if let (Some(self_n), Some(self_d), Some(other_n), Some(other_d)) = (
                self.numer.try_to_u64(),
                self.denom.try_to_u64(),
                other.numer.try_to_u64(),
                other.denom.try_to_u64(),
            ) {
                let ad = (self_n as u128) * (other_d as u128);
                let bc = (other_n as u128) * (self_d as u128);
                return if self.negative { ad < bc } else { ad > bc };
            }
        }

        let (ad, ad_hi) = self.numer.mul_wide(&other.denom);
        let (bc, bc_hi) = self.denom.mul_wide(&other.numer);

        match (ad_hi.cmp(&bc_hi), ad.cmp(&bc)) {
            (Ordering::Greater, _) => !self.negative,
            (Ordering::Less, _) => self.negative,
            (Ordering::Equal, ord) => {
                if self.negative {
                    ord == Ordering::Less
                } else {
                    ord == Ordering::Greater
                }
            }
        }
    }
}

// ============================================================================
// HELPERS
// ============================================================================

/// Fast u64 GCD using the Euclidean algorithm.
#[inline]
fn gcd_u64(mut a: u64, mut b: u64) -> u64 {
    while b != 0 {
        let temp = b;
        b = a % b;
        a = temp;
    }
    a
}

// ============================================================================
// TRAIT IMPLEMENTATIONS
// ============================================================================

use core::ops::{Add, Div, Mul, Neg, Sub};

impl<T: RatioInteger> Add for Ratio<T> {
    type Output = Self;
    #[inline(always)]
    fn add(self, other: Self) -> Self {
        Ratio::add(&self, &other)
    }
}

impl<T: RatioInteger> Add for &Ratio<T> {
    type Output = Ratio<T>;
    #[inline(always)]
    fn add(self, other: Self) -> Ratio<T> {
        Ratio::add(self, other)
    }
}

impl<T: RatioInteger> Mul for Ratio<T> {
    type Output = Self;
    #[inline(always)]
    fn mul(self, other: Self) -> Self {
        Ratio::mul(&self, &other)
    }
}

impl<T: RatioInteger> Mul for &Ratio<T> {
    type Output = Ratio<T>;
    #[inline(always)]
    fn mul(self, other: Self) -> Ratio<T> {
        Ratio::mul(self, other)
    }
}

impl<T: RatioInteger> Neg for Ratio<T> {
    type Output = Self;
    #[inline(always)]
    fn neg(self) -> Self {
        Ratio::neg(self)
    }
}

impl<T: RatioInteger> Sub for Ratio<T> {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        Ratio::sub(&self, &other)
    }
}

impl<T: RatioInteger> Sub for &Ratio<T> {
    type Output = Ratio<T>;
    fn sub(self, other: Self) -> Ratio<T> {
        Ratio::sub(self, other)
    }
}

impl<T: RatioInteger> Div for Ratio<T> {
    type Output = Self;
    fn div(self, other: Self) -> Self {
        Ratio::div(&self, &other)
    }
}

impl<T: RatioInteger> Div for &Ratio<T> {
    type Output = Ratio<T>;
    fn div(self, other: Self) -> Ratio<T> {
        Ratio::div(self, other)
    }
}

impl<T: RatioInteger> PartialEq for Ratio<T> {
    fn eq(&self, other: &Self) -> bool {
        if self.numer.is_zero_bool() && other.numer.is_zero_bool() {
            return true;
        }
        if self.negative != other.negative {
            return false;
        }

        let (ad, ad_hi) = self.numer.mul_wide(&other.denom);
        let (bc, bc_hi) = other.numer.mul_wide(&self.denom);

        ad == bc && ad_hi == bc_hi
    }
}

impl<T: RatioInteger> Eq for Ratio<T> {}

impl<T: RatioInteger> PartialOrd for Ratio<T> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<T: RatioInteger> Ord for Ratio<T> {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.gt(other) {
            Ordering::Greater
        } else if self.lt(other) {
            Ordering::Less
        } else {
            Ordering::Equal
        }
    }
}

// ============================================================================
// TYPE ALIASES
// ============================================================================

/// Ratio using 64-bit integers.
pub type RatioU64 = Ratio<crypto_bigint::U64>;

/// Ratio using 128-bit integers.
pub type RatioU128 = Ratio<crypto_bigint::U128>;

/// Ratio using 256-bit integers.
pub type RatioU256 = Ratio<crypto_bigint::U256>;

/// Ratio using 512-bit integers (recommended for most use cases).
pub type RatioU512 = Ratio<crypto_bigint::U512>;

/// Ratio using 1024-bit integers.
pub type RatioU1024 = Ratio<crypto_bigint::U1024>;

/// Ratio using 2048-bit integers.
pub type RatioU2048 = Ratio<crypto_bigint::U2048>;

/// Ratio using 4096-bit integers.
pub type RatioU4096 = Ratio<crypto_bigint::U4096>;

/// Ratio using 8192-bit integers.
pub type RatioU8192 = Ratio<crypto_bigint::U8192>;

/// Ratio using 16384-bit integers.
pub type RatioU16384 = Ratio<crypto_bigint::U16384>;

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_bigint::*;

    #[test]
    fn test_basic_u512() {
        let r = Ratio::<U512>::from_u64(3, 4);
        assert_eq!(r.numer, U512::from_u64(3));
        assert_eq!(r.denom, U512::from_u64(4));
    }

    #[test]
    fn test_basic_u256() {
        let r = Ratio::<U256>::from_u64(5, 10);
        assert_eq!(r.numer, U256::from_u64(1));
        assert_eq!(r.denom, U256::from_u64(2));
    }

    #[test]
    fn test_add_same_denom() {
        let r1 = Ratio::<U512>::from_u64(1, 4);
        let r2 = Ratio::<U512>::from_u64(1, 4);
        let sum = &r1 + &r2;
        assert_eq!(sum.numer, U512::from_u64(2));
        assert_eq!(sum.denom, U512::from_u64(4));
    }

    #[test]
    fn test_mul_unreduced() {
        let r1 = Ratio::<U256>::from_u64(2, 3);
        let r2 = Ratio::<U256>::from_u64(3, 4);
        let prod = &r1 * &r2;

        assert_eq!(prod.numer, U256::from_u64(6));
        assert_eq!(prod.denom, U256::from_u64(12));
    }

    #[test]
    fn test_mul_reduced() {
        let r1 = Ratio::<U256>::from_u64(2, 3);
        let r2 = Ratio::<U256>::from_u64(3, 4);
        let prod = r1.mul_reduced(&r2);

        assert_eq!(prod.numer, U256::from_u64(1));
        assert_eq!(prod.denom, U256::from_u64(2));
    }

    #[test]
    fn test_mul_reduced_power_of_2() {
        let r1 = Ratio::<U256>::from_u64(4, 8);
        let r2 = Ratio::<U256>::from_u64(2, 6);
        let prod = r1.mul_reduced(&r2);

        assert_eq!(prod.numer, U256::from_u64(1));
        assert_eq!(prod.denom, U256::from_u64(6));
    }

    #[test]
    fn test_flexible_wide_types() {
        let r576 = Ratio::<U576>::from_u64(1, 2);
        assert_eq!(r576.numer, U576::from_u64(1));

        let r640 = Ratio::<U640>::from_u64(3, 4);
        assert_eq!(r640.numer, U640::from_u64(3));
    }
}
