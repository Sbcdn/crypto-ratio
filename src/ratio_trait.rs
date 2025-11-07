//! Trait system for generic rational number arithmetic over crypto-bigint types.
//!
//! This module provides the foundational traits that enable `Ratio<T>` to work
//! with any crypto-bigint unsigned integer type, from U64 to U16384.
//!
//! # Architecture
//!
//! The trait system uses two levels:
//!
//! - [`WideInteger`]: Minimal operations for overflow handling types
//! - [`RatioInteger`]: Full operations for types that support `Ratio<T>`
//!
//!
//! # Example
//!
//! ```
//! use crypto_ratio::{Ratio, RatioInteger};
//! use crypto_bigint::U256;
//!
//! let r = Ratio::<U256>::from_u64(3, 4);
//! assert_eq!(r.numer, U256::from_u64(3));
//! ```

use core::fmt::Debug;
use crypto_bigint::*;

/// Operations for types used in overflow arithmetic.
///
/// This trait provides the minimal set of operations needed when a `RatioInteger`
/// computation overflows and temporarily uses a wider type.
///
/// # Relationship to RatioInteger
///
/// Every `RatioInteger` also implements `WideInteger`. Additionally, the `Wide`
/// associated type of each `RatioInteger` implements `WideInteger` (but not
/// necessarily `RatioInteger`).
///
/// This allows, for example:
/// - `U512` implements both `WideInteger` and `RatioInteger<Wide = U1024>`
/// - `U1024` implements `WideInteger` for use in U512 overflow handling
/// - `U32768` implements only `WideInteger`
pub trait WideInteger: Clone + Debug + PartialEq + Eq + PartialOrd + Ord + Sized + 'static {
    /// Number of bits in this integer type.
    const BITS: u32;

    /// The zero value.
    const ZERO: Self;

    /// The one value.
    const ONE: Self;

    /// Returns the number of significant bits in this value.
    fn bits_u32(&self) -> u32;

    /// Returns the number of trailing zero bits.
    fn trailing_zeros_u32(&self) -> u32;

    /// Right shift by a variable amount (variable-time).
    fn shr_vartime_u32(&self, shift: u32) -> Self;

    /// Left shift by a variable amount (variable-time).
    fn shl_vartime_u32(&self, shift: u32) -> Self;

    /// Returns `true` if this value is zero.
    fn is_zero_bool(&self) -> bool;

    /// Add with wrapping on overflow.
    fn wrapping_add(&self, other: &Self) -> Self;

    /// Subtract with wrapping on underflow.
    fn wrapping_sub(&self, other: &Self) -> Self;

    /// Multiply with wrapping on overflow.
    fn wrapping_mul(&self, other: &Self) -> Self;

    /// Divide, panicking on division by zero.
    fn wrapping_div(&self, other: &Self) -> Self;

    /// Remainder, panicking on division by zero.
    fn wrapping_rem(&self, other: &Self) -> Self;

    /// Compute the greatest common divisor using a hybrid algorithm.
    fn gcd(a: Self, b: Self) -> Self;

    /// Convert to a vector of little-endian bytes.
    fn to_le_bytes_vec(&self) -> Vec<u8>;

    /// Create from little-endian bytes.
    fn from_le_bytes_slice(bytes: &[u8]) -> Self;

    /// Get the first word (least significant 64 bits) for approximations.
    fn first_word(&self) -> u64;
}

/// Integer type suitable for use in `Ratio<T>`.
///
/// This trait extends `WideInteger` with conversion operations and an associated
/// `Wide` type for overflow handling.
///
/// # Associated Type: Wide
///
/// The `Wide` type must be large enough to hold products of two values of type `Self`:
/// - Minimum requirement: `Wide::BITS >= Self::BITS * 2`
/// - Exact doubling not required (e.g., U576 can use U1280 instead of U1152)
///
/// # Implemented Types
///
/// This trait is implemented for: U64, U128, U192, U256, U320, U384, U448, U512,
/// U576, U640, U704, U768, U832, U896, U960, U1024, U1280, U1536, U1792, U2048,
/// U3072, U3584, U4096, U4224, U4352, U6144, U8192, U16384.
///
/// U32768 is the terminal type and only implements `WideInteger`.
pub trait RatioInteger: WideInteger {
    /// The wide type for overflow arithmetic.
    ///
    /// Must satisfy: `Wide::BITS >= Self::BITS * 2`
    type Wide: WideInteger;

    /// Bit threshold triggering automatic reduction (typically 70% of `BITS`).
    const REDUCTION_THRESHOLD: u32;

    /// Bit size below which optimized small-value algorithms are used.
    const SMALL_SIZE: u32;

    /// Create from a 64-bit unsigned integer.
    fn from_u64(n: u64) -> Self;

    /// Create from a 128-bit unsigned integer.
    fn from_u128(n: u128) -> Self;

    /// Try to convert to u64, returning `None` if the value doesn't fit.
    fn try_to_u64(&self) -> Option<u64>;

    /// Convert to the wide type.
    fn to_wide(&self) -> Self::Wide;

    /// Try to convert from the wide type, returning `None` if the value doesn't fit.
    fn from_wide_checked(wide: &Self::Wide) -> Option<Self>;

    /// Multiply returning both low and high parts as `(low, high)`.
    fn mul_wide(&self, other: &Self) -> (Self, Self);
}

/// Macro to implement WideInteger for a crypto-bigint type.
macro_rules! impl_wide_integer {
    ($type:ty, $bits:expr) => {
        impl WideInteger for $type {
            const BITS: u32 = $bits;
            const ZERO: Self = <$type>::ZERO;
            const ONE: Self = <$type>::ONE;

            #[inline(always)]
            fn bits_u32(&self) -> u32 {
                self.bits() as u32
            }

            #[inline(always)]
            fn trailing_zeros_u32(&self) -> u32 {
                self.trailing_zeros() as u32
            }

            #[inline(always)]
            fn shr_vartime_u32(&self, shift: u32) -> Self {
                self.shr_vartime(shift as usize)
            }

            #[inline(always)]
            fn shl_vartime_u32(&self, shift: u32) -> Self {
                self.shl_vartime(shift as usize)
            }

            #[inline(always)]
            fn is_zero_bool(&self) -> bool {
                bool::from(<$type as Zero>::is_zero(self))
            }

            #[inline(always)]
            fn wrapping_add(&self, other: &Self) -> Self {
                self.wrapping_add(other)
            }

            #[inline(always)]
            fn wrapping_sub(&self, other: &Self) -> Self {
                self.wrapping_sub(other)
            }

            #[inline(always)]
            fn wrapping_mul(&self, other: &Self) -> Self {
                self.wrapping_mul(other)
            }

            #[inline(always)]
            fn wrapping_div(&self, other: &Self) -> Self {
                self.wrapping_div(other)
            }

            #[inline(always)]
            fn wrapping_rem(&self, other: &Self) -> Self {
                self.wrapping_rem(other)
            }

            #[inline]
            fn gcd(a: Self, b: Self) -> Self {
                gcd_generic(a, b)
            }

            #[inline]
            fn to_le_bytes_vec(&self) -> Vec<u8> {
                self.to_le_bytes().as_ref().to_vec()
            }

            #[inline]
            fn from_le_bytes_slice(bytes: &[u8]) -> Self {
                let mut arr = <$type>::ZERO.to_le_bytes();
                let arr_ref = arr.as_mut();
                let copy_len = arr_ref.len().min(bytes.len());
                arr_ref[..copy_len].copy_from_slice(&bytes[..copy_len]);
                <$type>::from_le_bytes(arr)
            }

            #[inline]
            fn first_word(&self) -> u64 {
                // Architecture-aware: handle both 32-bit and 64-bit word sizes
                let words = self.to_words();
                #[cfg(target_pointer_width = "32")]
                {
                    // On 32-bit: words are u32, combine first two into u64
                    if words.len() >= 2 {
                        (words[0] as u64) | ((words[1] as u64) << 32)
                    } else if words.len() == 1 {
                        words[0] as u64
                    } else {
                        0
                    }
                }
                #[cfg(not(target_pointer_width = "32"))]
                {
                    // On 64-bit: words are already u64
                    words[0]
                }
            }
        }
    };
}

/// Macro to implement RatioInteger for a (narrow, wide) type pair.
macro_rules! impl_ratio_integer {
    ($narrow:ty, $wide:ty, $bits:expr) => {
        impl_wide_integer!($narrow, $bits);

        impl RatioInteger for $narrow {
            type Wide = $wide;

            const REDUCTION_THRESHOLD: u32 = ($bits * 7) / 10;
            const SMALL_SIZE: u32 = 64;

            #[inline(always)]
            fn from_u64(n: u64) -> Self {
                <$narrow>::from_u64(n)
            }

            #[inline(always)]
            fn from_u128(n: u128) -> Self {
                <$narrow>::from_u128(n)
            }

            #[inline]
            fn try_to_u64(&self) -> Option<u64> {
                if self.bits() <= 64 {
                    let bytes = self.to_le_bytes();
                    let mut arr = [0u8; 8];
                    let copy_len = arr.len().min(bytes.as_ref().len());
                    arr[..copy_len].copy_from_slice(&bytes.as_ref()[..copy_len]);
                    Some(u64::from_le_bytes(arr))
                } else {
                    None
                }
            }

            #[inline]
            fn to_wide(&self) -> Self::Wide {
                let self_bytes = self.to_le_bytes();
                let mut wide_encoding = Self::Wide::ZERO.to_le_bytes();

                let len = self_bytes.as_ref().len();
                wide_encoding.as_mut()[..len].copy_from_slice(self_bytes.as_ref());

                Self::Wide::from_le_bytes(wide_encoding)
            }

            #[inline]
            fn from_wide_checked(wide: &Self::Wide) -> Option<Self> {
                let wide_bytes = WideInteger::to_le_bytes_vec(wide);
                let narrow_size = ($bits / 8) as usize;

                if wide_bytes.len() > narrow_size {
                    let has_high_bits = wide_bytes[narrow_size..].iter().any(|&b| b != 0);
                    if has_high_bits {
                        return None;
                    }
                }

                Some(WideInteger::from_le_bytes_slice(
                    &wide_bytes[..narrow_size.min(wide_bytes.len())],
                ))
            }

            #[inline(always)]
            fn mul_wide(&self, other: &Self) -> (Self, Self) {
                self.mul_wide(other)
            }
        }
    };
}

// Implement for all supported crypto-bigint types
impl_ratio_integer!(U64, U128, 64);
impl_ratio_integer!(U128, U256, 128);
impl_ratio_integer!(U192, U384, 192);
impl_ratio_integer!(U256, U512, 256);
impl_ratio_integer!(U320, U640, 320);
impl_ratio_integer!(U384, U768, 384);
impl_ratio_integer!(U448, U896, 448);
impl_ratio_integer!(U512, U1024, 512);
impl_ratio_integer!(U576, U1280, 576);
impl_ratio_integer!(U640, U1280, 640);
impl_ratio_integer!(U704, U1536, 704);
impl_ratio_integer!(U768, U1536, 768);
impl_ratio_integer!(U832, U1792, 832);
impl_ratio_integer!(U896, U1792, 896);
impl_ratio_integer!(U960, U2048, 960);
impl_ratio_integer!(U1024, U2048, 1024);
impl_ratio_integer!(U1280, U3072, 1280);
impl_ratio_integer!(U1536, U3072, 1536);
impl_ratio_integer!(U1792, U3584, 1792);
impl_ratio_integer!(U2048, U4096, 2048);
impl_ratio_integer!(U3072, U6144, 3072);
impl_ratio_integer!(U3584, U8192, 3584);
impl_ratio_integer!(U4096, U8192, 4096);
impl_ratio_integer!(U4224, U16384, 4224);
impl_ratio_integer!(U4352, U16384, 4352);
impl_ratio_integer!(U6144, U16384, 6144);
impl_ratio_integer!(U8192, U16384, 8192);
impl_ratio_integer!(U16384, U32768, 16384);

// U32768 is terminal - only WideInteger
impl_wide_integer!(U32768, 32768);

/// Compute GCD using a hybrid algorithm optimized for various input sizes.
///
/// The algorithm selects the most efficient approach based on input size:
/// - Small values (≤64 bits): Native u64 GCD
/// - Mismatched sizes: Euclidean reduction
/// - Similar-sized values: Binary GCD
///
/// # Examples
///
/// ```
/// use crypto_bigint::U256;
/// use crypto_ratio::WideInteger;
///
/// let a = U256::from_u64(48);
/// let b = U256::from_u64(18);
/// let g = U256::gcd(a, b);
/// assert_eq!(g, U256::from_u64(6));
/// ```
pub fn gcd_generic<T: WideInteger>(mut a: T, mut b: T) -> T {
    if a == b {
        return a;
    }
    if a == T::ONE || b == T::ONE {
        return T::ONE;
    }
    if a.is_zero_bool() {
        return b;
    }
    if b.is_zero_bool() {
        return a;
    }

    if a < b {
        core::mem::swap(&mut a, &mut b);
    }

    const SMALL_SIZE: u32 = 64;
    if a.bits_u32() <= SMALL_SIZE && b.bits_u32() <= SMALL_SIZE {
        let a_bytes = a.to_le_bytes_vec();
        let b_bytes = b.to_le_bytes_vec();

        if a_bytes.len() >= 8 && b_bytes.len() >= 8 {
            let mut a_arr = [0u8; 8];
            let mut b_arr = [0u8; 8];
            a_arr.copy_from_slice(&a_bytes[..8]);
            b_arr.copy_from_slice(&b_bytes[..8]);

            let a_u64 = u64::from_le_bytes(a_arr);
            let b_u64 = u64::from_le_bytes(b_arr);
            let g_u64 = gcd_u64(a_u64, b_u64);

            let g_bytes = g_u64.to_le_bytes();
            return T::from_le_bytes_slice(&g_bytes);
        }
    }

    let size_diff_threshold = T::BITS / 16;

    while !b.is_zero_bool() && a.bits_u32() > b.bits_u32() + size_diff_threshold {
        let rem = a.wrapping_rem(&b);
        a = b;
        b = rem;
    }

    if b.is_zero_bool() {
        return a;
    }

    if b.bits_u32() <= SMALL_SIZE {
        while a.bits_u32() > SMALL_SIZE && !b.is_zero_bool() {
            let rem = a.wrapping_rem(&b);
            a = b;
            b = rem;
        }

        if b.is_zero_bool() {
            return a;
        }

        let a_bytes = a.to_le_bytes_vec();
        let b_bytes = b.to_le_bytes_vec();

        if a_bytes.len() >= 8 && b_bytes.len() >= 8 {
            let mut a_arr = [0u8; 8];
            let mut b_arr = [0u8; 8];
            a_arr.copy_from_slice(&a_bytes[..8]);
            b_arr.copy_from_slice(&b_bytes[..8]);

            let a_u64 = u64::from_le_bytes(a_arr);
            let b_u64 = u64::from_le_bytes(b_arr);
            let g_u64 = gcd_u64(a_u64, b_u64);

            let g_bytes = g_u64.to_le_bytes();
            return T::from_le_bytes_slice(&g_bytes);
        }
    }

    let shift = a.trailing_zeros_u32().min(b.trailing_zeros_u32());
    a = a.shr_vartime_u32(a.trailing_zeros_u32());
    b = b.shr_vartime_u32(b.trailing_zeros_u32());

    loop {
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }
        b = b.wrapping_sub(&a);
        if b.is_zero_bool() {
            return a.shl_vartime_u32(shift);
        }
        b = b.shr_vartime_u32(b.trailing_zeros_u32());
    }
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_gcd_u512() {
        let a = U512::from_u64(48);
        let b = U512::from_u64(18);
        let g = U512::gcd(a, b);
        assert_eq!(g, U512::from_u64(6));
    }

    #[test]
    fn test_gcd_u256() {
        let a = U256::from_u64(100);
        let b = U256::from_u64(35);
        let g = U256::gcd(a, b);
        assert_eq!(g, U256::from_u64(5));
    }

    #[test]
    fn test_wide_conversion_u512() {
        let x = U512::from_u64(12345);
        let wide = x.to_wide();
        let back = U512::from_wide_checked(&wide).unwrap();
        assert_eq!(x, back);
    }

    #[test]
    fn test_flexible_wide_u576() {
        let x = U576::from_u64(999);
        let wide = x.to_wide();
        assert!(wide.bits_u32() <= U1280::BITS as u32);
    }

    #[test]
    fn test_u32768_only_wide() {
        let x = U32768::from_u64(42);
        assert!(!x.is_zero_bool());
    }
}
