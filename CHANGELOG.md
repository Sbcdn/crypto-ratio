## 0.2.0 (2026-06-11)

### Added
- `Ratio::add_sub` — computes `(self + other, self - other)` while sharing the
  three cross-multiplies (3 wide-multiplies instead of 6). Bit-for-bit equal to
  `(add, sub)`; unreduced like `add`.
- `Ratio::div_by_u64` — divide by a `u64` (scales the denominator) via a single
  limb-width multiply. Panics on denominator overflow.
- `Ratio::mul_u64` — multiply the numerator by a `u64` via a single limb-width
  multiply. Panics on numerator overflow.

### Changed
- Performance: cut redundant `U512` wide-multiplies in `add`/`sub`, added an
  integer-operand (`denom == 1`) fast path to `mul`. Results are unchanged.

### Breaking
- `RatioInteger` gains a new required method `mul_wide_u64`. Types implementing
  `RatioInteger` outside this crate must now provide it. All crypto-bigint types
  shipped by this crate implement it via the standard macro, so users of the
  built-in `Ratio<Uxxxx>` aliases are unaffected.

## 0.1.0 (2025-11-08)
- Initial Release
