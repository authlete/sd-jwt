CHANGES
=======

1.1 (2023-05-10)
----------------

Support Disclosures for array elements.

- `Disclosure` class
  - Added `Disclosure(String, int, Object)` constructor.
  - Added `Disclosure(String, String, int, Object)` constructor.
  - Added `getClaimIndex()` method.

- `SDObjectBuilder` class
  - Added `putSDClaim(String, int, Object)` method.
  - Added `putSDClaim(String, String, int, Object)` method.

1.0 (2023-02-28)
----------------

The initial implementation.

- New types
  - `Disclosure` class
  - `SDCombinedFormat` class
  - `SDIssuance` class
  - `SDObjectBuilder` class
  - `SDPresentation` class
