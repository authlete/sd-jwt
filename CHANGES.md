CHANGES
=======

1.2 (2023-06-19)
----------------

Update to follow the following normative changes of the SD-JWT specification.

1. A tilde (`~`) is appended to "Combined Format for Issuance", resulting in
   that there is no formal difference between (a) Combined Format for Issuance
   and (b) Combined Format for Presentation without a binding JWT.
2. The format of the base JSON of Disclosure for an array element has changed
   from `[salt, [name, index], value]` to `[salt, value]`.
3. Disclosures for array elements are not put in the `_sd` array. Instead,
   each array element is replaced with `{"...": "<digest>"}`.
4. Terminology changes. The terms "Combined Format for Issuance" and "Combined
   Format for Presentation" are obsoleted, and the entire combined format is
   called "SD-JWT".

- `Disclosure` class
  - Added `Disclosure(Object)` constructor.
  - Added `toArrayElement()` method.
  - Added `toArrayElement(String)` method.
  - Removed `Disclosure(String, int, Object)` constructor.
  - Removed `Disclosure(String, String, int, Object)` constructor.
  - Removed `getClaimIndex()` method.

- `SDObjectBuilder` class
  - Removed `putSDClaim(String, int, Object)` method.
  - Removed `putSDClaim(String, String, int, Object)` method.

- New types
  - `SDJWT` class

- Removed types
  - `SDCombinedFormat` class
  - `SDIssuance` class
  - `SDPresentation` class

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
