# ChangeLog for hpke

## 0.2.0

* Breaking change: `exportS` and `exportR` return `Either HPKEError Key`
  rather than `Key`.  RFC 9180 section 5.3 allows an export of at most
  `255 * Nh` octets and the length is the caller's to choose, so the refusal
  now has somewhere to go.  Nothing was total here before -- a length beyond
  65535 did not fit the two octets `LabeledExpand` writes it into, and
  crypton raised -- and from crypton 2.0.0 the shorter limit raises as well.
* Breaking change: `HPKEError` gains `ExportError`, which is what the above
  reports.  It is appended, so the existing constructors are where they
  were, but an exhaustive `case` without a wildcard will warn.
* Supporting crypton 2.0.

## 0.1.0

* Using "ram" instead of "memory".

## 0.0.0

* Initial release
