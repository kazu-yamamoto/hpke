# ChangeLog for hpke

## 0.2.1

* `Show EncodedSecretKey` no longer prints the key.  `Show` is what `print`,
  a message built with `error`, an exception and a test framework's failure
  output all reach for, so it is the instance a key travels on when nobody
  meant to send it anywhere; it now renders `<secret>`, and
  `Crypto.Debug.debugShow` returns the hexadecimal it used to.
  `EncodedPublicKey` is unchanged.
  [#2](https://github.com/kazu-yamamoto/hpke/pull/2)
* The lower bound on crypton moves to 2.0, which is where `Crypto.Debug` is.

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
