`medea-turn` changelog
======================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




## [0.10.0] · 2024-10-21
[0.10.0]: /../../tree/v0.10.0

[Diff](/../../compare/v0.9.2...v0.10.0)

### BC Breaks

- Bumped up [MSRV] to 1.81 because for `#[expect]` attribute usage. ([b0a1dfb6])
- Changed return type of `AuthHandler::auth_handle()` to [`secrecy::SecretString`]. ([#3])

[`secrecy::SecretString`]: https://docs.rs/secrecy/0.10.3/secrecy/type.SecretString.html
[#3]: /../../pull/3
[b0a1dfb6]: /../../commit/b0a1dfb696b044d08fa720f2d3e52ed65a12e521




## [0.9.2] · 2024-07-11
[0.9.2]: /../../tree/v0.9.2

[Diff](/../../compare/v0.9.1...v0.9.2)

### Fixed

- Unexported [STUN]/[TURN] attributes in `attr` module. ([6bb1822c])

[6bb1822c]: /../../commit/6bb1822c6de4f76ef2f7a7db89d3435e5151157e




## [0.9.1] · 2024-07-11
[0.9.1]: /../../tree/v0.9.1

[Diff](/../../compare/v0.9.0...v0.9.1)

### Added

- `attr` module with [STUN]/[TURN] attributes re-exported. ([c0d471ef])

[c0d471ef]: /../../commit/c0d471efd19b6dc35163956001d31dc09150fe8d




## [0.9.0] · 2024-07-09
[0.9.0]: /../../tree/v0.9.0

[Diff](/../../compare/89285ceba23dc57fc99386cb978d2d23fe909437...v0.9.0) | [Milestone](/../../milestone/1)

### Initially re-implemented

- Performed major refactoring with non-server code removing. ([#1], [#2])
- Added TCP transport. ([#1])

### [Upstream changes](https://github.com/webrtc-rs/webrtc/blob/89285ceba23dc57fc99386cb978d2d23fe909437/turn/CHANGELOG.md#unreleased)

- Fixed non-released UDP port of server relay. ([webrtc-rs/webrtc#330] by [@clia])
- Added `alloc_close_notify` config parameter to `ServerConfig` and `Allocation` to receive notify on allocation close event, with metrics data. ([webrtc-rs/webrtc#421] by [@clia])

[@clia]: https://github.com/clia
[#1]: /../../pull/1
[#2]: /../../pull/2
[webrtc-rs/webrtc#330]: https://github.com/webrtc-rs/webrtc/pull/330
[webrtc-rs/webrtc#421]: https://github.com/webrtc-rs/webrtc/pull/421




## Previous releases

See [old upstream CHANGELOG](https://github.com/webrtc-rs/webrtc/blob/turn-v0.6.1/turn/CHANGELOG.md).




[Semantic Versioning 2.0.0]: https://semver.org
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
