`medea-turn` changelog
======================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




## [0.11.1] · unreleased
[0.11.1]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.11.1

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.11.0...v0.11.1)

### Fixed

- Wrong transaction ID in binding `BINDING` response. ([#6])

[#6]: https://github.com/instrumentisto/medea-turn-rs/pull/6




## [0.11.0] · 2025-05-16
[0.11.0]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.11.0

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.10.1...v0.11.0)

### BC Breaks

- Bumped up [MSRV] to 1.85 because of migration to 2024 edition. ([c265d063])
- Upgraded `bytecodec` to 0.5 version. ([60a30d53])
- Upgraded `stun_codec` to 0.4 version. ([60a30d53])

[60a30d53]: https://github.com/instrumentisto/medea-turn-rs/commit/60a30d5326645963afb572a452df660e680978f3
[c265d063]: https://github.com/instrumentisto/medea-turn-rs/commit/c265d0638f34dd50284fc4fe83fdfa2329ff9ee8




## [0.10.1] · 2025-02-11
[0.10.1]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.10.1

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.10.0...v0.10.1)

### Updated

- `derive_more` to 2.0 version. ([70f36c85])
- `rand` to 0.9 version. ([ad50ff6c])

[70f36c85]: https://github.com/instrumentisto/medea-turn-rs/commit/70f36c85286d213104825909281593a8ca479456
[ad50ff6c]: https://github.com/instrumentisto/medea-turn-rs/commit/ad50ff6c177e0430a5048bd1bc413e908f7ed0f7




## [0.10.0] · 2024-10-21
[0.10.0]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.10.0

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.9.2...v0.10.0)

### BC Breaks

- Bumped up [MSRV] to 1.81 because for `#[expect]` attribute usage. ([b0a1dfb6])
- Changed return type of `AuthHandler::auth_handle()` to [`secrecy::SecretString`]. ([#3])

[`secrecy::SecretString`]: https://docs.rs/secrecy/0.10.3/secrecy/type.SecretString.html
[#3]: https://github.com/instrumentisto/medea-turn-rs/pull/3
[b0a1dfb6]: https://github.com/instrumentisto/medea-turn-rs/commit/b0a1dfb696b044d08fa720f2d3e52ed65a12e521




## [0.9.2] · 2024-07-11
[0.9.2]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.9.2

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.9.1...v0.9.2)

### Fixed

- Unexported [STUN]/[TURN] attributes in `attr` module. ([6bb1822c])

[6bb1822c]: https://github.com/instrumentisto/medea-turn-rs/commit/6bb1822c6de4f76ef2f7a7db89d3435e5151157e




## [0.9.1] · 2024-07-11
[0.9.1]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.9.1

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/v0.9.0...v0.9.1)

### Added

- `attr` module with [STUN]/[TURN] attributes re-exported. ([c0d471ef])

[c0d471ef]: https://github.com/instrumentisto/medea-turn-rs/commit/c0d471efd19b6dc35163956001d31dc09150fe8d




## [0.9.0] · 2024-07-09
[0.9.0]: https://github.com/instrumentisto/medea-turn-rs/tree/v0.9.0

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/89285ceba23dc57fc99386cb978d2d23fe909437...v0.9.0) | [Milestone](https://github.com/instrumentisto/medea-turn-rs/milestone/1)

### Initially re-implemented

- Performed major refactoring with non-server code removing. ([#1], [#2])
- Added TCP transport. ([#1])

### [Upstream changes](https://github.com/webrtc-rs/webrtc/blob/89285ceba23dc57fc99386cb978d2d23fe909437/turn/CHANGELOG.md#unreleased)

- Fixed non-released UDP port of server relay. ([webrtc-rs/webrtc#330] by [@clia])
- Added `alloc_close_notify` config parameter to `ServerConfig` and `Allocation` to receive notify on allocation close event, with metrics data. ([webrtc-rs/webrtc#421] by [@clia])

[@clia]: https://github.com/clia
[#1]: https://github.com/instrumentisto/medea-turn-rs/pull/1
[#2]: https://github.com/instrumentisto/medea-turn-rs/pull/2
[webrtc-rs/webrtc#330]: https://github.com/webrtc-rs/webrtc/pull/330
[webrtc-rs/webrtc#421]: https://github.com/webrtc-rs/webrtc/pull/421




## Previous releases

See [old upstream CHANGELOG](https://github.com/webrtc-rs/webrtc/blob/turn-v0.6.1/turn/CHANGELOG.md).




[Semantic Versioning 2.0.0]: https://semver.org
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
