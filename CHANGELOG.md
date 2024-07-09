`medea-turn` changelog
======================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




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
