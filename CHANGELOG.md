`medea-turn` changelog
======================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




## [0.7.0] · 2024-??-?? (unreleased)
[0.7.0]: /../../tree/v0.7.0

### Initially re-implemented

- Performed major refactoring with non-server code removing. ([#1])
- Added TCP transport. ([#1])

### [Upstream changes](https://github.com/webrtc-rs/webrtc/blob/89285ceba23dc57fc99386cb978d2d23fe909437/turn/CHANGELOG.md#unreleased)

- Fixed non-released UDP port of server relay. ([webrtc-rs/webrtc#330] by [@clia])
- Added `alloc_close_notify` config parameter to `ServerConfig` and `Allocation` to receive notify on allocation close event, with metrics data. ([webrtc-rs/webrtc#421] by [@clia])

[@clia]: https://github.com/clia
[#1]: /../../pull/1
[webrtc-rs/webrtc#330]: https://github.com/webrtc-rs/webrtc/pull/330
[webrtc-rs/webrtc#421]: https://github.com/webrtc-rs/webrtc/pull/421




## Previous releases

See [old upstream CHANGELOG](https://github.com/webrtc-rs/webrtc/blob/turn-v0.6.1/turn/CHANGELOG.md).




[Semantic Versioning 2.0.0]: https://semver.org







# webrtc-turn changelog

## Unreleased

* [#330 Fix the problem that the UDP port of the server relay is not released](https://github.com/webrtc-rs/webrtc/pull/330) by [@clia](https://github.com/clia).
* Added `alloc_close_notify` config parameter to `ServerConfig` and `Allocation`, to receive notify on allocation close event, with metrics data.
* Major refactor, add TCP transport [#1]

[#1]: https://github.com/instrumentisto/medea-turn-rs/pull/1

## v0.6.1

* Added `delete_allocations_by_username` method on `Server`. This method provides possibility to manually delete allocation [#263](https://github.com/webrtc-rs/webrtc/pull/263) by [@logist322](https://github.com/logist322).
* Added `get_allocations_info` method on `Server`. This method provides possibility to get information about allocations [#288](https://github.com/webrtc-rs/webrtc/pull/288) by [@logist322](https://github.com/logist322).
* Increased minimum support rust version to `1.60.0`.
* Increased required `webrtc-util` version to `0.7.0`.


## v0.6.0

* [#15 update deps + loosen some requirements](https://github.com/webrtc-rs/turn/pull/15) by [@melekes](https://github.com/melekes).
* [#11 Fixed spelling of convenience](https://github.com/webrtc-rs/turn/pull/11) by [@Charles-Schleich ](https://github.com/Charles-Schleich).
* Increase min version of `log` dependency to `0.4.16`. [#250 Fix log at ^0.4.16 to make tests compile](https://github.com/webrtc-rs/webrtc/pull/250) by [@k0nserv](https://github.com/k0nserv).
* [#246 Fix warnings on windows](https://github.com/webrtc-rs/webrtc/pull/246) by [@https://github.com/xnorpx](https://github.com/xnorpx).


## Prior to 0.6.0

Before 0.6.0 there was no changelog, previous changes are sometimes, but not always, available in the [GitHub Releases](https://github.com/webrtc-rs/turn/releases).

