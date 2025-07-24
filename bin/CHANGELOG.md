Lightweight [STUN]/[TURN] server changelog
==========================================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




## [0.1.0-lib.0.12.0] · 2025-07-24
[0.1.0-lib.0.12.0]: https://github.com/instrumentisto/medea-turn-rs/tree/bin@v0.1.0-lib.0.12.0/bin

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/091d2d72...bin@v0.1.0-lib.0.12.0)

## Added

- [STUN] server implementation based on [0.12.0 `medea-turn` crate]. ([#9], [#12])
- Configuration:
    - `[log]` section with `[log.mod.<path>]` support for concrete modules overriding. ([#9])
    - `[stun]` section. ([#9])
    - Ability to load from `.env` file. ([#9])
- [Docker] image. ([#12])

[#9]: https://github.com/instrumentisto/medea-turn-rs/pull/9
[#12]: https://github.com/instrumentisto/medea-turn-rs/pull/12
[0.12.0 `medea-turn` crate]: https://github.com/instrumentisto/medea-turn-rs/blob/v0.12.0/CHANGELOG.md#0120--2025-07-17



[Docker]: https://docker.com
[Semantic Versioning 2.0.0]: https://semver.org
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
