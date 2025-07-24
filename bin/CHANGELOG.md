Lightweight [STUN]/[TURN] server changelog
==========================================

All user visible changes to this project will be documented in this file. This project uses [Semantic Versioning 2.0.0].




## [0.1.0-lib.0.11.2] · unreleased
[0.1.0-lib.0.11.2]: https://github.com/instrumentisto/medea-turn-rs/tree/bin@v0.1.0-lib.0.11.2/bin

[Diff](https://github.com/instrumentisto/medea-turn-rs/compare/091d2d72...bin@v0.1.0-lib.0.11.2)

## Added

- [STUN] server implementation. ([#9])
- Configuration:
    - `[log]` section with `[log.mod.<path>]` support for concrete modules overriding. ([#9])
    - `[stun]` section. ([#9])
    - Ability to load from `.env` file. ([#9])

[#9]: https://github.com/instrumentisto/medea-turn-rs/pull/9




[Semantic Versioning 2.0.0]: https://semver.org
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
