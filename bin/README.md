Lightweight [STUN]/[TURN] server
================================

[![Release](https://img.shields.io/github/v/release/instrumentisto/medea-turn-rs?filter=q%3Dbin%252F&display_name=release "Release")](https://github.com/instrumentisto/medea-turn-rs/releases?q=bin%252F)
[![CI](https://github.com/instrumentisto/medea-turn-rs/actions/workflows/bin.yml/badge.svg?branch=main "Binary CI")](https://github.com/instrumentisto/medea-turn-rs/actions/workflows/bin.yml?query=branch%3Amain)\
[![Docker Hub](https://img.shields.io/docker/pulls/instrumentisto/medea-turn?label=Docker%20Hub%20pulls "Docker Hub pulls")](https://hub.docker.com/r/instrumentisto/geckodriver)
[![Quay.io](https://quay.io/repository/instrumentisto/medea-turn/status "Quay.io")](https://quay.io/repository/instrumentisto/medea-turn)

[Changelog](https://github.com/instrumentisto/medea-turn-rs/blob/main/bin/CHANGELOG.md)

[STUN] server binary based on [`medea-turn` crate].




## Usage

Can be configured with a `config.toml` file. Path to the configuration file can be provided:
- either via CLI argument `--conf=/path/to/config.tml`;
- or via environment variable `MEDEA_TURN__CONF=/path/to/config.toml`.

`.env` file is also supported.

If no configuration is provided, then the default values will be used. See the [`config.toml`](config.toml) for the configuration options.




## License

Copyright © 2025 Instrumentisto Team, <https://github.com/instrumentisto>

Licensed under either of [Apache License, Version 2.0][APACHE] or [MIT license][MIT] at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the [Apache-2.0 license][APACHE], shall be dual licensed as above, without any additional terms or conditions.




[`medea-turn` crate]: https://docs.rs/medea-turn
[APACHE]: https://github.com/instrumentisto/medea-turn-rs/blob/v0.12.0/LICENSE-APACHE
[MIT]: https://github.com/instrumentisto/medea-turn-rs/blob/v0.12.0/LICENSE-MIT
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
