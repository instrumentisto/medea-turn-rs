Lightweight [STUN]/[TURN] server
================================

[STUN] server binary based on [`medea-turn` crate].




## Usage

```
./stun --help
STUN/TURN server implementation used by Medea media server.

Usage: stun [OPTIONS]

Options:
      --log-level <LOG_LEVEL>
          Maximum allowed level of application log entries.
          
          Defaults to `INFO`.

      --bind-ip <BIND_IP>
          IP that STUN UDP socket will bind to.
          
          Defaults to `0.0.0.0`.

      --bind-port <BIND_PORT>
          Port that STUN UDP will use.
          
          Defaults to `3478`.

  -h, --help
          Print help (see a summary with '-h')

  -V, --version
          Print version
```

It can also be configured with an optional [`config.toml`](config.toml).




## License

Copyright © 2025 Instrumentisto Team, <https://github.com/instrumentisto>

Licensed under either of [Apache License, Version 2.0][APACHE] or [MIT license][MIT] at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in this crate by you, as defined in the [Apache-2.0 license][APACHE], shall be dual licensed as above, without any additional terms or conditions.




[`medea-turn` crate]: https://docs.rs/medea-turn
[APACHE]: https://github.com/instrumentisto/medea-turn-rs/blob/v0.11.2/LICENSE-APACHE
[MIT]: https://github.com/instrumentisto/medea-turn-rs/blob/v0.11.2/LICENSE-MIT
[STUN]: https://en.wikipedia.org/wiki/STUN
[TURN]: https://en.wikipedia.org/wiki/TURN
