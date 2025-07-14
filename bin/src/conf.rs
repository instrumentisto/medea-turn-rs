use std::{
    borrow::Cow,
    collections::HashMap,
    env,
    net::{IpAddr, Ipv4Addr},
};

use config::{Config, ConfigError, Environment, File};
use serde::{Deserialize, Serialize};
use smart_default::SmartDefault;
use tracing_core::LevelFilter;

/// CLI argument that is responsible for holding application configuration
/// file path.
static APP_CONF_PATH_CMD_ARG_NAME: &str = "--conf";

/// Environment variable that is responsible for holding application
/// configuration file path.
static APP_CONF_PATH_ENV_VAR_NAME: &str = "MEDEA_TURN__CONF";

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct Conf {
    /// Logging settings.
    pub log: Log,

    /// [STUN] server settings.
    ///
    /// [STUN]: https://webrtcglossary.com/stun
    pub stun: Stun,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SmartDefault)]
#[serde(default)]
pub struct Stun {
    /// IP that STUN UDP socket will bind to.
    ///
    /// Defaults to `0.0.0.0`.
    #[default(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)))]
    pub bind_ip: IpAddr,

    /// Port that STUN UDP will use.
    ///
    /// Defaults to `3478`.
    #[default = 3478]
    pub bind_port: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize, SmartDefault)]
#[serde(default)]
pub struct Log {
    /// Maximum allowed level of application log entries.
    ///
    /// Defaults to `INFO`.
    #[default(LevelFilter::INFO)]
    #[serde(with = "level")]
    pub level: LevelFilter,

    /// Settings of application log for specific modules.
    ///
    /// Override any common settings declared above.
    pub r#mod: HashMap<String, Module>,
}

/// Log settings for a specific module.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Module {
    /// Maximum allowed level of the module log entries.
    #[serde(with = "level")]
    pub level: LevelFilter,
}

impl Conf {
    /// Parses a [`Conf`] from all possible sources and evaluates its values.
    ///
    /// The sources and their priority are following (descending):
    /// - default values;
    /// - configuration `file` (if present);
    /// - environment variables (if present).
    ///
    /// # Errors
    ///
    /// If a [`Conf`] fails to be parsed from the `file` or environment
    /// variables.
    pub fn parse() -> Result<Self, ConfigError> {
        let file = get_conf_file_name(env::args())
            .map_or(Cow::Borrowed("turn.toml"), Cow::Owned);
        Config::builder()
            .add_source(File::with_name(file.as_ref()).required(false))
            .add_source(Environment::with_prefix("MEDEA_TURN").separator("__"))
            .build()?
            .try_deserialize()
    }
}

/// Custom [`serde`] implementation for a [`LevelFilter`].
pub(crate) mod level {
    use std::str::FromStr as _;

    use serde::{Deserialize as _, Deserializer, Serializer, de::Error as _};
    use tracing_core::{Level, LevelFilter};

    /// Serializes a [`LevelFilter`] as `OFF`, `ERROR`, `WARN`, `INFO`,
    /// `DEBUG` or `TRACE` values.
    #[expect( // required by `serde`
        clippy::trivially_copy_pass_by_ref,
        reason = "required by `serde`"
    )]
    pub(crate) fn serialize<S: Serializer>(
        lvl: &LevelFilter,
        s: S,
    ) -> Result<S::Ok, S::Error> {
        s.serialize_str(lvl.into_level().as_ref().map_or("OFF", Level::as_str))
    }

    /// Deserializes a [`LevelFilter`] from `OFF`, `ERROR`, `WARN`, `INFO`,
    /// `DEBUG` or `TRACE` values.
    pub(crate) fn deserialize<'de, D>(d: D) -> Result<LevelFilter, D::Error>
    where
        D: Deserializer<'de>,
    {
        LevelFilter::from_str(&String::deserialize(d)?)
            .map_err(D::Error::custom)
    }
}

fn get_conf_file_name<T>(args: T) -> Option<String>
where
    T: IntoIterator<Item = String>,
{
    // First, check CLI arguments as they have the highest priority.
    let mut args =
        args.into_iter().skip_while(|x| x != APP_CONF_PATH_CMD_ARG_NAME);
    if args.next().is_some() {
        return args.next().filter(|v| !v.is_empty());
    }

    // Then check env var.
    env::var(APP_CONF_PATH_ENV_VAR_NAME).ok().filter(|v| !v.is_empty())
}
