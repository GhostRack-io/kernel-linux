//! The machine's configuration, read from `fw_cfg` (interface versions 1
//! to 6): the process to run (from version 3, possibly the image's own
//! init system; from version 5 with the image's volume paths; from version
//! 6 with state disks), or (version 2's unpack mode) the image layers to
//! unpack onto the root disk (from version 4, possibly a redeploy keeping
//! some of its paths).
//!
//! The config may carry secrets (environment values, keys), so no error
//! message here quotes a value: they name the field at most.

use serde::Deserialize;
use serde_json::Value;

/// The `fw_cfg` entries the agent writes the config as, each with its
/// file: `opt/ghostrack/config` (`-fw_cfg name=opt/ghostrack/config`)
/// first, then the platform's old name `opt/gigahost/config`, read only
/// when the first is absent, so the init boots under an agent that
/// writes only the old name.
pub const ENTRIES: [(&str, &str); 2] = [
    (
        "opt/ghostrack/config",
        "/sys/firmware/qemu_fw_cfg/by_name/opt/ghostrack/config/raw",
    ),
    (
        "opt/gigahost/config",
        "/sys/firmware/qemu_fw_cfg/by_name/opt/gigahost/config/raw",
    ),
];

/// Opens the first of `entries` (name, file) that exists, with its name.
/// Only an absent file (`ENOENT`) moves on to the next: one present but
/// not openable is an error, never a reason to read an older entry.
pub fn open<'a>(entries: &[(&'a str, &str)]) -> Result<(&'a str, std::fs::File), String> {
    for &(name, file) in entries {
        match std::fs::File::open(file) {
            Ok(opened) => return Ok((name, opened)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(format!(
                    "the config (fw_cfg {name}) cannot be opened: {error}"
                ));
            }
        }
    }
    let names: Vec<&str> = entries.iter().map(|&(name, _)| name).collect();
    Err(format!(
        "the config (fw_cfg {}) is missing",
        names.join(" or ")
    ))
}

/// The largest config accepted.
pub const MAX_BYTES: usize = 1 << 20;

/// The longest stop timeout, in the config and in a stop command.
pub const MAX_STOP_TIMEOUT_SECONDS: u32 = 300;

const DEFAULT_STOP_TIMEOUT_SECONDS: u32 = 10;

/// The signal a stop sends first when the config names none (SIGTERM).
const DEFAULT_STOP_SIGNAL: i32 = 15;

/// The highest signal number a config may name (`SIGRTMAX` on Linux).
pub const MAX_SIGNAL: i32 = 64;

/// The config versions this init accepts.
pub const VERSIONS: &[u64] = &[1, 2, 3, 4, 5, 6];

/// The first config version with `init_system`.
const INIT_SYSTEM_VERSION: u64 = 3;

/// The first config version with the unpack mode's `keep`.
const KEEP_VERSION: u64 = 4;

/// The first config version with the run mode's `volumes`.
const VOLUMES_VERSION: u64 = 5;

/// The first config version with the run mode's `disks`.
const DISKS_VERSION: u64 = 6;

/// The most state disks a run config may list.
pub const MAX_DISKS: usize = 8;

/// The most binds one state disk may list.
pub const MAX_BINDS: usize = 16;

/// The longest state disk serial, in bytes (virtio-blk's ID is 20 bytes).
pub const MAX_SERIAL_BYTES: usize = 20;

/// The most volume paths a run config may list.
pub const MAX_VOLUMES: usize = 64;

/// The most paths a redeploy may keep.
pub const MAX_KEEP: usize = 64;

/// The longest kept path or volume path, in bytes (Linux's `PATH_MAX` less
/// its NUL).
pub const MAX_KEEP_BYTES: usize = 4095;

/// The most layers an unpack config may list.
pub const MAX_LAYERS: usize = 128;

/// How a layer's blob is compressed, from its media type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    None,
    Gzip,
    Zstd,
}

/// The layer media types the unpack mode takes. Non-distributable
/// (foreign) layers are not among them: their blobs are not in the image.
const MEDIA_TYPES: &[(&str, Compression)] = &[
    ("application/vnd.oci.image.layer.v1.tar", Compression::None),
    (
        "application/vnd.oci.image.layer.v1.tar+gzip",
        Compression::Gzip,
    ),
    (
        "application/vnd.oci.image.layer.v1.tar+zstd",
        Compression::Zstd,
    ),
    (
        "application/vnd.docker.image.rootfs.diff.tar.gzip",
        Compression::Gzip,
    ),
];

/// What the boot does: run the image's process (versions 1 and 2), or
/// unpack the image's layers onto the empty root disk (version 2).
#[derive(Debug)]
pub enum Boot {
    Run(Config),
    Unpack(Unpack),
}

/// The unpack mode's config: the layers, in order, as they lie one after
/// the other on the layers disk, and (version 4) the paths a redeploy
/// keeps.
#[derive(Debug)]
pub struct Unpack {
    pub layers: Vec<Layer>,
    /// Version 4's `keep`: present (even empty), the unpack is a redeploy
    /// onto a disk that need not be empty. Each path without its leading
    /// `/` (`data/db` for `/data/db`).
    pub keep: Option<Vec<Vec<u8>>>,
}

/// One layer of the layers disk.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Layer {
    pub compression: Compression,
    /// The blob's SHA-256.
    pub digest: [u8; 32],
    /// The blob's length in bytes, at least 1.
    pub size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LayerFields {
    media_type: String,
    digest: String,
    size: u64,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[allow(dead_code, reason = "checked before the typed parse")]
    pub version: u64,
    pub argv: Vec<String>,
    #[serde(default)]
    pub env: Vec<String>,
    /// Docker's `user[:group]`; absent means root (uid 0, gid 0).
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default = "default_workdir")]
    pub workdir: String,
    #[serde(default = "default_stop_timeout")]
    pub stop_timeout_seconds: u32,
    /// The image's `STOPSIGNAL`, as a number: what a stop sends the main
    /// process first.
    #[serde(default = "default_stop_signal")]
    pub stop_signal: i32,
    #[serde(default)]
    pub authorized_keys: Option<AuthorizedKeys>,
    /// Version 3: `argv` is the image's own init system (systemd, a
    /// SysV-style or busybox init), run as PID 1 of a PID namespace of its
    /// own.
    #[serde(default)]
    pub init_system: bool,
    /// Version 5's `volumes`: the image's `VOLUME` paths, each without its
    /// leading `/` (`app/data` for `/app/data`), parsed apart from the
    /// other fields.
    #[serde(skip)]
    pub volumes: Vec<Vec<u8>>,
    /// Version 6's `disks`: the state disks to mount, parsed apart from
    /// the other fields.
    #[serde(skip)]
    pub disks: Vec<Disk>,
}

/// One of version 6's state disks: the virtio-blk disk whose serial is
/// `serial`, mounted at `path`, with directories of it bound over paths
/// of the root.
pub struct Disk {
    pub serial: String,
    /// Where it is mounted, without the leading `/`.
    pub path: Vec<u8>,
    pub binds: Vec<Bind>,
}

/// A directory of a state disk bound over a path of the root.
pub struct Bind {
    /// The directory inside the disk, relative to its root.
    pub source: Vec<u8>,
    /// The path of the root it covers, without the leading `/`.
    pub path: Vec<u8>,
}

/// Shows the shape only, as [`Config`]'s does.
impl std::fmt::Debug for Disk {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Disk")
            .field("binds", &self.binds.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedKeys {
    pub user: String,
    pub keys: Vec<String>,
}

/// Shows the shape only: the config may hold secrets.
impl std::fmt::Debug for Config {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("Config")
            .field("argv", &self.argv.len())
            .field("env", &self.env.len())
            .field(
                "authorized_keys",
                &self.authorized_keys.as_ref().map(|keys| keys.keys.len()),
            )
            .field("init_system", &self.init_system)
            .field("volumes", &self.volumes.len())
            .field("disks", &self.disks)
            .finish_non_exhaustive()
    }
}

fn default_workdir() -> String {
    "/".into()
}

fn default_stop_timeout() -> u32 {
    DEFAULT_STOP_TIMEOUT_SECONDS
}

fn default_stop_signal() -> i32 {
    DEFAULT_STOP_SIGNAL
}

const FIELDS: &[&str] = &[
    "version",
    "argv",
    "env",
    "user",
    "workdir",
    "stop_timeout_seconds",
    "stop_signal",
    "authorized_keys",
    "init_system",
    "volumes",
    "disks",
];

/// Whether `key` is a run field of config `version`: `init_system` is
/// version 3's, unknown to versions 1 and 2, `volumes` version 5's and
/// `disks` version 6's.
fn known_field(key: &str, version: u64) -> bool {
    FIELDS.contains(&key)
        && (key != "init_system" || version >= INIT_SYSTEM_VERSION)
        && (key != "volumes" || version >= VOLUMES_VERSION)
        && (key != "disks" || version >= DISKS_VERSION)
}

/// Names what in `value` keeps it from parsing, without quoting a value.
fn diagnose(value: &Value, version: u64) -> String {
    let Some(object) = value.as_object() else {
        return "the config is not a JSON object".into();
    };
    for key in object.keys() {
        if !known_field(key, version) {
            return format!("the config has an unknown field `{}`", printable(key));
        }
    }
    for field in ["argv", "env"] {
        if let Some(item) = object.get(field)
            && Vec::<String>::deserialize(item).is_err()
        {
            return format!("config field `{field}` is not a list of strings");
        }
    }
    if object.get("argv").is_none() {
        return "config field `argv` is missing".into();
    }
    if let Some(item) = object.get("user")
        && !item.is_string()
        && !item.is_null()
    {
        return "config field `user` is not a string".into();
    }
    if object.get("workdir").is_some_and(|item| !item.is_string()) {
        return "config field `workdir` is not a string".into();
    }
    if object
        .get("stop_timeout_seconds")
        .is_some_and(|item| u32::deserialize(item).is_err())
    {
        return "config field `stop_timeout_seconds` is not a whole number of seconds".into();
    }
    if object
        .get("stop_signal")
        .is_some_and(|item| i32::deserialize(item).is_err())
    {
        return "config field `stop_signal` is not a signal number".into();
    }
    if object
        .get("init_system")
        .is_some_and(|item| !item.is_boolean())
    {
        return "config field `init_system` is not true or false".into();
    }
    if let Some(keys) = object.get("authorized_keys") {
        if let Some(inner) = keys.as_object() {
            for key in inner.keys() {
                if key != "user" && key != "keys" {
                    return format!(
                        "config field `authorized_keys` has an unknown field `{}`",
                        printable(key)
                    );
                }
            }
        }
        return "config field `authorized_keys` is not {\"user\": string, \"keys\": [string]}"
            .into();
    }
    format!("the config does not match interface version {version}")
}

/// A field name for a message: field names are the agent's, never secret,
/// but are cut short and kept to plain characters.
fn printable(key: &str) -> String {
    key.chars()
        .take(40)
        .map(|c| if c.is_ascii_graphic() { c } else { '?' })
        .collect()
}

/// Parses and checks the config of a boot of interface `boot_version`
/// (`gh.v`), whose version the config's must be.
pub fn parse(bytes: &[u8], boot_version: u32) -> Result<Boot, String> {
    if bytes.len() > MAX_BYTES {
        return Err("the config is larger than 1 MiB".into());
    }
    let mut value: Value = serde_json::from_slice(bytes).map_err(|error| {
        format!(
            "the config is not valid JSON (line {}, column {})",
            error.line(),
            error.column()
        )
    })?;
    let version = match value.get("version").map(Value::as_u64) {
        None => return Err("config field `version` is missing".into()),
        Some(Some(version)) if version == u64::from(boot_version) => version,
        // A boot answers a later version as one it does not support, as it
        // did before that version existed (a version-1 boot answers so
        // for every other version).
        Some(Some(version)) if VERSIONS.contains(&version) && version < u64::from(boot_version) => {
            return Err("the config's version is not the boot's interface version (gh.v)".into());
        }
        Some(_) => return Err("the config's version is not one this init supports".into()),
    };
    if version == 1 {
        return run_config(&mut value, version).map(Boot::Run);
    }
    let Some(object) = value.as_object_mut() else {
        return Err("the config is not a JSON object".into());
    };
    match object.get("mode") {
        None => {}
        Some(Value::String(mode)) if mode == "run" => {}
        Some(Value::String(mode)) if mode == "unpack" => {
            return unpack_config(object, version).map(Boot::Unpack);
        }
        Some(_) => return Err("config field `mode` is not \"run\" or \"unpack\"".into()),
    }
    object.remove("mode");
    if object.contains_key("layers") {
        return Err("config field `layers` is taken in the unpack mode only".into());
    }
    run_config(&mut value, version).map(Boot::Run)
}

/// The run mode's config, as version 1 has it; from version 5 with
/// `volumes` and from version 6 with `disks`, which are taken out of
/// `value` and parsed apart.
fn run_config(value: &mut Value, version: u64) -> Result<Config, String> {
    if (version < INIT_SYSTEM_VERSION && value.get("init_system").is_some())
        || (version < VOLUMES_VERSION && value.get("volumes").is_some())
        || (version < DISKS_VERSION && value.get("disks").is_some())
    {
        // Not a field of this version: refused as any unknown field.
        return Err(diagnose(value, version));
    }
    let volumes = value
        .as_object_mut()
        .and_then(|object| object.remove("volumes"));
    let disks = value
        .as_object_mut()
        .and_then(|object| object.remove("disks"));
    let mut config = Config::deserialize(&*value).map_err(|_| diagnose(value, version))?;
    check(&config)?;
    if let Some(volumes) = volumes {
        config.volumes = paths(&volumes, "volumes", MAX_VOLUMES)?;
    }
    if let Some(disks) = disks {
        config.disks = state_disks(&disks)?;
    }
    Ok(config)
}

/// The unpack mode's config: `version`, `mode`, `layers` and from
/// version 4 `keep`, nothing else.
fn unpack_config(object: &serde_json::Map<String, Value>, version: u64) -> Result<Unpack, String> {
    for key in object.keys() {
        if key == "mode" || key == "layers" || (key == "keep" && version >= KEEP_VERSION) {
            continue;
        }
        if !known_field(key, version) {
            return Err(format!(
                "the config has an unknown field `{}`",
                printable(key)
            ));
        }
        if key != "version" {
            return Err(format!(
                "config field `{key}` is not taken in the unpack mode"
            ));
        }
    }
    let Some(layers) = object.get("layers") else {
        return Err("config field `layers` is missing".into());
    };
    let Some(entries) = layers.as_array() else {
        return Err("config field `layers` is not a list".into());
    };
    if entries.is_empty() || entries.len() > MAX_LAYERS {
        return Err(format!(
            "config field `layers` does not hold 1 to {MAX_LAYERS} layers"
        ));
    }
    let mut total: u64 = 0;
    let mut checked = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let layer = layer(index, entry)?;
        total = total
            .checked_add(layer.size)
            .ok_or_else(|| format!("config field `layers` entry {index} ends beyond any disk"))?;
        checked.push(layer);
    }
    let keep = object
        .get("keep")
        .map(|keep| paths(keep, "keep", MAX_KEEP))
        .transpose()?;
    Ok(Unpack {
        layers: checked,
        keep,
    })
}

/// Version 4's `keep` and version 5's `volumes`, the config field
/// `field`: 0 to `max` absolute, normalised paths (no `.`, `..` or empty
/// component, no trailing slash, not `/` itself), each at most
/// [`MAX_KEEP_BYTES`] bytes, none twice. Each is returned without its
/// leading `/`.
fn paths(value: &Value, field: &str, max: usize) -> Result<Vec<Vec<u8>>, String> {
    let Some(entries) = value.as_array() else {
        return Err(format!("config field `{field}` is not a list"));
    };
    if entries.len() > max {
        return Err(format!(
            "config field `{field}` holds more than {max} paths"
        ));
    }
    let mut paths: Vec<Vec<u8>> = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let what = |problem: &str| format!("config field `{field}` entry {index} {problem}");
        let path = absolute_path(entry).map_err(|problem| what(&problem))?;
        if paths.contains(&path) {
            return Err(what("is given twice"));
        }
        paths.push(path);
    }
    Ok(paths)
}

/// One absolute, normalised path (no `.`, `..` or empty component, no
/// trailing slash, not `/` itself) of at most [`MAX_KEEP_BYTES`] bytes,
/// without its leading `/`; or what is wrong with it, without quoting it.
fn absolute_path(entry: &Value) -> Result<Vec<u8>, String> {
    let Some(text) = entry.as_str() else {
        return Err("is not a string".into());
    };
    if text.len() > MAX_KEEP_BYTES {
        return Err(format!("is longer than {MAX_KEEP_BYTES} bytes"));
    }
    if text.contains('\0') {
        return Err("holds a NUL byte".into());
    }
    let Some(relative) = text.strip_prefix('/') else {
        return Err("is not an absolute path".into());
    };
    if relative.is_empty() {
        return Err("is the root".into());
    }
    normalised(relative)?;
    Ok(relative.as_bytes().to_vec())
}

/// Whether `path` (no leading `/`) has only plain components.
fn normalised(path: &str) -> Result<(), String> {
    if path
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err("is not a normalised path".into());
    }
    Ok(())
}

/// The paths a state disk or a bind may not be at or below: the init's
/// mounts `/proc`, `/sys` and `/dev` (as for volumes) and its tmpfs
/// `/run`.
fn reserved(path: &[u8]) -> bool {
    crate::volumes::is_system(path)
        || path.split(|&byte| byte == b'/').next() == Some(b"run".as_slice())
}

/// Whether `a` and `b` (no leading `/`) are the same path or one is
/// below the other.
fn overlaps(a: &[u8], b: &[u8]) -> bool {
    let below = |inner: &[u8], outer: &[u8]| {
        inner.len() > outer.len()
            && inner.starts_with(outer)
            && inner.get(outer.len()) == Some(&b'/')
    };
    a == b || below(a, b) || below(b, a)
}

/// Whether `serial` is 1 to [`MAX_SERIAL_BYTES`] letters, digits, `.`,
/// `_` and `-`.
fn valid_serial(serial: &str) -> bool {
    (1..=MAX_SERIAL_BYTES).contains(&serial.len())
        && serial
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
}

/// Checks that `object` holds `required` and nothing but `allowed`;
/// `what` words the problem for the message.
fn object_fields<'a>(
    entry: &'a Value,
    allowed: &[&str],
    required: &[&str],
    what: &dyn Fn(&str) -> String,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let Some(object) = entry.as_object() else {
        return Err(what("is not an object"));
    };
    for key in object.keys() {
        if !allowed.contains(&key.as_str()) {
            return Err(what(&format!("has an unknown field `{}`", printable(key))));
        }
    }
    for key in required {
        if !object.contains_key(*key) {
            return Err(what(&format!("lacks `{key}`")));
        }
    }
    Ok(object)
}

/// Version 6's `disks`: 0 to [`MAX_DISKS`] state disks, each `serial`
/// (none twice), `path` (absolute, normalised, not reserved) and 0 to
/// [`MAX_BINDS`] `binds`, each `source` (a normalised path inside the
/// disk) and `path` (as a disk's). No disk's or bind's path is at, inside
/// or above another's: each mount covers a place of its own.
fn state_disks(value: &Value) -> Result<Vec<Disk>, String> {
    let Some(entries) = value.as_array() else {
        return Err("config field `disks` is not a list".into());
    };
    if entries.len() > MAX_DISKS {
        return Err(format!(
            "config field `disks` holds more than {MAX_DISKS} disks"
        ));
    }
    let mut disks: Vec<Disk> = Vec::with_capacity(entries.len());
    // Every disk's and bind's path so far.
    let mut taken: Vec<Vec<u8>> = Vec::new();
    for (index, entry) in entries.iter().enumerate() {
        let what = |problem: &str| format!("config field `disks` entry {index} {problem}");
        let object = object_fields(
            entry,
            &["serial", "path", "binds"],
            &["serial", "path"],
            &what,
        )?;
        let serial = object
            .get("serial")
            .and_then(Value::as_str)
            .filter(|serial| valid_serial(serial))
            .ok_or_else(|| {
                what(&format!(
                    "`serial` is not 1 to {MAX_SERIAL_BYTES} letters, digits, `.`, `_` and `-`"
                ))
            })?;
        if disks.iter().any(|disk| disk.serial == serial) {
            return Err(what("`serial` is given twice"));
        }
        let path = mount_path(object.get("path"), &taken)
            .map_err(|problem| what(&format!("`path` {problem}")))?;
        taken.push(path.clone());
        let binds = match object.get("binds") {
            None => Vec::new(),
            Some(binds) => {
                let Some(binds) = binds.as_array() else {
                    return Err(what("`binds` is not a list"));
                };
                if binds.len() > MAX_BINDS {
                    return Err(what(&format!("`binds` holds more than {MAX_BINDS} binds")));
                }
                let mut checked = Vec::with_capacity(binds.len());
                for (number, bind) in binds.iter().enumerate() {
                    let what = |problem: &str| what(&format!("bind {number} {problem}"));
                    let object =
                        object_fields(bind, &["source", "path"], &["source", "path"], &what)?;
                    let source = relative_path(object.get("source"))
                        .map_err(|problem| what(&format!("`source` {problem}")))?;
                    let path = mount_path(object.get("path"), &taken)
                        .map_err(|problem| what(&format!("`path` {problem}")))?;
                    taken.push(path.clone());
                    checked.push(Bind { source, path });
                }
                checked
            }
        };
        disks.push(Disk {
            serial: serial.to_owned(),
            path,
            binds,
        });
    }
    Ok(disks)
}

/// A state disk's or a bind's `path`: absolute and normalised, not in a
/// [`reserved`] place, at, inside or above none of `taken`.
fn mount_path(entry: Option<&Value>, taken: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let path = absolute_path(entry.unwrap_or(&Value::Null))?;
    if reserved(&path) {
        return Err("is in /proc, /sys, /dev or /run".into());
    }
    if taken.iter().any(|other| overlaps(other, &path)) {
        return Err("is at, inside or above another disk's or bind's path".into());
    }
    Ok(path)
}

/// A bind's `source`: a normalised path relative to the disk's root, at
/// most [`MAX_KEEP_BYTES`] bytes.
fn relative_path(entry: Option<&Value>) -> Result<Vec<u8>, String> {
    let Some(text) = entry.and_then(Value::as_str) else {
        return Err("is not a string".into());
    };
    if text.len() > MAX_KEEP_BYTES {
        return Err(format!("is longer than {MAX_KEEP_BYTES} bytes"));
    }
    if text.contains('\0') {
        return Err("holds a NUL byte".into());
    }
    if text.starts_with('/') {
        return Err("is not a relative path".into());
    }
    normalised(text)?;
    Ok(text.as_bytes().to_vec())
}

fn layer(index: usize, entry: &Value) -> Result<Layer, String> {
    let what = |problem: &str| format!("config field `layers` entry {index} {problem}");
    let Some(object) = entry.as_object() else {
        return Err(what("is not an object"));
    };
    for key in object.keys() {
        if !["media_type", "digest", "size"].contains(&key.as_str()) {
            return Err(what(&format!("has an unknown field `{}`", printable(key))));
        }
    }
    for key in ["media_type", "digest", "size"] {
        if !object.contains_key(key) {
            return Err(what(&format!("lacks `{key}`")));
        }
    }
    let fields = LayerFields::deserialize(entry).map_err(|_| {
        what("is not {\"media_type\": string, \"digest\": string, \"size\": number}")
    })?;
    let compression = MEDIA_TYPES
        .iter()
        .find(|(name, _)| *name == fields.media_type)
        .map(|&(_, compression)| compression)
        .ok_or_else(|| what("has a media type this init does not unpack"))?;
    let digest = parse_digest(&fields.digest)
        .ok_or_else(|| what("has a digest that is not sha256: and 64 lowercase hex digits"))?;
    if fields.size == 0 {
        return Err(what("has a size of 0"));
    }
    Ok(Layer {
        compression,
        digest,
        size: fields.size,
    })
}

/// `sha256:` and 64 lowercase hex digits, as bytes.
fn parse_digest(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix("sha256:")?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let nibble = |byte: u8| match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    };
    let mut digest = [0u8; 32];
    for (out, pair) in digest.iter_mut().zip(hex.chunks_exact(2)) {
        let [high, low] = pair else { return None };
        *out = nibble(*high)? << 4 | nibble(*low)?;
    }
    Some(digest)
}

fn check(config: &Config) -> Result<(), String> {
    if config.argv.is_empty() {
        return Err("config field `argv` is empty".into());
    }
    if config.argv.iter().any(|arg| arg.contains('\0')) {
        return Err("config field `argv` holds a NUL byte".into());
    }
    for (index, entry) in config.env.iter().enumerate() {
        match entry.split_once('=') {
            Some((key, _)) if !key.is_empty() && !entry.contains('\0') => {}
            _ => return Err(format!("config field `env` entry {index} is not KEY=value")),
        }
    }
    if config
        .user
        .as_deref()
        .is_some_and(|user| user.contains('\0'))
    {
        return Err("config field `user` holds a NUL byte".into());
    }
    if !config.workdir.starts_with('/') || config.workdir.contains('\0') {
        return Err("config field `workdir` is not an absolute path".into());
    }
    if config.stop_timeout_seconds > MAX_STOP_TIMEOUT_SECONDS {
        return Err(format!(
            "config field `stop_timeout_seconds` is above {MAX_STOP_TIMEOUT_SECONDS}"
        ));
    }
    if !(1..=MAX_SIGNAL).contains(&config.stop_signal) {
        return Err(format!(
            "config field `stop_signal` is not a signal number from 1 to {MAX_SIGNAL}"
        ));
    }
    if config.init_system {
        check_init_system(config)?;
    }
    if let Some(keys) = &config.authorized_keys {
        if keys.user.is_empty() || keys.user.contains('\0') {
            return Err("config field `authorized_keys.user` is empty".into());
        }
        if keys
            .keys
            .iter()
            .any(|key| key.is_empty() || key.contains(['\n', '\r', '\0']))
        {
            return Err(
                "config field `authorized_keys.keys` holds an empty or multi-line key".into(),
            );
        }
    }
    Ok(())
}

/// The `user` values that name root (uid 0, gid 0) without looking at the
/// image: absent, or root by name or number, with or without its group.
const ROOT_USERS: &[&str] = &["", "root", "0", "root:root", "root:0", "0:root", "0:0"];

/// What `init_system` requires of the rest of the run config: an absolute
/// path to the image's init, root, and `/` as the working directory.
fn check_init_system(config: &Config) -> Result<(), String> {
    if !config
        .argv
        .first()
        .is_some_and(|program| program.starts_with('/'))
    {
        return Err(
            "config field `argv` does not start with an absolute path, which `init_system` requires"
                .into(),
        );
    }
    if !ROOT_USERS.contains(&config.user.as_deref().unwrap_or("")) {
        return Err("config field `user` is not root, which `init_system` requires".into());
    }
    if config.workdir != "/" {
        return Err("config field `workdir` is not /, which `init_system` requires".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "s3cr3t-value-never-shown";

    /// A fresh directory standing in for `by_name/`, with the two entries'
    /// files below it.
    fn entries_in(name: &str) -> (std::path::PathBuf, [(&'static str, String); 2]) {
        let dir = std::env::temp_dir().join(format!(
            "ghostrack-init-config-{}-{name}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let file = |entry: &str| dir.join(entry).join("raw").to_string_lossy().into_owned();
        let entries = [
            ("opt/ghostrack/config", file("opt/ghostrack/config")),
            ("opt/gigahost/config", file("opt/gigahost/config")),
        ];
        (dir, entries)
    }

    fn write_entry(file: &str, text: &str) {
        let path = std::path::Path::new(file);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn open_text(entries: &[(&'static str, String); 2]) -> Result<(&'static str, String), String> {
        use std::io::Read;
        let borrowed = entries
            .each_ref()
            .map(|(name, file)| (*name, file.as_str()));
        open(&borrowed).map(|(name, mut file)| {
            let mut text = String::new();
            file.read_to_string(&mut text).unwrap();
            (name, text)
        })
    }

    #[test]
    fn the_entries_are_the_new_name_then_the_old() {
        assert_eq!(
            ENTRIES,
            [
                (
                    "opt/ghostrack/config",
                    "/sys/firmware/qemu_fw_cfg/by_name/opt/ghostrack/config/raw"
                ),
                (
                    "opt/gigahost/config",
                    "/sys/firmware/qemu_fw_cfg/by_name/opt/gigahost/config/raw"
                ),
            ]
        );
    }

    #[test]
    fn the_new_entry_is_read_first() {
        let (dir, entries) = entries_in("both");
        write_entry(&entries[0].1, "new");
        write_entry(&entries[1].1, "old");
        assert_eq!(
            open_text(&entries),
            Ok(("opt/ghostrack/config", "new".into()))
        );
        write_entry(&entries[0].1, "");
        assert_eq!(
            open_text(&entries),
            Ok(("opt/ghostrack/config", String::new())),
            "an empty new entry is still the config"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn the_old_entry_is_read_when_the_new_is_absent() {
        let (dir, entries) = entries_in("old");
        write_entry(&entries[1].1, "old");
        assert_eq!(
            open_text(&entries),
            Ok(("opt/gigahost/config", "old".into()))
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn no_entry_is_an_error_naming_both() {
        let (dir, entries) = entries_in("neither");
        assert_eq!(
            open_text(&entries),
            Err(
                "the config (fw_cfg opt/ghostrack/config or opt/gigahost/config) is missing".into()
            )
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn a_new_entry_that_cannot_be_opened_is_an_error_not_the_old() {
        let (dir, entries) = entries_in("unopenable");
        write_entry(&entries[1].1, "old");
        // A link to itself: present, but opening it fails (ELOOP) for
        // root too.
        let new = std::path::Path::new(&entries[0].1);
        std::fs::create_dir_all(new.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink("raw", new).unwrap();
        let error = open_text(&entries).unwrap_err();
        assert!(
            error.starts_with("the config (fw_cfg opt/ghostrack/config) cannot be opened: "),
            "{error}"
        );
        std::fs::remove_dir_all(dir).unwrap();
    }

    /// A version-1 boot's run config.
    fn parse_text(text: &str) -> Result<Config, String> {
        parse_boot(text, 1).map(|boot| match boot {
            Boot::Run(config) => config,
            Boot::Unpack(_) => panic!("a version-1 config gave the unpack mode"),
        })
    }

    fn parse_boot(text: &str, boot_version: u32) -> Result<Boot, String> {
        parse(text.as_bytes(), boot_version)
    }

    fn unpack(text: &str) -> Result<Vec<Layer>, String> {
        parse_boot(text, 2).map(|boot| match boot {
            Boot::Unpack(unpack) => unpack.layers,
            Boot::Run(_) => panic!("not the unpack mode"),
        })
    }

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const TAR: &str = "application/vnd.oci.image.layer.v1.tar";

    fn layer_json(media_type: &str, digest: &str, size: &str) -> String {
        format!(r#"{{"media_type": "{media_type}", "digest": "{digest}", "size": {size}}}"#)
    }

    fn unpack_json(layers: &[String]) -> String {
        format!(
            r#"{{"version": 2, "mode": "unpack", "layers": [{}]}}"#,
            layers.join(", ")
        )
    }

    #[test]
    fn version_two_run_mode() {
        for text in [
            r#"{"version": 2, "argv": ["nginx"]}"#,
            r#"{"version": 2, "mode": "run", "argv": ["nginx"], "stop_signal": 3}"#,
        ] {
            match parse_boot(text, 2).unwrap() {
                Boot::Run(config) => assert_eq!(config.argv, ["nginx"]),
                Boot::Unpack(_) => panic!("{text}"),
            }
        }
        assert_eq!(
            parse_boot(r#"{"version": 2, "mode": "run"}"#, 2).unwrap_err(),
            "config field `argv` is missing"
        );
        let with_layers = format!(
            r#"{{"version": 2, "argv": ["a"], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&with_layers, 2).unwrap_err(),
            "config field `layers` is taken in the unpack mode only"
        );
        for mode in [r#""Run""#, r#""""#, "1", "null", r#"["run"]"#] {
            let text = format!(r#"{{"version": 2, "mode": {mode}, "argv": ["a"]}}"#);
            assert_eq!(
                parse_boot(&text, 2).unwrap_err(),
                r#"config field `mode` is not "run" or "unpack""#,
                "{mode}"
            );
        }
        assert_eq!(
            parse_boot(r#"{"version": 2, "argv": ["a"], "x": 1}"#, 2).unwrap_err(),
            "the config has an unknown field `x`"
        );
        assert_eq!(
            parse_boot(r#"{"version": 2, "argv": 5}"#, 2).unwrap_err(),
            "config field `argv` is not a list of strings"
        );
    }

    #[test]
    fn versions_must_match_the_boot() {
        // A version-1 boot refuses version 2 as it refused any other.
        assert_eq!(
            parse_boot(r#"{"version": 2, "argv": ["a"]}"#, 1).unwrap_err(),
            "the config's version is not one this init supports"
        );
        assert_eq!(
            parse_boot(&unpack_json(&[layer_json(TAR, DIGEST, "1")]), 1).unwrap_err(),
            "the config's version is not one this init supports"
        );
        assert_eq!(
            parse_boot(r#"{"version": 1, "argv": ["a"]}"#, 2).unwrap_err(),
            "the config's version is not the boot's interface version (gh.v)"
        );
        assert_eq!(
            parse_boot(r#"{"version": 3, "argv": ["a"]}"#, 2).unwrap_err(),
            "the config's version is not one this init supports"
        );
        // Version 1 knows no mode and no layers.
        assert_eq!(
            parse_boot(r#"{"version": 1, "mode": "run", "argv": ["a"]}"#, 1).unwrap_err(),
            "the config has an unknown field `mode`"
        );
        assert_eq!(
            parse_boot(r#"{"version": 1, "argv": ["a"], "layers": []}"#, 1).unwrap_err(),
            "the config has an unknown field `layers`"
        );
    }

    fn run_v3(text: &str) -> Result<Config, String> {
        parse_boot(text, 3).map(|boot| match boot {
            Boot::Run(config) => config,
            Boot::Unpack(_) => panic!("not the run mode"),
        })
    }

    #[test]
    fn version_three_init_system() {
        let config = run_v3(r#"{"version": 3, "argv": ["nginx"]}"#).unwrap();
        assert!(!config.init_system);
        assert_eq!(config.stop_signal, 15);
        let config = run_v3(
            r#"{"version": 3, "mode": "run", "argv": ["/sbin/init"], "init_system": true, "stop_signal": 37}"#,
        )
        .unwrap();
        assert!(config.init_system);
        assert_eq!(config.argv, ["/sbin/init"]);
        assert_eq!(config.stop_signal, 37);
        assert!(
            !run_v3(r#"{"version": 3, "argv": ["a"], "init_system": false}"#)
                .unwrap()
                .init_system
        );
        for user in ["root", "0", "0:0", "root:root", "root:0", "0:root"] {
            let text = format!(
                r#"{{"version": 3, "argv": ["/sbin/init"], "init_system": true, "user": "{user}", "workdir": "/"}}"#
            );
            assert!(run_v3(&text).is_ok(), "{user}");
        }
        for user in ["nobody", "1000", "0:1", "root:adm", "1:0", "root "] {
            let text = format!(
                r#"{{"version": 3, "argv": ["/sbin/init"], "init_system": true, "user": "{user}"}}"#
            );
            assert_eq!(
                run_v3(&text).unwrap_err(),
                "config field `user` is not root, which `init_system` requires",
                "{user}"
            );
        }
        assert_eq!(
            run_v3(
                r#"{"version": 3, "argv": ["/sbin/init"], "init_system": true, "workdir": "/srv"}"#
            )
            .unwrap_err(),
            "config field `workdir` is not /, which `init_system` requires"
        );
        assert_eq!(
            run_v3(r#"{"version": 3, "argv": ["init"], "init_system": true}"#).unwrap_err(),
            "config field `argv` does not start with an absolute path, which `init_system` requires"
        );
        // Without init_system, the same fields are v2's run mode.
        assert!(
            run_v3(r#"{"version": 3, "argv": ["init"], "user": "nobody", "workdir": "/srv"}"#)
                .is_ok()
        );
        for value in ["1", r#""true""#, "null", "[]"] {
            let text =
                format!(r#"{{"version": 3, "argv": ["/sbin/init"], "init_system": {value}}}"#);
            assert_eq!(
                run_v3(&text).unwrap_err(),
                "config field `init_system` is not true or false",
                "{value}"
            );
        }
    }

    #[test]
    fn init_system_unknown_before_version_three() {
        assert_eq!(
            parse_text(r#"{"version": 1, "argv": ["/sbin/init"], "init_system": true}"#)
                .unwrap_err(),
            "the config has an unknown field `init_system`"
        );
        for text in [
            r#"{"version": 2, "argv": ["/sbin/init"], "init_system": true}"#,
            r#"{"version": 2, "mode": "run", "argv": ["/sbin/init"], "init_system": false}"#,
        ] {
            assert_eq!(
                parse_boot(text, 2).unwrap_err(),
                "the config has an unknown field `init_system`",
                "{text}"
            );
        }
        // The first unknown field is named, as before version 3.
        assert_eq!(
            parse_boot(
                r#"{"version": 2, "argv": ["a"], "init_system": true, "a": 1}"#,
                2
            )
            .unwrap_err(),
            "the config has an unknown field `a`"
        );
        let text = format!(
            r#"{{"version": 2, "mode": "unpack", "init_system": true, "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 2).unwrap_err(),
            "the config has an unknown field `init_system`"
        );
        let text = format!(
            r#"{{"version": 3, "mode": "unpack", "init_system": true, "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 3).unwrap_err(),
            "config field `init_system` is not taken in the unpack mode"
        );
        let text = format!(
            r#"{{"version": 3, "mode": "unpack", "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert!(matches!(parse_boot(&text, 3), Ok(Boot::Unpack(_))));
    }

    /// A version-4 unpack config with `keep` set to the JSON `keep`.
    fn keep(keep: &str) -> Result<Option<Vec<Vec<u8>>>, String> {
        let text = format!(
            r#"{{"version": 4, "mode": "unpack", "layers": [{}]{keep}}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        match parse_boot(&text, 4)? {
            Boot::Unpack(unpack) => Ok(unpack.keep),
            Boot::Run(_) => panic!("not the unpack mode"),
        }
    }

    #[test]
    fn version_four_keep() {
        assert_eq!(keep("").unwrap(), None);
        assert_eq!(keep(r#", "keep": []"#).unwrap(), Some(vec![]));
        assert_eq!(
            keep(r#", "keep": ["/data", "/var/lib/db", "/data/db", "/a b/ü"]"#).unwrap(),
            Some(vec![
                b"data".to_vec(),
                b"var/lib/db".to_vec(),
                b"data/db".to_vec(),
                "a b/ü".as_bytes().to_vec()
            ])
        );
        let longest = format!("/{}", "a".repeat(MAX_KEEP_BYTES - 1));
        assert_eq!(
            keep(&format!(r#", "keep": ["{longest}"]"#)).unwrap(),
            Some(vec![longest.as_bytes()[1..].to_vec()])
        );
        let many: Vec<String> = (0..MAX_KEEP).map(|n| format!(r#""/p{n}""#)).collect();
        assert_eq!(
            keep(&format!(r#", "keep": [{}]"#, many.join(",")))
                .unwrap()
                .unwrap()
                .len(),
            MAX_KEEP
        );
        let too_many: Vec<String> = (0..=MAX_KEEP).map(|n| format!(r#""/p{n}""#)).collect();
        assert_eq!(
            keep(&format!(r#", "keep": [{}]"#, too_many.join(","))).unwrap_err(),
            "config field `keep` holds more than 64 paths"
        );
        assert_eq!(
            keep(&format!(r#", "keep": ["/{}"]"#, "a".repeat(MAX_KEEP_BYTES))).unwrap_err(),
            "config field `keep` entry 0 is longer than 4095 bytes"
        );
        for (value, problem) in [
            (r#""/""#, "is the root"),
            (r#""data""#, "is not an absolute path"),
            (r#""""#, "is not an absolute path"),
            (r#""/data/""#, "is not a normalised path"),
            (r#""//data""#, "is not a normalised path"),
            (r#""/data//db""#, "is not a normalised path"),
            (r#""/data/./db""#, "is not a normalised path"),
            (r#""/data/..""#, "is not a normalised path"),
            (r#""/.""#, "is not a normalised path"),
            (r#""/a\u0000b""#, "holds a NUL byte"),
            ("1", "is not a string"),
            ("null", "is not a string"),
        ] {
            assert_eq!(
                keep(&format!(r#", "keep": ["/ok", {value}]"#)).unwrap_err(),
                format!("config field `keep` entry 1 {problem}"),
                "{value}"
            );
        }
        assert_eq!(
            keep(r#", "keep": ["/data", "/data"]"#).unwrap_err(),
            "config field `keep` entry 1 is given twice"
        );
        assert_eq!(
            keep(r#", "keep": "/data""#).unwrap_err(),
            "config field `keep` is not a list"
        );
        // Not a field before version 4, nor of the run mode.
        for version in [2, 3] {
            let text = format!(
                r#"{{"version": {version}, "mode": "unpack", "keep": [], "layers": [{}]}}"#,
                layer_json(TAR, DIGEST, "1")
            );
            assert_eq!(
                parse_boot(&text, u32::try_from(version).unwrap()).unwrap_err(),
                "the config has an unknown field `keep`"
            );
        }
        assert_eq!(
            parse_boot(r#"{"version": 4, "argv": ["a"], "keep": []}"#, 4).unwrap_err(),
            "the config has an unknown field `keep`"
        );
        // Version 4 is version 3 elsewhere.
        let Boot::Run(config) = parse_boot(
            r#"{"version": 4, "argv": ["/sbin/init"], "init_system": true}"#,
            4,
        )
        .unwrap() else {
            panic!("not the run mode")
        };
        assert!(config.init_system);
        assert_eq!(
            parse_boot(r#"{"version": 4, "argv": ["a"]}"#, 3).unwrap_err(),
            "the config's version is not one this init supports"
        );
        assert_eq!(
            parse_boot(r#"{"version": 3, "argv": ["a"]}"#, 4).unwrap_err(),
            "the config's version is not the boot's interface version (gh.v)"
        );
    }

    /// A version-5 run config with `volumes` set to the JSON `volumes`.
    fn volumes(volumes: &str) -> Result<Vec<Vec<u8>>, String> {
        let text = format!(r#"{{"version": 5, "argv": ["a"]{volumes}}}"#);
        match parse_boot(&text, 5)? {
            Boot::Run(config) => Ok(config.volumes),
            Boot::Unpack(_) => panic!("not the run mode"),
        }
    }

    #[test]
    fn version_five_volumes() {
        assert_eq!(volumes("").unwrap(), Vec::<Vec<u8>>::new());
        assert_eq!(
            volumes(r#", "volumes": []"#).unwrap(),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            volumes(r#", "volumes": ["/app/data", "/var/lib/mysql", "/a b/ü"]"#).unwrap(),
            vec![
                b"app/data".to_vec(),
                b"var/lib/mysql".to_vec(),
                "a b/ü".as_bytes().to_vec()
            ]
        );
        let longest = format!("/{}", "a".repeat(MAX_KEEP_BYTES - 1));
        assert_eq!(
            volumes(&format!(r#", "volumes": ["{longest}"]"#)).unwrap(),
            vec![longest.as_bytes()[1..].to_vec()]
        );
        let many: Vec<String> = (0..MAX_VOLUMES).map(|n| format!(r#""/p{n}""#)).collect();
        assert_eq!(
            volumes(&format!(r#", "volumes": [{}]"#, many.join(",")))
                .unwrap()
                .len(),
            MAX_VOLUMES
        );
        let too_many: Vec<String> = (0..=MAX_VOLUMES).map(|n| format!(r#""/p{n}""#)).collect();
        assert_eq!(
            volumes(&format!(r#", "volumes": [{}]"#, too_many.join(","))).unwrap_err(),
            "config field `volumes` holds more than 64 paths"
        );
        assert_eq!(
            volumes(&format!(
                r#", "volumes": ["/{}"]"#,
                "a".repeat(MAX_KEEP_BYTES)
            ))
            .unwrap_err(),
            "config field `volumes` entry 0 is longer than 4095 bytes"
        );
        for (value, problem) in [
            (r#""/""#, "is the root"),
            (r#""data""#, "is not an absolute path"),
            (r#""/data/""#, "is not a normalised path"),
            (r#""/data/../etc""#, "is not a normalised path"),
            (r#""/./data""#, "is not a normalised path"),
            (r#""/a\u0000b""#, "holds a NUL byte"),
            ("1", "is not a string"),
        ] {
            assert_eq!(
                volumes(&format!(r#", "volumes": ["/ok", {value}]"#)).unwrap_err(),
                format!("config field `volumes` entry 1 {problem}"),
                "{value}"
            );
        }
        assert_eq!(
            volumes(r#", "volumes": ["/data", "/data"]"#).unwrap_err(),
            "config field `volumes` entry 1 is given twice"
        );
        assert_eq!(
            volumes(r#", "volumes": "/data""#).unwrap_err(),
            "config field `volumes` is not a list"
        );
        // With the other fields of version 4, init_system among them.
        let Boot::Run(config) = parse_boot(
            r#"{"version": 5, "mode": "run", "argv": ["/sbin/init"], "init_system": true, "volumes": ["/srv"]}"#,
            5,
        )
        .unwrap() else {
            panic!("not the run mode")
        };
        assert!(config.init_system);
        assert_eq!(config.volumes, [b"srv".to_vec()]);
        // A bad other field is named as before.
        assert_eq!(
            parse_boot(r#"{"version": 5, "argv": 5, "volumes": []}"#, 5).unwrap_err(),
            "config field `argv` is not a list of strings"
        );
    }

    #[test]
    fn volumes_unknown_before_version_five() {
        for version in 1..=4u32 {
            let text = format!(r#"{{"version": {version}, "argv": ["a"], "volumes": ["/data"]}}"#);
            assert_eq!(
                parse_boot(&text, version).unwrap_err(),
                "the config has an unknown field `volumes`",
                "{version}"
            );
        }
        // Not a field of the unpack mode, nor keep of the run mode.
        let text = format!(
            r#"{{"version": 5, "mode": "unpack", "volumes": [], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 5).unwrap_err(),
            "config field `volumes` is not taken in the unpack mode"
        );
        let text = format!(
            r#"{{"version": 4, "mode": "unpack", "volumes": [], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 4).unwrap_err(),
            "the config has an unknown field `volumes`"
        );
        assert_eq!(
            parse_boot(r#"{"version": 5, "argv": ["a"], "keep": []}"#, 5).unwrap_err(),
            "the config has an unknown field `keep`"
        );
        // Version 5's unpack mode is version 4's, keep included.
        let text = format!(
            r#"{{"version": 5, "mode": "unpack", "keep": ["/data"], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        let Boot::Unpack(unpack) = parse_boot(&text, 5).unwrap() else {
            panic!("not the unpack mode")
        };
        assert_eq!(unpack.keep, Some(vec![b"data".to_vec()]));
        assert_eq!(
            parse_boot(r#"{"version": 5, "argv": ["a"]}"#, 4).unwrap_err(),
            "the config's version is not one this init supports"
        );
        assert_eq!(
            parse_boot(r#"{"version": 4, "argv": ["a"]}"#, 5).unwrap_err(),
            "the config's version is not the boot's interface version (gh.v)"
        );
    }

    /// A version-6 run config with `disks` set to the JSON `disks`.
    fn disks(disks: &str) -> Result<Vec<Disk>, String> {
        let text = format!(r#"{{"version": 6, "argv": ["a"], "disks": {disks}}}"#);
        match parse_boot(&text, 6)? {
            Boot::Run(config) => Ok(config.disks),
            Boot::Unpack(_) => panic!("not the run mode"),
        }
    }

    #[test]
    fn version_six_disks() {
        let Boot::Run(config) = parse_boot(r#"{"version": 6, "argv": ["a"]}"#, 6).unwrap() else {
            panic!("not the run mode")
        };
        assert!(config.disks.is_empty());
        assert!(disks("[]").unwrap().is_empty());
        let parsed = disks(
            r#"[{"serial": "state-0", "path": "/var/lib/state",
                 "binds": [{"source": "etc/wireguard", "path": "/etc/wireguard"},
                           {"source": "db", "path": "/srv/db"}]},
                {"serial": "A.b_9-z", "path": "/data"}]"#,
        )
        .unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].serial, "state-0");
        assert_eq!(parsed[0].path, b"var/lib/state");
        assert_eq!(parsed[0].binds.len(), 2);
        assert_eq!(parsed[0].binds[0].source, b"etc/wireguard");
        assert_eq!(parsed[0].binds[0].path, b"etc/wireguard");
        assert_eq!(parsed[0].binds[1].source, b"db");
        assert_eq!(parsed[1].serial, "A.b_9-z");
        assert!(parsed[1].binds.is_empty());
        // With the other fields of version 5.
        let Boot::Run(config) = parse_boot(
            r#"{"version": 6, "mode": "run", "argv": ["/sbin/init"], "init_system": true,
                "volumes": ["/srv"], "disks": [{"serial": "s", "path": "/state", "binds": []}]}"#,
            6,
        )
        .unwrap() else {
            panic!("not the run mode")
        };
        assert!(config.init_system);
        assert_eq!(config.volumes, [b"srv".to_vec()]);
        assert_eq!(config.disks.len(), 1);
    }

    #[test]
    fn disks_bounds() {
        let disk = |n: usize| format!(r#"{{"serial": "s{n}", "path": "/d{n}"}}"#);
        let eight: Vec<String> = (0..MAX_DISKS).map(disk).collect();
        assert_eq!(disks(&format!("[{}]", eight.join(","))).unwrap().len(), 8);
        let nine: Vec<String> = (0..=MAX_DISKS).map(disk).collect();
        assert_eq!(
            disks(&format!("[{}]", nine.join(","))).unwrap_err(),
            "config field `disks` holds more than 8 disks"
        );
        let bind = |n: usize| format!(r#"{{"source": "b{n}", "path": "/p{n}"}}"#);
        let sixteen: Vec<String> = (0..MAX_BINDS).map(bind).collect();
        let text = format!(
            r#"[{{"serial": "s", "path": "/d", "binds": [{}]}}]"#,
            sixteen.join(",")
        );
        assert_eq!(disks(&text).unwrap()[0].binds.len(), 16);
        let seventeen: Vec<String> = (0..=MAX_BINDS).map(bind).collect();
        let text = format!(
            r#"[{{"serial": "s", "path": "/d", "binds": [{}]}}]"#,
            seventeen.join(",")
        );
        assert_eq!(
            disks(&text).unwrap_err(),
            "config field `disks` entry 0 `binds` holds more than 16 binds"
        );
        let longest = format!("/{}", "a".repeat(MAX_KEEP_BYTES - 1));
        assert!(disks(&format!(r#"[{{"serial": "s", "path": "{longest}"}}]"#)).is_ok());
        assert_eq!(
            disks(&format!(
                r#"[{{"serial": "s", "path": "/{}"}}]"#,
                "a".repeat(MAX_KEEP_BYTES)
            ))
            .unwrap_err(),
            "config field `disks` entry 0 `path` is longer than 4095 bytes"
        );
        let source = "a".repeat(MAX_KEEP_BYTES);
        assert!(
            disks(&format!(
                r#"[{{"serial": "s", "path": "/d", "binds": [{{"source": "{source}", "path": "/p"}}]}}]"#
            ))
            .is_ok()
        );
        assert_eq!(
            disks(&format!(
                r#"[{{"serial": "s", "path": "/d", "binds": [{{"source": "{source}a", "path": "/p"}}]}}]"#
            ))
            .unwrap_err(),
            "config field `disks` entry 0 bind 0 `source` is longer than 4095 bytes"
        );
        assert_eq!(
            disks(r#"{"serial": "s"}"#).unwrap_err(),
            "config field `disks` is not a list"
        );
    }

    #[test]
    fn disks_fields_checked() {
        let one = |fields: &str| disks(&format!("[{{{fields}}}]"));
        for (fields, error) in [
            (r#""serial": "s""#, "entry 0 lacks `path`"),
            (r#""path": "/d""#, "entry 0 lacks `serial`"),
            (
                r#""serial": "s", "path": "/d", "size": 1"#,
                "entry 0 has an unknown field `size`",
            ),
            (
                r#""serial": "s", "path": "/d", "binds": {}"#,
                "entry 0 `binds` is not a list",
            ),
            (
                r#""serial": "s", "path": "/d", "binds": [{"source": "a"}]"#,
                "entry 0 bind 0 lacks `path`",
            ),
            (
                r#""serial": "s", "path": "/d", "binds": [{"path": "/a"}]"#,
                "entry 0 bind 0 lacks `source`",
            ),
            (
                r#""serial": "s", "path": "/d", "binds": [{"source": "a", "path": "/a", "ro": true}]"#,
                "entry 0 bind 0 has an unknown field `ro`",
            ),
            (
                r#""serial": "s", "path": "/d", "binds": [5]"#,
                "entry 0 bind 0 is not an object",
            ),
        ] {
            assert_eq!(
                one(fields).unwrap_err(),
                format!("config field `disks` {error}"),
                "{fields}"
            );
        }
        assert_eq!(
            disks("[5]").unwrap_err(),
            "config field `disks` entry 0 is not an object"
        );
    }

    #[test]
    fn disks_serials_checked() {
        let error = "config field `disks` entry 0 `serial` is not 1 to 20 letters, digits, `.`, `_` and `-`";
        for serial in [
            r#""""#,
            r#""a b""#,
            r#""a/b""#,
            r#""ü""#,
            r#""a\u0000""#,
            r#""123456789012345678901""#,
            "5",
            "null",
        ] {
            assert_eq!(
                disks(&format!(r#"[{{"serial": {serial}, "path": "/d"}}]"#)).unwrap_err(),
                error,
                "{serial}"
            );
        }
        assert!(disks(r#"[{"serial": "12345678901234567890", "path": "/d"}]"#).is_ok());
        assert_eq!(
            disks(r#"[{"serial": "s", "path": "/a"}, {"serial": "s", "path": "/b"}]"#).unwrap_err(),
            "config field `disks` entry 1 `serial` is given twice"
        );
    }

    #[test]
    fn disks_paths_checked() {
        for (value, problem) in [
            (r#""/""#, "is the root"),
            (r#""data""#, "is not an absolute path"),
            (r#""/data/""#, "is not a normalised path"),
            (r#""/data/../etc""#, "is not a normalised path"),
            (r#""/a\u0000b""#, "holds a NUL byte"),
            ("1", "is not a string"),
            (r#""/proc""#, "is in /proc, /sys, /dev or /run"),
            (r#""/sys/fs/x""#, "is in /proc, /sys, /dev or /run"),
            (r#""/dev/shm/x""#, "is in /proc, /sys, /dev or /run"),
            (r#""/run""#, "is in /proc, /sys, /dev or /run"),
            (r#""/run/state""#, "is in /proc, /sys, /dev or /run"),
        ] {
            assert_eq!(
                disks(&format!(r#"[{{"serial": "s", "path": {value}}}]"#)).unwrap_err(),
                format!("config field `disks` entry 0 `path` {problem}"),
                "{value}"
            );
            assert_eq!(
                disks(&format!(
                    r#"[{{"serial": "s", "path": "/d", "binds": [{{"source": "a", "path": {value}}}]}}]"#
                ))
                .unwrap_err(),
                format!("config field `disks` entry 0 bind 0 `path` {problem}"),
                "{value}"
            );
        }
        // Names that only start like the reserved ones are the image's.
        assert!(disks(r#"[{"serial": "s", "path": "/runner/process/devices"}]"#).is_ok());
        for (value, problem) in [
            (r#""/abs""#, "is not a relative path"),
            (r#""""#, "is not a normalised path"),
            (r#""a/../b""#, "is not a normalised path"),
            (r#""..""#, "is not a normalised path"),
            (r#""a/""#, "is not a normalised path"),
            (r#""./a""#, "is not a normalised path"),
            (r#""a\u0000""#, "holds a NUL byte"),
            ("[]", "is not a string"),
        ] {
            assert_eq!(
                disks(&format!(
                    r#"[{{"serial": "s", "path": "/d", "binds": [{{"source": {value}, "path": "/p"}}]}}]"#
                ))
                .unwrap_err(),
                format!("config field `disks` entry 0 bind 0 `source` {problem}"),
                "{value}"
            );
        }
        // No path at, inside or above another disk's or bind's.
        let overlap = "is at, inside or above another disk's or bind's path";
        for (second_disk, error) in [
            (r#""/state""#, format!("entry 1 `path` {overlap}")),
            (r#""/state/inner""#, format!("entry 1 `path` {overlap}")),
            (r#""/etc""#, format!("entry 1 `path` {overlap}")),
            (r#""/etc/app/x""#, format!("entry 1 `path` {overlap}")),
        ] {
            let text = format!(
                r#"[{{"serial": "a", "path": "/state", "binds": [{{"source": "x", "path": "/etc/app"}}]}},
                    {{"serial": "b", "path": {second_disk}}}]"#
            );
            assert_eq!(
                disks(&text).unwrap_err(),
                format!("config field `disks` {error}"),
                "{second_disk}"
            );
        }
        for bind_path in [r#""/state""#, r#""/state/x""#, r#""/""#] {
            let text = format!(
                r#"[{{"serial": "a", "path": "/state", "binds": [{{"source": "x", "path": {bind_path}}}]}}]"#
            );
            assert!(disks(&text).is_err(), "{bind_path}");
        }
        assert_eq!(
            disks(
                r#"[{"serial": "a", "path": "/state", "binds": [{"source": "x", "path": "/etc/a"}, {"source": "y", "path": "/etc/a"}]}]"#
            )
            .unwrap_err(),
            format!("config field `disks` entry 0 bind 1 `path` {overlap}")
        );
        // Siblings and names sharing a prefix are apart.
        assert!(
            disks(
                r#"[{"serial": "a", "path": "/state", "binds": [{"source": "x", "path": "/statefile"}, {"source": "x", "path": "/etc/a"}, {"source": "y", "path": "/etc/ab"}]}]"#
            )
            .is_ok()
        );
    }

    #[test]
    fn disks_unknown_before_version_six() {
        for version in 1..=5u32 {
            let text = format!(
                r#"{{"version": {version}, "argv": ["a"], "disks": [{{"serial": "s", "path": "/d"}}]}}"#
            );
            assert_eq!(
                parse_boot(&text, version).unwrap_err(),
                "the config has an unknown field `disks`",
                "{version}"
            );
        }
        let text = format!(
            r#"{{"version": 6, "mode": "unpack", "disks": [], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 6).unwrap_err(),
            "config field `disks` is not taken in the unpack mode"
        );
        let text = format!(
            r#"{{"version": 5, "mode": "unpack", "disks": [], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert_eq!(
            parse_boot(&text, 5).unwrap_err(),
            "the config has an unknown field `disks`"
        );
        // Version 6's unpack mode is version 5's, keep included.
        let text = format!(
            r#"{{"version": 6, "mode": "unpack", "keep": ["/data"], "layers": [{}]}}"#,
            layer_json(TAR, DIGEST, "1")
        );
        assert!(matches!(parse_boot(&text, 6), Ok(Boot::Unpack(_))));
        assert_eq!(
            parse_boot(r#"{"version": 6, "argv": ["a"]}"#, 5).unwrap_err(),
            "the config's version is not one this init supports"
        );
        assert_eq!(
            parse_boot(r#"{"version": 5, "argv": ["a"]}"#, 6).unwrap_err(),
            "the config's version is not the boot's interface version (gh.v)"
        );
    }

    #[test]
    fn disks_never_shown() {
        let config = disks(&format!(
            r#"[{{"serial": "s", "path": "/{SECRET}", "binds": [{{"source": "{SECRET}", "path": "/x{SECRET}"}}]}}]"#
        ))
        .unwrap();
        let shown = format!("{config:?}");
        assert!(!shown.contains(SECRET), "{shown}");
        let Boot::Run(full) = parse_boot(
            &format!(r#"{{"version": 6, "argv": ["a"], "disks": [{{"serial": "{}", "path": "/{SECRET}"}}]}}"#, &SECRET[..6]),
            6,
        )
        .unwrap() else {
            panic!("not the run mode")
        };
        let shown = format!("{full:?}");
        assert!(
            !shown.contains(SECRET) && !shown.contains(&SECRET[..6]),
            "{shown}"
        );
        for text in [
            format!(r#"[{{"serial": "{SECRET}!", "path": "/d"}}]"#),
            format!(r#"[{{"serial": "s", "path": "{SECRET}"}}]"#),
            format!(
                r#"[{{"serial": "s", "path": "/d", "binds": [{{"source": "/{SECRET}", "path": "/p"}}]}}]"#
            ),
        ] {
            let error = disks(&text).unwrap_err();
            assert!(!error.contains(SECRET), "{text}: {error}");
        }
    }

    #[test]
    fn version_three_boot() {
        for (config, boot, error) in [
            (
                2,
                3,
                "the config's version is not the boot's interface version (gh.v)",
            ),
            (
                1,
                3,
                "the config's version is not the boot's interface version (gh.v)",
            ),
            (4, 3, "the config's version is not one this init supports"),
            (3, 2, "the config's version is not one this init supports"),
            (3, 1, "the config's version is not one this init supports"),
        ] {
            let text = format!(r#"{{"version": {config}, "argv": ["a"]}}"#);
            assert_eq!(
                parse_boot(&text, boot).unwrap_err(),
                error,
                "{config} on {boot}"
            );
        }
    }

    #[test]
    fn unpack_mode() {
        let layers = unpack(&unpack_json(&[
            layer_json(TAR, DIGEST, "1"),
            layer_json(
                "application/vnd.oci.image.layer.v1.tar+gzip",
                DIGEST,
                "1024",
            ),
            layer_json(
                "application/vnd.oci.image.layer.v1.tar+zstd",
                DIGEST,
                "1099511627776",
            ),
            layer_json(
                "application/vnd.docker.image.rootfs.diff.tar.gzip",
                DIGEST,
                "1",
            ),
        ]))
        .unwrap();
        let compressions: Vec<_> = layers.iter().map(|layer| layer.compression).collect();
        assert_eq!(
            compressions,
            [
                Compression::None,
                Compression::Gzip,
                Compression::Zstd,
                Compression::Gzip
            ]
        );
        assert_eq!(layers[1].size, 1024);
        assert_eq!(layers[0].digest[0], 0x01);
        assert_eq!(layers[0].digest[31], 0xef);
    }

    #[test]
    fn unpack_refuses_run_fields() {
        for field in [
            r#""argv": ["a"]"#,
            r#""env": []"#,
            r#""user": "root""#,
            r#""workdir": "/""#,
            r#""stop_timeout_seconds": 1"#,
            r#""stop_signal": 15"#,
            r#""authorized_keys": {"user": "root", "keys": []}"#,
        ] {
            let text = format!(
                r#"{{"version": 2, "mode": "unpack", {field}, "layers": [{}]}}"#,
                layer_json(TAR, DIGEST, "1")
            );
            let error = unpack(&text).unwrap_err();
            assert!(
                error.ends_with("is not taken in the unpack mode"),
                "{field}: {error}"
            );
        }
        assert_eq!(
            unpack(r#"{"version": 2, "mode": "unpack", "layers": [], "x": 1}"#).unwrap_err(),
            "the config has an unknown field `x`"
        );
        assert_eq!(
            unpack(r#"{"version": 2, "mode": "unpack"}"#).unwrap_err(),
            "config field `layers` is missing"
        );
    }

    #[test]
    fn layer_count_bounds() {
        let one = layer_json(TAR, DIGEST, "1");
        assert_eq!(
            unpack(&unpack_json(&[])).unwrap_err(),
            "config field `layers` does not hold 1 to 128 layers"
        );
        assert_eq!(
            unpack(&unpack_json(&vec![one.clone(); 128])).unwrap().len(),
            128
        );
        assert_eq!(
            unpack(&unpack_json(&vec![one; 129])).unwrap_err(),
            "config field `layers` does not hold 1 to 128 layers"
        );
        assert_eq!(
            unpack(r#"{"version": 2, "mode": "unpack", "layers": {}}"#).unwrap_err(),
            "config field `layers` is not a list"
        );
    }

    #[test]
    fn layer_fields_checked() {
        for digest in [
            "sha256:0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcde",
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0",
            "sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "sha256:g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "",
        ] {
            assert_eq!(
                unpack(&unpack_json(&[layer_json(TAR, digest, "1")])).unwrap_err(),
                "config field `layers` entry 0 has a digest that is not sha256: and 64 lowercase hex digits",
                "{digest}"
            );
        }
        for media_type in [
            "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip",
            "application/vnd.docker.image.rootfs.foreign.diff.tar.gzip",
            "application/vnd.oci.image.layer.v1.tar+bzip2",
            "application/vnd.oci.image.layer.v1.tar ",
            "",
        ] {
            let text = unpack_json(&[
                layer_json(TAR, DIGEST, "1"),
                layer_json(media_type, DIGEST, "1"),
            ]);
            assert_eq!(
                unpack(&text).unwrap_err(),
                "config field `layers` entry 1 has a media type this init does not unpack",
                "{media_type}"
            );
        }
        assert_eq!(
            unpack(&unpack_json(&[layer_json(TAR, DIGEST, "0")])).unwrap_err(),
            "config field `layers` entry 0 has a size of 0"
        );
        for size in ["-1", "1.5", r#""1""#, "null", "18446744073709551616"] {
            let error = unpack(&unpack_json(&[layer_json(TAR, DIGEST, size)])).unwrap_err();
            assert!(
                error.starts_with("config field `layers` entry 0 is not"),
                "{size}: {error}"
            );
        }
        let text = unpack_json(&[
            layer_json(TAR, DIGEST, "18446744073709551615"),
            layer_json(TAR, DIGEST, "1"),
        ]);
        assert_eq!(
            unpack(&text).unwrap_err(),
            "config field `layers` entry 1 ends beyond any disk"
        );
        let text = unpack_json(&[format!(
            r#"{{"media_type": "{TAR}", "digest": "{DIGEST}"}}"#
        )]);
        assert_eq!(
            unpack(&text).unwrap_err(),
            "config field `layers` entry 0 lacks `size`"
        );
        let text = unpack_json(&[format!(
            r#"{{"media_type": "{TAR}", "digest": "{DIGEST}", "size": 1, "urls": []}}"#
        )]);
        assert_eq!(
            unpack(&text).unwrap_err(),
            "config field `layers` entry 0 has an unknown field `urls`"
        );
        assert_eq!(
            unpack(&unpack_json(&["5".into()])).unwrap_err(),
            "config field `layers` entry 0 is not an object"
        );
    }

    #[test]
    fn defaults() {
        let config = parse_text(r#"{"version": 1, "argv": ["nginx"]}"#).unwrap();
        assert_eq!(config.argv, ["nginx"]);
        assert!(config.env.is_empty());
        assert_eq!(config.user, None);
        assert_eq!(config.workdir, "/");
        assert_eq!(config.stop_timeout_seconds, 10);
        assert_eq!(config.stop_signal, 15);
        assert!(config.authorized_keys.is_none());
    }

    #[test]
    fn every_field() {
        let config = parse_text(
            r#"{ "version": 1,
                 "argv": ["nginx", "-g", "daemon off;"],
                 "env": ["KEY=value", "EMPTY="],
                 "user": "101:101",
                 "workdir": "/srv",
                 "stop_timeout_seconds": 300,
                 "stop_signal": 3,
                 "authorized_keys": { "user": "root", "keys": ["ssh-ed25519 AAAA x"] } }"#,
        )
        .unwrap();
        assert_eq!(config.argv.len(), 3);
        assert_eq!(config.env, ["KEY=value", "EMPTY="]);
        assert_eq!(config.user.as_deref(), Some("101:101"));
        assert_eq!(config.workdir, "/srv");
        assert_eq!(config.stop_timeout_seconds, 300);
        assert_eq!(config.stop_signal, 3);
        let keys = config.authorized_keys.unwrap();
        assert_eq!(keys.user, "root");
        assert_eq!(keys.keys, ["ssh-ed25519 AAAA x"]);
    }

    #[test]
    fn unknown_field_refused() {
        let error = parse_text(r#"{"version": 1, "argv": ["a"], "extra": true}"#).unwrap_err();
        assert_eq!(error, "the config has an unknown field `extra`");
        let error = parse_text(
            r#"{"version": 1, "argv": ["a"], "authorized_keys": {"user": "r", "keys": [], "x": 1}}"#,
        )
        .unwrap_err();
        assert!(error.contains("unknown field `x`"), "{error}");
    }

    #[test]
    fn other_versions_refused() {
        for text in [
            r#"{"version": 2, "argv": ["a"]}"#,
            r#"{"version": 0, "argv": ["a"]}"#,
            r#"{"version": "1", "argv": ["a"]}"#,
            r#"{"version": 2, "argv": ["a"], "new_field": 1}"#,
        ] {
            let error = parse_text(text).unwrap_err();
            assert!(error.contains("version"), "{text}: {error}");
        }
        assert_eq!(
            parse_text(r#"{"argv": ["a"]}"#).unwrap_err(),
            "config field `version` is missing"
        );
    }

    #[test]
    fn size_cap() {
        let head = r#"{"version": 1, "argv": ["a"], "env": [""#;
        let tail = r#""]}"#;
        let fill = |total: usize| {
            let mut text = String::from(head);
            text.push_str("K=");
            text.push_str(&"x".repeat(total - head.len() - tail.len() - 2));
            text.push_str(tail);
            assert_eq!(text.len(), total);
            text
        };
        assert!(parse_text(&fill(MAX_BYTES)).is_ok());
        assert_eq!(
            parse_text(&fill(MAX_BYTES + 1)).unwrap_err(),
            "the config is larger than 1 MiB"
        );
    }

    #[test]
    fn argv_checked() {
        assert_eq!(
            parse_text(r#"{"version": 1, "argv": []}"#).unwrap_err(),
            "config field `argv` is empty"
        );
        assert_eq!(
            parse_text(r#"{"version": 1}"#).unwrap_err(),
            "config field `argv` is missing"
        );
        assert!(parse_text(r#"{"version": 1, "argv": ["a\u0000b"]}"#).is_err());
    }

    #[test]
    fn stop_timeout_cap() {
        assert!(
            parse_text(r#"{"version": 1, "argv": ["a"], "stop_timeout_seconds": 300}"#).is_ok()
        );
        assert!(
            parse_text(r#"{"version": 1, "argv": ["a"], "stop_timeout_seconds": 301}"#).is_err()
        );
        assert!(
            parse_text(r#"{"version": 1, "argv": ["a"], "stop_timeout_seconds": -1}"#).is_err()
        );
    }

    #[test]
    fn stop_signal_range() {
        let signal = |value: &str| {
            parse_text(&format!(
                r#"{{"version": 1, "argv": ["a"], "stop_signal": {value}}}"#
            ))
            .map(|config| config.stop_signal)
        };
        assert_eq!(signal("1"), Ok(1));
        assert_eq!(signal("3"), Ok(3));
        assert_eq!(signal("64"), Ok(64));
        for value in ["0", "65", "-1"] {
            assert_eq!(
                signal(value).unwrap_err(),
                "config field `stop_signal` is not a signal number from 1 to 64",
                "{value}"
            );
        }
        for value in [r#""SIGQUIT""#, "3.5", "null", "99999999999", "[3]"] {
            assert_eq!(
                signal(value).unwrap_err(),
                "config field `stop_signal` is not a signal number",
                "{value}"
            );
        }
    }

    #[test]
    fn other_checks() {
        for text in [
            r#"{"version": 1, "argv": ["a"], "env": ["NOEQUALS"]}"#,
            r#"{"version": 1, "argv": ["a"], "env": ["=v"]}"#,
            r#"{"version": 1, "argv": ["a"], "workdir": "relative"}"#,
            r#"{"version": 1, "argv": ["a"], "authorized_keys": {"user": "", "keys": []}}"#,
            r#"{"version": 1, "argv": ["a"], "authorized_keys": {"user": "r", "keys": ["a\nb"]}}"#,
            r#"{"version": 1, "argv": ["a"], "authorized_keys": {"user": "r"}}"#,
            r"[1]",
            r"not json",
        ] {
            assert!(parse_text(text).is_err(), "{text}");
        }
    }

    #[test]
    fn errors_never_quote_values() {
        for text in [
            format!(r#"{{"version": 1, "argv": ["a"], "env": ["A={SECRET}", 5]}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "env": ["{SECRET}"]}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "env": "{SECRET}"}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "user": ["{SECRET}"]}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "stop_timeout_seconds": "{SECRET}"}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "workdir": "{SECRET}"}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "stop_signal": "{SECRET}"}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "authorized_keys": "{SECRET}"}}"#),
            format!(
                r#"{{"version": 1, "argv": ["a"], "authorized_keys": {{"user": "r", "keys": ["{SECRET}\n"]}}}}"#
            ),
            format!(r#"{{"version": "{SECRET}", "argv": ["a"]}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "env": ["A={SECRET}"], "x": 1}}"#),
            format!(r#"{{"version": 1, "argv": ["a"], "env": ["A={SECRET}"#),
        ] {
            let error = parse_text(&text).unwrap_err();
            assert!(!error.contains(SECRET), "{text}: {error}");
        }
    }
}
