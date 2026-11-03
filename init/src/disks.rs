//! Version 6's state disks (docs/interface.md, step 4a): each disk the
//! config lists is found by its virtio serial, mounted at its path, grown
//! with its disk, and directories of it are bound over paths of the root,
//! before anything of the image runs. A disk that is missing or does not
//! mount, or a bind that cannot be made, fails the boot: an image that
//! names its state must never run without it.
//!
//! No path is followed through a symbolic link: the root's paths and the
//! disk's are resolved with `openat2` and `RESOLVE_NO_SYMLINKS` (inside
//! their root), and the mounts are made on the descriptors so resolved
//! (through `/proc/self/fd`), never on a path resolved again.

use crate::config::{Bind, Disk};
use crate::console::{self, log};
use crate::grow;
use crate::seed::{self, Bounds};
use crate::sys::{fs, mount};
use crate::unpack::apply;
use crate::volumes;
use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, OwnedFd};
use std::path::Path;
use std::time::{Duration, Instant};

/// How long a state disk may take to appear, as the root disk may.
const WAIT: Duration = Duration::from_secs(5);

/// The root disk's name in `/sys/block`: no state disk may be it.
const ROOT: &str = "vda";

/// The name a bind's source is first filled under, then renamed from once
/// the copy is on the disk, so a copy cut short (a power cut) is never
/// taken for a filled source: it is removed and made again at the next
/// boot.
const FILLING: &CStr = c".gigahost-init-filling";

/// How much of the image's directory a bind's first fill copies at most:
/// as Docker copies a new volume's contents, whole; the bounds keep the
/// walk finite, never the data (the disk's size bounds that).
pub const FILL_BOUNDS: Bounds = Bounds {
    entries: 1 << 20,
    bytes: u64::MAX,
    depth: 64,
};

/// Mounts every disk of `disks`, in order, with its binds; the error
/// names the disk (and bind) by its index in the config, never a value.
pub fn mount_all(disks: &[Disk]) -> Result<(), String> {
    if disks.is_empty() {
        return Ok(());
    }
    let root = std::fs::File::open("/").map_err(|error| format!("opening / failed: {error}"))?;
    for (index, disk) in disks.iter().enumerate() {
        let what = |problem: &str| format!("config field `disks` entry {index}{problem}");
        mount_one(root.as_fd(), index, disk, &what)?;
    }
    log(&format!("mounted {} state disk(s)", disks.len()));
    Ok(())
}

fn mount_one(
    root: BorrowedFd<'_>,
    index: usize,
    disk: &Disk,
    what: &dyn Fn(&str) -> String,
) -> Result<(), String> {
    let name =
        wait_for_serial(Path::new("/sys/block"), &disk.serial).map_err(|error| what(&error))?;
    let device = format!("/dev/{name}");
    let target = directory(root, &disk.path).map_err(|error| what(&format!(" `path` {error}")))?;
    let flags = mount::NODEV | mount::NOSUID | mount::NOATIME;
    mount::mount(Some(&device), &fd_path(&target), Some("ext4"), flags, None)
        .map_err(|error| what(&format!(": mounting the disk (ext4) failed: {error}")))?;
    let mounted = open_mounted(root, &disk.path, &target)
        .map_err(|error| what(&format!(": opening the mounted disk failed: {error}")))?;
    // Held for the end's read-only remount from here on, whatever fails
    // after.
    if let Ok(held) = mounted.try_clone() {
        console::add_state_disk(held);
    }
    let mounted = std::fs::File::from(mounted);
    grow::state_disk(index, &device, &mounted);
    for (number, bind) in disk.binds.iter().enumerate() {
        let filled = bind_one(root, mounted.as_fd(), bind)
            .map_err(|error| what(&format!(" bind {number}{error}")))?;
        if let Some(outcome) = filled {
            let skipped = if outcome.skipped > 0 {
                format!(" ({} FIFO(s), socket(s) or device(s) not)", outcome.skipped)
            } else {
                String::new()
            };
            log(&format!(
                "state disk {index} bind {number}: copied {} entries of the image's path{skipped}",
                outcome.copied
            ));
        }
    }
    Ok(())
}

/// The descriptor's path through `/proc/self/fd`, which `mount(2)` takes
/// to the very directory the descriptor is, resolving nothing again.
fn fd_path(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", fd.as_raw_fd())
}

/// Waits up to [`WAIT`] for the block device whose virtio serial is
/// `serial` and for its node in `/dev`; its name (`vdb`).
fn wait_for_serial(sys_block: &Path, serial: &str) -> Result<String, String> {
    let deadline = Instant::now() + WAIT;
    loop {
        if let Some(name) = find_serial(sys_block, serial)?
            && Path::new("/dev").join(&name).exists()
        {
            return Ok(name);
        }
        if Instant::now() >= deadline {
            return Err(": no disk with its serial appeared within 5 s".into());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// The virtio-blk disk under `sys_block` (`/sys/block`) whose `serial`
/// is `serial`, if one is there now. The root disk, or two disks with
/// the serial, are refused.
pub fn find_serial(sys_block: &Path, serial: &str) -> Result<Option<String>, String> {
    let Ok(entries) = std::fs::read_dir(sys_block) else {
        return Ok(None);
    };
    let mut found: Option<String> = None;
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if !name.starts_with("vd") {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(entry.path().join("serial")) else {
            continue;
        };
        if text.trim_end_matches(['\n', '\0']) != serial {
            continue;
        }
        if name == ROOT {
            return Err(" `serial` is the root disk's".into());
        }
        if found.is_some() {
            return Err(" `serial` is two disks'".into());
        }
        found = Some(name);
    }
    Ok(found)
}

/// The words for a failed resolution of a path of the config.
fn problem(error: &io::Error) -> String {
    match error.raw_os_error() {
        Some(libc::ELOOP) => "is or passes through a symbolic link".into(),
        Some(libc::ENOTDIR) => "is or passes through something that is not a directory".into(),
        _ => format!("cannot be made a directory: {error}"),
    }
}

fn c_path(path: &[u8]) -> io::Result<CString> {
    CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))
}

/// The directory `path` of `root`, made (owned by root, mode 0755) when
/// missing, opened as `O_PATH` through no symbolic link.
fn directory(root: BorrowedFd<'_>, path: &[u8]) -> Result<OwnedFd, String> {
    volumes::make_no_links(root, path).map_err(|error| problem(&error))?;
    let flags = libc::O_PATH | libc::O_DIRECTORY;
    fs::open_no_links(root, &c_path(path).map_err(|error| problem(&error))?, flags)
        .map_err(|error| problem(&error))
}

/// The root of the disk just mounted at `path`, which must be another
/// file system than the directory `under` it was mounted on.
fn open_mounted(root: BorrowedFd<'_>, path: &[u8], under: &OwnedFd) -> io::Result<OwnedFd> {
    let mounted = fs::open_no_links(root, &c_path(path)?, libc::O_RDONLY | libc::O_DIRECTORY)?;
    let before = fs::stat_at(under.as_fd(), c"")?;
    let now = fs::stat_at(mounted.as_fd(), c"")?;
    if before.dev == now.dev {
        return Err(io::Error::from_raw_os_error(libc::EXDEV));
    }
    Ok(mounted)
}

/// What the root has at a bind's `path` before the bind covers it.
enum Image {
    Missing,
    /// A directory, whose contents fill a source made now.
    Directory(OwnedFd),
}

fn image_path(root: BorrowedFd<'_>, path: &[u8]) -> Result<Image, String> {
    let name = c_path(path).map_err(|error| problem(&error))?;
    // Without O_NOFOLLOW: a symbolic link at the end is ELOOP then, as
    // one on the way is, not ENOTDIR.
    let flags = libc::O_RDONLY | libc::O_DIRECTORY;
    match fs::open_no_links(root, &name, flags) {
        Ok(fd) => Ok(Image::Directory(fd)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(Image::Missing),
        Err(error) => Err(format!(" `path` {}", problem(&error))),
    }
}

/// One bind: its source made in the disk (filled from the image's `path`
/// when made now and the image has it: what the copy did), then bound
/// over `path`.
fn bind_one(
    root: BorrowedFd<'_>,
    disk: BorrowedFd<'_>,
    bind: &Bind,
) -> Result<Option<seed::Outcome>, String> {
    let image = image_path(root, &bind.path)?;
    let filled = source(disk, &bind.source, &image)?;
    let target = directory(root, &bind.path).map_err(|error| format!(" `path` {error}"))?;
    let name = c_path(&bind.source).map_err(|error| format!(" `source` {}", problem(&error)))?;
    let source = fs::open_no_links(disk, &name, libc::O_PATH | libc::O_DIRECTORY)
        .map_err(|error| format!(" `source` {}", problem(&error)))?;
    mount::bind(&fd_path(&source), &fd_path(&target))
        .map_err(|error| format!(": binding failed: {error}"))?;
    Ok(filled)
}

/// Makes the bind's `source` in `disk` when missing: filled with a copy
/// of the image's directory when there is one, else empty (owned by
/// root, mode 0755). One that exists, as a directory, is left as it is.
/// What the copy did, when there was one.
fn source(
    disk: BorrowedFd<'_>,
    source: &[u8],
    image: &Image,
) -> Result<Option<seed::Outcome>, String> {
    let wrong = |error: &io::Error| format!(" `source` {}", problem(error));
    let (parent, last) = match source.iter().rposition(|&byte| byte == b'/') {
        Some(slash) => (
            source.get(..slash).unwrap_or_default(),
            source.get(slash + 1..).unwrap_or_default(),
        ),
        None => (&[][..], source),
    };
    if !parent.is_empty() {
        volumes::make_no_links(disk, parent).map_err(|error| wrong(&error))?;
    }
    let parent_name = if parent.is_empty() {
        c".".to_owned()
    } else {
        c_path(parent).map_err(|error| wrong(&error))?
    };
    let parent = fs::open_no_links(disk, &parent_name, libc::O_RDONLY | libc::O_DIRECTORY)
        .map_err(|error| wrong(&error))?;
    let last = c_path(last).map_err(|error| wrong(&error))?;
    match fs::stat_at(parent.as_fd(), &last) {
        Ok(stat) if stat.is_dir() => return Ok(None),
        Ok(stat) => {
            let code = if stat.is_symlink() {
                libc::ELOOP
            } else {
                libc::ENOTDIR
            };
            return Err(wrong(&io::Error::from_raw_os_error(code)));
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(wrong(&error)),
    }
    match image {
        Image::Missing => {
            fs::mkdir_at(parent.as_fd(), &last, 0o755).map_err(|error| wrong(&error))?;
            fs::chmod_at(parent.as_fd(), &last, 0o755).map_err(|error| wrong(&error))?;
            Ok(None)
        }
        Image::Directory(image) => {
            fill(parent.as_fd(), &last, image.as_fd(), &mut fs::sync_fs).map(Some)
        }
    }
}

/// Fills a new `name` in `parent` with a copy of the image's directory
/// `image`: copied under [`FILLING`], written to the disk with `sync` (the
/// disk's `syncfs`: ext4 writes file data back well after the names), then
/// renamed to `name` and synced again, so a copy that did not finish or is
/// not yet on the disk is never `name`, and the rename is on the disk
/// before anything of the image runs.
fn fill(
    parent: BorrowedFd<'_>,
    name: &CStr,
    image: BorrowedFd<'_>,
    sync: &mut dyn FnMut(BorrowedFd<'_>) -> io::Result<()>,
) -> Result<seed::Outcome, String> {
    let failed = |what: &str, error: &dyn std::fmt::Display| format!(": {what} failed: {error}");
    apply::remove_below(parent, FILLING, 0)
        .map_err(|_| ": removing an unfinished copy failed".to_owned())?;
    fs::mkdir_at(parent, FILLING, 0o700).map_err(|error| failed("making the copy", &error))?;
    let target = fs::open_at(
        parent,
        FILLING,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        0,
    )
    .map_err(|error| failed("opening the copy", &error))?;
    let mut from = fs::Dir::open_at(image, c".")
        .map_err(|error| failed("reading the image's `path`", &error))?;
    let outcome = seed::copy_all(&mut from, target.as_fd(), FILL_BOUNDS);
    if let Some(stop) = outcome.stopped {
        return Err(format!(
            ": copying the image's `path` stopped after {} entries: {}",
            outcome.copied,
            stop.describe(&FILL_BOUNDS)
        ));
    }
    sync(target.as_fd()).map_err(|error| failed("writing the copy to the disk", &error))?;
    fs::rename_at(parent, FILLING, name).map_err(|error| failed("renaming the copy", &error))?;
    sync(parent).map_err(|error| failed("writing the rename to the disk", &error))?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs as stdfs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new() -> Self {
            static NEXT: AtomicU32 = AtomicU32::new(0);
            let dir = std::env::temp_dir().join(format!(
                "gigahost-init-disks-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::SeqCst)
            ));
            let _ = stdfs::remove_dir_all(&dir);
            stdfs::create_dir_all(dir.join("root")).unwrap();
            stdfs::create_dir_all(dir.join("disk")).unwrap();
            Scratch { dir }
        }

        fn root(&self) -> PathBuf {
            self.dir.join("root")
        }

        fn disk(&self) -> PathBuf {
            self.dir.join("disk")
        }

        fn open(path: &Path) -> stdfs::File {
            stdfs::File::open(path).unwrap()
        }

        /// The bind's source made as `bind_one` makes it, from the
        /// image's `path` in the root.
        fn source(&self, source: &str, path: &str) -> Result<(), String> {
            let root = Self::open(&self.root());
            let disk = Self::open(&self.disk());
            let image = image_path(root.as_fd(), path.as_bytes())?;
            super::source(disk.as_fd(), source.as_bytes(), &image).map(drop)
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = stdfs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn a_new_source_is_filled_from_the_image() {
        let scratch = Scratch::new();
        let etc = scratch.root().join("etc/app");
        stdfs::create_dir_all(etc.join("conf.d")).unwrap();
        stdfs::write(etc.join("conf.d/a.conf"), "a").unwrap();
        stdfs::write(etc.join("main.conf"), "main").unwrap();
        symlink("main.conf", etc.join("link")).unwrap();
        stdfs::set_permissions(&etc, stdfs::Permissions::from_mode(0o750)).unwrap();
        scratch.source("state/app", "etc/app").unwrap();
        let made = scratch.disk().join("state/app");
        assert_eq!(
            stdfs::read_to_string(made.join("main.conf")).unwrap(),
            "main"
        );
        assert_eq!(
            stdfs::read_to_string(made.join("conf.d/a.conf")).unwrap(),
            "a"
        );
        assert_eq!(
            stdfs::read_link(made.join("link")).unwrap(),
            Path::new("main.conf")
        );
        let meta = stdfs::symlink_metadata(&made).unwrap();
        assert_eq!(meta.mode() & 0o7777, 0o750);
        assert_eq!(meta.mtime(), stdfs::symlink_metadata(&etc).unwrap().mtime());
        // The parent made on the way is root's 0755, the copy's name gone.
        let parent = stdfs::symlink_metadata(scratch.disk().join("state")).unwrap();
        assert_eq!(parent.mode() & 0o7777, 0o755);
        assert!(
            !scratch
                .disk()
                .join("state")
                .join(".gigahost-init-filling")
                .exists()
        );
    }

    #[test]
    fn an_existing_source_is_never_filled_again() {
        let scratch = Scratch::new();
        stdfs::create_dir_all(scratch.root().join("etc/app")).unwrap();
        stdfs::write(scratch.root().join("etc/app/new-in-image"), "x").unwrap();
        stdfs::create_dir_all(scratch.disk().join("app")).unwrap();
        stdfs::write(scratch.disk().join("app/kept"), "kept").unwrap();
        scratch.source("app", "etc/app").unwrap();
        assert!(!scratch.disk().join("app/new-in-image").exists());
        assert_eq!(
            stdfs::read_to_string(scratch.disk().join("app/kept")).unwrap(),
            "kept"
        );
    }

    #[test]
    fn without_the_image_path_the_source_starts_empty() {
        let scratch = Scratch::new();
        scratch.source("a/b", "srv/data").unwrap();
        let made = scratch.disk().join("a/b");
        assert!(made.is_dir());
        assert_eq!(stdfs::read_dir(&made).unwrap().count(), 0);
        assert_eq!(
            stdfs::symlink_metadata(&made).unwrap().mode() & 0o7777,
            0o755
        );
    }

    #[test]
    fn an_unfinished_copy_is_removed_and_made_again() {
        let scratch = Scratch::new();
        stdfs::create_dir_all(scratch.root().join("etc/app")).unwrap();
        stdfs::write(scratch.root().join("etc/app/f"), "f").unwrap();
        let left = scratch.disk().join(".gigahost-init-filling");
        stdfs::create_dir_all(left.join("half/deep")).unwrap();
        stdfs::write(left.join("half/deep/old"), "old").unwrap();
        scratch.source("app", "etc/app").unwrap();
        assert!(!left.exists());
        assert_eq!(
            stdfs::read_to_string(scratch.disk().join("app/f")).unwrap(),
            "f"
        );
        assert!(!scratch.disk().join("app/half").exists());
    }

    #[test]
    fn the_copy_is_on_the_disk_before_its_rename_and_the_rename_after() {
        let scratch = Scratch::new();
        stdfs::create_dir_all(scratch.root().join("etc/app")).unwrap();
        stdfs::write(scratch.root().join("etc/app/f"), "f").unwrap();
        let disk = Scratch::open(&scratch.disk());
        let image = Scratch::open(&scratch.root().join("etc/app"));
        let copy = scratch.disk().join(".gigahost-init-filling/f");
        let made = scratch.disk().join("app");
        // At each sync: is the copy's file there, and is the source?
        let mut seen = Vec::new();
        let mut sync = |fd: BorrowedFd<'_>| {
            seen.push((copy.is_file(), made.exists()));
            fs::sync_fs(fd)
        };
        fill(disk.as_fd(), c"app", image.as_fd(), &mut sync).unwrap();
        assert_eq!(seen, [(true, false), (false, true)]);
        assert_eq!(stdfs::read_to_string(made.join("f")).unwrap(), "f");
    }

    #[test]
    fn a_copy_that_does_not_reach_the_disk_is_not_the_source() {
        let scratch = Scratch::new();
        stdfs::create_dir_all(scratch.root().join("etc/app")).unwrap();
        stdfs::write(scratch.root().join("etc/app/f"), "f").unwrap();
        let disk = Scratch::open(&scratch.disk());
        let image = Scratch::open(&scratch.root().join("etc/app"));
        let mut sync = |_: BorrowedFd<'_>| Err(io::Error::from_raw_os_error(libc::EIO));
        assert_eq!(
            fill(disk.as_fd(), c"app", image.as_fd(), &mut sync).unwrap_err(),
            ": writing the copy to the disk failed: Input/output error (os error 5)"
        );
        assert!(!scratch.disk().join("app").exists());
    }

    #[test]
    fn symbolic_links_are_refused() {
        let scratch = Scratch::new();
        // In the image's path.
        stdfs::create_dir_all(scratch.root().join("real")).unwrap();
        symlink("/real", scratch.root().join("linked")).unwrap();
        assert_eq!(
            scratch.source("a", "linked").unwrap_err(),
            " `path` is or passes through a symbolic link"
        );
        assert_eq!(
            scratch.source("a", "linked/inner").unwrap_err(),
            " `path` is or passes through a symbolic link"
        );
        // In the source, on the way or at its end.
        stdfs::create_dir_all(scratch.disk().join("elsewhere")).unwrap();
        symlink("elsewhere", scratch.disk().join("via")).unwrap();
        assert_eq!(
            scratch.source("via/x", "srv").unwrap_err(),
            " `source` is or passes through a symbolic link"
        );
        assert_eq!(
            scratch.source("via", "srv").unwrap_err(),
            " `source` is or passes through a symbolic link"
        );
        assert!(!scratch.disk().join("elsewhere/x").exists());
        // A file where a directory must be.
        stdfs::write(scratch.disk().join("file"), "").unwrap();
        assert_eq!(
            scratch.source("file", "srv").unwrap_err(),
            " `source` is or passes through something that is not a directory"
        );
        stdfs::write(scratch.root().join("plain"), "").unwrap();
        assert_eq!(
            scratch.source("b", "plain").unwrap_err(),
            " `path` is or passes through something that is not a directory"
        );
    }

    #[test]
    fn the_mount_point_is_made_through_no_link() {
        let scratch = Scratch::new();
        let root = Scratch::open(&scratch.root());
        assert!(directory(root.as_fd(), b"var/lib/state").is_ok());
        assert!(scratch.root().join("var/lib/state").is_dir());
        stdfs::create_dir_all(scratch.dir.join("outside")).unwrap();
        symlink("../outside", scratch.root().join("up")).unwrap();
        assert_eq!(
            directory(root.as_fd(), b"up/state").unwrap_err(),
            "is or passes through a symbolic link"
        );
        assert!(!scratch.dir.join("outside/state").exists());
    }

    #[test]
    fn serials() {
        let scratch = Scratch::new();
        let block = scratch.dir.join("block");
        for (name, serial) in [
            ("vda", "root-disk"),
            ("vdb", "state-1\n"),
            ("vdc", "state-2"),
            ("sda", "state-3"),
            ("vdd", "twice"),
            ("vde", "twice"),
        ] {
            stdfs::create_dir_all(block.join(name)).unwrap();
            stdfs::write(block.join(name).join("serial"), serial).unwrap();
        }
        stdfs::create_dir_all(block.join("vdf")).unwrap();
        assert_eq!(
            find_serial(&block, "state-1").unwrap().as_deref(),
            Some("vdb")
        );
        assert_eq!(
            find_serial(&block, "state-2").unwrap().as_deref(),
            Some("vdc")
        );
        assert_eq!(find_serial(&block, "state-3").unwrap(), None);
        assert_eq!(find_serial(&block, "missing").unwrap(), None);
        assert_eq!(
            find_serial(&block, "root-disk").unwrap_err(),
            " `serial` is the root disk's"
        );
        assert_eq!(
            find_serial(&block, "twice").unwrap_err(),
            " `serial` is two disks'"
        );
        assert_eq!(find_serial(&scratch.dir.join("none"), "x").unwrap(), None);
    }
}
