//! The init's own output (the serial console), its reports and the end of
//! the machine.

use crate::protocol::Report;
use crate::sys::{self, mount, vsock};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::time::{Duration, Instant};

/// The host's report port, `u32::MAX` while unknown.
static PORT: AtomicU32 = AtomicU32::new(u32::MAX);

/// Set once the renter's disk is the root, so the end remounts it
/// read-only.
static ON_DISK: AtomicBool = AtomicBool::new(false);

/// The roots of version 6's mounted state disks, held open so the end
/// remounts each read-only, as it does the root.
static STATE_DISKS: Mutex<Vec<OwnedFd>> = Mutex::new(Vec::new());

/// How long a report retries a host that does not answer.
const REPORT_RETRY: Duration = Duration::from_secs(2);

/// What begins every line the init writes on the console, reports included
/// (`gigahost-init: ` before release 6.18.57-gh8).
pub const PREFIX: &str = "ghostrack-init: ";

/// Writes `ghostrack-init: <message>` on the console. Never pass a config
/// value here: the console is the host's log.
pub fn log(message: &str) {
    sys::write_all(2, line(message).as_bytes());
}

/// The console line of `message`.
fn line(message: &str) -> String {
    format!("{PREFIX}{message}\n")
}

pub fn set_port(port: u32) {
    PORT.store(port, Ordering::SeqCst);
}

pub fn set_on_disk() {
    ON_DISK.store(true, Ordering::SeqCst);
}

/// Keeps the root of a mounted state disk, for [`power_off`].
pub fn add_state_disk(root: OwnedFd) {
    if let Ok(mut disks) = STATE_DISKS.lock() {
        disks.push(root);
    }
}

/// Sends a report: on the console, then over vsock to the host.
pub fn report(report: &Report) {
    let line = report.encode();
    log(&format!("report {line}"));
    let port = PORT.load(Ordering::SeqCst);
    if port != u32::MAX {
        send(port, &line);
    }
}

/// Connects, writes the line and closes, retrying for [`REPORT_RETRY`]
/// while the host does not answer. A machine without a vsock device
/// (`ENODEV`) is not retried: the console line is the report there.
fn send(port: u32, line: &str) {
    let deadline = Instant::now() + REPORT_RETRY;
    loop {
        match vsock::Stream::connect(vsock::HOST_CID, port).and_then(|mut stream| {
            stream.set_timeouts(Duration::from_secs(1))?;
            stream.write_all(format!("{line}\n").as_bytes())?;
            stream.shutdown_write();
            // Wait for the host to close (or the timeout), so the line is
            // delivered before the machine powers off.
            let mut rest = [0u8; 64];
            while stream.read(&mut rest).is_ok_and(|count| count > 0) {}
            Ok(())
        }) {
            Ok(()) => return,
            Err(error) => {
                let unavailable = matches!(
                    error.raw_os_error(),
                    Some(libc::ENODEV | libc::EAFNOSUPPORT)
                );
                if unavailable || Instant::now() >= deadline {
                    log(&format!(
                        "vsock report to port {port} not delivered: {error}"
                    ));
                    return;
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

/// Reports an error and powers off: the end of every failure.
pub fn fail(message: &str) -> ! {
    report(&Report::error(message));
    power_off()
}

/// Flushes the disks, remounts the state disks and the root read-only and
/// powers the machine off.
pub fn power_off() -> ! {
    sys::sync();
    if let Ok(disks) = STATE_DISKS.lock() {
        for (index, root) in disks.iter().enumerate() {
            let path = format!("/proc/self/fd/{}", root.as_raw_fd());
            if let Err(error) = mount::remount_readonly(&path) {
                log(&format!(
                    "remounting state disk {index} read-only failed: {error}"
                ));
            }
        }
    }
    if ON_DISK.load(Ordering::SeqCst)
        && let Err(error) = mount::remount_root_readonly()
    {
        log(&format!("remounting the root read-only failed: {error}"));
    }
    sys::power_off()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_line_starts_with_the_prefix() {
        assert_eq!(PREFIX, "ghostrack-init: ");
        assert_eq!(line("start 871"), "ghostrack-init: start 871\n");
        assert_eq!(
            line(&format!("report {}", r#"{"v":1}"#)),
            "ghostrack-init: report {\"v\":1}\n"
        );
    }
}
