//! Client-side pseudo-terminal for warm execution.
//!
//! Handing a warm command the caller's own descriptors is not enough to make it
//! interactive: the command lives in the mother's session, not the terminal's,
//! so reads on the inherited terminal return `EIO` and job control is
//! unavailable (`sh: can't access tty; job control turned off`).
//!
//! This module allocates a pty in the client, gives the slave to the command and
//! proxies the master to the caller's terminal — the same model as
//! `docker run -t`. The caller's terminal is put into raw mode for the duration,
//! so Ctrl+C, Ctrl+D and Ctrl+Z travel as bytes through the pty's line
//! discipline and become real signals for the command.

use anyhow::{Context, Result};
use std::os::unix::io::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;

use super::{close_fds, read_message_with_fds, Message};

/// A pty owned by the client, with the caller's terminal in raw mode.
pub struct PtySession {
    master: RawFd,
    slave: RawFd,
    saved: libc::termios,
    raw: bool,
    last_ws: libc::winsize,
}

impl PtySession {
    /// Allocate a pty sized like the caller's terminal.
    ///
    /// Returns `None` when stdin or stdout is not a terminal: a pipe needs no
    /// pty, and the existing direct descriptor path is both cheaper and correct
    /// there.
    pub fn open() -> Option<Self> {
        // Interactive means the caller is looking at a terminal and the command's
        // output goes there. A tty on stdin with stdout redirected (`run ... >
        // file`) must keep the plain fd path, or the file would receive CRLF and
        // terminal escape sequences.
        // SAFETY: isatty only inspects the descriptor.
        if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1
            || unsafe { libc::isatty(libc::STDOUT_FILENO) } != 1
        {
            return None;
        }

        // SAFETY: a zeroed winsize is a valid output buffer for TIOCGWINSZ.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: stdin is a valid fd; a failure leaves the zeros in place.
        unsafe {
            libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws);
        }

        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;
        // SAFETY: both out-parameters are valid; a null name/termios asks for
        // defaults, and `ws` carries the caller's size.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &ws,
            )
        };
        if rc != 0 {
            return None;
        }

        // SAFETY: zeroed termios is a valid output buffer for tcgetattr.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        let mut raw = false;
        // SAFETY: stdin is a terminal (checked by the caller); tcgetattr fills
        // `saved` and cfmakeraw/tcsetattr operate on a copy of it.
        unsafe {
            if libc::tcgetattr(libc::STDIN_FILENO, &mut saved) == 0 {
                let mut raw_mode = saved;
                libc::cfmakeraw(&mut raw_mode);
                if libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &raw_mode) == 0 {
                    raw = true;
                }
            }
        }

        Some(Self {
            master,
            slave,
            saved,
            raw,
            last_ws: ws,
        })
    }

    /// Descriptor to hand to the command (stdin, stdout and stderr).
    pub fn slave_fd(&self) -> RawFd {
        self.slave
    }

    /// Allocate a fresh pty after a failed attempt.
    ///
    /// The previous slave was handed to the daemon and closed here, so a retry
    /// has nothing left to send. The caller's terminal stays in raw mode.
    pub fn reopen(&mut self) -> bool {
        if self.master >= 0 {
            // SAFETY: this struct owns the descriptor.
            unsafe {
                libc::close(self.master);
            }
            self.master = -1;
        }
        if self.slave >= 0 {
            // SAFETY: this struct owns the descriptor.
            unsafe {
                libc::close(self.slave);
            }
            self.slave = -1;
        }

        let mut master: RawFd = -1;
        let mut slave: RawFd = -1;
        // SAFETY: both out-parameters are valid; `last_ws` holds the last size
        // the caller's terminal reported.
        let rc = unsafe {
            libc::openpty(
                &mut master,
                &mut slave,
                std::ptr::null_mut(),
                std::ptr::null(),
                &self.last_ws,
            )
        };
        if rc != 0 {
            return false;
        }
        self.master = master;
        self.slave = slave;
        true
    }

    /// Drop the client's copy of the slave.
    ///
    /// Without this the pty never reports EOF to the master, because one slave
    /// descriptor is always open in the client.
    pub fn close_slave(&mut self) {
        if self.slave >= 0 {
            // SAFETY: this struct owns the descriptor.
            unsafe {
                libc::close(self.slave);
            }
            self.slave = -1;
        }
    }

    /// Pump the command's output to the caller and the caller's input back,
    /// until the daemon answers with the exit status.
    ///
    /// Returns the response frame. The socket is read here (not by the caller)
    /// because output must keep flowing while the command runs: a full pty
    /// buffer would otherwise block the command while everyone waits.
    pub fn proxy(&mut self, stream: &UnixStream) -> Result<Message> {
        let sock = stream.as_raw_fd();
        let mut buf = [0u8; 8192];
        let mut master_open = true;
        let mut stdin_open = true;

        loop {
            let mut pfds = [
                libc::pollfd {
                    fd: if master_open { self.master } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: if stdin_open { libc::STDIN_FILENO } else { -1 },
                    events: libc::POLLIN,
                    revents: 0,
                },
                libc::pollfd {
                    fd: sock,
                    events: libc::POLLIN,
                    revents: 0,
                },
            ];

            // SAFETY: three initialised pollfds; the timeout bounds resize
            // polling rather than liveness.
            let ready = unsafe { libc::poll(pfds.as_mut_ptr(), 3, 100) };
            if ready < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(err).context("poll failed while proxying the terminal");
            }

            // The terminal can be resized at any moment; SIGWINCH is not
            // forwarded into the mother, so copy the size directly.
            self.sync_window();

            if ready == 0 {
                continue;
            }

            // The daemon answered: the command has exited.
            if pfds[2].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                let mut fds = Vec::new();
                let response = read_message_with_fds(stream, &mut fds)?;
                close_fds(&fds);
                self.drain(&mut buf);
                return Ok(response);
            }

            if master_open && pfds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0
            {
                // SAFETY: `buf` is writable for its whole length.
                let n = unsafe {
                    libc::read(
                        self.master,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n > 0 {
                    write_all(libc::STDOUT_FILENO, &buf[..n as usize]);
                } else {
                    // EIO means every slave is closed: the command is gone.
                    master_open = false;
                }
            }

            if stdin_open && pfds[1].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
                // SAFETY: `buf` is writable for its whole length.
                let n = unsafe {
                    libc::read(
                        libc::STDIN_FILENO,
                        buf.as_mut_ptr() as *mut libc::c_void,
                        buf.len(),
                    )
                };
                if n > 0 {
                    if master_open {
                        // SAFETY: writing `n` bytes from `buf` to the master.
                        unsafe {
                            libc::write(
                                self.master,
                                buf.as_ptr() as *const libc::c_void,
                                n as usize,
                            );
                        }
                    }
                } else {
                    stdin_open = false;
                }
            }
        }
    }

    /// Copy the caller's terminal size onto the pty when it changes.
    fn sync_window(&mut self) {
        // SAFETY: zeroed winsize is a valid output buffer.
        let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
        // SAFETY: stdin is a valid fd.
        if unsafe { libc::ioctl(libc::STDIN_FILENO, libc::TIOCGWINSZ, &mut ws) } != 0 {
            return;
        }
        if ws.ws_row == self.last_ws.ws_row && ws.ws_col == self.last_ws.ws_col {
            return;
        }
        // SAFETY: `ws` was filled by the kernel for this terminal.
        unsafe {
            libc::ioctl(self.master, libc::TIOCSWINSZ, &ws);
        }
        self.last_ws = ws;
    }

    /// Read whatever is still buffered in the pty after the command exited.
    ///
    /// The response can arrive while the pty still holds output the command
    /// wrote just before exiting, so this must run until the pty reports EIO
    /// (every slave closed), not for a fixed number of reads: a fixed count
    /// truncated anything larger than a few buffers.
    fn drain(&mut self, buf: &mut [u8]) {
        loop {
            let mut pfd = libc::pollfd {
                fd: self.master,
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one valid pollfd.
            let ready = unsafe { libc::poll(&mut pfd, 1, 200) };
            if ready <= 0 {
                return;
            }
            // SAFETY: `buf` is writable for its whole length.
            let n = unsafe {
                libc::read(
                    self.master,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            };
            if n <= 0 {
                return;
            }
            write_all(libc::STDOUT_FILENO, &buf[..n as usize]);
        }
    }
}

impl Drop for PtySession {
    fn drop(&mut self) {
        // Restore the terminal before anything else: a panic or early return
        // must not leave the caller's shell in raw mode.
        if self.raw {
            // SAFETY: `saved` was filled by tcgetattr on this fd.
            unsafe {
                libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, &self.saved);
            }
        }
        if self.slave >= 0 {
            // SAFETY: this struct owns the descriptor.
            unsafe {
                libc::close(self.slave);
            }
        }
        if self.master >= 0 {
            // SAFETY: this struct owns the descriptor.
            unsafe {
                libc::close(self.master);
            }
        }
    }
}

/// Write the whole buffer to a descriptor, retrying short writes and EINTR.
fn write_all(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        // SAFETY: `data` is readable for its whole length.
        let n = unsafe { libc::write(fd, data.as_ptr() as *const libc::c_void, data.len()) };
        if n <= 0 {
            let err = std::io::Error::last_os_error();
            if n < 0 && err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        data = &data[n as usize..];
    }
}
