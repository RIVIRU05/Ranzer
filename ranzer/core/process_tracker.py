"""
RANZER - Process Behavior Tracker
Monitors running processes for ransomware-like behavior using psutil.

Detection logic:
- Watches processes writing to monitored directories at high rates
- Uses /proc/[pid]/io to track actual write syscall counts (Linux)
- Whitelists known user-interactive processes completely
- Requires BOTH high write rate AND high entropy signals before terminating
"""

import os
import time
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False

logger = logging.getLogger("ranzer.process")

# ------------------------------------------------------------------ #
# Whitelist - these processes are NEVER flagged in normal scanning    #
# ------------------------------------------------------------------ #
WHITELISTED_PROCESSES = {
    # File managers
    "nautilus", "thunar", "nemo", "dolphin", "pcmanfm", "caja",
    "ranger", "mc", "midnight-commander", "krusader",
    # Shells
    "bash", "zsh", "fish", "sh", "dash", "tcsh", "ksh",
    # Common user commands
    "cat", "echo", "cp", "mv", "touch", "tee", "dd", "rsync",
    "tar", "gzip", "bzip2", "xz", "zip", "unzip",
    # Text editors
    "nano", "vim", "vi", "nvim", "emacs", "gedit", "kate",
    "mousepad", "pluma", "xed", "leafpad", "geany", "code",
    "vscodium", "sublime_text", "atom",
    # Browsers
    "firefox", "chromium", "chrome", "brave", "opera",
    # Core system processes - NEVER terminate these
    "systemd", "init", "kthreadd", "apt", "dpkg", "pip", "pip3",
    "dbus-daemon", "dbus", "networkmanager", "wpa_supplicant",
    "sshd", "cron", "crond", "atd",
    "systemd-journald", "systemd-logind", "systemd-udevd", "udevd",
    "polkitd", "accounts-daemon", "rtkit-daemon",
    # Display servers and compositors - killing these logs the user out
    "xorg", "x", "xwayland", "weston", "mutter",
    "kwin_x11", "kwin_wayland", "sway", "i3", "bspwm", "awesome",
    # Display managers
    "gdm", "gdm3", "lightdm", "sddm", "xdm", "lxdm",
    # Desktop environment
    "xfwm4", "openbox", "gnome-shell", "plasmashell",
    "xfce4-session", "xfdesktop", "xfce4-panel",
    # Terminal emulators - killing these would destroy the session
    "xfce4-terminal", "xterm", "lxterm", "konsole", "gnome-terminal",
    "qterminal", "terminator", "tilix", "alacritty", "kitty", "rxvt",
    "urxvt", "st", "terminology",
    # Audio servers
    "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber", "jackd",
    # Privilege escalation - sudo is the launcher, not the threat
    "sudo", "su", "pkexec",
    # Package managers
    "apt-get", "apt", "dpkg", "rpm", "yum", "dnf", "pacman",
    # Sandboxing / container runtime - used by Flatpak, not ransomware
    "bwrap", "bubblewrap", "flatpak",
    # Desktop indexers - spike on rapid file creation, not ransomware
    "tracker3", "tracker-store", "baloo_file",
    # Credential / keyring daemons
    "kwalletd5", "kwalletd",
    # Session / accessibility buses
    "dconf-service", "ibus-daemon", "ibus-portal",
    # Misc desktop services that write on filesystem events
    "colord", "upowerd", "udisksd", "bluetoothd",
    "goa-daemon", "zeitgeist-fts",
    # Desktop tray applets and notification daemons - killing these breaks the UI
    "nm-applet", "nm-connection-e",
    "blueman-applet", "blueman-tray",
    "pa-applet", "volumeicon", "cbatticon",
    "dunst", "notify-osd", "xfce4-notifyd",
    "clipit", "parcellite", "gpaste-daemon",
    "redshift", "redshift-gtk",
    "caffeine", "caffeine-ng",
    "xdg-desktop-por",   # xdg-desktop-portal (Flatpak portals)
    "tumbler",           # XFCE thumbnail service
    "thunar-volman",     # XFCE volume manager
    "light-locker",      # screen locker
    "xscreensaver",
    # RANZER itself
    "ranzer",
}

# Whitelisted by prefix - covers GVFS/GSD/Evolution daemons whose names
# exceed the 15-char Linux /proc truncation limit, making exact matching unreliable.
WHITELISTED_PREFIXES = {
    # GNOME Virtual Filesystem daemons
    "gvfsd",          # gvfsd, gvfsd-metadata, gvfsd-trash, etc.
    "gvfs-",          # gvfs-udisks2-volume-monitor, gvfs-goa-*, etc.
    # GNOME settings daemons
    "gsd-",           # gsd-power, gsd-media-keys, gsd-housekeeping, etc.
    # XFCE panel plugins and helpers - killing these causes "unexpectedly left the panel"
    "xfce4-",         # xfce4-whiskermenu-plugin, xfce4-power-manager, xfce4-notifyd, etc.
    "xfce-",          # xfce-polkit, etc.
    # Other desktop environment helpers
    "evolution-",     # evolution-source-registry, evolution-calendar-*, etc.
    "zeitgeist-",     # zeitgeist-daemon, zeitgeist-datahub, etc.
    "at-spi",         # at-spi-bus-launcher, at-spi2-registryd
    "gnome-keyring",  # gnome-keyring-daemon
    "tracker-",       # tracker-miner-fs, tracker-extract, tracker-miner-rss
    "baloo_file",     # baloo_file, baloo_file_extractor
    "goa-identity",   # goa-identity-service
    "flatpak-",       # flatpak-session-helper, etc.
    "kde",            # kdeconnectd, kded5, kdeinit5, etc.
}

# Tools that are whitelisted during normal scanning to avoid false positives,
# but are NOT whitelisted during the emergency scan (triggered only when
# entropy is already CRITICAL). Real ransomware uses these for LotL attacks.
LOTL_TOOLS = {
    "openssl", "gpg", "gpg2",
    "python3", "python",   # caught in normal scan now; listed here so emergency scan also catches them
    "tar", "zip", "gzip", "bzip2", "xz",
    "dd", "rsync",
}


@dataclass
class ProcessEvent:
    pid: int
    process_name: str
    exe_path: Optional[str]
    event_reason: str
    open_file_count: int
    file_access_rate: float
    write_bytes_per_sec: float = 0.0
    flagged_files: list = field(default_factory=list)
    timestamp: float = field(default_factory=time.time)

    @property
    def severity(self) -> str:
        if "honeyfile" in self.event_reason:
            return "CRITICAL"
        elif self.event_reason == "entropy_correlated_writer":
            return "HIGH"
        elif self.write_bytes_per_sec > 500 * 1024:  # 500KB/s
            return "HIGH"
        elif self.file_access_rate > 20:
            return "MEDIUM"
        return "LOW"

    def to_dict(self) -> dict:
        return {
            "type": "process",
            "pid": self.pid,
            "process_name": self.process_name,
            "exe_path": self.exe_path,
            "event_reason": self.event_reason,
            "open_file_count": self.open_file_count,
            "file_access_rate": round(self.file_access_rate, 2),
            "write_bytes_per_sec": round(self.write_bytes_per_sec, 0),
            "severity": self.severity,
            "flagged_files": self.flagged_files[:10],
            "timestamp": self.timestamp,
        }


def _read_proc_io(pid: int) -> Optional[dict]:
    """
    Read /proc/[pid]/io to get actual kernel-level write counts.
    IMPORTANT: Use 'wchar' not 'write_bytes'.
    - write_bytes = actual disk writes (buffered, often 0 for short-lived writes)
    - wchar = bytes passed to write() syscall (immediate, accurate)
    Returns dict or None.
    """
    try:
        io_path = Path(f"/proc/{pid}/io")
        if not io_path.exists():
            return None
        data = {}
        for line in io_path.read_text().splitlines():
            if ":" in line:
                key, val = line.split(":", 1)
                data[key.strip()] = int(val.strip())
        return data
    except (OSError, PermissionError, ValueError):
        return None


def _get_proc_open_files_in_dir(pid: int, monitored_dirs: list) -> list:
    """Get list of files this PID has open that are in any monitored directory."""
    result = []
    try:
        proc = psutil.Process(pid)
        for f in proc.open_files():
            for d in monitored_dirs:
                if f.path.startswith(d):
                    result.append(f.path)
                    break
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        pass
    return result


def _proc_targets_monitored_dir(pid: int, monitored_dirs: list) -> bool:
    """
    Check /proc/[pid]/cwd and cmdline to confirm the process is targeting a
    monitored directory.  Used when open_files() misses quickly-closed files.
    """
    try:
        cwd = str(Path(f"/proc/{pid}/cwd").resolve())
        for d in monitored_dirs:
            if cwd.startswith(d):
                return True
        raw = Path(f"/proc/{pid}/cmdline").read_bytes()
        cmdline = raw.replace(b"\x00", b" ").decode(errors="replace")
        for d in monitored_dirs:
            if d in cmdline:
                return True
    except (OSError, PermissionError):
        pass
    return False


class _ProcIOSnapshot:
    """Tracks /proc/[pid]/io write_bytes over time to calculate write rate."""

    def __init__(self, pid: int):
        self.pid = pid
        self._samples: list = []  # (timestamp, write_bytes)

    def sample(self) -> bool:
        """Take a sample. Returns False if process is gone."""
        io = _read_proc_io(self.pid)
        if io is None:
            return False
        # Use wchar (write syscall bytes) not write_bytes (disk flush bytes)
        # wchar is immediate and accurate; write_bytes is buffered and often 0
        write_bytes = io.get("wchar", 0)
        self._samples.append((time.time(), write_bytes))
        # Keep only last 10 seconds
        cutoff = time.time() - 10.0
        self._samples = [(t, b) for t, b in self._samples if t > cutoff]
        return True

    def write_rate_bytes_per_sec(self, window: float = 5.0) -> float:
        """Calculate bytes written per second over the last window seconds."""
        cutoff = time.time() - window
        recent = [(t, b) for t, b in self._samples if t > cutoff]
        if len(recent) < 2:
            return 0.0
        elapsed = recent[-1][0] - recent[0][0]
        if elapsed <= 0:
            return 0.0
        delta_bytes = recent[-1][1] - recent[0][1]
        return max(0.0, delta_bytes / elapsed)

    def write_syscalls_per_sec(self, window: float = 5.0) -> float:
        """Estimate write syscall rate (approximated from byte rate)."""
        return self.write_rate_bytes_per_sec(window)


class ProcessBehaviorTracker:
    """
    Tracks process I/O behavior using /proc/[pid]/io for accurate write detection.

    Flags processes that:
    1. Write data at high rates (>500KB/s sustained)
    2. Have many files open simultaneously in monitored directories
    3. Access honey files

    Does NOT flag:
    - Whitelisted interactive processes (bash, nautilus, cat, echo, etc.)
    - Processes writing to non-monitored directories
    - Single file operations (cat, echo single file)
    """

    # Write rate threshold: 200KB/s sustained for 5s = suspicious
    WRITE_RATE_THRESHOLD_BYTES = 100 * 1024  # 100KB/s via wchar - ransomware easily exceeds this

    # Open files threshold: 10+ files open simultaneously in monitored dir
    OPEN_FILES_THRESHOLD = 10

    def __init__(
        self,
        file_access_threshold: int = 10,
        rate_threshold: float = 10.0,
        honey_file_paths: Optional[list] = None,
        alert_callback=None,
        ignored_pids: Optional[set] = None,
        monitored_dirs: Optional[list] = None,
        testing_mode: bool = False,
    ):
        if not PSUTIL_AVAILABLE:
            logger.error("psutil not installed. Run: pip install psutil")

        self.file_access_threshold = file_access_threshold
        self.rate_threshold = rate_threshold
        self.honey_file_paths: set = set(honey_file_paths or [])
        self.alert_callback = alert_callback
        self.ignored_pids: set = ignored_pids or {0, 1, 2}
        self.monitored_dirs: list = monitored_dirs or []
        self.testing_mode = testing_mode  # if True, python3 is NOT whitelisted

        self._io_snapshots: dict = {}    # pid -> _ProcIOSnapshot
        self._alerted_pids: set = set()
        self._event_history: list = []
        self._quarantined_pids: set = set()

    def scan(self) -> list:
        """
        Scan all running processes.
        Uses /proc/[pid]/io for write rate - much more accurate than open files.
        """
        if not PSUTIL_AVAILABLE:
            return []

        events = []

        whitelist = set(WHITELISTED_PROCESSES)

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()

                # Skip whitelisted, ignored, quarantined
                if pid in self.ignored_pids:
                    continue
                if pid in self._quarantined_pids:
                    continue
                if pid == os.getpid():
                    continue
                if name in whitelist:
                    continue
                if any(name.startswith(p) for p in WHITELISTED_PREFIXES):
                    continue
                if pid in self._alerted_pids:
                    continue

                # Take /proc/io snapshot
                if pid not in self._io_snapshots:
                    self._io_snapshots[pid] = _ProcIOSnapshot(pid)
                alive = self._io_snapshots[pid].sample()
                if not alive:
                    continue

                write_rate = self._io_snapshots[pid].write_rate_bytes_per_sec()

                # Get open files in monitored directories
                open_in_monitored = []
                if self.monitored_dirs:
                    open_in_monitored = _get_proc_open_files_in_dir(pid, self.monitored_dirs)

                # Check honey file access
                honey_hits = [p for p in open_in_monitored if p in self.honey_file_paths]

                event = None

                if honey_hits:
                    event = self._build(
                        proc, len(open_in_monitored), write_rate,
                        "honeyfile_access", honey_hits, write_rate,
                    )
                elif write_rate > self.WRITE_RATE_THRESHOLD_BYTES:
                    # open_in_monitored misses files closed in <0.5s; fall back to
                    # /proc/[pid]/cwd + cmdline to confirm the process targets a monitored dir
                    touches = (
                        open_in_monitored
                        or not self.monitored_dirs
                        or _proc_targets_monitored_dir(pid, self.monitored_dirs)
                    )
                    if touches:
                        event = self._build(
                            proc, len(open_in_monitored), write_rate / 1024,
                            "high_write_rate", open_in_monitored[:10], write_rate,
                        )
                elif len(open_in_monitored) > self.OPEN_FILES_THRESHOLD:
                    event = self._build(
                        proc, len(open_in_monitored), write_rate / 1024,
                        "high_open_file_count", open_in_monitored[:10], write_rate,
                    )

                if event:
                    self._alerted_pids.add(pid)
                    self._event_history.append(event)
                    events.append(event)
                    logger.warning(
                        f"[PROCESS] {event.severity} | PID {pid} ({name}) | "
                        f"reason={event.event_reason} | "
                        f"write_rate={write_rate/1024:.1f}KB/s | "
                        f"open_files={len(open_in_monitored)}"
                    )
                    if self.alert_callback:
                        self.alert_callback(event)

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Clean up dead processes
        try:
            active = {p.pid for p in psutil.process_iter(["pid"])}
            for pid in list(self._io_snapshots.keys()):
                if pid not in active:
                    del self._io_snapshots[pid]
                    self._alerted_pids.discard(pid)
        except Exception:
            pass

        return events

    def terminate_process(self, pid: int) -> bool:
        if not PSUTIL_AVAILABLE:
            return False
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.terminate()
            proc.wait(timeout=3)
            self._quarantined_pids.add(pid)
            logger.warning(f"[PROCESS] Terminated PID {pid} ({name})")
            return True
        except Exception as e:
            logger.error(f"Could not terminate PID {pid}: {e}")
            return False

    def kill_process(self, pid: int) -> bool:
        if not PSUTIL_AVAILABLE:
            return False
        try:
            proc = psutil.Process(pid)
            proc.kill()
            self._quarantined_pids.add(pid)
            logger.warning(f"[PROCESS] Killed PID {pid}")
            return True
        except Exception as e:
            logger.error(f"Could not kill PID {pid}: {e}")
            return False

    def get_process_info(self, pid: int) -> Optional[dict]:
        if not PSUTIL_AVAILABLE:
            return None
        try:
            proc = psutil.Process(pid)
            return {
                "pid": pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "status": proc.status(),
                "cpu_percent": proc.cpu_percent(interval=0.1),
                "memory_mb": round(proc.memory_info().rss / (1024 * 1024), 1),
                "open_files": len(proc.open_files()),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def find_writers_targeting_dirs(self, dirs: list) -> list:
        """
        Emergency scan: find processes whose cmdline or cwd references a monitored
        directory. Called when entropy is CRITICAL but no PID was correlated.
        Uses a tighter whitelist - LotL tools (openssl, python3, tar, dd, etc.)
        are NOT excluded here because at CRITICAL entropy they're suspects.
        """
        if not PSUTIL_AVAILABLE:
            return []

        events = []
        # Strip LotL tools from the whitelist so they're catchable at CRITICAL entropy
        whitelist = set(WHITELISTED_PROCESSES) - LOTL_TOOLS

        for proc in psutil.process_iter(["pid", "name"]):
            try:
                pid = proc.info["pid"]
                name = (proc.info["name"] or "").lower()
                if pid in self.ignored_pids or pid == os.getpid():
                    continue
                if name in whitelist:
                    continue
                if any(name.startswith(p) for p in WHITELISTED_PREFIXES):
                    continue
                if pid in self._quarantined_pids or pid in self._alerted_pids:
                    continue
                if _proc_targets_monitored_dir(pid, dirs):
                    event = self._build(proc, 0, 0.0, "entropy_correlated_writer", [], 0.0)
                    self._alerted_pids.add(pid)
                    self._event_history.append(event)
                    events.append(event)
                    logger.warning(
                        f"[PROCESS] Emergency scan found PID {pid} ({name}) "
                        f"targeting monitored dir"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        return events

    def add_honey_file(self, path: str):
        self.honey_file_paths.add(path)

    def add_monitored_dir(self, directory: str):
        if directory not in self.monitored_dirs:
            self.monitored_dirs.append(directory)

    def is_quarantined(self, pid: int) -> bool:
        return pid in self._quarantined_pids

    def record_external_event(self, event: "ProcessEvent"):
        """
        Record an event generated outside the scan loop (e.g. from the file watcher
        rapid-write path). Adds to history, marks PID as alerted, and fires the
        alert callback so the GUI event queue and alert handler both receive it.
        """
        self._event_history.append(event)
        self._alerted_pids.add(event.pid)
        if self.alert_callback:
            self.alert_callback(event)

    def get_recent_events(self, limit: int = 50) -> list:
        return self._event_history[-limit:]

    def clear_history(self):
        self._event_history.clear()
        self._alerted_pids.clear()

    def _build(self, proc, open_count, rate, reason,
               flagged, write_bytes_per_sec=0.0) -> ProcessEvent:
        try:
            exe = proc.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            exe = None
        return ProcessEvent(
            pid=proc.pid,
            process_name=proc.name(),
            exe_path=exe,
            event_reason=reason,
            open_file_count=open_count,
            file_access_rate=rate,
            write_bytes_per_sec=write_bytes_per_sec,
            flagged_files=flagged,
        )
