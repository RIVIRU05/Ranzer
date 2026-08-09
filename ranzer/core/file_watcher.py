"""
RANZER - File System Watcher
Real-time filesystem event listener using watchdog.

Key design decisions:
- on_created only counts toward write rate (actual new files)
- on_modified only does entropy check (can fire on reads too)
- Interactive/GUI processes are whitelisted and never flagged
- PID detection uses /proc at the exact moment of the write event
"""

import logging
import os
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Optional, Callable

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    FileSystemEventHandler = object

from .entropy_monitor import EntropyMonitor
from .honey_file_engine import HoneyFileEngine

logger = logging.getLogger("ranzer.watcher")

# Processes that are always user-interactive - never flag these
# These are things a person clicks/opens, not ransomware
INTERACTIVE_PROCESS_WHITELIST = {
    # File managers
    "nautilus", "thunar", "nemo", "dolphin", "pcmanfm", "caja",
    "ranger", "midnight-commander", "mc", "krusader",
    # Text editors
    "gedit", "kate", "mousepad", "pluma", "xed", "leafpad",
    "nano", "vim", "vi", "nvim", "emacs", "geany", "vscodium",
    "code", "sublime_text", "atom",
    # Terminals
    "bash", "zsh", "fish", "sh", "dash",
    "xfce4-terminal", "xterm", "lxterm", "konsole", "gnome-terminal",
    # Browsers
    "firefox", "chromium", "chrome", "brave", "opera",
    # Document viewers
    "evince", "okular", "atril", "xreader", "eog", "ristretto",
    # Display servers and compositors - killing these logs the user out
    "xorg", "x", "xwayland", "weston", "mutter",
    "kwin_x11", "kwin_wayland", "sway", "i3", "bspwm", "awesome",
    # Display managers
    "gdm", "gdm3", "lightdm", "sddm", "xdm", "lxdm",
    # System UI / desktop environment
    "xfwm4", "openbox", "gnome-shell", "plasmashell", "xfce4-session",
    "xfdesktop", "xfce4-panel",
    # Terminal emulators
    "xfce4-terminal", "xterm", "lxterm", "konsole", "gnome-terminal",
    "qterminal", "terminator", "tilix", "alacritty", "kitty", "rxvt",
    "urxvt", "st", "terminology",
    # Audio servers
    "pulseaudio", "pipewire", "pipewire-pulse", "wireplumber",
    # Privilege escalation
    "sudo", "su", "pkexec",
    # Core system daemons
    "systemd", "init", "dbus-daemon", "networkmanager",
    "systemd-journald", "systemd-logind", "systemd-udevd",
    # Archive managers
    "file-roller", "ark", "engrampa",
    # Media
    "vlc", "mpv", "totem", "rhythmbox",
    # XFCE panel plugins and tray applets
    "xfce4-whiskermen", "xfce4-power-mana", "xfce4-notifyd",
    "xfce4-clipman", "xfce4-screensave", "tumbler", "thunar-volman",
    "nm-applet", "blueman-applet", "dunst", "notify-osd",
    "light-locker", "xscreensaver", "redshift", "redshift-gtk",
    "xdg-desktop-por",
}


def _get_pid_of_file(file_path: str) -> list:
    """
    Scan /proc/*/fd RIGHT NOW to find which PIDs have this exact file open.
    This is called immediately when a file event fires - most accurate method.
    Returns list of (pid, process_name).
    """
    results = []
    try:
        target = str(Path(file_path).resolve())
        for pid_dir in Path("/proc").iterdir():
            if not pid_dir.name.isdigit():
                continue
            try:
                fd_dir = pid_dir / "fd"
                if not fd_dir.exists():
                    continue
                for fd in fd_dir.iterdir():
                    try:
                        resolved = str(fd.resolve())
                        if resolved == target:
                            pid = int(pid_dir.name)
                            comm = (pid_dir / "comm").read_text().strip()
                            results.append((pid, comm))
                            break
                    except (OSError, PermissionError):
                        continue
            except (OSError, PermissionError):
                continue
    except Exception:
        pass
    return results


def _get_high_write_pids(monitored_dir: str) -> list:
    """
    Fallback: use psutil to find processes with multiple files open in monitored_dir.
    Returns list of (pid, name, open_count).
    """
    results = []
    try:
        import psutil
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                name = proc.info["name"] or ""
                # Skip whitelisted interactive processes
                if name.lower() in INTERACTIVE_PROCESS_WHITELIST:
                    continue
                matching = [
                    f.path for f in proc.open_files()
                    if f.path.startswith(monitored_dir)
                ]
                if len(matching) >= 3:
                    results.append((proc.pid, name, len(matching)))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    except Exception:
        pass
    return results


_INTERACTIVE_PREFIXES = {
    "xfce4-", "xfce-", "gvfsd", "gvfs-", "gsd-",
    "evolution-", "zeitgeist-", "gnome-keyring", "tracker-",
    "flatpak-", "kde",
}

def _is_interactive_process(name: str) -> bool:
    """Return True if this process is a known user-interactive application."""
    n = name.lower().strip()
    return n in INTERACTIVE_PROCESS_WHITELIST or any(n.startswith(p) for p in _INTERACTIVE_PREFIXES)


class _Handler(FileSystemEventHandler if WATCHDOG_AVAILABLE else object):
    def __init__(self, entropy_monitor, honey_file_engine,
                 max_file_size=10*1024*1024,
                 pid_alert_callback=None,
                 monitored_dirs=None):
        if WATCHDOG_AVAILABLE:
            super().__init__()
        self.entropy_monitor = entropy_monitor
        self.honey_file_engine = honey_file_engine
        self.max_file_size = max_file_size
        self.pid_alert_callback = pid_alert_callback
        self.monitored_dirs = monitored_dirs or []
        self.events_processed = 0

        # Write rate tracking: directory -> [timestamps of NEW file creations]
        self._write_counts: dict = defaultdict(list)
        self._alerted_pids: set = set()
        self._lock = threading.Lock()
        self._wchar_prev: dict = {}   # pid -> (timestamp, wchar)
        self._wchar_rate: dict = {}   # pid -> (bytes_per_sec, comm)
        self._last_wchar_snap: float = 0.0

    # ------------------------------------------------------------------ #
    # Watchdog event handlers                                              #
    # ------------------------------------------------------------------ #

    def on_modified(self, event):
        """
        Fires when an existing file is written to OR just read/opened.
        We ONLY do entropy check here - do NOT count toward write rate
        because normal file opens trigger this too.
        """
        if not event.is_directory:
            self._entropy_only(event.src_path)

    def on_created(self, event):
        """
        Fires only when a NEW file is created.
        Real ransomware creates new encrypted files - this is what we count.
        Normal file opens do NOT trigger on_created.
        """
        if not event.is_directory:
            self._full_check(event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and self.honey_file_engine.is_honey_file(event.src_path):
            self.honey_file_engine.check_file(event.src_path, event_type="deleted")

    def on_moved(self, event):
        if not event.is_directory and self.honey_file_engine.is_honey_file(event.src_path):
            self.honey_file_engine.check_file(event.src_path, event_type="renamed")

    # ------------------------------------------------------------------ #
    # Internal routing                                                     #
    # ------------------------------------------------------------------ #

    def _entropy_only(self, file_path: str):
        """
        Only run entropy analysis and honey file check.
        Called from on_modified - no rate counting, no PID tracking.
        This ensures normal file opens never contribute to threat scoring.
        """
        # Honey file tamper check
        if self.honey_file_engine.is_honey_file(file_path):
            self.honey_file_engine.check_file(file_path, event_type="modified")
            return  # Already handled

        # Entropy check
        try:
            size = Path(file_path).stat().st_size
            if size == 0 or size > self.max_file_size:
                return
        except OSError:
            return

        pid, name = self._detect_pid(file_path)
        self.entropy_monitor.analyze_file(file_path, process_pid=pid, process_name=name)

    def _full_check(self, file_path: str):
        """
        Full check: entropy + honey file + write rate tracking + PID detection.
        Called from on_created only - actual new file writes.
        """
        self.events_processed += 1

        # Honey file check
        if self.honey_file_engine.is_honey_file(file_path):
            self.honey_file_engine.check_file(file_path, event_type="modified")

        # Update write rate counter for this directory
        parent = str(Path(file_path).parent)
        now = time.time()
        with self._lock:
            self._write_counts[parent].append(now)
            # Keep only last 5 seconds
            self._write_counts[parent] = [
                t for t in self._write_counts[parent] if now - t <= 5.0
            ]
            rate = len(self._write_counts[parent])

        # 10+ NEW files created in 5 seconds → look for the responsible PID
        if rate >= 10 and self.pid_alert_callback:
            self._snapshot_wchar()
            self._find_and_report_pid(file_path, rate)

        # Entropy check
        try:
            size = Path(file_path).stat().st_size
            if size == 0 or size > self.max_file_size:
                return
        except OSError:
            return

        pid, name = self._detect_pid(file_path)
        self.entropy_monitor.analyze_file(file_path, process_pid=pid, process_name=name)

    def _snapshot_wchar(self):
        """Sample /proc/*/io wchar for all non-interactive processes (throttled to 2×/s)."""
        now = time.time()
        if now - self._last_wchar_snap < 0.5:
            return
        self._last_wchar_snap = now
        try:
            for pid_dir in Path("/proc").iterdir():
                if not pid_dir.name.isdigit():
                    continue
                pid = int(pid_dir.name)
                if pid <= 2 or pid == os.getpid():
                    continue
                try:
                    comm = (pid_dir / "comm").read_text().strip()
                    if _is_interactive_process(comm):
                        continue
                    io_data = {}
                    for line in (pid_dir / "io").read_text().splitlines():
                        if ":" in line:
                            k, v = line.split(":", 1)
                            io_data[k.strip()] = int(v.strip())
                    wchar = io_data.get("wchar", 0)
                    if pid in self._wchar_prev:
                        prev_t, prev_w = self._wchar_prev[pid]
                        elapsed = now - prev_t
                        if elapsed > 0:
                            self._wchar_rate[pid] = ((wchar - prev_w) / elapsed, comm)
                    self._wchar_prev[pid] = (now, wchar)
                except (OSError, PermissionError, ValueError):
                    continue
        except Exception:
            pass

    def _detect_pid(self, file_path: str):
        """
        Best-effort: find which non-whitelisted PID has file_path open right now.
        Returns (pid, name) or (None, None) if nothing found.
        Used to attach a PID to entropy events.
        """
        pids = _get_pid_of_file(file_path)
        for pid, name in pids:
            if pid == os.getpid() or pid <= 2:
                continue
            if _is_interactive_process(name):
                continue
            return pid, name
        return None, None

    def _find_and_report_pid(self, file_path: str, rate: int):
        """
        Find which PID created this file and fire the callback if it's suspicious.
        Skips whitelisted interactive processes entirely.
        """
        # Method 1: /proc/fd scan - most accurate, catches file while open
        pids = _get_pid_of_file(file_path)

        # Filter out interactive processes immediately
        pids = [(pid, name) for pid, name in pids
                if not _is_interactive_process(name) and pid != os.getpid() and pid > 2]

        # Method 2: psutil fallback if /proc scan found nothing
        if not pids:
            parent = str(Path(file_path).parent)
            pids = [(p, n) for p, n, _ in _get_high_write_pids(parent)
                    if p != os.getpid() and p > 2]

        # Method 3: wchar rate - catches scripts that close files before /proc/fd can scan them
        if not pids and self._wchar_rate:
            HIGH = 50 * 1024  # 50 KB/s sustained
            candidates = [
                (pid, name)
                for pid, (r, name) in self._wchar_rate.items()
                if r > HIGH and pid != os.getpid() and pid > 2
                and not _is_interactive_process(name)
            ]
            if candidates:
                candidates.sort(key=lambda x: self._wchar_rate[x[0]][0], reverse=True)
                pids = [candidates[0]]

        for pid, name in pids:
            if pid in self._alerted_pids:
                continue
            self._alerted_pids.add(pid)
            logger.warning(
                f"[WATCHER] Suspicious writer: PID {pid} ({name}) | "
                f"{rate} new files in 5s"
            )
            if self.pid_alert_callback:
                self.pid_alert_callback(pid, name, rate, file_path)


class FileSystemWatcher:
    def __init__(self, entropy_monitor, honey_file_engine,
                 recursive=True, pid_alert_callback=None):
        if not WATCHDOG_AVAILABLE:
            raise RuntimeError("watchdog not installed. Run: pip install watchdog")
        self.recursive = recursive
        self._observer = None
        self._dirs: set = set()
        self._running = False
        self._lock = threading.Lock()
        self._handler = _Handler(
            entropy_monitor, honey_file_engine,
            pid_alert_callback=pid_alert_callback,
        )

    def add_directory(self, directory: str):
        directory = str(Path(directory).resolve())
        if not Path(directory).is_dir():
            logger.warning(f"Not a directory: {directory}")
            return
        with self._lock:
            if directory in self._dirs:
                return
            self._dirs.add(directory)
            self._handler.monitored_dirs.append(directory)
            if self._running and self._observer:
                self._observer.schedule(self._handler, directory, recursive=self.recursive)
                logger.info(f"[WATCHER] Added: {directory}")

    def start(self):
        if not self._dirs or self._running:
            return
        self._observer = Observer()
        with self._lock:
            for d in self._dirs:
                self._observer.schedule(self._handler, d, recursive=self.recursive)
                logger.info(f"[WATCHER] Watching: {d}")
        self._observer.start()
        self._running = True
        logger.info("[WATCHER] Started.")

    def stop(self):
        if not self._running or not self._observer:
            return
        self._observer.stop()
        self._observer.join(timeout=5)
        self._running = False
        logger.info("[WATCHER] Stopped.")

    @property
    def is_running(self) -> bool:
        return self._running

    @property
    def monitored_directories(self) -> list:
        return list(self._dirs)

    @property
    def events_processed(self) -> int:
        return self._handler.events_processed
