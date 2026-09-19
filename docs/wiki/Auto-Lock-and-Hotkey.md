# Auto-Lock & Hotkey

VaultLock can lock folders for you when you step away, and provides a panic
hotkey for immediate lockdown. All options live under **Tools → Auto-lock**.

Auto-locking an **AES** folder requires the password, so VaultLock caches the
password for the session when you unlock (the `CachePasswords` setting, on by
default). Disable it in `settings.json` for stricter security; then only ACL
folders participate in auto-lock.

## Lock on screen lock / sign-out

Uses Windows session notifications (`WTSRegisterSessionNotification`). When the
workstation locks (`WTS_SESSION_LOCK`) or the user signs out (`WTS_SESSION_LOGOFF`),
all unlocked folders with cached passwords are locked.

## Lock when idle

Uses `GetLastInputInfo`, polled every 20 seconds. Enable *Lock when idle for
15 min*. When there is no keyboard/mouse input for the interval, all folders are
locked.

## Re-lock after temporary unlock

Enable *Re-lock 10 min after unlock*. Each folder you unlock starts a timer; when
it expires the folder is locked again automatically.

## Panic hotkey

*Panic hotkey Ctrl+Alt+L* registers a global hotkey (via `RegisterHotKey`). When
pressed it:

1. Locks every folder with a cached password.
2. Clears the clipboard.
3. Minimizes the window.

## Notifications

Auto-lock, temporary re-lock and integrity warnings appear as tray balloon
notifications.

## Notes

- These features require the app to be running. Combine with **Start with
  Windows (tray)** and the optional **guard service** for continuous protection.
- The list of ACL-locked folders is published to a machine-wide watchlist
  (`%PROGRAMDATA%\FolderLock\watchlist.json`, or the portable `data\` folder) so
  the guard service can re-apply locks independently of the UI.
