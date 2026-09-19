# Usage

## Adding a folder

1. Click **Add folder** (bottom-left) or drag folders onto the list.
2. Set a password. Confirm it.
3. Optionally tick **Use AES-256 encryption and wipe source files** — this is the
   strong mode. Save the **recovery code** shown afterwards.
4. The folder appears in the list. Use the sidebar filters
   *All / Locked / Unlocked / AES* and the search box to find it.

## Locking and unlocking

Select a folder and press **Lock** or **Unlock** (or double-click to
unlock-and-open).

- **ACL lock** is instant: it backs up the original permissions, denies access,
  and hides the folder. Unlock restores the exact original permissions.
- **AES vault** operations encrypt/decrypt the whole folder and show a progress
  overlay with a **Cancel** button. Large folders take time.

## The detail pane

With a folder selected, the right pane shows its path, mode (ACL / AES) and last
lock time, with buttons for **Open**, **Lock**, **Unlock**, **Change password**,
**View recovery code** and **Remove**.

## Tools menu (⋯)

| Item | What it does |
|---|---|
| Refresh | Re-sync lock state with disk |
| Register / Remove context menu | Explorer right-click integration |
| Start with Windows (tray) | Adds a per-user autostart entry |
| Auto-lock ▸ | Lock on sign-out/screen lock, when idle 15 min, re-lock 10 min after unlock, panic hotkey |
| Require Windows Hello on unlock | Optional biometric/PIN gate (full build only) |
| Install / Uninstall guard service | Background re-lock service (admin) |
| Theme ▸ | Follow system / Dark / Light |
| Language ▸ | Follow system / 简体中文 / English |
| View log | Audit trail with CSV export |
| Verify / salvage vault | Check an encrypted container; recover what is possible |
| Export / Import recovery kit | Password-protected `.flkit` backup |
| Check for updates | Uses the manifest URL configured in settings |
| Open data folder | Opens where data lives |
| Security notes | In-app explanation of the security model |

## Right-click in Explorer

After registering the context menu, right-click a folder to
**Add to VaultLock**, **Lock with VaultLock**, or **Unlock with VaultLock**. The
command is forwarded to the running instance; if the app is not running it starts
it.

## Temporary unlock

Unlocking caches the password for the session so the folder can be re-locked
automatically (idle, sign-out, or the temporary-unlock timeout). This requires
**Cache passwords** (on by default). Disable it in `settings.json`
(`CachePasswords: false`) for stricter security — then only ACL-locked folders
can be auto-locked without re-entering a password.

## Panic hotkey

`Ctrl+Alt+L` (when enabled) immediately locks every folder with a cached
password, clears the clipboard and minimizes the app.
