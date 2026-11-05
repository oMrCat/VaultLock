# Usage

## Adding a folder

1. Click **Add folder** (bottom-left) or drag folders onto the list.
2. Set a password. Confirm it. Optionally add a **password hint** — it is
   encrypted with DPAPI, stored only in the local database, and never written
   into the `.flvault` container.
3. Optionally tick **Use AES-256 encryption and wipe source files** — this is the
   strong mode. Save the **recovery code** shown afterwards. The dialog can print
   the code, copying it clears the clipboard, and it can be viewed again without
   the password for **7 days** after creation or last viewing.
4. The folder appears in the list. Use the sidebar filters
   *All / Locked / Unlocked / AES* and the search box to find it.

## Locking and unlocking

Select a folder and press **Lock** or **Unlock** (or double-click to
unlock-and-open).

- **ACL lock** is instant: it backs up the original permissions, denies access,
  and hides the folder. Unlock re-applies the saved DACL; if another account has
  taken ownership, recovery is manual (`takeown` + `icacls`).
- **AES vault** operations encrypt/decrypt the whole folder and show a progress
  overlay with a **Cancel** button. Large folders take time.

If the password is lost, the unlock dialog offers a **Forgot password** wizard.
It tries each available recovery channel in turn and reports **channel missing /
wrong key / success** for every one — the channels are the password, the
recovery code, the optional emergency password, and local auto-unlock (DPAPI) on
the same Windows account/machine. After a channel succeeds, you set a new
password; the data itself is not re-encrypted.

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

After registering the context menu (from v1.1 it is a **cascade menu** written to
`HKCU` and it supports multi-selection), right-click a folder for:

- **Lock** / **Unlock** / **Add to list** / **Remove from list** / **Open**

and right-click a `.flvault` file for:

- **Verify** / **Decrypt** / **Salvage** / **Open**

The command is forwarded to the running instance; if the app is not running it
starts it.

## Temporary unlock

Unlocking caches the password for the session so the folder can be re-locked
automatically (idle, sign-out, or the temporary-unlock timeout). This requires
**Cache passwords** (on by default). Disable it in `settings.json`
(`CachePasswords: false`) for stricter security — then no folder can be
auto-locked without re-entering a password, and the app prompts you to lock it
manually instead of failing silently.

## Panic hotkey

`Ctrl+Alt+L` (when enabled) immediately locks every folder with a cached
password, clears the clipboard and minimizes the app.
