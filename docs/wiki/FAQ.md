# FAQ

### Is the ACL lock really secure?
No — it is convenience-grade. It stops other standard users and casual access,
but an administrator can take ownership, and Safe Mode or another OS bypasses it
entirely. For real protection use **AES encryption**.

### What happens if I forget the password?
For an **encrypted** folder, use the **recovery code** you saved. There is no
other way to recover it. For an **ACL-locked** folder, you can restore access
from the folder's *Properties → Security* page.

### Where is my data stored?
- Database, key, settings: `%APPDATA%\FolderLock\` (or `<app>\data\` in portable
  mode).
- Guard watchlist: `%PROGRAMDATA%\FolderLock\watchlist.json`.
- Encrypted vaults: a `.flvault` file next to the original folder.

### Does locking delete my files?
No. ACL locking never moves or deletes data. AES locking encrypts then securely
wipes the original — that is intentional, so no plaintext copy remains.

### Why is the single-file download so large?
The full build bundles the Windows Runtime projections for the optional Windows
Hello unlock (~35 MB). Use the **lite** release or `publish.ps1 -NoHello`
(~9 MB) if you do not need Hello.

### Can I lock an entire drive or my Desktop?
No. VaultLock refuses drive roots, `Windows`, `System32`, `Program Files*`,
`ProgramData`, profile roots, Desktop and Documents, to avoid self-locking or
breaking the system.

### Is secure deletion reliable on SSDs?
Not fully. Due to TRIM and wear-levelling, copies may survive. Secure deletion is
best-effort; combine with full-disk encryption for strong guarantees.

### Why can't I change the password of a locked encrypted folder?
The vault key is wrapped with the password when it is locked. Unlock it first,
then change the password.

### Does it work on multiple user accounts / machines?
The database is per Windows user. The guard service is machine-wide and re-locks
whatever is in the watchlist. To move to another machine, use
**Export/Import recovery kit** and copy the `.flvault` files.

### Is there a portable version?
Yes — drop a `portable.flag` file next to the executable.

### How do I update it?
*Tools → Check for updates* reads a manifest URL you configure in
`settings.json` (`UpdateUrl`). Otherwise download a newer release and replace the
executable; your data and vaults stay.
