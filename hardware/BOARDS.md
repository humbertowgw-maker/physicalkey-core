# Board registry

The single source of truth for "which physical board is which, and what state is it
actually in" — CHECKPOINT.md and SETUP_COMPLETE.md have the narrative history of how
each board got here, but neither is a clean lookup table. This is that table. Update it
whenever a board's firmware, passkey, or pairing state changes — don't let it go stale
the way the passkey gap below did.

**Last updated:** 2026-08-15, from live production data (`railway ssh` query against
the real `identities` table) — not from memory or narrative docs.

## Boards

| Nickname | Full device ID | Passkey | Registered | Last seen | Access count | Secure Boot / Release flash enc. |
|---|---|---|---|---|---|---|
| `...00800` | `physicalkey-device-680947e00800` | `853203` | 2026-08-05 | 2026-08-13 | 14 | Not yet — still on Development-mode flash encryption, no Secure Boot |
| `...03c9c` | `physicalkey-device-680947e03c9c` | `717621` | 2026-08-04 | 2026-08-13 | 24 | Not yet — same as above |
| `...0684c` | `physicalkey-device-680947e0684c` | `969735` | 2026-08-10 | 2026-08-12 | 5 | Not yet — same as above |

All three: `status: active`, `recovery_policy: self-service`, currently running
pre-Secure-Boot firmware (encrypted-flash with Development-mode flash encryption, per
`CONFIG_SECURE_FLASH_ENCRYPTION_MODE_DEVELOPMENT` before the 2026-08-14 sdkconfig
change). None have had the new Secure Boot + Release-mode-flash-encryption build
flashed yet — that build exists (`build/PhysicalKeyDevice.bin`, signed) but hasn't
touched real hardware.

## Passkeys — resolved 2026-08-15

All three boards are physically labeled with their device ID and passkey, confirmed by
Humberto directly (not inferred). The gap noted earlier was only that the *digital*
registry didn't have them, not that the passkeys were actually lost — `...03c9c`
(`717621`) and `...00800` (`853203`) were read off the physical labels and are now
recorded above alongside `...0684c` (`969735`). Keep this table as the durable digital
backup going forward — a label on a board isn't searchable or backed up the way this
file is, so if a board ever gets relabeled or a passkey regenerated, update here in the
same session, not "later."

## Secure Boot / Release-mode rollout plan

Per the 2026-08-14 audit's one real hardware-level finding (`CONFIG_SECURE_BOOT` was
never enabled; flash encryption was in Development mode, not Release). Both are now
configured in `sdkconfig` and produce a real signed build
(`espsecure.py` confirmed: "Signed 589744 bytes"). **Both are irreversible eFuse burns on
first boot** — no board gets touched without deciding here first.

Rollout order, one board at a time, this table updated after each step:

1. Pick one board to go first (Humberto's call — since all three are already real,
   paired, in-use boards, not a spare/throwaway unit, whichever one is picked carries
   real risk of a permanent brick if something's wrong).
2. Flash the new signed build. First boot burns the Secure Boot + Release-mode-flash-
   encryption eFuses on that specific chip — permanent from that moment on.
3. Confirm it still boots, still re-pairs (new passkey will print once — capture it in
   this table immediately), still signs challenges correctly against production.
4. Only after that board is confirmed fully working, move to the next one.

**Not started yet** — this table's "Secure Boot / Release flash enc." column will move
to "Yes, verified live" for a board only after that board has actually been reflashed
and confirmed working, not just after the signed build exists.
