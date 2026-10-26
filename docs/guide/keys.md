<!-- SPDX-License-Identifier: AGPL-3.0-only -->
# Keys and attestation

Every device in a group has keys: one proves who it is to the others, and the root's and
admins' keys add and remove devices. Where a device keeps its keys decides what a thief
gets with the device. This page says where each kind of device keeps them, how the group
can check it, and which level of strictness to choose. The exact rules are in the
[protocol](../protocol.md), section 17.

## Where keys live

| Where | Devices | What a thief gets |
|---|---|---|
| **In a file** | computers today, the lite member | a copy of the file, which works anywhere until an admin removes the device |
| **In hardware** | iPhones (Secure Enclave), Android phones (Keystore: StrongBox or the TEE), computers with a TPM or a Secure Enclave | nothing to copy: the key signs only on that device, and the root's and admins' keys only after your face, fingerprint or passcode |
| **Proven hardware** | an Android phone whose key the group's root checked | the same as hardware, and the group knows it is true, not only that the device says so |

The devices list in the apps and `cbb status` (the KEYS column) show which one each device
has.

## How a key is proven

A device can say its key is in hardware, but a modified program could say so too. Some
hardware can prove it:

- **Android.** When the app makes its key, the phone's Keystore signs a certificate that
  describes the key: in StrongBox or the TEE, on a phone with a locked bootloader and a
  verified system. The certificate leads up to Google's attestation root. The app sends it
  to the group's root, which checks it and records the phone as **proven**. Nothing is sent
  to Google for this.
- **A phone with an unlocked bootloader, or a system signed with its own key** (GrapheneOS
  and the like) keeps its key in hardware, but the check cannot vouch for the system around
  it. It counts as hardware, not proven.
- **Revoked phones.** Google publishes a list of phones whose attestation keys leaked. A
  server of the project, `cbb.tools`, copies it once a day and signs the copy. The group's
  root fetches that copy, so your devices never ask Google. A phone on the list drops from
  proven to hardware.
- **Computers with a TPM** and **Apple devices** (App Attest) come later in 0.6.

## The three levels

Your group has a level, which decides how sure the group must be before a device may act as
the root, an admin or the hub.

1. **Strict.** Only proven hardware may be the root, an admin or the hub. To prove more
   devices, this level also asks services outside your home: Apple for App Attest, and
   Intel or AMD for some TPM certificates. Those services learn that a device of that kind
   asked, from your address. Android chains count only when they came through Google's Remote
   Key Provisioning.
2. **Hardware (the default, recommended).** Keys in hardware may be the root, an admin or the
   hub, proven or not. Proofs that need no outside service (Android, TPMs with their
   certificate on the chip) are still checked and shown. Nothing about your devices leaves
   your home, apart from fetching the revocation copy from `cbb.tools`, which is the same
   file for everyone.
3. **Files allowed (least safe).** A device with keys in a file may be an admin too, after a
   warning: whoever copies the file acts as an admin until another admin removes the device.
   Until computers keep their keys in a TPM or the Secure Enclave, a computer becomes an
   admin only this way (`cbb admin -allow-file-key`, or the warning in the phone's "Make it an
   admin" dialog).

Level 2 is the default because it keeps keys out of files wherever the hardware allows,
without telling any outside service which devices you have.

## If a device is lost

Remove it from the group (`cbb revoke NAME`, or the device page in the app). A key in hardware
cannot be used without the device, and the phone asks for your face, fingerprint or
passcode before the root's or an admin's key signs anything. A key in a file can: remove
such a device as soon as you can.

## What is not built yet

This page describes 0.6 as planned. Today:

- Android phones prove their keys, and the root checks the proof and Google's list. The
  copy on `cbb.tools` starts once the project's signing keys exist.
- The levels are not a setting yet. Groups work as at level 2, and a computer becomes an
  admin only with the warning of level 3.
- Computers keep their keys in files. TPM, the Mac's Secure Enclave and App Attest come
  later in 0.6.
