# TestFlight submission — PhysicalKey iOS

Salvaged from an earlier session's TestFlight research (originally split across
`~/physicalkey-app/TESTFLIGHT_SETUP.md` and `SUBMIT_TO_TESTFLIGHT.md`, both since deleted —
those predated the real app existing in one buildable place and described a "which project is
the real one" problem that no longer applies. The real, current app is
`mobile/ios/PhysicalKey/` in this repo; nothing else. The process below is still accurate and
worth keeping for when TestFlight submission is actually attempted.

**Prerequisite**: an [Apple Developer Program](https://developer.apple.com/programs/)
membership ($99/year). If not already enrolled, budget 24–48 hours for approval before
anything else here is possible.

## 1. App Store Connect: create the app record

1. Go to [appstoreconnect.apple.com](https://appstoreconnect.apple.com) and sign in.
2. **My Apps → the "+" button → New App.**
3. Fill in:
   - **Platform:** iOS
   - **Name:** PhysicalKey (must be unique App Store–wide — check availability first)
   - **Primary language:** English (U.S.) or your preference
   - **Bundle ID:** select the app's bundle identifier from the dropdown. If it's not listed,
     register it first under **Certificates, Identifiers & Profiles → Identifiers → "+"** in
     the Apple Developer portal, matching exactly what's set in the Xcode target.
   - **SKU:** any unique internal string, e.g. `physicalkey-ios-001` (not shown to users)
4. Save — this creates the record TestFlight builds attach to.

## 2. Archive and upload

Once the project builds and runs on a real device:

**Xcode GUI**: select **Any iOS Device (arm64)** as the destination (not a simulator —
archives can't be built for the simulator) → **Product → Archive** → in the Organizer,
**Distribute App → App Store Connect → Upload** → "Automatically manage signing" is simplest
if not already managing certificates manually.

**Command line equivalent:**
```bash
xcodebuild -project PhysicalKey.xcodeproj \
  -scheme PhysicalKey \
  -sdk iphoneos \
  -configuration Release \
  -destination "generic/platform=iOS" \
  -archivePath build/PhysicalKey.xcarchive \
  archive

xcodebuild -exportArchive \
  -archivePath build/PhysicalKey.xcarchive \
  -exportPath build/export \
  -exportOptionsPlist ExportOptions.plist
```
`ExportOptions.plist` (Xcode can generate a starting one via **Organizer → Distribute App →
App Store Connect → Export**, or write by hand):
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>method</key>
    <string>app-store</string>
    <key>teamID</key>
    <string>YOUR_TEAM_ID</string>
    <key>signingStyle</key>
    <string>automatic</string>
</dict>
</plist>
```
(`YOUR_TEAM_ID` is under **Apple Developer → Membership** — a 10-character alphanumeric ID.)

```bash
xcrun altool --upload-app \
  -f build/export/PhysicalKey.ipa \
  -t ios \
  -u "your-apple-id@example.com" \
  -p "@keychain:AC_PASSWORD"
```
`-p "@keychain:AC_PASSWORD"` refers to an app-specific password stored in the local Keychain
under that name — generate one at [appleid.apple.com](https://appleid.apple.com) → Sign-In
and Security → App-Specific Passwords, then store it once:
```bash
xcrun altool --store-password-in-keychain-item "AC_PASSWORD" \
  -u "your-apple-id@example.com" -p "the-app-specific-password"
```
`altool` is deprecated in favor of the newer upload path but still works as of writing. The
modern equivalent (really meant for notarization, but works as a fallback):
```bash
xcrun notarytool submit build/export/PhysicalKey.ipa \
  --apple-id "your-apple-id@example.com" \
  --team-id "YOUR_TEAM_ID" \
  --password "the-app-specific-password" \
  --wait
```

Confirm it landed via `xcrun altool --list-apps -u "your-apple-id@example.com" -p
"@keychain:AC_PASSWORD"`, or just check **App Store Connect → TestFlight → iOS Builds** in
the browser — appears once processing finishes (10–30 min typically).

## 3. Fill in TestFlight's required info

Before adding external testers:

- **What to Test** (per build): short changelog note, e.g. "Initial beta — phone Face ID
  authentication and Bluetooth pairing with the PhysicalKey device."
- **Beta App Description**: what testers should focus on (Bluetooth pairing reliability, Face
  ID prompt timing, crashes/unexpected errors).
- **Feedback Email**: an address actually monitored.
- **Marketing URL** (optional): the landing page.
- **Privacy Policy URL**: **required** for any app requesting device permissions (Face ID,
  Bluetooth) — needed before Apple approves external testing. A simple policy covering what's
  collected (device public keys, auth timestamps, no biometric data ever leaves the device)
  is enough to start.

## 4. Internal vs. external testers

- **Internal** (up to 100, must be on the App Store Connect team with an assigned role): no
  App Review needed, available as soon as the build finishes processing. Start here to
  sanity-check the build works before burning a review cycle on something broken.
- **External** (up to 10,000, via email or a public link): requires a beta app review
  (typically 24–48 hours, can run longer — especially for a first-time submission requesting
  Bluetooth + biometric permissions). Submit under **TestFlight → [build] → Submit for
  Review** once the info above is filled in.

**Via CSV (bulk tester import):**
```csv
First Name,Last Name,Email
Ada,Lovelace,ada@example.com
Alan,Turing,alan@example.com
```
Column headers must match exactly (`First Name`, `Last Name`, `Email`).

**Public link**: **External Testing → Public Link** — lets anyone install without adding
emails individually, at the cost of curating who's testing.

## 5. Managing builds and versions

- Every archive upload gets a new **build number** (`CFBundleVersion`) — must increase every
  upload, even within the same marketing version.
- **Marketing version** (`CFBundleShortVersionString`, e.g. `1.0`) is what testers/users see.
- Builds expire from TestFlight **90 days** after upload.
- Multiple builds can be live at once across different tester groups.

## Timeline, realistically

- Apple Developer Program enrollment (if needed): 24–48 hours, can be longer for new accounts.
- App record + bundle ID registration: minutes, no review.
- Archive → upload → processing: 10–30 minutes typically.
- Internal testing: immediate once processing finishes.
- External testing review: 24–48 hours typical, can run longer.
