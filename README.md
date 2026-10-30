# Remote2FA

Remote2FA is a web app [https://xmayoral.free.je/](https://xmayoral.free.je/) that keeps a two-factor authentication (2FA) code available from any browser. Each code is protected by three words that you memorise. It is meant as a backup for when the phone that normally holds your 2FA codes is lost, stolen or out of reach.

## What it does

- **Get a code with 3 words.** Type your three words and the current 6- or 8-digit 2FA code appears, with a countdown. Click it to copy it.
- **Set up a new code from a QR.** Scan a 2FA setup QR with the camera, upload a picture of it, or paste the key. Then choose three words to protect it.
- **Import from Google Authenticator.** Export QRs that contain several accounts are supported. You pick which code to save by matching the current code with the one on your phone.

## How it works

- **One code per combination.** Each combination of three words holds exactly one 2FA code. If a combination is already in use, it can't be reused or overwritten.
- **Encryption happens in the browser.** The three words are turned into an encryption key on your device. The server only stores encrypted data. It never sees the words, the 2FA secret, or which service the code belongs to.
- **No names are shown or stored.** The service name (issuer) and the account name are discarded on purpose. Anyone who learns the three words gets a code, but no hint of where to use it.
- **Brute-force protection.** After 5 failed attempts in 15 minutes, the server blocks the IP address for 15 minutes. The block doubles on every repeat, up to 24 hours. New-code creation and total requests are capped too.

## Use case: losing your phone while travelling

Laura travels with only her phone. Her email account asks for a 2FA code from an authenticator app on that phone.

**Before the trip**
1. On her email account's security page, she starts setting up a new authenticator. She scans the QR with Remote2FA as well as with her phone app.
2. She saves the code in Remote2FA with three words she can remember, for example `mountain lemon harbour`.

**During the trip**
1. Laura's phone is stolen. She has no access to the authenticator app.
2. She borrows a trusted device, opens Remote2FA and types `mountain lemon harbour`.
3. Remote2FA shows the current code. She signs in to her email with her password and that code.
4. From her email she can contact her bank, block her SIM card and recover her other accounts.

**After the trip**
1. She signs out of every session from the email account's security settings.
2. She changes her email password.
3. She sets up 2FA again with a new key, and deletes the old entry in Remote2FA.

## Limitations

- **Most banks aren't covered.** Many banks confirm sign-ins through their own app, SMS or a card reader instead of standard 2FA codes, so Remote2FA can't replace those methods.
- **You also need your password.** Remote2FA only gives the second factor. You still have to remember the account password.
- **It weakens 2FA's "something you have" factor.** The three words become something you know. Anyone with your password and your three words can sign in.
- **Avoid untrusted computers.** Malware on a public computer can capture the words, the password and the session. After using one, follow the "after the trip" steps.
- **The server matters.** If the server is down, codes are unavailable. If its `data/` folder is lost, the codes are gone. Back up the server.

## Requirements

- A web server with PHP 8.1 or later (for example Apache with PHP).
- HTTPS with a valid certificate. Browsers only allow the encryption the app uses, and camera access, on secure pages.
- The `data/` folder must be writable by PHP and blocked from direct web access. The included `.htaccess` blocks it on Apache.

QR decoding falls back to the [jsQR](https://github.com/cozmo/jsQR) library, loaded from the jsDelivr CDN, in browsers without a built-in QR reader.

## Files

| File | Purpose |
|---|---|
| `index.html`, `style.css`, `favicon.svg` | User interface |
| `app.js` | Interface logic, QR scanning |
| `totp.js` | 2FA code generation; reading setup and Google Authenticator export QRs |
| `vault.js` | Turning the three words into a key; encryption and decryption in the browser |
| `api.php` | Stores and returns encrypted entries, one per three-word combination |
| `ratelimit.php` | Per-IP brute-force protection |

## License

[MIT](LICENSE)
