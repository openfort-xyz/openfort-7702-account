---
## Why WebAuthn + P256 for Smart Accounts?
Customary wallets leave private keys open to the application layer since they form many attack vectors. Fundamentally, WebAuthn changes this via keeping private keys where extraction is impossible in secure hardware (like your device's secure enclave or a hardware security key).

This approach delivers when it is combined along with EIP-4337 and EIP-7702 abstraction standards.

- Private keys never leave from the secure hardware. Security is therefore able to be maintained.
- For superior UX no seed phrases are needed. Superior UX also means there is no key management for the users.
- Biometrics grant authentication across many device types.
- Future-Proof: Web standards that are widely adopted are leveraged.
