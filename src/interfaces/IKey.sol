// SPDX-License-Identifier: MIT

pragma solidity 0.8.29;

/// @title IKey
/// @author Openfort@0xkoiner
/// @notice Common key types and registration payloads used by OPF 7702 accounts.
/// @dev Consumed by KeysManager / OPF7702 / OPF7702Recoverable.
/// @custom:encoding EOA keys are `abi.encode(address)`. P-256 / WebAuthn keys are `abi.encode(bytes32 x, bytes32 y)`.
interface IKey {
    /**
     * @notice Types of keys supported by the account.
     * @dev
     * - EOA:        secp256k1 ECDSA signatures (r,s,v). Standard Ethereum accounts.
     * - WEBAUTHN:   FIDO2/WebAuthn P-256 (secp256r1) with authenticatorData/clientDataJSON;
     *               validated via the WebAuthn verifier.
     * - P256:       Raw P-256 (secp256r1) signatures over the message, using an extractable
     *               public key provided on registration (`PubKey{x,y}`).
     * - P256NONKEY: P-256 signatures produced by non-extractable WebCrypto keys; message is
     *               prehashed on-chain with SHA-256 before verification to match the key’s usage.
     */
    enum KeyType {
        EOA,
        WEBAUTHN,
        P256,
        P256NONKEY
    }

    /// @notice Control mode for a key: self-managed or custodial.
    /// @dev `Custodial` keys may delegate gas/policy logic (e.g. via `GAS_POLICY`).
    enum KeyControl {
        Self,
        Custodial
    }

    /**
     * @notice Public key structure for P256 curve used in WebAuthn
     * @param x X-coordinate of the public key
     * @param y Y-coordinate of the public key
     */
    struct PubKey {
        bytes32 x;
        bytes32 y;
    }

    /// @notice Stored key metadata and state.
    /// @dev `limits` is a TX quota (consumed on successful calls); spend limits for tokens are tracked separately.
    struct KeyData {
        /// @notice Cryptographic key type (e.g., EOA / P256 / WEBAUTHN).
        KeyType keyType;
        /// @notice Whether the key is currently active (paused/revoked sets this to false).
        bool isActive;
        /// @notice True if this is the master/admin key.
        bool masterKey;
        /// @notice True if control is delegated (see {KeyControl.Custodial}).
        bool isDelegatedControl;
        /// @notice Inclusive expiry timestamp (key invalid after this time).
        uint48 validUntil;
        /// @notice Not-before timestamp (key invalid before this time).
        uint48 validAfter;
        /// @notice Remaining transactions quota for this key (decremented on use).
        uint48 limits;
        /// @notice Encoded key
        bytes key;
    }

    /// @notice Registration payload for creating a new key.
    /// @dev Mirrors {KeyData} minus derived fields; used during `registerKey`.
    struct KeyDataReg {
        /// @notice Cryptographic key type (e.g., EOA / P256 / WEBAUTHN).
        KeyType keyType;
        /// @notice Inclusive expiry timestamp for the new key.
        uint48 validUntil;
        /// @notice Not-before timestamp for the new key.
        uint48 validAfter;
        /// @notice Initial transactions quota (must be zero for master keys).
        uint48 limits;
        /// @notice Encoded key
        bytes key;
        /// @notice Control mode for this key (self vs custodial).
        KeyControl keyControl;
    }
}
