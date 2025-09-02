// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {IKeysManager} from "src/interfaces/IKeysManager.sol";

library SigLengthLib {
    uint256 private constant _WORD = 32;
    /// @notice Assert that the outer `(KeyType.WEBAUTHN, bytes inner)` size matches
    ///         the canonical ABI size implied by the decoded WebAuthn fields.
    /// @dev    Assumes your signature encoding is: abi.encode(KeyType.WEBAUTHN, inner)
    ///         and inner fields layout is:
    ///           (bool, bytes authenticatorData, string clientDataJSON,
    ///            uint256 challengeIndex, uint256 typeIndex, bytes32 r, bytes32 s, PubKey{bytes32 x, bytes32 y})
    ///         Head size for inner = 9 * 32 bytes (incl. PubKey.x,y).
    ///         Dynamic tails: bytes + string -> each 32 (len) + padded payload.

    function assertWebAuthnOuterLen(
        uint256 signatureLen,
        uint256 authenticatorDataLen,
        uint256 clientDataJSONLen
    ) internal pure {
        // pad to 32 (readable form)
        uint256 adRem = authenticatorDataLen % _WORD;
        uint256 adPad = adRem == 0 ? authenticatorDataLen : authenticatorDataLen + (_WORD - adRem);

        uint256 cjRem = clientDataJSONLen % _WORD;
        uint256 cjPad = cjRem == 0 ? clientDataJSONLen : clientDataJSONLen + (_WORD - cjRem);

        // inner head = 9 words (bool + bytes off + string off + 2 uints + 2 bytes32 + PubKey(2 words))
        uint256 innerExpected = (9 * _WORD) + _WORD + adPad // bytes authenticatorData
            + _WORD + cjPad; // string clientDataJSON

        // signature `(KeyType, bytes)` = 64 (head) + 32 (bytes length) + padded inner
        // _WORD * 3 == 32 * 3 = 96
        uint256 expectedOuter = (_WORD * 3) + innerExpected;

        if (signatureLen != expectedOuter) {
            revert IKeysManager.KeyManager__InvalidSignatureLength();
        }
    }
}
