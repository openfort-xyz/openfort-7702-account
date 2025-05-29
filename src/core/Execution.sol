/*
░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
░░░░░     ░░░░░░        ░░░         ░    ░░░░░   ░        ░░░░░░     ░░░░░░        ░░░░░           ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░
▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒  ▒   ▒▒▒   ▒   ▒▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒      ▒   ▒      ▒   ▒▒▒▒▒   ▒▒▒▒▒▒▒   ▒  ▒▒▒
▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒   ▒▒▒▒▒▒▒   ▒   ▒▒   ▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒   ▒▒▒▒   ▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒▒▒▒   ▒▒▒▒▒▒▒▒   ▒▒▒▒   ▒▒   ▒▒▒  ▒▒▒▒▒   
▓   ▓▓▓▓▓▓▓▓   ▓        ▓▓▓       ▓▓▓   ▓▓   ▓   ▓       ▓▓▓   ▓▓▓▓▓▓▓▓   ▓  ▓   ▓▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓   ▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓
▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓  ▓   ▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓   ▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓▓▓   ▓▓▓▓   ▓▓▓▓
▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓  ▓  ▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓   ▓▓▓▓   ▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓▓   ▓▓▓▓▓▓▓▓   ▓▓▓▓▓   ▓▓▓▓   ▓▓▓   ▓▓▓▓▓▓
█████     ██████   ████████         █   ██████   █   ███████████     ██████   ██████   █████   █████████   ████████   ████████    █████         █
█████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████████
 */

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.29;

import {KeysManager} from "src/core/KeysManager.sol";
import {ReentrancyGuard} from "lib/openzeppelin-contracts/contracts/utils/ReentrancyGuard.sol";

abstract contract Execution is KeysManager, ReentrancyGuard {
    bytes4 internal constant EXECUTE_SELECTOR = 0xb61d27f6;
    bytes4 internal constant EXECUTEBATCH_SELECTOR = 0x47e1da2a;

    /// @notice Emitted when a transaction is executed
    event TransactionExecuted(address indexed target, uint256 value, bytes data);
    /**
     * @notice Executes a batch of transactions
     * @dev Can only be called via EntryPoint or by self
     * @param _transactions Array of transactions to execute
     */

    function execute(Call[] calldata _transactions) external payable virtual nonReentrant {
        _requireForExecute();
        if (_transactions.length == 0 || _transactions.length > 9) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }

        uint256 transactionsLength = _transactions.length;
        Call calldata transactionCall;

        for (uint256 i = 0; i < transactionsLength; i++) {
            transactionCall = _transactions[i];
            address target = transactionCall.target;
            uint256 value = transactionCall.value;
            bytes memory data = transactionCall.data;

            if (target == address(this)) {
                revert OpenfortBaseAccount7702V1__InvalidTransactionTarget();
            }

            (bool success, bytes memory returnData) = target.call{value: value}(data);

            if (!success) {
                revert OpenfortBaseAccount7702V1__TransactionFailed(returnData);
            }

            emit TransactionExecuted(target, value, data);
        }
    }

    /**
     * Execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address _target, uint256 _value, bytes calldata _calldata)
        public
        virtual
        override
        nonReentrant
    {
        _requireForExecute();
        _call(_target, _value, _calldata);
    }

    /**
     * Execute a sequence of transactions. Maximum 9.
     */
    function executeBatch(
        address[] calldata _target,
        uint256[] calldata _value,
        bytes[] calldata _calldata
    ) public payable virtual nonReentrant {
        _requireForExecute();
        if (
            _target.length > 9 || _target.length != _calldata.length
                || _target.length != _value.length
        ) {
            revert OpenfortBaseAccount7702V1__InvalidTransactionLength();
        }
        uint256 i;
        for (i; i < _target.length;) {
            _call(_target[i], _value[i], _calldata[i]);
            unchecked {
                ++i;
            }
        }
    }

    /**
     * @dev Call a target contract and reverts if it fails.
     */
    function _call(address _target, uint256 _value, bytes calldata _calldata) internal virtual {
        emit TransactionExecuted(_target, _value, _calldata);
        (bool success, bytes memory result) = _target.call{value: _value}(_calldata);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }
}
