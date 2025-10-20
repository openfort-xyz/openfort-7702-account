# Load environment variables from .env
include .env
export $(shell sed 's/=.*//' .env)

.SILENT:

install-ts:
	npm install viem dotenv permissionless tslib

check-code:
	cast code $(ADDRESS_OPENFORT_USER_ADDRESS_7702) --rpc-url $(SEPOLIA_RPC_URL)
	
openzeppelin:
	forge install openzeppelin/openzeppelin-contracts

account-abstraction:
	forge install eth-infinitism/account-abstraction

solady:
	forge install Vectorized/solady

install-forge: openzeppelin account-abstraction solady

test-keys:
	forge test --mp test/unit/KeysManager.t.sol -vv 

test-upgrade-addresses:
	forge test --mp test/unit/UpgradeAddresses.t.sol -vv

test-eth:
	npx tsx --experimental-global-webcrypto script/P256_ETH.ts && npx tsx --experimental-global-webcrypto script/P256_ETH_Batch.ts && forge test --mp test/unit/DepositAndTransferETH.t.sol -vv

test-execution:
	npx tsx --experimental-global-webcrypto script/P256_EXE.ts && npx tsx --experimental-global-webcrypto script/P256_EXE_Batch.ts && forge test --mp test/unit/Execution.t.sol -vv

test-recovery:
	forge test --mp test/unit/Recoverable.t.sol -vv

test-gas:
	forge test --mp test/gas/GasFuzzing.t.sol -vv  && forge test --mp test/gas/GasPolicyTest.t.sol -vv 

test-by-contract:
	forge test --mp test/by-contract/BaseOPF7702Test.t.sol && forge test --mp test/by-contract/KeyManagerTest.t.sol && forge test --mp test/by-contract/OPF7702RecoverableTest.t.sol && forge test --mp test/by-contract/OPF7702Test.t.sol && forge test --mp test/by-contract/OPF7702WithDiffKeys.t.sol && forge test --mp test/by-contract/RecoverableReverts.t.sol && forge test --mp test/by-contract/Upgrade7702.sol

test-fuzz:
	forge test --mp test/fuzz/ExecutionFuzz.t.sol && forge test --mp test/fuzz/KeysManagerFuzz.t.sol && forge test --mp test/fuzz/RecoverableGuardiansFuzz.t.sol && forge test --mp test/fuzz/RecoveryFuzz.t.sol && forge test --mp test/fuzz/UserOpExecutionFuzz.t.sol

test-invariant:
	forge clean && forge build --quiet && forge test --mp test/invariant/CoreInvariant.t.sol && forge test --mp test/invariant/KeysManagerInvariant.t.sol

test-all: test-keys test-upgrade-addresses test-eth test-execution test-recovery test-gas test-by-contract

test-all-fuzz: test-keys test-upgrade-addresses test-eth test-execution test-recovery test-gas test-by-contract test-fuzz

test-all-fuzz-invariant: 
	forge clean && forge build --quiet && forge test

coverage:
	forge coverage --ir-minimum >> coverage.txt

report-debug:
	forge coverage --match-path "src/core/BaseOPF7702.sol" --ir-minimum --rpc-url $(SEPOLIA_RPC_URL) >> report_debug_BaseOPF7702.txt

report-json:
	forge coverage --report json --ir-minimum --rpc-url $(SEPOLIA_RPC_URL) >> coverage.json

lcov:
	forge coverage --report lcov --ir-minimum && genhtml lcov.info -o coverage-html/ --ignore-errors inconsistent,corrupt

size:
	forge clean && forge build --sizes

storage:
	forge clean && forge inspect src/core/OPFMain.sol:OPFMain storageLayout
	
deploy-webauthn:
	forge create src/utils/WebAuthnVerifier.sol:WebAuthnVerifier  \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast 

deploy-webauthnv2:
	forge create src/utils/WebAuthnVerifierV2.sol:WebAuthnVerifierV2  \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast 

deploy-7702-base:
	forge create src/core/OPF7702Recoverable.sol:OPF7702Recoverable \
	--rpc-url $(SEPOLIA_BASE_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY_BASE) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1 172800 604800 129600 43200

# 0xDCeaC68C8463Ed6b1026a47fe935dBC41392490f
deploy-7702-mainnet:
	forge create src/core/OPFMain.sol:OPFMain \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 0xeD43b3a3D00d791BC0B353666b5780B0F9245CC1 172800 604800 129600 43200

simple-mainnet:
	forge create src/mocks/SimpleContract.sol:SimpleContract \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 

script-deploy-upgradeable:
	forge script script/DeployUpgradeable.s.sol:DeployUpgradeable \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast

script-init:
	forge script script/InitProxy.s.sol:InitProxy \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--private-key $(PRIVATE_KEY_PROXY) \
	-vvvv

push:
	git push -u origin 0xkoiner/Social-Recovery-Contract