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
	forge test --mp test/unit/Keys.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-upgrade-addresses:
	forge test --mp test/unit/UpgradeAddresses.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-P256:
	npx tsx --experimental-global-webcrypto script/P256_Single_Mint.ts && forge test --mp test/unit/P256.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-registartion:
	forge test --mp test/unit/Registartion.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-eth:
	npx tsx --experimental-global-webcrypto script/P256_ETH.ts && forge test --mp test/unit/DepositAndTransferETH.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-execution:
	npx tsx --experimental-global-webcrypto script/P256_Single_Mint.ts && npx tsx --experimental-global-webcrypto script/P256.ts && forge test --mp test/unit/Execution.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-recovery:
	forge test --mp test/unit/Recoverable.t.sol --rpc-url $(SEPOLIA_RPC_URL) -vv 

test-gas:
	forge test --mp test/gas/GasFuzzing.t.sol --rpc-url $(SEPOLIA_RPC_URL) -vv  && forge test --mp test/gas/GasPolicyTest.t.sol --rpc-url $(SEPOLIA_RPC_URL) -vv 

test-all:
	npx tsx --experimental-global-webcrypto  script/P256_Single_Mint.ts && npx tsx --experimental-global-webcrypto  script/P256_ETH.ts && npx tsx --experimental-global-webcrypto  script/P256.ts && forge test -vv --rpc-url $(SEPOLIA_RPC_URL)

coverage:
	forge coverage --ir-minimum --rpc-url $(SEPOLIA_RPC_URL) >> coverage.txt

gas:
	forge test --gas-report --rpc-url $(SEPOLIA_RPC_URL)
	
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
	git push -u origin OPF7702_PROXY_After_Audit_Gas_Policy_Module