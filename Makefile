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

test-registartion:
	forge test --mp test/unit/Registartion.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-execution:
	node script/P256_Single_Mint.ts && node script/P256.ts && forge test --mp test/unit/Execution.t.sol -vv --rpc-url $(SEPOLIA_RPC_URL)

test-recovery:
	forge test --mp test/unit/Recoverable.t.sol --rpc-url $(SEPOLIA_RPC_URL) -vv 
test-all:
	node script/P256_Single_Mint.ts && node script/P256_ETH.ts && node script/P256.ts && forge test -vv --rpc-url $(SEPOLIA_RPC_URL)

coverage:
	forge coverage --ir-minimum --rpc-url $(SEPOLIA_RPC_URL) >> coverage.txt

gas:
	forge test --gas-report --rpc-url $(SEPOLIA_RPC_URL)
	
storage:
	forge clean && forge inspect src/core/OPF7702Recoverable.sol:OPF7702Recoverable storageLayout
	
deploy-webauthn:
	forge create src/utils/WebAuthnVerifier.sol:WebAuthnVerifier  \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast 

deploy-7702-base:
	forge create src/core/OPF7702.sol:OPF7702 \
	--rpc-url $(SEPOLIA_BASE_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY_BASE) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 


deploy-7702-mainnet:
	forge create src/core/OPF7702.sol:OPF7702 \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 

simple-mainnet:
	forge create src/mocks/SimpleContract.sol:SimpleContract \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast \
	--constructor-args 0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108 

push:
	git push -u origin OPF7702_Recoverable