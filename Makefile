# Load environment variables from .env
include .env
export $(shell sed 's/=.*//' .env)

# Deploy the OpenfortBaseAccount7702 contract
deploy:
	forge create contracts/core/OpenfortBaseAccount7702V1_4337.sol:OpenfortBaseAccount7702V1_4337 \
		--rpc-url $(HOLESKY_RPC_URL) \
		--private-key $(PRIVATE_KEY_OPENFORT_USER_7702) \
		--broadcast \
		--constructor-args $(HOLESKY_ENTRYPOINT_ADDRESS)

# Attach a delegator to the deployed account
attach:
	node script/attach-delegator.js

check code:
	cast code $(ADDRESS_OPENFORT_USER_ADDRESS_7702) --rpc-url $(SEPOLIA_RPC_URL)

# Initialize the deployed account
init:
	node script/initialize.js

getters:
	node script/getters.js

deposit entrypoint:
	node script/deposit-to-entrypoint.js

execute:
	node script/execute.js
	
# Run everything in order
all: deploy attach init


# Load environment variables from .env
include .env
export $(shell sed 's/=.*//' .env)

openzeppelin:
	forge install openzeppelin/openzeppelin-contracts --no-commit

account-abstraction:
	forge install eth-infinitism/account-abstraction --no-commit

create3:
	forge install 0xSequence/create3 --no-commit

size:
	forge inspect contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol:OpenfortBaseAccount7702V1SessionKey bytecode | wc -c

deploy-verifier:
	forge create contracts/utils/WebAuthnVerifier.sol:WebAuthnVerifier --broadcast --private-key $(BURNER_KEY) --verify --etherscan-api-key $(ETHERSCAN_KEY) --rpc-url $(SEPOLIA_RPC_URL)

deploy-7702:
	forge create contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol:OpenfortBaseAccount7702V1SessionKey \
	--rpc-url $(SEPOLIA_RPC_URL) \
	--account BURNER_KEY \
	--verify \
	--etherscan-api-key $(ETHERSCAN_KEY) \
	--broadcast \
	--constructor-args 0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B 0xc3F5De14f8925cAB747a531B53FE2094C2C5f597 \
	--dry-run

flatten:
	forge flatten contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol > Flatten.sol

verify:
	forge verify-contract 0x42f5A9BD10766acf09D1c437B732F9D57B9619f3 contracts/core/OpenfortBaseAccount7702V1_SessionKey.sol:OpenfortBaseAccount7702V1SessionKey \
		--chain-id 11155111 \
		--constructor-args 0x000000000000000000000000c92bb50de4af8fc3eaad61b3855fb55356a64a4b000000000000000000000000c3f5de14f8925cab747a531b53fe2094c2c5f597 \
		--compiler-version 0.8.29+commit.ab55807c \
		--num-of-optimizations 20000000 \
		--etherscan-api-key $(ETHERSCAN_KEY) \
		--watch

register webauthn:
	forge script script/RegisterWebauthn.s.sol:RegisterWebAuthnSelfCall --rpc-url $(SEPOLIA_RPC_URL) --broadcast --private-key $(PRIVATE_KEY_OPENFORT_USER_7702)

register webauthn no MK:
	forge script script/RegisterWebauthnNoMK.s.sol:RegisterWebAuthnSelfCall --rpc-url $(SEPOLIA_RPC_URL) --broadcast --private-key $(PRIVATE_KEY_OPENFORT_USER_7702)


revoke:
	forge script script/RevokeSessionKeySelf.s.sol:RevokeSelfCall --rpc-url $(SEPOLIA_RPC_URL) --broadcast --private-key $(PRIVATE_KEY_OPENFORT_USER_7702)

execute owner:
	forge script script/ExecuteOwnerViaEntryPoint.s.sol:ExecuteViaEntryPointOwner --rpc-url $(SEPOLIA_RPC_URL) --private-key $(PRIVATE_KEY_OPENFORT_USER_7702) -vvvv --broadcast
# Run everything in order
install all: openzeppelin account-abstraction create3

