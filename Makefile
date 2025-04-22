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
	cast code $(ADDRESS_OPENFORT_USER_ADDRESS_7702) --rpc-url $(HOLESKY_RPC_URL)

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