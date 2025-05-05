#!/bin/bash

set -e

# Load env variables
source .env

# Deploy
forge script script/OpenfortBaseAccount7702V1Script.s.sol:OpenfortBaseAccount7702V1Deployer \
  --rpc-url "$SEPOLIA_RPC_URL" \
  --private-key "$ANVIL_PRIVATE_KEY_DEPLOYER" \
  --broadcast

export OpenfortBaseAccount7702V1_ADDRESS=0x8464135c8F25Da09e49BC8782676a84730C318bC

export SIGNED_MESSAGE=$(cast wallet sign-auth 0x8464135c8F25Da09e49BC8782676a84730C318bC --private-key $ANVIL_PRIVATE_KEY)

export ANVIL_PRIVATE_KEY_DEPLOYER_RAW="${ANVIL_PRIVATE_KEY_DEPLOYER#0x}"

cast send $(cast az) --private-key "$ANVIL_PRIVATE_KEY_DEPLOYER_RAW" --auth "$SIGNED_MESSAGE"