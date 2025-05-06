/*********************************************************************
 *  execute_via_entrypoint.js
 *  npm i ethers dotenv
 *********************************************************************/

import "dotenv/config";
import { ethers } from "ethers";

/**************************************************************
 * 0.  ENV, PROVIDER, WALLET
 **************************************************************/
const {
  SEPOLIA_RPC_URL,
  PRIVATE_KEY_OPENFORT_USER_7702,
  ADDRESS_OPENFORT_USER_ADDRESS_7702
} = process.env;

if (!SEPOLIA_RPC_URL || !PRIVATE_KEY_OPENFORT_USER_7702 || !ADDRESS_OPENFORT_USER_ADDRESS_7702) {
  console.error("❌  Missing env vars (.env)");
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(SEPOLIA_RPC_URL);
const wallet   = new ethers.Wallet(PRIVATE_KEY_OPENFORT_USER_7702, provider);

/**************************************************************
 * 1.  CONSTANTS
 **************************************************************/
const ENTRY_POINT = "0xC92bb50De4af8Fc3EAAd61b3855fb55356a64a4B";
const ACCOUNT     = ADDRESS_OPENFORT_USER_ADDRESS_7702;
const DEST_TOKEN  = "0xd1F228d963E6910412a021aF009583B239b4aA77";   // ERC-20 to call

// --- WebAuthn constants ----------------------------------------------------
const PUB_X = "0x349f670ed4e7cd75f89f1a253d3794b1c52be51a9b03579f7160ae88121e7878";
const PUB_Y = "0x0a0e01b7c0626be1b8dc3846d145ef31287a555873581ad6f8bee21914ee5eb1";

const CHALLENGE           = "0xddddbeee";
const AUTHENTICATOR_DATA  = "0x49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97631d00000000";
const CLIENT_DATA_JSON    = "{\"type\":\"webauthn.get\",\"challenge\":\"3d2-7g\",\"origin\":\"http://localhost:5173\",\"crossOrigin\":false}";
const CHALLENGE_INDEX     = 23;
const TYPE_INDEX          = 1;
const SIG_R               = "0x70b14935dd469e1952920e0164f06cbd809f0ab5a8d033395f8f4051643dac39";
const SIG_S               = "0x5b71c773e78a3104b7bca532f3ce9ac9b13e6d9a4aad2b8d99114c362ffff585";

// --- gas settings ----------------------------------------------------------
const CALL_GAS_LIMIT         = 400_000;
const VERIFICATION_GAS_LIMIT = 300_000;
const PRE_VERIF_GAS          = 800_000;
const MAX_FEE_PER_GAS        = ethers.utils.parseUnits("80", "gwei");
const MAX_PRIORITY_FEE       = ethers.utils.parseUnits("15", "gwei");

/**************************************************************
 * 2.  ABI FRAGMENTS
 **************************************************************/
const ACCOUNT_ABI = [
  // 2.a execute() we are calling *inside* the account
  "function execute(address dest,uint256 value,bytes data) external",

  // 2.b helper to encode the WebAuthn signature
  "function encodeWebAuthnSignature(bytes challenge,bool valid,bytes authenticatorData,string clientDataJSON,uint256 challengeIdx,uint256 typeIdx,bytes32 r,bytes32 s,(bytes32 x,bytes32 y) pubKey) external pure returns (bytes)",

  // 2.c EntryPoint helper (if your acct exposes it)
  "function getDigestToSign(bytes32 userOpHash) external view returns (bytes32)"
];

const ENTRY_POINT_ABI = [
  "function getNonce(address sender,uint192 key) external view returns (uint256)",

  // userOp hash
  "function getUserOpHash((" +
  "  address sender," +
  "  uint256 nonce," +
  "  bytes   initCode," +
  "  bytes   callData," +
  "  bytes32 accountGasLimits," +
  "  uint256 preVerificationGas," +
  "  bytes32 gasFees," +
  "  bytes   paymasterAndData," +
  "  bytes   signature" +
  ") userOp) external view returns (bytes32)",

  // main entry
  "function handleOps((" +
  "  address sender," +
  "  uint256 nonce," +
  "  bytes   initCode," +
  "  bytes   callData," +
  "  bytes32 accountGasLimits," +
  "  uint256 preVerificationGas," +
  "  bytes32 gasFees," +
  "  bytes   paymasterAndData," +
  "  bytes   signature" +
  ")[] ops,address payable beneficiary) external"
];

/**************************************************************
 * 3.  CONTRACT INSTANCES
 **************************************************************/
const account    = new ethers.Contract(ACCOUNT, ACCOUNT_ABI, wallet);
const entryPoint = new ethers.Contract(ENTRY_POINT, ENTRY_POINT_ABI, wallet);

/**************************************************************
 * 4.  BUILD INNER execute() CALLDATA
 *      execute(address dest, uint256 value, bytes data)
 *      data  = ERC-20 approve selector as in Foundry script
 **************************************************************/
const innerData  =
  "0x095ea7b3000000000000000000000000abcdefabcdef1234567890abcdef1234567890120000000000000000000000000000000000000000000000000000000000000000";

const callData   = account.interface.encodeFunctionData(
  "execute",
  [DEST_TOKEN, 0, innerData]
);

/**************************************************************
 * 5.  ENCODE WEBAUTHN SIGNATURE
 **************************************************************/
const webAuthnSignature = await account.encodeWebAuthnSignature(
  CHALLENGE,
  true,                                // "valid" flag
  AUTHENTICATOR_DATA,
  CLIENT_DATA_JSON,
  CHALLENGE_INDEX,
  TYPE_INDEX,
  SIG_R,
  SIG_S,
  { x: PUB_X, y: PUB_Y }
);

/**************************************************************
 * 6.  NONCE & GAS PACKING
 **************************************************************/
const nonce = await entryPoint.getNonce(ACCOUNT, 1);

function pack128x128(high, low) {
  return ethers.BigNumber.from(high).shl(128).or(ethers.BigNumber.from(low));
}

const accountGasLimits = ethers.utils.hexZeroPad(
  pack128x128(CALL_GAS_LIMIT, VERIFICATION_GAS_LIMIT).toHexString(),
  32
);

const gasFees = ethers.utils.hexZeroPad(
  pack128x128(MAX_FEE_PER_GAS, MAX_PRIORITY_FEE).toHexString(),
  32
);

/**************************************************************
 * 7.  BUILD USER OPERATION (signature attached already)
 **************************************************************/
const userOp = {
  sender: ACCOUNT,
  nonce,
  initCode: "0x7702",
  callData,
  accountGasLimits,
  preVerificationGas: PRE_VERIF_GAS,
  gasFees,
  paymasterAndData: "0x",
  signature: webAuthnSignature            // <- attach
};

/**************************************************************
 * 8.  SEND handleOps
 **************************************************************/
(async () => {
  console.log("📨  handleOps( execute(...) ) via EntryPoint…");

  const tx = await entryPoint.handleOps([userOp], wallet.address, {
    gasLimit: 1_500_000
  });

  console.log(`⛓  Tx sent: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`✅  Confirmed in block ${receipt.blockNumber}`);
  console.log(`🔎  Explorer: https://sepolia.etherscan.io/tx/${tx.hash}`);
})();