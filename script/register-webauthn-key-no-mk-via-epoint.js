/*********************************************************************
 *  registerSessionKey_viaEntryPoint.js
 *
 *  npm i ethers dotenv
 *********************************************************************/

import "dotenv/config";
import { ethers } from "ethers";

/**************************************************************
 * 0.  ENV & PROVIDER
 **************************************************************/
const {
  SEPOLIA_RPC_URL,
  ENTRY_POINT_ADDRESS,
  PRIVATE_KEY_OPENFORT_USER_7702,
  ADDRESS_OPENFORT_USER_ADDRESS_7702
} = process.env;

if (!SEPOLIA_RPC_URL || !PRIVATE_KEY_OPENFORT_USER_7702 || !ADDRESS_OPENFORT_USER_ADDRESS_7702) {
  console.error("❌  Missing SEPOLIA_RPC_URL / PRIVATE_KEY_OPENFORT_USER_7702 / ADDRESS_OPENFORT_USER_ADDRESS_7702");
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(SEPOLIA_RPC_URL);
const wallet   = new ethers.Wallet(PRIVATE_KEY_OPENFORT_USER_7702, provider);

/**************************************************************
 * 1.  CONSTANTS
 **************************************************************/
const ENTRY_POINT = ENTRY_POINT_ADDRESS;
const ACCOUNT     = ADDRESS_OPENFORT_USER_ADDRESS_7702;

const { utils, constants, BigNumber } = ethers;

const BURN_ADDRESS   = constants.AddressZero;
const TOKEN_ADDRESS  = "0xd1F228d963E6910412a021aF009583B239b4aA77";
const CONTRACT_ADDR  = "0xd1F228d963E6910412a021aF009583B239b4aA77";

const SPEND_LIMIT    = utils.parseEther("10");
const ETH_LIMIT      = utils.parseEther("0.5");
const LIMIT          = 3;

const PUB_X = "0x74163ec7cf74d23b3020c87c6827aa5f7e08b6cb04afc64aefa564ec8852cbcb";
const PUB_Y = "0x9453029b4f36c4d6105d295d95a9862ccd81fafbe221215bdbc22af96cf76e26";

const ALLOWED = ["0x095ea7b3"];                 // approve(address,uint256)

/**************************************************************
 * 2.  ABI FRAGMENTS
 **************************************************************/
const ACCOUNT_ABI = [
  // registerSessionKey (with names)
  "function registerSessionKey((" +
  "  (bytes32 x,bytes32 y) pubKey," +
  "  address eoaAddress,uint8 keyType) key," +
  "  uint48 validUntil,uint48 validAfter,uint48 limit,bool whitelisting," +
  "  address contractAddress,(address token,uint256 limit) spendTokenInfo," +
  "  bytes4[] allowedSelectors,uint256 ethLimit) external",

  // digest helper
  "function getDigestToSign(bytes32 userOpHash) external view returns (bytes32)"
];

const ENTRY_POINT_ABI = [
  "function getNonce(address sender,uint192 key) external view returns (uint256)",
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
const account     = new ethers.Contract(ACCOUNT, ACCOUNT_ABI, wallet);
const entryPoint  = new ethers.Contract(ENTRY_POINT, ENTRY_POINT_ABI, wallet);

/**************************************************************
 * 4.  BUILD registerSessionKey CALLDATA
 **************************************************************/
const keyTuple = [
  [PUB_X, PUB_Y],    // pubKey
  BURN_ADDRESS,      // eoaAddress
  1                  // keyType (WEBAUTHN)
];

const spendTuple = [TOKEN_ADDRESS, SPEND_LIMIT];

const now         = Math.floor(Date.now() / 1000);
const VALID_AFTER = now;
const VALID_UNTIL = now + 60 * 60 * 24 * 30;

const callData = account.interface.encodeFunctionData(
  "registerSessionKey",
  [
    keyTuple,
    VALID_UNTIL,
    VALID_AFTER,
    LIMIT,
    true,                   // whitelisting
    CONTRACT_ADDR,
    spendTuple,
    ALLOWED,
    ETH_LIMIT
  ]
);

/**************************************************************
 * 5.  FETCH NONCE & FEES
 **************************************************************/
const nonce   = await entryPoint.getNonce(ACCOUNT, 1);          // key = 1 (same as foundry)
const feeData = await provider.getFeeData();

/**************************************************************
 * 6.  PACK GAS FIELDS
 **************************************************************/
function pack128x128(high, low) {
  return BigNumber.from(high).shl(128).or(BigNumber.from(low));
}

const callGasLimit         = 200_000;
const verificationGasLimit = 150_000;
const preVerificationGas   = 80_000;

const maxFeePerGas         = feeData.maxFeePerGas   || utils.parseUnits("50", "gwei");
const maxPriorityFeePerGas = feeData.maxPriorityFeePerGas || utils.parseUnits("2", "gwei");

const accountGasLimits = utils.hexZeroPad(
  pack128x128(callGasLimit, verificationGasLimit).toHexString(),
  32
);

const gasFees = utils.hexZeroPad(
  pack128x128(maxFeePerGas, maxPriorityFeePerGas).toHexString(),
  32
);

/**************************************************************
 * 7.  BUILD THE USER OPERATION (signature blank for now)
 **************************************************************/
let userOp = {
  sender: ACCOUNT,
  nonce:  nonce,
  initCode: "0x7702",                   // account is already deployed
  callData,
  accountGasLimits,
  preVerificationGas,
  gasFees,
  paymasterAndData: "0x",
  signature: "0x"
};

/**************************************************************
 * 8.  HASH & SIGN
 **************************************************************/
const userOpHash = await entryPoint.getUserOpHash(userOp);
const digest     = await account.getDigestToSign(userOpHash);

// r|s|v  →  65-byte sig
const sigParts   = wallet._signingKey().signDigest(digest);
const sigBytes   = utils.joinSignature(sigParts);

// encode with KeyType = 0 (EOA)
const finalSig   = utils.defaultAbiCoder.encode(["uint8","bytes"], [0, sigBytes]);
userOp.signature = finalSig;

/**************************************************************
 * 9.  SEND handleOps
 **************************************************************/
(async () => {
  console.log("📨  Sending PackedUserOperation via EntryPoint…");

  const tx = await entryPoint.handleOps([userOp], wallet.address, {
    gasLimit: 1_500_000      // enough to cover inner call & entry-point work
  });

  console.log(`⛓  Tx sent: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`✅  handleOps confirmed in block ${receipt.blockNumber}`);
  console.log(`🔎  Explorer: https://sepolia.etherscan.io/tx/${tx.hash}`);
})();