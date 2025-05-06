/*********************************************************************
 *  registerSessionKey.js — full implementation with duplicate check
 *
 *  npm i ethers dotenv
 *********************************************************************/

import "dotenv/config";                // loads .env automatically
import { ethers } from "ethers";       // v5

/********************** 1.  ENV & PROVIDER ***************************/
const {
  SEPOLIA_RPC_URL,
  PRIVATE_KEY_OPENFORT_USER_7702,
  ADDRESS_OPENFORT_USER_ADDRESS_7702
} = process.env;

if (!SEPOLIA_RPC_URL || !PRIVATE_KEY_OPENFORT_USER_7702 || !ADDRESS_OPENFORT_USER_ADDRESS_7702) {
  console.error("❌  Missing SEPOLIA_RPC_URL / PRIVATE_KEY_OPENFORT_USER_7702 / ADDRESS_OPENFORT_USER_ADDRESS_7702 in .env");
  process.exit(1);
}

const provider = new ethers.providers.JsonRpcProvider(SEPOLIA_RPC_URL);
const wallet   = new ethers.Wallet(PRIVATE_KEY_OPENFORT_USER_7702, provider);

/********************** 2.  CONSTANTS *********************************/
const { utils, constants } = ethers;

const BURN_ADDRESS   = constants.AddressZero;
const TOKEN_ADDRESS  = "0xd1F228d963E6910412a021aF009583B239b4aA77";
const CONTRACT_ADDR  = "0xd1F228d963E6910412a021aF009583B239b4aA77";

const SPEND_LIMIT    = utils.parseEther("10");
const ETH_LIMIT      = utils.parseEther("0.5");
const LIMIT          = 3;

const PUB_X = "0x349f670ed4e7cd75f89f1a253d3794b1c52be51a9b03579f7160ae88121e7878";
const PUB_Y = "0x0a0e01b7c0626be1b8dc3846d145ef31287a555873581ad6f8bee21914ee5eb1";

const ALLOWED = ["0x095ea7b3"];                 // approve(address,uint256)

/********************** 3.  ABI  **************************************/
const ACCOUNT_ABI = [
  // execute() – lets the account call itself (not needed if your
  // contract allows direct calls; keep for extension)
  "function execute(address dest,uint256 value,bytes data) external",

  // target function
  "function registerSessionKey((" +
  "  (bytes32,bytes32) pubKey," +
  "  address,uint8) key," +
  "  uint48,uint48,uint48,bool," +
  "  address,(address,uint256)," +
  "  bytes4[],uint256) external",

  // custom revert
  "error SessionKeyManager__SessionKeyRegistered()"
];

/********************** 4.  CONTRACT HANDLE ***************************/
const account = new ethers.Contract(
  ADDRESS_OPENFORT_USER_ADDRESS_7702,
  ACCOUNT_ABI,
  wallet
);

/********************** 5.  ARGUMENT PACKING **************************/

// »key« tuple (arrays because ABI components are unnamed)
const key = [
  [PUB_X, PUB_Y],       // pubKey (x,y)
  BURN_ADDRESS,         // eoaAddress
  1                     // keyType = WEBAUTHN
];

// spend-limit struct
const spendTokenInfo = [
  TOKEN_ADDRESS,
  SPEND_LIMIT
];

// validity window (now .. +30d)
const now         = Math.floor(Date.now() / 1000);
const VALID_AFTER = now;
const VALID_UNTIL = now + 60 * 60 * 24 * 30;

/********************** 6.  INTERFACE FOR ERROR DECODING *************/
const iface = new ethers.utils.Interface(ACCOUNT_ABI);

/********************** 7.  DRY-RUN TO CATCH “ALREADY REGISTERED” ****/
async function alreadyRegistered() {
  try {
    await account.callStatic.registerSessionKey(
      key,
      VALID_UNTIL,
      VALID_AFTER,
      LIMIT,
      true,               // whitelisting
      CONTRACT_ADDR,
      spendTokenInfo,
      ALLOWED,
      ETH_LIMIT
    );
    return false;         // no revert ⇒ not yet registered
  } catch (err) {
    const data = err.error?.data || err.data;
    if (!data) throw err;

    const decoded = iface.parseError(data);
    if (decoded && decoded.name === "SessionKeyManager__SessionKeyRegistered") {
      return true;        // exact custom error matched
    }
    throw err;            // some other revert – bubble up
  }
}

/********************** 8.  MAIN FLOW ********************************/
(async () => {
  if (await alreadyRegistered()) {
    console.log("ℹ️  Session key already registered");
    return;
  }

  console.log(`📨  Sending registerSessionKey() from ${wallet.address}`);

  const tx = await account.registerSessionKey(
    key,
    VALID_UNTIL,
    VALID_AFTER,
    LIMIT,
    true,                 // whitelisting
    CONTRACT_ADDR,
    spendTokenInfo,
    ALLOWED,
    ETH_LIMIT,
    { gasLimit: 1_000_000 }     // let provider estimate if you like
  );

  console.log(`⛓  Tx sent: ${tx.hash}`);
  const receipt = await tx.wait();
  console.log(`✅  Confirmed in block ${receipt.blockNumber}`);
  console.log(`🔎  Explorer: https://sepolia.etherscan.io/tx/${tx.hash}`);
})();