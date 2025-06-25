import 'dotenv/config';
import { createPublicClient, http } from 'viem'
import { sepolia } from 'viem/chains'
import { keccak256, hexToBytes, encodeFunctionData, decodeFunctionResult } from 'viem'

const RPC_URL = process.env.SEPOLIA_RPC_URL;
if (!RPC_URL) {
  console.error("Please set SEPOLIA_RPC_URL in your environment.");
  process.exit(1);
}

const PROXY_ADDRESS = "0x5f41D7672CB83996CCC5E8C9Ce60Ba2a3D2DeaAe";
const BURN_ADDRESS = "0x0000000000000000000000000000000000000000"; // adjust as needed

const publicClient = createPublicClient({
  chain: sepolia,
  transport: http(RPC_URL),
});

// ABI fragments
const proxyAbi = [
  {
    inputs: [],
    name: "getImplementation",
    outputs: [{ internalType: "address", name: "", type: "address" }],
    stateMutability: "view",
    type: "function",
  },
];
const getDigestAbi = [
  {
    inputs: [
      {
        internalType: "tuple(tuple(bytes32 x, bytes32 y) pubKey, address eoaAddress, uint8 keyType)",
        name: "_key",
        type: "tuple",
        components: [
          {
            internalType: "tuple(bytes32 x, bytes32 y)",
            name: "pubKey",
            type: "tuple",
            components: [
              { internalType: "bytes32", name: "x", type: "bytes32" },
              { internalType: "bytes32", name: "y", type: "bytes32" },
            ],
          },
          { internalType: "address", name: "eoaAddress", type: "address" },
          { internalType: "uint8", name: "keyType", type: "uint8" },
        ],
      },
      { internalType: "bytes32", name: "_initialGuardian", type: "bytes32" },
    ],
    name: "getDigestToInit",
    outputs: [{ internalType: "bytes32", name: "digest", type: "bytes32" }],
    stateMutability: "view",
    type: "function",
  },
];

async function main() {
  // 1. Fetch implementation address
  let implAddress;
  try {
    implAddress = await publicClient.readContract({
      address: PROXY_ADDRESS,
      abi: proxyAbi,
      functionName: "getImplementation",
    });
    console.log("Implementation address:", implAddress);
  } catch (err) {
    console.error("Error fetching implementation:", err);
    return;
  }
  if (
    !implAddress ||
    implAddress === "0x0000000000000000000000000000000000000000"
  ) {
    console.error("Proxy implementation is zero. Please initialize the account first.");
    return;
  }

  // 2. Prepare inputs
  const PUB_X = "0x349f670ed4e7cd75f89f1a253d3794b1c52be51a9b03579f7160ae88121e7878";
  const PUB_Y = "0x0a0e01b7c0626be1b8dc3846d145ef31287a555873581ad6f8bee21914ee5eb1";
  const initialGuardian = keccak256(hexToBytes("0x15A788835Ae4a92f0C1A29599A8688aD2bFa34Ac"));
  console.log("initialGuardian bytes32:", initialGuardian);

  const keyArg = {
    pubKey: { x: PUB_X, y: PUB_Y },
    eoaAddress: BURN_ADDRESS,
    keyType: 1,
  };

  // 3. Low-level call via proxy with a non-admin “from”
  const NON_ADMIN = "0x0000000000000000000000000000000000000001";
  const data = encodeFunctionData({
    abi: getDigestAbi,
    functionName: "getDigestToInit",
    args: [keyArg, initialGuardian],
  });
  try {
    const resultHex = await publicClient.call({
      to: PROXY_ADDRESS,
      data,
      account: NON_ADMIN,
    });
    if (!resultHex || resultHex === "0x") {
      console.error("Empty return from getDigestToInit. Check implementation or proxy flow.");
      return;
    }
    const [digest] = decodeFunctionResult({
      abi: getDigestAbi,
      functionName: "getDigestToInit",
      data: resultHex,
    });
    console.log("getDigestToInit digest:", digest);
  } catch (err) {
    console.error("Error calling getDigestToInit via low-level call:", err);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});