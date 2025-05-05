import { recoverAddress, hashTypedData } from "viem";

const userOpHash = "0x91752388114c9bdb074479df02082d9a3846a60e9b25d43effcba210d1462e67";
const domain = {
  name: "OpenfortBaseAccount7702V1SessionKey",
  version: "1",
  chainId: 11155111,
  verifyingContract: "0x6386b339C3DEc11635C5829025eFE8964DE03b05"
};
const types = {
  UserOperation: [
    { name: "userOpHash", type: "bytes32" }
  ]
};
const message = { userOpHash };

const digest = hashTypedData({ domain, types, primaryType: "UserOperation", message });
const signature = "0xa216a8013dd1860c261959ed496146304736fa53631c3d9895176cf81d88e0192042a01aaf49998e61720bc460005b48184d81dba1302d678d60c7672c0854fb1c";
const recovered = await recoverAddress({ hash: digest, signature });

console.log("Recovered address:", recovered);