import { serializeSignDoc, StdSignDoc } from "@cosmjs/amino";
import {
  ExtendedSecp256k1Signature,
  Keccak256,
  Secp256k1,
  Secp256k1Signature,
} from "@cosmjs/crypto";
import { fromBase64, fromHex, toBase64, toBech32 } from "@cosmjs/encoding";
import { pubToAddress } from "ethereumjs-util";

export async function recoverSigningAddress(
  signature: string,
  hash: Uint8Array,
  recoveryIndex: number,
): Promise<string | null> {
  if (recoveryIndex > 3) {
    throw new Error("Invalid recovery index");
  }
  //   console.log("=============signature", signature);
  //   console.log("=============hash", hash);
  //   console.log("=============recoverSigningAddress", fromBase64(signature));

  const sig = Secp256k1Signature.fromFixedLength(fromBase64(signature));
  //   console.log("=============sig", sig);
  const extendedSig = new ExtendedSecp256k1Signature(sig.r(), sig.s(), recoveryIndex);
  try {
    const recoveredPubKey = await Secp256k1.recoverPubkey(extendedSig, hash);
    const address = `0x${pubToAddress(Buffer.from(recoveredPubKey), true).toString("hex")}`;
    console.log(
      "=============recoveredPubKey",
      toBase64(Secp256k1.compressPubkey(recoveredPubKey)),
    );
    // return pubkeyToAddress(
    //   {
    //     type: "tendermint/PubKeySecp256k1",
    //     value: toBase64(Secp256k1.compressPubkey(recoveredPubKey)),
    //   },
    //   "titan",
    // );
    const compressedPubKey = fromHex(address.replace("0x", ""));
    return toBech32("titan", compressedPubKey);
  } catch {
    return null;
  }
}

export async function verifySignature(
  address: string,
  signature: string,
  hash: Uint8Array,
): Promise<boolean> {
  for (let i = 0; i < 4; i++) {
    const recoveredAddress = await recoverSigningAddress(signature, hash, i);
    console.log("=============recoveredAddress", recoveredAddress);
    if (recoveredAddress === address) {
      return true;
    }
  }
  return false;
}

export const verifyAminoSignature = (address: string, signature: string, signDoc: StdSignDoc) => {
  console.log("=============verifyAminoSignature");
  const messageHash = new Keccak256(serializeSignDoc(signDoc)).digest();
  return verifySignature(address, signature, messageHash);
};
