import { JsonRpcRequest } from "@walletconnect/jsonrpc-utils";

import { NamespaceMetadata, ChainMetadata, ChainRequestRender } from "../helpers";

export const CosmosChainData = {
  // "cosmoshub-4": {
  //   name: "Cosmos Hub",
  //   id: "cosmos:cosmoshub-4",
  //   rpc: ["https://rpc.cosmos.network"],
  //   slip44: 118,
  //   testnet: false,
  // },
  "titan_18889-1": {
    name: "Titan Testnet",
    id: "cosmos:titan_18889-1",
    rpc: ["https://titan-testnet-json-rpc.titanlab.io"],
    slip44: 118,
    testnet: true,
  },
  // "irishub-1": {
  //   name: "Irisnet",
  //   id: "cosmos:irishub-1",
  //   rpc: ["https://rpc.irisnet.org"],
  //   slip44: 566,
  //   testnet: false,
  // },
  // "kava-4": {
  //   name: "Kava",
  //   id: "cosmos:kava-4",
  //   rpc: ["https://kava4.data.kava.io"],
  //   slip44: 459,
  //   testnet: false,
  // },
  // "columbus-4": {
  //   name: "Terra",
  //   id: "cosmos:columbus-4",
  //   rpc: [],
  //   slip44: 330,
  //   testnet: false,
  // },
};

export const CosmosMetadata: NamespaceMetadata = {
  "cosmoshub-4": {
    logo: "/assets/" + "cosmos-cosmoshub-4.png",
    rgb: "27, 31, 53",
  },
  "titan_18889-1": {
    logo: "/assets/" + "cosmos-cosmoshub-4.png",
    rgb: "27, 31, 53",
  },
};

export function getChainMetadata(chainId: string): ChainMetadata {
  const reference = chainId.split(":")[1];
  const metadata = CosmosMetadata[reference];
  if (typeof metadata === "undefined") {
    throw new Error(`No chain metadata found for chainId: ${chainId}`);
  }
  return metadata;
}

export function getChainRequestRender(request: JsonRpcRequest): ChainRequestRender[] {
  return [
    { label: "Method", value: request.method },
    {
      label: "params",
      value: JSON.stringify(request.params, null, "\t"),
    },
  ];
}
