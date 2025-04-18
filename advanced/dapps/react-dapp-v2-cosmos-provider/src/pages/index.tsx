import React, { useState } from "react";
import { RELAYER_SDK_VERSION as version } from "@walletconnect/core";
import { formatDirectSignDoc, stringifySignDocValues, verifyDirectSignature } from "cosmos-wallet";

import Banner from "./../components/Banner";
import Blockchain from "./../components/Blockchain";
import Column from "./../components/Column";
import Header from "./../components/Header";
import Modal from "./../components/Modal";
import { DEFAULT_MAIN_CHAINS } from "./../constants";
import { AccountAction } from "./../helpers";
import RequestModal from "./../modals/RequestModal";
import PingModal from "./../modals/PingModal";
import {
  SAccounts,
  SAccountsContainer,
  SButtonContainer,
  SContent,
  SLanding,
  SLayout,
} from "./../components/app";
import { useWalletConnectClient } from "./../contexts/ClientContext";
import { verifyAminoSignature } from "../helpers/amino-verifier";
import { AminoMsg, StdSignDoc } from "@cosmjs/amino";
import { AuthInfo, Fee, TxBody, TxRaw } from "cosmjs-types/cosmos/tx/v1beta1/tx";
import { MsgSend } from "cosmjs-types/cosmos/bank/v1beta1/tx";
import { PubKey } from "cosmjs-types/cosmos/crypto/secp256k1/keys";
import { SignMode } from "cosmjs-types/cosmos/tx/signing/v1beta1/signing";
import { fromBase64 } from "@cosmjs/encoding";
import axios from "axios";
import { coins } from "@cosmjs/amino";

interface IFormattedRpcResponse {
  method?: string;
  address?: string;
  valid?: boolean;
  result: string;
}

interface CosmosRpcResponse {
  pub_key: {
    type: string;
    value: string;
  };
  signature: string;
}

export default function App() {
  const [isRpcRequestPending, setIsRpcRequestPending] = useState(false);
  const [rpcResult, setRpcResult] = useState<IFormattedRpcResponse | null>();

  const [modal, setModal] = useState("");

  const closeModal = () => setModal("");
  const openPingModal = () => setModal("ping");
  const openRequestModal = () => setModal("request");

  // Initialize the WalletConnect client.
  const {
    client,
    session,
    disconnect,
    chain,
    accounts,
    balances,
    chainData,
    isInitializing,
    onEnable,
    cosmosProvider,
  } = useWalletConnectClient();

  const ping = async () => {
    if (typeof client === "undefined") {
      throw new Error("WalletConnect Client is not initialized");
    }

    try {
      setIsRpcRequestPending(true);
      const session = cosmosProvider?.session;
      if (!session) return;
      await cosmosProvider.client?.ping({ topic: session.topic! });
      setRpcResult({
        address: "",
        method: "ping",
        valid: true,
        result: "success",
      });
    } catch (error) {
      console.error("RPC request failed:", error);
    } finally {
      setIsRpcRequestPending(false);
    }
  };

  const onPing = async () => {
    openPingModal();
    await ping();
  };

  const testSignDirect: (account: string) => Promise<IFormattedRpcResponse> = async account => {
    if (!cosmosProvider) {
      throw new Error("cosmosProvider not connected");
    }

    // test direct sign doc inputs
    const inputs = {
      fee: [{ amount: "2000", denom: "ucosm" }],
      pubkey: "AgSEjOuOr991QlHCORRmdE5ahVKeyBrmtgoYepCpQGOW",
      gasLimit: 200000,
      accountNumber: 1,
      sequence: 1,
      bodyBytes:
        "0a90010a1c2f636f736d6f732e62616e6b2e763162657461312e4d736753656e6412700a2d636f736d6f7331706b707472653766646b6c366766727a6c65736a6a766878686c63337234676d6d6b38727336122d636f736d6f7331717970717870713971637273737a673270767871367273307a716733797963356c7a763778751a100a0575636f736d120731323334353637",
      authInfoBytes:
        "0a500a460a1f2f636f736d6f732e63727970746f2e736563703235366b312e5075624b657912230a21034f04181eeba35391b858633a765c4a0c189697b40d216354d50890d350c7029012040a020801180112130a0d0a0575636f736d12043230303010c09a0c",
    };

    // format sign doc
    const signDoc = formatDirectSignDoc(
      inputs.fee,
      inputs.pubkey,
      inputs.gasLimit,
      inputs.accountNumber,
      inputs.sequence,
      inputs.bodyBytes,
      "cosmoshub-4",
    );

    const address = account.split(":").pop();

    if (!address) {
      throw new Error(`Could not derive address from account: ${account}`);
    }

    // cosmos_signDirect params
    const params = {
      signerAddress: address,
      signDoc: stringifySignDocValues(signDoc),
    };

    const result = await cosmosProvider.request<CosmosRpcResponse>({
      method: "cosmos_signDirect",
      params,
    });

    const valid = await verifyDirectSignature(address, result.signature, signDoc);

    return {
      method: "cosmos_signDirect",
      address,
      valid,
      result: result.signature,
    };
  };

  const testSignAmino: (account: string) => Promise<IFormattedRpcResponse> = async account => {
    if (!cosmosProvider) {
      throw new Error("cosmosProvider not connected");
    }
    console.log("=============testSignAmino", account);

    const address = account.split(":").pop();

    if (!address) {
      throw new Error(`Could not derive address from account: ${account}`);
    }

    const accountRes = await axios.get(
      `https://titan-testnet-lcd.titanlab.io/cosmos/auth/v1beta1/accounts/${address}`,
    );
    console.log("=============accountRes", accountRes);

    const sendMsg: AminoMsg = {
      type: "cosmos-sdk/MsgSend",
      value: {
        from_address: address,
        to_address: address,
        amount: [{ denom: "atkx", amount: "100000000000000000" }],
      },
    };

    // test amino sign doc
    const signDoc: StdSignDoc = {
      chain_id: "titan_18889-1",
      account_number: accountRes.data.account.base_account.account_number,
      sequence: accountRes.data.account.base_account.sequence,
      fee: {
        amount: [
          {
            denom: "atkx",
            amount: "13749600000000000",
          },
        ],
        gas: "127496",
      },
      msgs: [sendMsg],
      memo: "test",
    };

    // cosmos_signAmino params
    const params = { signerAddress: address, signDoc };

    const result = await cosmosProvider.request<CosmosRpcResponse>({
      method: "cosmos_signAmino",
      params,
    });
    console.log("=============testSignAmino", result);
    const { signature, pub_key } = result.signature as any;
    const valid = await verifyAminoSignature(address, signature, signDoc);
    console.log("=============valid", valid, pub_key);

    const bodyByte = TxBody.encode(
      TxBody.fromPartial({
        messages: [
          {
            typeUrl: "/cosmos.bank.v1beta1.MsgSend",
            value: MsgSend.encode({
              fromAddress: address,
              toAddress: address,
              amount: [{ denom: "atkx", amount: "100000000000000000" }],
            }).finish(),
          },
        ],
        memo: "test",
      }),
    ).finish();
    const authInfoBytes = AuthInfo.encode({
      signerInfos: [
        {
          publicKey: {
            typeUrl: "/ethermint.crypto.v1.ethsecp256k1.PubKey",
            value: PubKey.encode({
              key: fromBase64(pub_key.value.key),
              // key: pub_key.value.key,
            }).finish(),
          },
          modeInfo: {
            single: {
              mode: SignMode.SIGN_MODE_LEGACY_AMINO_JSON,
            },
          },
          sequence: BigInt(accountRes.data.account.base_account.sequence),
        },
      ],
      fee: Fee.fromPartial({
        amount: [...signDoc.fee.amount],
        gasLimit: BigInt("127496"),
      }),
    }).finish();

    const tx = TxRaw.encode({
      bodyBytes: bodyByte,
      authInfoBytes: authInfoBytes,
      signatures: [fromBase64(signature)],
    }).finish();

    console.log("=============tx", tx);
    const res = await axios.post(
      `https://titan-testnet-lcd.titanlab.io/cosmos/tx/v1beta1/txs`,
      JSON.stringify({
        tx_bytes: Buffer.from(tx).toString("base64"),
        mode: "BROADCAST_MODE_SYNC",
      }),
    );
    console.log("=============res", res);
    return {
      method: "cosmos_signAmino",
      address,
      valid,
      result: result.signature,
    };
  };

  const getCosmosActions = (): AccountAction[] => {
    const wrapRpcRequest =
      (rpcRequest: (account: string) => Promise<IFormattedRpcResponse>) =>
      async (account: string) => {
        openRequestModal();
        try {
          setIsRpcRequestPending(true);
          console.log("=============account", account);
          const result = await rpcRequest(account);
          console.log("=============result", result);
          setRpcResult(result);
        } catch (error) {
          console.error("RPC request failed:", error);
          setRpcResult({ result: (error as Error).message as string });
        } finally {
          setIsRpcRequestPending(false);
        }
      };

    return [
      { method: "cosmos_signDirect", callback: wrapRpcRequest(testSignDirect) },
      { method: "cosmos_signAmino", callback: wrapRpcRequest(testSignAmino) },
    ];
  };

  // Renders the appropriate model for the given request that is currently in-flight.
  const renderModal = () => {
    switch (modal) {
      case "request":
        return <RequestModal pending={isRpcRequestPending} result={rpcResult} />;
      case "ping":
        return <PingModal pending={isRpcRequestPending} result={rpcResult} />;
      default:
        return null;
    }
  };

  const renderContent = () => {
    const chainOptions = DEFAULT_MAIN_CHAINS;
    return !accounts.length && !Object.keys(balances).length ? (
      <SLanding center>
        <Banner />
        <h6>
          <span>{`Using v${version}`}</span>
        </h6>
        <SButtonContainer>
          <h6>Select Cosmos chain:</h6>
          {chainOptions.map(chainId => (
            <Blockchain key={chainId} chainId={chainId} chainData={chainData} onClick={onEnable} />
          ))}
        </SButtonContainer>
      </SLanding>
    ) : (
      <SAccountsContainer>
        <h3>Account</h3>
        <SAccounts>
          {accounts.map(account => {
            return (
              <Blockchain
                key={account}
                active={true}
                chainData={chainData}
                address={account}
                chainId={chain}
                balances={balances}
                actions={getCosmosActions()}
              />
            );
          })}
        </SAccounts>
      </SAccountsContainer>
    );
  };

  return (
    <SLayout>
      <Column maxWidth={1000} spanHeight>
        <Header ping={onPing} disconnect={disconnect} session={session} />
        <SContent>{isInitializing ? "Loading..." : renderContent()}</SContent>
      </Column>
      <Modal show={!!modal} closeModal={closeModal}>
        {renderModal()}
      </Modal>
    </SLayout>
  );
}
