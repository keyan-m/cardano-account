import {
  Data,
  LucidEvolution,
  PlutusVersion,
  Script,
  ScriptType,
  TxSignBuilder,
  applyParamsToScript,
  validatorToAddress,
} from "@lucid-evolution/lucid";
import { OutputReference, Result } from "../types";
import { flattenAssets, genericCatch } from "../utils";
import blueprint from "../../../on-chain/plutus.json";

const x = {
  a: 0,
  b: 1,
  c: 2,
  d: 3,
};

const y = Object.entries(x);
const z = y[0];
z;

export const tx = async (
  lucid: LucidEvolution
): Promise<Result<TxSignBuilder>> => {
  const network = lucid.config().network;
  try {
    const signerUTxOs = await lucid.wallet().getUtxos();
    const largeEnoughUTxO = signerUTxOs.find((u) => {
      const flattened = flattenAssets(u.assets);
      return flattened.length === 1 && flattened[0][2] >= BigInt(50_000_000);
    });
    if (largeEnoughUTxO) {
      const unappliedRecordCBOR = blueprint.validator.find(
        (v: any) => v.title === "record.mint"
      )?.compiledCode;
      const appliedRecordCBOR = applyParamsToScript(unappliedRecordCBOR, [
        Data.to(
          {
            txHash: { hash: largeEnoughUTxO.txHash },
            outputIndex: BigInt(largeEnoughUTxO.outputIndex),
          },
          OutputReference
        ),
      ]);
      const appliedRecordScript: Script = {
        type: "PlutusV2",
        script: appliedRecordCBOR,
      };
      const recordContractAddress = validatorToAddress(
        network,
        appliedRecordScript
      );
      const x = lucid.newTx().collectFrom([largeEnoughUTxO]).mintAssets(
    } else {
      return {
        type: "error",
        error: new Error(
          "Selected wallet doesn't have an ADA-only UTxO with at least 50₳."
        ),
      };
    }
  } catch (e) {
    genericCatch(e);
  }
};
