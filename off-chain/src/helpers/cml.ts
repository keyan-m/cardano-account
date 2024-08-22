import * as CML from "@dcspark/cardano-multiplatform-lib-browser";
import { Assets, PolicyId, TxOutput } from "@lucid-evolution/lucid";
import { flattenAssets } from "../utils";
import { TokenName } from "../types";


export function assetsToValue(assets: Assets): CML.Value {
  // {{{
  const flattenedAssets = flattenAssets(assets);
  const multiAsset = CML.MultiAsset.new();
  flattenedAssets.map(
    ([policyHex, tokenNameHex, qty]: [PolicyId, TokenName, bigint]) => {
      if (policyHex !== "") {
        const assetQty = CML.MapAssetNameToCoin.new();
        assetQty.insert(CML.AssetName.from_cbor_hex(tokenNameHex), qty);
        multiAsset.insert_assets(CML.ScriptHash.from_hex(policyHex), assetQty);
      }
    }
  );
  const flattenedLovelaces = flattenedAssets.find(
    ([policyHex, _tokenNameHex, _qty]) => policyHex === ""
  );
  return CML.Value.new(
    flattenedLovelaces ? flattenedLovelaces[2] : BigInt(0),
    multiAsset
  );
  // }}}
}

export function txOutputToTransactionOutput(
  txOut: TxOutput
): CML.TransactionOutput {
  // {{{
  const txOutBuilder = CML.TransactionOutputBuilder.new().with_address(
    CML.Address.from_bech32(txOut.address)
  );
  if (txOut.scriptRef) {
    if (txOut.scriptRef.type === "PlutusV1") {
      txOutBuilder.with_reference_script(
        CML.Script.new_plutus_v1(
          CML.PlutusV1Script.from_cbor_hex(txOut.scriptRef.script)
        )
      );
    } else if (txOut.scriptRef.type === "PlutusV2") {
      txOutBuilder.with_reference_script(
        CML.Script.new_plutus_v2(
          CML.PlutusV2Script.from_cbor_hex(txOut.scriptRef.script)
        )
      );
      // } else if (txOut.scriptRef.type === "PlutusV3") {
      //   txOutBuilder.with_reference_script(CML.Script.new_plutus_v3(CML.PlutusV3Script.from_cbor_hex(txOut.scriptRef.script)));
    } else {
      txOutBuilder.with_reference_script(
        CML.Script.new_native(
          CML.NativeScript.from_cbor_hex(txOut.scriptRef.script)
        )
      );
    }
  }
  if (txOut.datum) {
    txOutBuilder.with_data(CML.DatumOption.from_cbor_hex(txOut.datum));
  }
  return txOutBuilder
    .next()
    .with_value(assetsToValue(txOut.assets))
    .build()
    .output();
  // }}}
}

/*

[
  Output {
    address: Address {
      payment_credential: ScriptCredential(
        #"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
      ),
      stake_credential: None,
    },
    value: Value(
      Dict(
        [
          Pair(#"", Dict([Pair(#"", 200000)])),
          Pair(#"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
          Dict([Pair(#"9e", 1)])),
        ],
      ),
    ),
    datum: InlineDatum(1),
    reference_script: None,
  },
  Output {
    address: Address {
      payment_credential: ScriptCredential(
        #"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
      ),
      stake_credential: None,
    },
    value: Value(
      Dict(
        [
          Pair(#"", Dict([Pair(#"", 200000)])),
          Pair(#"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
          Dict([Pair(#"9e", 1)])),
        ],
      ),
    ),
    datum: InlineDatum(1),
    reference_script: None,
  },
  Output {
    address: Address {
      payment_credential: ScriptCredential(
        #"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
      ),
      stake_credential: None,
    },
    value: Value(
      Dict([Pair(#"", Dict([Pair(#"", 200000)]))]),
    ),
    datum: InlineDatum(1),
    reference_script: None,
  },
  Output {
    address: Address {
      payment_credential: ScriptCredential(
        #"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
      ),
      stake_credential: None,
    },
    value: Value(
      Dict([Pair(#"", Dict([Pair(#"", 200000)]))]),
    ),
    datum: InlineDatum(1),
    reference_script: None,
  },
  Output {
    address: Address {
      payment_credential: ScriptCredential(
        #"9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616",
      ),
      stake_credential: None,
    },
    value: Value(
      Dict([Pair(#"", Dict([Pair(#"", 200000)]))]),
    ),
    datum: InlineDatum(1),
    reference_script: None,
  },
]

h'9FD8799FD8799FD87A9F581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616FFD87A80FFA240A1401A00030D40581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616A1419E01D87B9F01FFD87A80FFD8799FD8799FD87A9F581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616FFD87A80FFA240A1401A00030D40581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616A1419E01D87B9F01FFD87A80FFD8799FD8799FD87A9F581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616FFD87A80FFA140A1401A00030D40D87B9F01FFD87A80FFD8799FD8799FD87A9F581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616FFD87A80FFA140A1401A00030D40D87B9F01FFD87A80FFD8799FD8799FD87A9F581C9EE6DFB61A2FB903DF487C401663825643BB825D41695E63DF8AF616FFD87A80FFA140A1401A00030D40D87B9F01FFD87A80FFFF'
*/
