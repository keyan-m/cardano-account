use aiken/list
use aiken/transaction.{
  InlineDatum, Mint, OutputReference, Output, Redeemer, ScriptContext, Transaction,
}
use aiken/transaction/credential.{ScriptCredential}
use aiken/transaction/value
use cardano_walletless_onboarding/utils as utils

type Datum {
  RecordHead { next_username: Option<ByteArray> }
}

type MintAction {
  Initiate
  NewAccount { username: ByteArray, password_hash: ByteArray }
}

validator(utxo_ref: OutputReference) {
  fn mint(action: MintAction, ctx: ScriptContext) {
    let ScriptContext { transaction: tx, purpose } = ctx

    expect Mint(own_policy) = purpose

    let Transaction { inputs, outputs, mint, .. } = tx

    expect [mint_triplet] =
      mint
        |> value.from_minted_value
        |> value.flatten

    let (mint_policy, mint_name, mint_quantity) = mint_triplet

    expect (mint_policy == own_policy)?
    when action is {
      Initiate -> {
        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted.
        expect (mint_name == #"")?
        expect (mint_quantity == 1)?

        // Only one UTxO must be produced at the script address.
        expect [
          Output {
            datum: InlineDatum(list_head_datum),
            value: list_head_value,
            ..
          },
        ] =
          list.filter(
            outputs,
            fn(output) {
              output.address.payment_credential == ScriptCredential(own_policy)
            },
          )

        // Linked list must be empty at initiation.
        expect RecordHead { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from Lovelaces.
        let list_head_asset = utils.get_single_asset_from_value(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      NewAccount { username, password_hash } -> True
    }
  }

  fn spend(_datum: Datum, _redeemer: Redeemer, _ctx: ScriptContext) {
    True
  }
}
