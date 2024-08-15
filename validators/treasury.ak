use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Output, Redeemer, ScriptContext, Spend, Transaction,
}
use aiken/transaction/credential.{Address, Inline, ScriptCredential}
use cardano_account/utils.{ScriptHash} as utils

type Contributor {
  address: Address,
}

validator(record_script_hash: ScriptHash) {
  fn spend(contributor: Contributor, input_index: Int, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, .. } = tx

    expect [
      Input {
        output: Output {
          address: Address {
            payment_credential: ScriptCredential(own_script_hash),
            ..
          },
          ..
        },
        output_reference: filtered_output_reference,
      },
    ] =
      list.filter(
        inputs,
        fn(i) {
          !(i.output.address.payment_credential == ScriptCredential(
            record_script_hash,
          ))
        },
      )

    let mint_qty = utils.get_two_mint_nfts_of(mint, record_script_hash)

    expect and {
        // Apart from UTxOs spent from `record` script, only one UTxO is expected
        // to be spent, which will be from this `treasury` contract.
        filtered_output_reference == own_out_ref,
        // `record` contract's `MintNewAccount` must be the invoked endpoint.
        mint_qty == 1,
      }?

    // Note that this ordering must remain in sync with `record`'s new account
    // minting endpoint.
    // 1. Updated previous entry input ------> (this script)
    // 2. New entry -------------------------> (this script)
    // 3. User's account UTxO ---------------> (outside)
    expect [
      _updated_previous_entrys_utxo,
      Output {
        address: Address {
          stake_credential: Some(Inline(new_entrys_stake_credential)),
          ..
        },
        datum: InlineDatum(new_entrys_datum_data),
        ..
      },
      Output {
        address: Address {
          stake_credential: Some(Inline(users_account_stake_credential)),
          ..
        },
        datum: InlineDatum(users_account_datum_data),
        ..
      },
      ..
    ] = outputs
    True
  }
}
