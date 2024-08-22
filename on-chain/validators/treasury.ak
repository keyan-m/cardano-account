use aiken/collection/list
use cardano/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spending, Transaction,
}
use cardano/credential.{Address, Script}
use cardano_account/types.{Entry}
use cardano_account/utils.{ScriptHash} as utils

type Contributor {
  address: Address,
}

validator(record_script_hash: ScriptHash) {
  fn spend(_: Data, __: Data, ctx: ScriptContext) {
    let ScriptContext { transaction: tx, redeemer: _, info } = ctx

    expect Spending(_, Some(contributor_data)) = info

    expect Contributor(contributors_address) = contributor_data

    let Transaction { inputs, outputs, mint, .. } = tx

    let Address { stake_credential: contributors_stake_credential, .. } =
      contributors_address

    // Apart from UTxOs spent from `record` script, only one UTxO is expected to
    // be spent, which will be from this `treasury` contract.
    expect [_] =
      list.filter(
        inputs,
        fn(i) {
          !(i.output.address.payment_credential == Script(
            record_script_hash,
          ))
        },
      )

    let mint_qty = utils.get_two_mint_nfts_of(mint, record_script_hash)

    // Note that this ordering must remain in sync with `record`'s new account
    // minting endpoint.
    // 1. Updated previous entry input ------> (this script)
    // 2. New entry -------------------------> (this script)
    // 3. User's account UTxO ---------------> (outside)
    expect [
      _updated_previous_entrys_utxo,
      Output {
        address: Address { stake_credential: new_entrys_stake_credential, .. },
        datum: InlineDatum(new_entrys_datum_data),
        ..
      },
      Output {
        address: Address {
          stake_credential: users_account_stake_credential,
          ..
        },
        ..
      },
      ..
    ] = outputs
    expect Entry { contributor: new_entrys_contributor, .. }: Entry =
      new_entrys_datum_data
    and {
      // `record` contract's `MintNewAccount` must be the invoked endpoint.
      mint_qty == 1,
      // Staking parts of the 2 newly produced UTxOs must match that of
      // contributor's
      new_entrys_stake_credential == contributors_stake_credential,
      users_account_stake_credential == contributors_stake_credential,
      // Contributor's address must be stored in record entry's datum
      new_entrys_contributor == contributors_address,
    }?
  }
}
