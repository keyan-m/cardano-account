use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Inline, Script}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use cardano_account/types.{Contributor, Entry}
use cardano_account/utils as utils

validator treasury(record_script_hash: ScriptHash) {
  spend(
    datum: Option<Contributor>,
    _: Data,
    __: OutputReference,
    tx: Transaction,
  ) {
    expect Some(contributor) = datum

    let Contributor(_, contributors_stake_credential) = contributor

    let Transaction { inputs, outputs, mint, .. } = tx

    // Apart from UTxOs spent from `record` script, only one script UTxO is
    // expected to be spent, which will be from this `treasury` contract.
    expect [_] =
      list.filter(
        inputs,
        fn(i) {
          !(i.output.address.payment_credential == Script(record_script_hash))
        },
      )

    let mint_qty = utils.get_two_mint_nfts_of(mint, record_script_hash)

    // Note that this ordering must remain in sync with `record`'s new account
    // minting endpoint.
    // 1. Updated previous entry input ------> (record script)
    // 2. New entry -------------------------> (record script)
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
      // Contributor must be stored in record entry's datum
      new_entrys_contributor == contributor,
    }?
  }

  else(_) {
    fail
  }
}
