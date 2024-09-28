use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Inline, Script}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use cardano_account/types.{Contributor, Entry, RecordDatum}
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

    // `record` contract's `MintNewAccount` must be the invoked endpoint. Note
    // the mint quantity of 3 implies this (and therefore it must remain in
    // sync!).
    let mint_qty =
      utils.get_single_mint_quantity_of(mint, record_script_hash)
    expect (mint_qty == 3)?

    // Apart from UTxOs spent from `record` script, only one script UTxO is
    // expected to be spent, which will be from this `treasury` contract.
    let records_script = Script(record_script_hash)
    expect [_] =
      list.filter(
        inputs,
        fn(i) {
          !(i.output.address.payment_credential == records_script)
        },
      )

    // Note that this ordering must remain in sync with `record`'s new account
    // minting endpoint.
    // 1. Updated previous entry input
    // 2. New entry
    // 3. User's account UTxO
    // 4. User's account reference script
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
      Output {
        address: Address {
          stake_credential: Some(Inline(ref_scripts_stake_credential)),
          ..
        },
        ..
      },
      ..
    ] = outputs
    expect Entry { contributor: new_entrys_contributor, .. }: RecordDatum =
      new_entrys_datum_data
    and {
      // Staking parts of the 3 newly produced UTxOs must match that of
      // contributor's
      new_entrys_stake_credential == contributors_stake_credential,
      users_account_stake_credential == contributors_stake_credential,
      ref_scripts_stake_credential == contributors_stake_credential,
      // Contributor must be stored in record entry's datum
      new_entrys_contributor == contributor,
    }?
  }

  else(_) {
    fail
  }
}
