use aiken/collection/list
use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Inline, Script}
use cardano/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Transaction,
}
use cardano_account/types.{
  Contributor, DeployedScript, Entry, MintNewAccount, RecordDatum,
  RecordMintAction,
}
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

    let Transaction { inputs, outputs, mint, redeemers, .. } = tx

    // `record` contract's `MintNewAccount` must be the invoked endpoint.
    let records_mint_purpose = Mint(record_script_hash)
    let records_script = Script(record_script_hash)
    expect Some(mint_redeemer) = pairs.get_first(redeemers, records_mint_purpose)
    expect MintNewAccount(username, _): RecordMintAction = mint_redeemer
    let Pair(mint_name, mint_qty) =
      utils.get_single_mint_token_of(mint, record_script_hash)
    expect and {
      mint_name == username,
      mint_qty == 3,
    }?

    // Apart from UTxOs spent from `record` script, only one script UTxO is
    // expected to be spent, which will be from this `treasury` contract.
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
    // 4. User's deployed script
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
          stake_credential: Some(Inline(deployed_scripts_stake_credential)),
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
      deployed_scripts_stake_credential == contributors_stake_credential,
      // Contributor must be stored in record entry's datum
      new_entrys_contributor == contributor,
    }?
  }

  else(_) {
    fail
  }
}
