//// ## Treasury Validator – Funding Source for Deployment Costs
////
//// This contract allows a single UTxO to be spent for each new account. One
//// other requirement is that all newly created UTxOs must have staking parts
//// that match that of the UTxO's contributor (store in datum).

// === IMPORTS =================================================================
use aiken/collection/list
use aiken/crypto.{ScriptHash}
use cardano/address.{Address, Inline, Script}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use cardano_account/types.{Account,
  ContributionReturn, Contributor, RecordDatum}
use cardano_account/utils as utils

// === THE VALIDATOR ===========================================================
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
    // the mint quantity of 4 implies this (and therefore it must remain in
    // sync!).
    let mint_qty = utils.get_single_mint_quantity_of(mint, record_script_hash)
    expect (mint_qty == 4)?

    // Apart from UTxOs spent from `record` script, only one script UTxO is
    // expected to be spent, which will be from this `treasury` contract.
    let records_script = Script(record_script_hash)
    expect [Input { output: Output { address: treasury_address, .. }, .. }] =
      list.filter(
        inputs,
        fn(i) { !(i.output.address.payment_credential == records_script) },
      )

    // Note that this ordering must remain in sync with `record`'s new account
    // minting endpoint.
    // 1. Updated previous entry input
    // 2. New entry
    // 3. User's account UTxO
    // 4. User's account reference script
    // 5. User's staking reference script
    expect [
      _updated_previous_entrys_utxo,
      Output {
        address: Address {
          stake_credential: Some(Inline(new_entrys_stake_credential)),
          ..
        },
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
      Output {
        address: Address {
          stake_credential: Some(Inline(spending_ref_script_stake_credential)),
          ..
        },
        ..
      },
      Output {
        address: Address {
          stake_credential: Some(Inline(staking_ref_script_stake_credential)),
          ..
        },
        ..
      },
      ..
    ] = outputs
    expect Account {
      contribution_return: Some(ContributionReturn {
        contributor: users_account_contributor,
        treasury_address: users_account_treasury_address,
      }),
      ..
    }: RecordDatum = users_account_datum_data
    and {
      // Staking parts of the 4 newly produced UTxOs must match that of
      // contributor's
      new_entrys_stake_credential == contributors_stake_credential,
      users_account_stake_credential == contributors_stake_credential,
      spending_ref_script_stake_credential == contributors_stake_credential,
      staking_ref_script_stake_credential == contributors_stake_credential,
      // Contributor must be stored in record entry's datum
      users_account_contributor == contributor,
      // This treausry's address must also be correctly stored.
      users_account_treasury_address == treasury_address,
    }?
  }

  else(_) {
    fail
  }
}
