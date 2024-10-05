// === IMPORTS =================================================================
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, Signature}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Spend, Transaction,
}
use cardano_account/types.{
  Account, AuthorizedSpend, Contributor, Entry, RecordDatum, RecordSpendAction,
}
use cardano_account/utils as utils

// === DATATYPES ===============================================================
pub type AccountSpendAction {
  VerifySpentAccount { accounts_input_index: Int }
  VerifyAuthority { accounts_reference_input_index: Int, signature: Signature }
  VerifyStaleness {
    accounts_reference_input_index: Int,
    record_entrys_reference_input_index: Int,
  }
}

// === THE VALIDATOR ===========================================================
validator account(record_script_hash: ScriptHash, username: ByteArray) {
  // Depending on the redeemer, it either validates account's authentication
  // UTxO is spent/referred (and subsequently the tx is signed by the stored
  // ED25519 key), or the account is stale and can be claimed (either by its
  // original contributor, or enough time has passed that it's open for public
  // claim).
  spend(
    _datum: Option<Datum>,
    action: AccountSpendAction,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction {
      extra_signatories,
      inputs,
      outputs,
      redeemers,
      reference_inputs,
      validity_range,
      ..
    } = tx

    when action is {
      VerifySpentAccount { accounts_input_index } -> {
        let Input {
          output_reference: accounts_out_ref,
          output: accounts_resolved_input,
        } =
          utils.get_authentic_input_of_at(
            inputs,
            record_script_hash,
            username,
            accounts_input_index,
          )

        expect Some(account_spend_redeemer_data) =
          pairs.get_first(redeemers, Spend(accounts_out_ref))

        expect AuthorizedSpend { .. }: RecordSpendAction =
          account_spend_redeemer_data

        expect InlineDatum(accounts_datum_data) = accounts_resolved_input.datum

        expect accounts_datum: RecordDatum = accounts_datum_data

        when accounts_datum is {
          Account { .. } -> True
          _ -> False
        }
      }
      VerifyAuthority { accounts_reference_input_index, signature } -> {
        expect Input {
          output: Output { datum: InlineDatum(accounts_datum_data), .. },
          ..
        } =
          utils.get_authentic_input_of_at(
            reference_inputs,
            record_script_hash,
            username,
            accounts_reference_input_index,
          )
        expect Account { pubkey, .. }: RecordDatum = accounts_datum_data
        utils.outputs_signed_by_ed25519_key(pubkey, outputs, signature)?
      }
      VerifyStaleness {
        accounts_reference_input_index,
        record_entrys_reference_input_index,
      } -> {
        expect Input {
          output: Output { datum: InlineDatum(accounts_datum_data), .. },
          ..
        } =
          utils.get_authentic_input_of_at(
            reference_inputs,
            record_script_hash,
            username,
            accounts_reference_input_index,
          )
        expect Input {
          output: Output { datum: InlineDatum(entrys_datum_data), .. },
          ..
        } =
          utils.get_authentic_input_of_at(
            reference_inputs,
            record_script_hash,
            username,
            record_entrys_reference_input_index,
          )

        // Closing account must be considered stale.
        expect Account { latest_activity, .. }: RecordDatum =
          accounts_datum_data
        expect Entry {
          contributor: Contributor {
            verification_key_hash: entrys_contributor,
            ..
          },
          ..
        }: RecordDatum = entrys_datum_data
        utils.account_is_stale(
          latest_activity,
          entrys_contributor,
          extra_signatories,
          validity_range,
        )?
      }
    }
  }

  else(_) {
    fail
  }
}
