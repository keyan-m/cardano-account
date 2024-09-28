// === IMPORTS =================================================================
use aiken/crypto.{ScriptHash}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Transaction,
}
use cardano_account/types.{
  Account, Contributor, Entry, RecordDatum,
}
use cardano_account/utils as utils

// === DATATYPES ===============================================================

pub type AccountSpendAction {
  VerifySpentAccount { accounts_input_index: Int }
  VerifyStaleness {
    accounts_reference_input_index: Int,
    record_entrys_reference_input_index: Int,
  }
}

// === THE VALIDATOR ===========================================================
validator account(record_script_hash: ScriptHash, username: ByteArray) {
  // Depending on the redeemer, it either validates account's authentication
  // UTxO is spent (and subsequently the tx is signed by the stored ED25519
  // key), or the account is stale and can be claimed (either by its original
  // contributor, or enough time has passed that it's open for public claim).
  spend(
    _datum: Option<Datum>,
    action: AccountSpendAction,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction {
      extra_signatories,
      inputs,
      reference_inputs,
      validity_range,
      ..
    } = tx

    when action is {
      VerifySpentAccount { accounts_input_index } -> {
        let account_input =
          utils.get_authentic_input_of_at(
            inputs,
            record_script_hash,
            username,
            accounts_input_index,
          )

        expect InlineDatum(accounts_datum_data) = account_input.output.datum

        expect accounts_datum: RecordDatum = accounts_datum_data

        when accounts_datum is {
          Account {..} -> True
          _ -> False
        }
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
