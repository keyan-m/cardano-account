//// ## Account Validator – User Wallet
////
//// The spending contract is a minimal logic for validating a provided
//// signature by looking up the public key hash in account's corresponding UTxO
//// stored at the linked list's (record's) contract.
////
//// The staking part (WIP) will be responsible for reward withdrawals and
//// delegations.

// === IMPORTS =================================================================
use aiken/collection/pairs
use aiken/crypto.{ScriptHash, Signature}
use cardano/address.{Credential}
use cardano/assets.{Value}
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Redeemer, Spend,
  Transaction,
}
use cardano_account/types.{
  Account, AuthorizedSpend, RecordDatum, RecordSpendAction,
}
use cardano_account/utils as utils

// === DATATYPES ===============================================================
pub type AccountSpendAction {
  VerifyAuthority { accounts_reference_input_index: Int, signature: Signature }
  VerifyExtraObserved
}

pub type AccountStakeAction {
  VerifySpentAccount { accounts_input_index: Int }
  VerifySignature { accounts_reference_input_index: Int, signature: Signature }
}

// === VALIDATORS ==============================================================
validator account_spend(
  extra_observer_script: Credential,
  record_script_hash: ScriptHash,
  username: ByteArray,
) {
  // Minimal validation that only checks to see if its authentic corresponding
  // account UTxO is referred to, so that it can verfify the provided signature.
  //
  // `extra_observer_script` is an additional script for validating more
  // advanced signatures.
  spend(
    _datum: Option<Datum>,
    action: AccountSpendAction,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { outputs, reference_inputs, withdrawals, .. } = tx
    when action is {
      VerifyAuthority { accounts_reference_input_index, signature } -> {
        verify_signature_from_reference_inputs(
          outputs,
          reference_inputs,
          record_script_hash,
          username,
          accounts_reference_input_index,
          signature,
        )
      }
      VerifyExtraObserved ->
        when pairs.get_first(withdrawals, extra_observer_script) is {
          Some(_) -> True
          None -> False
        }
    }
  }

  else(_) {
    fail
  }
}

validator account_staking(record_script_hash: ScriptHash, username: ByteArray) {
  // This validates account's authentication UTxO is spent (and subsequently the
  // tx is signed by the stored ED25519 key).
  withdraw(action: AccountStakeAction, _own_cred: Credential, tx: Transaction) {
    let Transaction {
      inputs,
      outputs,
      redeemers,
      reference_inputs,
      ..
    } = tx
    when action is {
      // For withdrawing while changing pubkey.
      VerifySpentAccount { accounts_input_index } -> {
        let Input {
          output_reference: accounts_out_ref,
          output: accounts_resolved_input,
        } = utils.get_authentic_input_of_at(
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
      VerifySignature { accounts_reference_input_index, signature } -> {
        verify_signature_from_reference_inputs(
          outputs,
          reference_inputs,
          record_script_hash,
          username,
          accounts_reference_input_index,
          signature,
        )
      }
    }
  }

  publish(_action: Redeemer, certificate: Certificate, tx: Transaction) {
    when certificate is {
      // Anyone can register
      RegisterCredential { .. } -> True
      // Unregistration can only happen when closing an account
      UnregisterCredential { .. } -> {
        validate_mint(tx.mint, record_script_hash, username, -4)?
      }
      _ -> False
    }
  }

  else(_) {
    fail
  }
}

fn verify_signature_from_reference_inputs(
  outputs: List<Output>,
  reference_inputs: List<Input>,
  record_script_hash: ScriptHash,
  username: ByteArray,
  accounts_reference_input_index: Int,
  signature: Signature,
) -> Bool {
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
  utils.outputs_signed_by_ed25519_key(pubkey, outputs, signature)
}

fn validate_mint(
  mint: Value,
  record_script_hash: ScriptHash,
  username: ByteArray,
  expected_mint_quantity: Int,
) -> Bool {
  expect [(mint_policy, mint_name, mint_qty)] = mint |> assets.flatten
  and {
    mint_policy == record_script_hash,
    mint_name == username,
    mint_qty == expected_mint_quantity,
  }
}
