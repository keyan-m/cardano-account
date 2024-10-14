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
use cardano/assets
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  Datum, InlineDatum, Input, Output, OutputReference, Redeemer, Transaction,
}
use cardano_account/types.{Account, RecordDatum}
use cardano_account/utils as utils

// === DATATYPES ===============================================================
pub type AccountSpendAction {
  VerifyAuthority { accounts_reference_input_index: Int, signature: Signature }
  VerifyExtraObserved
}

pub type VerifySignature {
  accounts_reference_input_index: Int,
  signature: Signature,
}

// === VALIDATORS ==============================================================
validator account_spend(observer_script: Credential) {
  // Minimal validation that only checks to see if `observer_script` is invoked.
  // This allows cheap spends of multiple UTxOs.
  spend(
    _datum: Option<Datum>,
    _action: Redeemer,
    _own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    when pairs.get_first(tx.withdrawals, observer_script) is {
      Some(_) -> True
      None -> False
    }
  }

  else(_) {
    fail
  }
}

validator account_staking(record_script_hash: ScriptHash, username: ByteArray) {
  // This validates transaction's output is signed by the reference account
  // UTxO.
  withdraw(action: VerifySignature, _own_cred: Credential, tx: Transaction) {
    let Transaction { outputs, reference_inputs, .. } = tx
    let VerifySignature { accounts_reference_input_index, signature } = action
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

  publish(_action: Redeemer, certificate: Certificate, tx: Transaction) {
    when certificate is {
      // Anyone can register
      RegisterCredential { .. } -> True
      // Unregistration can only happen when closing an account
      UnregisterCredential { .. } -> {
        expect [(mint_policy, mint_name, mint_qty)] = tx.mint |> assets.flatten
        and {
          mint_policy == record_script_hash,
          mint_name == username,
          mint_qty == -4,
        }
      }
      _ -> False
    }
  }

  else(_) {
    fail
  }
}
