// === IMPORTS =================================================================
use aiken/primitive/bytearray
use aiken/cbor
use aiken/collection/pairs
use aiken/crypto.{ScriptHash}
use cardano/address.{
  Address, Credential, Script, VerificationKey,
}
use cardano/assets
use cardano/certificate.{Certificate, RegisterCredential, UnregisterCredential}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Spend, Transaction, ValidityRange,
}
use cardano_account/constants as constants
use cardano_account/types.{AccountDatum, Entry}
use cardano_account/utils as utils

// === DATATYPES ===============================================================
type Intent {
  UpdatePubkey { signature: ByteArray }
  ProveActivity
}

type AccountAction {
  Authorized { signature: ByteArray, intent: Intent }
  OpenClaim
}

type ObserverAction {
  VerifySpentAccount {
    accounts_input_index: Int
  }
  VerifyStaleness {
    accounts_reference_input_index: Int,
    record_entrys_reference_input_index: Int,
  }
}

// === THE VALIDATOR ===========================================================
validator account(record_script_hash: ScriptHash, username: ByteArray) {
  spend(datum: Option<AccountDatum>, action: AccountAction, own_out_ref: OutputReference, tx: Transaction) {
    let Transaction { inputs, outputs, mint, withdrawals, validity_range, .. } =
      tx

    when datum is {
      None -> {
        let Output { address: own_address, .. } =
          utils.resolve_output_reference(inputs, own_out_ref)

        // This transaction has to be witnessed by the reward withdrawal
        // endpoint of this validator. This allows efficient batch spends.
        pairs.has_key(withdrawals, own_address.payment_credential)
      }
      Some(in_datum_data) -> {
        expect AccountDatum { pubkey, nonce, latest_activity: _ } =
          in_datum_data
        when action is {
          Authorized { signature, intent } -> {
            // For changing the stored public key, or deleting the account, only
            // 1 UTxO must be getting spent from a script address (i.e. this
            // script).
            expect Input {
              output: Output {
                address: Address {
                  payment_credential: Script(own_script_hash),
                  ..
                } as own_address,
                value: in_value,
                ..
              },
              output_reference: own_out_ref,
            } = utils.get_single_script_input(inputs)

            let (accounts_policy, accounts_token_name, accounts_qty) =
              utils.get_single_asset_from_value_apart_from_ada(in_value)

            let accounts_tn =
              username
                |> bytearray.push(constants.accounts_token_name_byte_value)

            // 1. Spent UTxO must be authentic
            // 2. Outputs must be signed by account owner
            expect and {
                utils.outputs_signed_by_ed25519_key(pubkey, outputs, signature),
                accounts_policy == record_script_hash,
                accounts_token_name == accounts_tn,
                accounts_qty == 1,
              }?

            when intent is {
              UpdatePubkey { signature: signature_with_new_key } -> {
                expect [
                  Output {
                    address: out_address,
                    value: out_value,
                    datum: InlineDatum(out_datum_data),
                    reference_script: None,
                  },
                  ..
                ] = outputs

                expect AccountDatum {
                  pubkey: new_pubkey,
                  nonce: new_nonce,
                  latest_activity: new_latest_activity,
                } = out_datum_data

                // 1. Account UTxO must go back to the script
                // 2. Account's value must remain unchanged (this is fine as the
                //    datum size won't change)
                // 3. Outputs must also be signed by the new key pair, to ensure
                //    the new public key is correct
                // 4. New nonce must be equal to output reference of the spent
                //    UTxO
                and {
                  own_address == out_address,
                  in_value == out_value,
                  !(new_pubkey == pubkey),
                  utils.outputs_signed_by_ed25519_key(
                    new_pubkey,
                    outputs,
                    signature_with_new_key,
                  ),
                  new_nonce == cbor.serialise(own_out_ref),
                  new_latest_activity == utils.get_upper_bound(validity_range),
                }?
              }
              ProveActivity -> {
                expect [
                  Output {
                    address: cont_address,
                    datum: InlineDatum(cont_datum_data),
                    value: cont_value,
                    reference_script: None,
                  },
                  ..
                ] = outputs
                expect AccountDatum {
                  pubkey: cont_pubkey,
                  nonce: cont_nonce,
                  latest_activity: cont_latest_activity,
                } = cont_datum_data
                and {
                  cont_address == own_address,
                  cont_pubkey == pubkey,
                  cont_nonce == nonce,
                  cont_latest_activity == utils.get_upper_bound(validity_range),
                  cont_value == in_value,
                }?
              }
            }
          }
          OpenClaim -> {
            // Similar to `record`'s `DepleteAccount` endpoint, this only needs
            // to make sure the minting endpoint is invoked with two NFTs burnt
            // with own script hash.
            let mint_qty =
              mint |> utils.get_two_mint_nfts_of(record_script_hash)
            mint_qty == -1
          }
        }
      }
    }
  }

  // Depending on the redeemer, it either validates account's authentication
  // UTxO is spent (and subsequently the tx is signed by the stored ED25519
  // key), or the account is stale and can be claimed (either by its original
  // contributor, or enough time has passed that it's open for public claim).
  withdraw(withdraw_action: ObserverAction, own_credential: Credential, tx: Transaction) {
    let Transaction {
      extra_signatories,
      inputs,
      reference_inputs,
      redeemers,
      validity_range,
      ..
    } = tx

    when withdraw_action is {
      VerifySpentAccount { accounts_input_index } -> {
        verify_spent_account(
          inputs,
          redeemers,
          own_credential,
          record_script_hash,
          username,
          accounts_input_index,
        )?
      }
      VerifyStaleness {accounts_reference_input_index, record_entrys_reference_input_index} -> {
        verify_staleness(
          reference_inputs,
          own_credential,
          record_script_hash,
          username,
          extra_signatories,
          validity_range,
          accounts_reference_input_index,
          record_entrys_reference_input_index
        )?
      }
    }
  }

  // Allows credential registration freely, but for unregistration it'll need to
  // verify the account is stale (by requiring both account's, and its entry's
  // UTxOs present as references).
  publish(publish_action: ObserverAction, certificate: Certificate, tx: Transaction) {
    when certificate is {
      RegisterCredential(_, __) -> True
      UnregisterCredential(own_credential, _) -> {
        let Transaction {
          extra_signatories,
          inputs,
          reference_inputs,
          redeemers,
          validity_range,
          ..
        } = tx
        expect VerifyStaleness {
          accounts_reference_input_index,
          record_entrys_reference_input_index,
        } = publish_action
        verify_staleness(
          reference_inputs,
          own_credential,
          record_script_hash,
          username,
          extra_signatories,
          validity_range,
          accounts_reference_input_index,
          record_entrys_reference_input_index
        )?
      }
      _ -> False
    }
  }
}


fn verify_spent_account(
  inputs: List<Input>,
  redeemers: Pairs<ScriptPurpose, Redeemer>,
  own_credential: Credential,
  record_script_hash: ScriptHash,
  username: ByteArray,
  accounts_input_index: Int
) {
  expect Script(own_script_hash) = own_credential

  let account_input =
    utils.get_authentic_input_at(
      inputs,
      own_script_hash,
      record_script_hash,
      username |> bytearray.push(constants.accounts_token_name_byte_value),
      accounts_input_index,
    )

  // Spending of the account UTxO must be authorized.
  expect Some(accounts_redeemer_data) =
    redeemers |> pairs.get_first(Spend(account_input.output_reference))
  expect Authorized { intent, .. } = accounts_redeemer_data
  (intent == ProveActivity)?
}

fn verify_staleness(
  reference_inputs: List<Input>,
  own_credential: Credential,
  record_script_hash: ScriptHash,
  username: ByteArray,
  extra_signatories: List<PubKeyHash>,
  validity_range: ValidityRange,
  accounts_reference_input_index: Int,
  record_entrys_reference_input_index: Int,
) { expect Script(own_script_hash) = own_credential
  expect Input {
    output: Output { datum: InlineDatum(accounts_datum_data), .. },
    ..
  } =
    utils.get_authentic_input_at(
      reference_inputs,
      own_script_hash,
      record_script_hash,
      username |> bytearray.push(constants.accounts_token_name_byte_value),
      accounts_reference_input_index,
    )
  expect Input {
    output: Output { datum: InlineDatum(entrys_datum_data), .. },
    ..
  } =
    utils.get_authentic_input_at(
      reference_inputs,
      record_script_hash,
      record_script_hash,
      username |> bytearray.push(constants.entrys_token_name_byte_value),
      record_entrys_reference_input_index,
    )

  // Closing account must be considered stale.
  expect AccountDatum { latest_activity, .. } = accounts_datum_data
  expect Entry {
    contributor: Contributor {
      payment_credential: VerificationKey(
        closing_entrys_contributor,
      ),
      ..
    },
    ..
  } = entrys_datum_data
  utils.account_is_stale(
    latest_activity,
    closing_entrys_contributor,
    extra_signatories,
    validity_range,
  )?
}
