// === IMPORTS =================================================================
use aiken/bytearray
use aiken/cbor
use aiken/pairs
use aiken/transaction.{
  InlineDatum, Input, Output, Publish, ScriptContext, Spend, Transaction, WithdrawFrom,
}
use aiken/transaction/certificate.{CredentialDeregistration}
use aiken/transaction/credential.{Address, Inline, ScriptCredential}
use aiken/transaction/value
use cardano_account/constants as constants
use cardano_account/types.{Account, AccountDatum, NoDatum}
use cardano_account/utils.{ScriptHash} as utils

// === DATATYPES ===============================================================
type Intent {
  UpdatePubkey { signature: ByteArray }
  DeleteAccount
  ProveActivity
}

type AccountAction {
  Authorized { signature: ByteArray, intent: Intent }
  OpenClaim
}

type WithdrawAction {
  VerifySpentAccount { accounts_input_index: Int }
  VerifyStaleness { reference_input_index: Int }
}

// === THE VALIDATOR ===========================================================
validator(record_script_hash: ScriptHash, username: ByteArray) {
  fn spend(in_datum: AccountDatum, action: AccountAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, withdrawals, validity_range, .. } =
      tx

    when in_datum is {
      NoDatum -> {
        let Output { address: own_address, .. } =
          utils.resolve_output_reference(inputs, own_out_ref)

        let own_withdrawal = Inline(own_address.payment_credential)

        // This transaction has to be witnessed by the reward withdrawal
        // endpoint of this validator. This allows efficient batch spends.
        pairs.has_key(withdrawals, own_withdrawal)
      }
      Account { pubkey, nonce, latest_activity: _ } -> {
        when action is {
          Authorized { signature, intent } -> {
            // For changing the stored public key, or deleting the account, only
            // 1 UTxO must be getting spent from a script address (i.e. this
            // script).
            expect Input {
              output: Output {
                address: Address {
                  payment_credential: ScriptCredential(own_script_hash),
                  ..
                },
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
                    address: Address {
                      payment_credential: ScriptCredential(out_script_hash),
                      ..
                    },
                    value: out_value,
                    datum: InlineDatum(out_datum_data),
                    reference_script: None,
                  },
                  ..
                ] = outputs

                expect Account {
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
                  own_script_hash == out_script_hash,
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
              DeleteAccount -> {
                let entrys_tn =
                  username
                    |> bytearray.push(constants.entrys_token_name_byte_value)

                let expected_mint =
                  value.merge(
                    value.from_asset(record_script_hash, entrys_tn, -1),
                    value.from_asset(record_script_hash, accounts_tn, -1),
                  )
                    |> value.to_minted_value

                (mint == expected_mint)?
              }
              ProveActivity -> {
                expect [
                  Output {
                    address: Address {
                      payment_credential: ScriptCredential(cont_script_hash),
                      ..
                    },
                    datum: InlineDatum(cont_datum_data),
                    value: cont_value,
                    reference_script: None,
                  },
                  ..
                ] = outputs
                expect Account {
                  pubkey: cont_pubkey,
                  nonce: cont_nonce,
                  latest_activity: cont_latest_activity,
                } = cont_datum_data
                and {
                  utils.outputs_signed_by_ed25519_key(
                    pubkey,
                    outputs,
                    signature,
                  ),
                  cont_script_hash == own_script_hash,
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
            let mint_qty = mint |> utils.get_two_mint_nfts_of(record_script_hash)
            mint_qty == -1
          }
        }
      }
    }
  }

  // Verifies the authentic account UTxO is being spent, and that the outputs of
  // the transaction are signed by the stored ED25519 public key.
  fn withdraw(withdraw_action: WithdrawAction, ctx: ScriptContext) {
    let ScriptContext { transaction: tx, purpose } = ctx

    let Transaction { inputs, reference_inputs, redeemers, validity_range, .. } =
      tx
    when withdraw_action is {
      VerifySpentAccount { accounts_input_index } -> {
        expect WithdrawFrom(Inline(ScriptCredential(own_script_hash))) = purpose
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
      VerifyStaleness { reference_input_index } -> {
        let own_script_hash = {
          when purpose is {
            WithdrawFrom(Inline(ScriptCredential(script_hash))) -> script_hash
            Publish(CredentialDeregistration(Inline(ScriptCredential(script_hash)))) -> script_hash
            _ -> fail @"Unexpected script purpose"
          }
        }
        expect Input {
          output: Output { datum: InlineDatum(accounts_datum_data), .. },
          ..
        } =
          utils.get_authentic_input_at(
            reference_inputs,
            own_script_hash,
            record_script_hash,
            username |> bytearray.push(constants.accounts_token_name_byte_value),
            reference_input_index,
          )

        // Recorded latest activity in account's datum must date back to at
        // `constants.allowed_inactivity_period` milliseconds ago.
        expect Account { latest_activity, .. } = accounts_datum_data
        (utils.get_upper_bound(validity_range) - latest_activity > constants.allowed_inactivity_period)?
      }
    }
  }
}
