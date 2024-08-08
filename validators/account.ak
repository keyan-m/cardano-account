// === IMPORTS =================================================================
use aiken/bytearray
use aiken/cbor
use aiken/list
use aiken/pairs
use aiken/transaction.{
  InlineDatum, Input, Output, ScriptContext, Spend, Transaction, WithdrawFrom,
}
use aiken/transaction/credential.{Address, Inline, ScriptCredential}
use aiken/transaction/value
use cardano_account/constants.{
  accounts_token_name_byte_value, entrys_token_name_byte_value,
}
use cardano_account/types.{Account, AccountDatum, NoDatum}
use cardano_account/utils.{
  ScriptHash, get_single_asset_from_value_apart_from_ada,
  outputs_signed_by_ed25519_key, resolve_output_reference,
} as utils

// === DATATYPES ===============================================================
type Intent {
  UpdatePubkey { signature: ByteArray }
  DeleteAccount
}

type AccountAction {
  signature: ByteArray,
  intent: Intent,
}

type WithdrawAction {
  reference_input_index: Int,
  signature: ByteArray,
}

// === THE VALIDATOR ===========================================================
validator(record_script_hash: ScriptHash, username: ByteArray) {
  fn spend(in_datum: AccountDatum, action: AccountAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, withdrawals, .. } = tx

    let AccountAction { signature, intent } = action

    when in_datum is {
      NoDatum -> {
        let Output { address: own_address, .. } =
          resolve_output_reference(inputs, own_out_ref)

        let own_withdrawal = Inline(own_address.payment_credential)

        // This transaction has to be witnessed by the reward withdrawal
        // endpoint of this validator. This allows efficient batch spends.
        pairs.has_key(withdrawals, own_withdrawal)
      }
      Account { pubkey, nonce: _nonce } -> {
        // For changing the stored public key, or deleting the account, only 1
        // UTxO must be getting spent from a script address (i.e. this script).
        expect [
          Input {
            output: Output {
              address: Address {
                payment_credential: ScriptCredential(own_script_hash),
                ..
              },
              value: in_value,
              ..
            },
            output_reference: own_out_ref,
          },
        ] =
          list.filter(
            inputs,
            fn(i) {
              let Input {
                output: Output {
                  address: Address { payment_credential, .. },
                  ..
                },
                ..
              } = i
              when payment_credential is {
                ScriptCredential(_) -> True
                _ -> False
              }
            },
          )
        let (accounts_policy, accounts_token_name, accounts_qty) =
          get_single_asset_from_value_apart_from_ada(in_value)

        let accounts_tn =
          username |> bytearray.push(accounts_token_name_byte_value)

        // 1. Spent UTxO must be authentic
        // 2. Outputs must be signed by account owner
        expect and {
            outputs_signed_by_ed25519_key(pubkey, outputs, signature),
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

            expect Account { pubkey: new_pubkey, nonce: new_nonce } =
              out_datum_data

            // 1. Account UTxO must go back to the script
            // 2. Account's value must remain unchanged (this is fine as the
            //    datum size won't change)
            // 3. Outputs must also be signed by the new key pair, to ensure the
            //    new public key is correct
            // 4. New nonce must be equal to output reference of the spent UTxO
            and {
              own_script_hash == out_script_hash,
              in_value == out_value,
              !(new_pubkey == pubkey),
              outputs_signed_by_ed25519_key(
                new_pubkey,
                outputs,
                signature_with_new_key,
              ),
              new_nonce == cbor.serialise(own_out_ref),
            }?
          }
          DeleteAccount -> {
            let entrys_tn =
              username |> bytearray.push(entrys_token_name_byte_value)

            let expected_mint =
              value.merge(
                value.from_asset(record_script_hash, entrys_tn, -1),
                value.from_asset(record_script_hash, accounts_tn, -1),
              )
                |> value.to_minted_value

            (mint == expected_mint)?
          }
        }
      }
    }
  }

  // Only checks to find the authentic account UTxO is referred to, and that the
  // outputs of the transaction are signed by the stored ED25519 public key.
  fn withdraw(withdraw_action: WithdrawAction, ctx: ScriptContext) {
    expect ScriptContext {
      transaction: tx,
      purpose: WithdrawFrom(Inline(ScriptCredential(own_script_hash))),
    } = ctx
    let Transaction { reference_inputs, outputs, .. } = tx
    let WithdrawAction { reference_input_index, signature } = withdraw_action
    expect Some(Input {
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(accounts_script_hash),
          ..
        },
        datum: InlineDatum(accounts_datum_data),
        value: accounts_value,
        ..
      },
      ..
    }) = list.at(reference_inputs, reference_input_index)
    expect Account { pubkey, nonce: _nonce } = accounts_datum_data
    let accounts_tn = username |> bytearray.push(accounts_token_name_byte_value)
    let (accounts_policy, accounts_token_name, accounts_qty) =
      utils.get_single_asset_from_value_apart_from_ada(accounts_value)
    and {
      accounts_script_hash == own_script_hash,
      outputs_signed_by_ed25519_key(pubkey, outputs, signature),
      accounts_policy == record_script_hash,
      accounts_token_name == accounts_tn,
      accounts_qty == 1,
    }?
  }
}
