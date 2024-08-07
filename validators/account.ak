// IMPORTS
use aiken/bytearray
use aiken/cbor
use aiken/list
use aiken/pairs
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, ScriptContext, Spend,
  Transaction,
}
use aiken/transaction/credential.{Address, Inline, ScriptCredential}
use aiken/transaction/value.{Value}
use cardano_account/constants.{
  entrys_token_name_byte_value, entrys_token_name_byte,
  accounts_token_name_byte_value, accounts_token_name_byte
}
use cardano_account/types.{AccountDatum, NoDatum, Account}
use cardano_account/utils.{
  get_single_asset_from_value_apart_from_ada,
  outputs_signed_by_ed25519_key, resolve_output_reference, ScriptHash
} as utils

// DATATYPES
type Intent {
  UpdatePubkey {
    signature: ByteArray
  }
  DeleteAccount
}

type AccountAction {
  input_index: Int,
  signature: ByteArray,
  intent: Intent,
}

// THE VALIDATOR
validator(record_script_hash: ScriptHash, username: ByteArray) {
  fn spend(in_datum: AccountDatum, action: AccountAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, withdrawals, .. } = tx

    let AccountAction { input_index, signature, intent } = action

    when in_datum is {
      NoDatum -> {
        let Output { address: own_address, .. } =
          resolve_output_reference(inputs, own_out_ref)

        let own_withdrawal = Inline(own_address.payment_credential)

        // This transaction has to be witnessed by the reward withdrawal
        // endpoint of this validator.
        pairs.has_key(withdrawals, own_withdrawal)
      }
      Account { pubkey, nonce } -> {
        // Only 1 UTxO must be getting spent from a script address (i.e. this
        // script).
        expect [
          Input {
            output: Output {
              address: Address {payment_credential: ScriptCredential(own_script_hash), ..},
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
        let (beacon_sym, beacon_tn, beacon_qty) =
          get_single_asset_from_value_apart_from_ada(in_value)

        let accounts_tn = username |> bytearray.push(accounts_token_name_byte_value)

        expect and {
          outputs_signed_by_ed25519_key(pubkey, outputs, signature),
          beacon_sym == record_script_hash,
          beacon_tn == accounts_tn,
          beacon_qty == 1,
        }?

        when intent is {
          UpdatePubkey { signature: signature_with_new_key } -> {
            expect [
              Output {
                address: Address { payment_credential: ScriptCredential(out_script_hash), .. },
                value: out_value,
                datum: InlineDatum(out_datum_data),
                reference_script: None,
              },
              ..
            ] = outputs
            expect Account {pubkey: new_pubkey, nonce: new_nonce} = out_datum_data
            and {
              own_script_hash == out_script_hash,
              in_value == out_value,
              !(new_pubkey == pubkey),
              outputs_signed_by_ed25519_key(new_pubkey, outputs, signature_with_new_key),
              new_nonce == cbor.serialise(own_out_ref),
            }?
          }
          DeleteAccount -> {
            let entrys_tn = username |> bytearray.push(entrys_token_name_byte_value)
            let expected_mint =
              value.merge(
                value.from_asset(record_script_hash, entrys_tn, -1),
                value.from_asset(own_script_hash, accounts_tn, -1),
              ) |> value.to_minted_value
            (mint == expected_mint)?
          }
        }
      }
    }
  }

  fn mint_or_withdraw(_, _ctx: ScriptContext) {
    True
  }
}
