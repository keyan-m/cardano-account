// IMPORTS
use aiken/bytearray
use aiken/cbor
use aiken/dict
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, ScriptContext, Spend,
  Transaction,
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value.{Value}
use cardano_account/constants.{
  entrys_token_name_byte_value, entrys_token_name_byte,
  accounts_token_name_byte_value, accounts_token_name_byte
}
use cardano_account/utils.{ScriptHash} as utils

// === DATATYPES ===============================================================
type Datum {
  Entry { next_username: Option<ByteArray> }
  Account { pubkey: ByteArray, nonce: ByteArray }
}

type MintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: ByteArray }
  CloseAccount {
    prev_entrys_out_ref: OutputReference,
    entrys_out_ref: OutputReference,
    signature: ByteArray,
  }
}

type SpendAction {
  AppendToNewAccount { input_index: Int }
  Deposit { input_index: Int, lovelace_count: Int }
  Withdraw { input_index: Int, signature: ByteArray }
  UpdatePubkey { input_index: Int, signature: ByteArray }
  DepleteAccount { input_index: Int }
}

// === THE VALIDATOR ===========================================================
validator(utxo_ref: OutputReference) {
  fn mint(action: MintAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Mint(own_policy) } = ctx

    let Transaction { inputs, outputs, mint, .. } = tx

    let own_script_cred = ScriptCredential(own_policy)

    when action is {
      InitiateRecord -> {
        // Initial endpoint for starting the linked list. Requirements are:
        // 1. Specified UTxO must be getting spent
        // 2. A single, nameless NFT is minted at the script address
        // 3. Output datum is `Entry { next_username: None }`

        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted.
        expect [mint_triplet] =
          mint
            |> value.from_minted_value
            |> value.flatten
        expect (_, mint_name, 1) = mint_triplet
        expect (mint_name == #"")?

        // First produced UTxO must go to the script.
        expect [
          Output {
            datum: InlineDatum(list_head_datum),
            value: list_head_value,
            address: Address { payment_credential: dest_script_cred, .. },
            reference_script: None,
          },
          ..
        ] = outputs
        expect (dest_script_cred == own_script_cred)?

        // Linked list must be empty at initiation.
        expect Entry { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from ADA.
        let list_head_asset =
          utils.get_single_asset_from_value_apart_from_ada(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      MintNewAccount { username, signature } -> {
        // Requires the proper entry in the list to be spent so that its datum
        // correctly points to the new account's username. The proper entry is
        // a previously created entry such that:
        // 1. Its own token name (i.e. `entrys_token_name_byte` + username) is
        //    smaller than the new account's entry token name
        // 2. The account it (potentially) points to as its `next_username` has
        //    a username that is larger than the new account's

        // Security measure to prevent raw usernames getting submitted. It's 31
        // rather than 32 since one extra byte needs to be prepended.
        expect (bytearray.length(username) == 31)?

        // Exactly two assets must be minted for `username`.
        expect [(_, entrys_mint_name, 1), (_, accounts_mint_name, 1)] =
          mint
            |> value.from_minted_value
            |> value.flatten

        let entrys_token_name =
          username |> bytearray.push(entrys_token_name_byte_value)

        let accounts_token_name =
          username |> bytearray.push(accounts_token_name_byte_value)

        expect and {
            entrys_mint_name == entrys_token_name,
            accounts_mint_name == accounts_token_name,
          }?

        // Only 1 UTxO must be getting spent from the script address.
        expect [
          Input {
            output: Output {
              datum: InlineDatum(prev_entry),
              value: curr_value,
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
              payment_credential == own_script_cred
            },
          )

        // Only Ada and previous user's NFT must be carried in the UTxO.
        let curr_asset =
          utils.get_single_asset_from_value_apart_from_ada(curr_value)
        let (curr_asset_policy, curr_asset_tn, _) = curr_asset
        expect and {
            curr_asset_policy == own_policy,
            bytearray.compare(curr_asset_tn, entrys_token_name) == Less,
          }?

        expect Entry { next_username }: Datum = prev_entry
        let updated_datum = Entry { next_username: Some(username) }

        // New username must be smaller than a potential next user.
        expect
          when next_username is {
            None -> True
            Some(prev_next_user) ->
              bytearray.compare(entrys_token_name, prev_next_user) == Less
          }?

        // First 3 outputs are expected to be produced at the script address:
        // 1. Updated previous entry input
        // 2. New entry
        // 3. User's account UTxO
        expect [
          Output {
            address: Address { payment_credential: o0_pay_cred, .. },
            value: o0_value,
            datum: o0_datum,
            reference_script: None,
          },
          Output {
            address: Address { payment_credential: o1_pay_cred, .. },
            value: o1_value,
            datum: o1_datum,
            reference_script: None,
          },
          Output {
            address: Address { payment_credential: o2_pay_cred, .. },
            value: o2_value,
            datum: o2_datum,
            reference_script: None,
          },
          ..
        ] = outputs

        let entrys_datum: Datum = Entry { next_username }
        let (entrys_asset_policy, entrys_asset_name, entrys_asset_quantity) =
          utils.get_single_asset_from_value_apart_from_ada(o1_value)

        expect InlineDatum(specified_account_datum_data) = o2_datum
        expect Account { pubkey: specified_pubkey, nonce: specified_nonce } =
          specified_account_datum_data
        let (
          accounts_asset_policy,
          accounts_asset_name,
          accounts_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o2_value)

        and {
          o0_pay_cred == own_script_cred,
          o1_pay_cred == own_script_cred,
          o2_pay_cred == own_script_cred,
          o0_datum == InlineDatum(updated_datum),
          o1_datum == InlineDatum(entrys_datum),
          specified_nonce == cbor.serialise(own_out_ref),
          utils.outputs_signed_by_ed25519_key(
            specified_pubkey,
            outputs,
            signature,
          ),
          o0_value == curr_value,
          entrys_asset_policy == own_policy,
          entrys_asset_name == entrys_token_name,
          entrys_asset_quantity == 1,
          accounts_asset_policy == own_policy,
          accounts_asset_name == accounts_token_name,
          accounts_asset_quantity == 1,
        }?
      }
      CloseAccount { prev_entrys_out_ref, entrys_out_ref, signature } -> {
        // This is essentially a combination of the account creation and the
        // withdrawal endpoints.
        // 1. Three UTxOs are expected to be spent such that one of them points
        //    to the closing account's username, and the other two are closing
        //    account's entry and balance UTxOs
        // 2. The closing account's NFTs must be getting burnt
        // 3. Datum of the previous account must be updated so that it points to
        //    the (potential) account that the closing account points to
        // 4. Outputs of the transactions must be signed by the owner

        // Only 3 UTxOs must be getting spent from the script:
        // 1. Previous entry
        // 2. Closing entry
        // 3. Closing account
        expect [
          Input { output: o0, output_reference: o0_out_ref },
          Input { output: o1, output_reference: o1_out_ref },
          Input { output: o2, output_reference: o2_out_ref },
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
              payment_credential == own_script_cred
            },
          )
        let o0_is_prev = o0_out_ref == prev_entrys_out_ref
        let o0_is_entrys = o0_out_ref == entrys_out_ref
        let o1_is_prev = o1_out_ref == prev_entrys_out_ref
        let o1_is_entrys = o1_out_ref == entrys_out_ref
        let o2_is_prev = o2_out_ref == prev_entrys_out_ref
        let o2_is_entrys = o2_out_ref == entrys_out_ref

        expect (
          Output {
            datum: InlineDatum(prev_datum),
            value: prev_value,
            address: prev_address,
            ..
          },
          Output { datum: InlineDatum(entrys_datum), value: entrys_value, .. },
          Output {
            datum: InlineDatum(accounts_datum),
            value: accounts_value,
            ..
          },
        ) =
          if and {
            o0_is_prev,
            o1_is_entrys,
          } {
            (o0, o1, o2)
          } else if and {
            o0_is_prev,
            o2_is_entrys,
          } {
            (o0, o2, o1)
          } else if and {
            o1_is_prev,
            o0_is_entrys,
          } {
            (o1, o0, o2)
          } else if and {
            o1_is_prev,
            o2_is_entrys,
          } {
            (o1, o2, o0)
          } else if and {
            o2_is_prev,
            o0_is_entrys,
          } {
            (o2, o0, o1)
          } else if and {
            o2_is_prev,
            o1_is_entrys,
          } {
            (o2, o1, o0)
          } else {
            fail @"Given out refs don't match with found inputs properly"
          }

        expect [Pair(entrys_token_name, _)] =
          entrys_value
            |> value.tokens(own_policy)
            |> dict.to_pairs
        expect (bytearray.take(entrys_token_name, 1) == entrys_token_name_byte)?

        expect [Pair(accounts_token_name, _)] =
          accounts_value
            |> value.tokens(own_policy)
            |> dict.to_pairs
        expect
          (bytearray.take(accounts_token_name, 1) == accounts_token_name_byte)?

        let closing_username = bytearray.drop(accounts_token_name, 1)

        expect (bytearray.drop(entrys_token_name, 1) == closing_username)?

        expect Entry{next_username: Some(stored_closing_username)}: Datum =
          prev_datum

        expect (stored_closing_username == closing_username)?

        expect Entry { next_username: prevs_new_next_username }: Datum =
          entrys_datum

        expect Account { pubkey: accounts_pubkey, .. }: Datum = accounts_datum

        let prev_entrys_updated_datum: Data =
          Entry { next_username: prevs_new_next_username }

        // First produced UTxO must go back to the script.
        expect [
          Output {
            datum: InlineDatum(cont_prev_datum),
            value: cont_prev_value,
            address: cont_prev_address,
            reference_script: None,
          },
          ..
        ] = outputs

        // Exactly two assets must be getting burnt for `closing_username`.
        expect [(_, entrys_mint_name, -1), (_, accounts_mint_name, -1)] =
          mint
            |> value.from_minted_value
            |> value.flatten

        let entrys_token_name =
          closing_username |> bytearray.push(entrys_token_name_byte_value)

        let accounts_token_name =
          closing_username |> bytearray.push(accounts_token_name_byte_value)

        expect and {
            entrys_mint_name == entrys_token_name,
            accounts_mint_name == accounts_token_name,
          }?

        and {
          utils.outputs_signed_by_ed25519_key(
            accounts_pubkey,
            outputs,
            signature,
          ),
          cont_prev_datum == prev_entrys_updated_datum,
          prev_value == cont_prev_value,
          prev_address == cont_prev_address,
        }?
      }
    }
  }

  fn spend(in_datum: Datum, action: SpendAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, .. } = tx

    when action is {
      AppendToNewAccount { input_index } -> {
        // This only needs to make sure the minting endpoint is invoked with a
        // quantity of 1.

        expect Output {
          address: Address {
            payment_credential: ScriptCredential(own_script),
            ..
          },
          ..
        } = utils.get_own_input_at(inputs, own_out_ref, input_index)

        let mint_quantity = utils.get_single_mint_quantity_of(mint, own_script)
        mint_quantity == 1
      }
      Deposit { input_index, lovelace_count } -> {
        // Allows anyone to "charge" an account. This is limited to Ada to
        // prevent token dust attacks.

        expect (lovelace_count > 0)?
        let lovelace_value: Value = value.from_lovelace(lovelace_count)

        let Output {
          address: in_address,
          value: in_value,
          datum: in_inline_datum,
          ..
        } = utils.get_own_input_at(inputs, own_out_ref, input_index)

        // First output must be the reproduced UTxO.
        expect [
          Output {
            address: out_address,
            value: out_value,
            datum: out_datum,
            reference_script: None,
          },
          ..
        ] = outputs

        and {
          in_address == out_address,
          in_inline_datum == out_datum,
          value.merge(in_value, lovelace_value) == out_value,
        }?
      }
      Withdraw { input_index, signature } -> {
        // Allows withdraw iff:
        // 1. Outputs are signed by the stored ed25519 pubkey
        // 2. The UTxO is reproduced at the incoming address (staking part can
        //    be changed) with an unchanged datum
        // 3. Datum must remain unchanged
        // 4. Account's NFT must not leave the UTxO

        let (own_script, in_value, out_value, out_datum_data) =
          validate_spending_utxo_at_index_and_continuing_output(
            own_out_ref,
            in_datum,
            inputs,
            outputs,
            input_index,
            signature,
          )

        let in_datum_data: Data = in_datum

        // Only requirement is that username's NFT is not leaving the UTxO. No
        // need to check the quantities here.
        expect [Pair(in_username, _)] =
          in_value
            |> value.tokens(own_script)
            |> dict.to_pairs
        expect [Pair(out_username, _)] =
          out_value
            |> value.tokens(own_script)
            |> dict.to_pairs

        and {
          in_datum_data == out_datum_data,
          in_username == out_username,
        }
      }
      UpdatePubkey { input_index, signature } -> {
        // 1. Outputs are signed by the stored ed25519 pubkey
        // 2. The UTxO is reproduced at the incoming address (staking part can
        //    be changed)
        // 3. The new pubkey must be changed
        // 4. Nonce must also be updated (equal to own input's outref)

        let (_own_script, in_value, out_value, out_datum_data) =
          validate_spending_utxo_at_index_and_continuing_output(
            own_out_ref,
            in_datum,
            inputs,
            outputs,
            input_index,
            signature,
          )

        expect Account { pubkey: curr_pubkey, .. }: Datum = in_datum
        expect Account { pubkey: new_pubkey, nonce: new_nonce } = out_datum_data

        and {
          // Protection layer to prevent resubmitting the same pubkey.
          !(new_pubkey == curr_pubkey),
          // New nonce must be the same as the spending outref.
          new_nonce == cbor.serialise(own_out_ref),
          // Value must not change.
          in_value == out_value,
        }
      }
      DepleteAccount { input_index } -> {
        // Only needs to ensure the burn endpoint is invoked.

        expect Output {
          address: Address {
            payment_credential: ScriptCredential(own_script),
            ..
          },
          ..
        } = utils.get_own_input_at(inputs, own_out_ref, input_index)

        let mint_quantity = utils.get_single_mint_quantity_of(mint, own_script)
        mint_quantity == -1
      }
    }
  }
}

// === HELPER FUNCTIONS ========================================================
// Checks:
// 1. The input index matches the spending outref
// 2. Address of output at index 0 has the same payment part as the input
// 3. Outputs are signed by the spent account UTxO
//
// And returns:
// 1. Own script hash
// 2. Input value
// 3. Output value
// 4. Output datum's data (attached as inline)
fn validate_spending_utxo_at_index_and_continuing_output(
  own_out_ref: OutputReference,
  in_datum: Datum,
  inputs: List<Input>,
  outputs: List<Output>,
  input_index: Int,
  signature: ByteArray,
) -> (ScriptHash, Value, Value, Data) {
  expect Output {
    address: Address { payment_credential: ScriptCredential(own_script), .. },
    value: in_value,
    ..
  } = utils.get_own_input_at(inputs, own_out_ref, input_index)

  // Validate the password.
  expect Account { pubkey: curr_pubkey, .. }: Datum = in_datum
  expect utils.outputs_signed_by_ed25519_key(curr_pubkey, outputs, signature)?

  expect [
    Output {
      address: Address {
        payment_credential: ScriptCredential(out_script_cred),
        ..
      },
      value: out_value,
      datum: InlineDatum(out_datum),
      reference_script: None,
    },
    ..
  ] = outputs
  expect (own_script == out_script_cred)?
  (own_script, in_value, out_value, out_datum)
}
