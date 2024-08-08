// === IMPORTS =================================================================
use aiken/bytearray
use aiken/cbor
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, ScriptContext, Spend,
  Transaction,
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use cardano_account/constants.{
  entrys_token_name_byte_value, entrys_token_name_byte,
  accounts_token_name_byte_value, accounts_token_name_byte
}
use cardano_account/types.{Account, AccountDatum} as types
use cardano_account/utils as utils

// === DATATYPES ===============================================================
type Datum {
  Entry { next_username: Option<ByteArray> }
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
            address: Address {
              payment_credential: ScriptCredential(o0_pay_cred_hash),
              ..
            },
            value: o0_value,
            datum: o0_datum,
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: ScriptCredential(o1_pay_cred_hash),
              ..
            },
            value: o1_value,
            datum: o1_datum,
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: ScriptCredential(o2_pay_cred_hash),
              ..
            },
            value: o2_value,
            datum: InlineDatum(o2_datum_data),
            reference_script: None,
          },
          ..
        ] = outputs

        let entrys_datum: Datum = Entry { next_username }
        let (entrys_asset_policy, entrys_asset_name, entrys_asset_quantity) =
          utils.get_single_asset_from_value_apart_from_ada(o1_value)

        expect Account { pubkey: specified_pubkey, nonce: specified_nonce } =
          o2_datum_data

        let (
          accounts_asset_policy,
          accounts_asset_name,
          accounts_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o2_value)

        and {
          o0_pay_cred_hash == own_policy,
          o1_pay_cred_hash == own_policy,
          // Account NFT is meant to be sent to the user-specific `account`
          // smart contract.
          !(o2_pay_cred_hash == own_policy),
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
              when payment_credential is {
                ScriptCredential (_) -> True
                _ -> False
              }
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
            address: Address {
              payment_credential: ScriptCredential(prev_entrys_script_hash),
              ..
            },
            datum: InlineDatum(prev_datum),
            value: prev_value,
            ..
          },
          Output {
            address: Address {
              payment_credential: ScriptCredential(closing_entrys_script_hash),
              ..
            },
            datum: InlineDatum(entrys_datum),
            value: entrys_value,
            ..
          },
          Output {
            address: Address {
              payment_credential: ScriptCredential(accounts_script_hash),
              ..
            },
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

        // Both entry UTxOs are expected to be coming from this script address,
        // while account's UTxO is expected to come from somewhere else.
        expect and {
          prev_entrys_script_hash == own_policy,
          closing_entrys_script_hash == own_policy,
          !(accounts_script_hash == own_policy)
        }?

        let (prev_entrys_policy, _, prev_entrys_qty) =
          utils.get_single_asset_from_value_apart_from_ada(prev_value)
        let (entrys_policy, entrys_token_name, entrys_qty) =
          utils.get_single_asset_from_value_apart_from_ada(entrys_value)
        let (accounts_policy, accounts_token_name, accounts_qty) =
          utils.get_single_asset_from_value_apart_from_ada(accounts_value)

        expect and {
          prev_entrys_policy == own_policy,
          entrys_policy == own_policy,
          accounts_policy == own_policy,
          bytearray.take(entrys_token_name, 1) == entrys_token_name_byte,
          bytearray.take(accounts_token_name, 1) == accounts_token_name_byte,
          prev_entrys_qty == 1,
          entrys_qty == 1,
          accounts_qty == 1,
        }?

        let closing_username = bytearray.drop(accounts_token_name, 1)
        expect (bytearray.drop(entrys_token_name, 1) == closing_username)?

        expect Entry{next_username: Some(stored_closing_username)}: Datum =
          prev_datum
        expect (stored_closing_username == closing_username)?

        expect Entry { next_username: prevs_new_next_username }: Datum =
          entrys_datum

        expect Account { pubkey: accounts_pubkey, .. }: AccountDatum =
          accounts_datum

        let prev_entrys_updated_datum: Data =
          Entry { next_username: prevs_new_next_username }

        // First produced UTxO must go back to the script.
        expect [
          Output {
            datum: InlineDatum(cont_prev_datum),
            value: cont_prev_value,
            address: Address {
              payment_credential: ScriptCredential(cont_prev_script_hash)
              ..
            },
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
          prev_entrys_script_hash == cont_prev_script_hash,
        }?
      }
    }
  }

  fn spend(_, action: SpendAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, mint, .. } = tx

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
