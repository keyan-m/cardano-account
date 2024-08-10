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
  accounts_token_name_byte, accounts_token_name_byte_value,
  entrys_token_name_byte, entrys_token_name_byte_value,
}
use cardano_account/types.{Account, AccountDatum} as types
use cardano_account/utils as utils

// === DATATYPES ===============================================================
type Entry {
  next_username: Option<ByteArray>,
}

type MintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: ByteArray }
  CloseStaleAccount {
    prev_entrys_out_ref: OutputReference,
    entrys_out_ref: OutputReference,
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

    let Transaction { inputs, outputs, mint, validity_range, .. } = tx

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
            address: Address {
              payment_credential: ScriptCredential(own_script_hash),
              ..
            },
            reference_script: None,
          },
          ..
        ] = outputs
        expect (own_script_hash == own_policy)?

        // Linked list must be empty at initiation.
        expect Entry { next_username: None } = list_head_datum

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

        // Security measure to prevent raw username submissions. It's 31 rather
        // than 32 since one extra byte needs to be prepended.
        expect (bytearray.length(username) == 31)?

        // Exactly two assets must be minted for `username`.
        let (mint_username, mint_qty) =
          utils.get_entry_and_account_mint_username_and_quantity_of(
            mint,
            own_policy,
          )
        expect and {
            mint_username == username,
            mint_qty == 1,
          }?

        // Minted tokens must have identical names apart from their first bytes.
        let entrys_token_name =
          username |> bytearray.push(entrys_token_name_byte_value)
        let accounts_token_name =
          username |> bytearray.push(accounts_token_name_byte_value)

        // Only 1 UTxO must be spent from the script address.
        expect [
          Input {
            output: Output {
              datum: InlineDatum(prev_entry_data),
              value: curr_value,
              ..
            },
            output_reference: own_out_ref,
          },
        ] =
          list.filter(
            inputs,
            fn(i) {
              i.output.address.payment_credential == ScriptCredential(
                own_policy,
              )
            },
          )

        // Only Ada and previous entry's NFT must be carried in the UTxO. Note
        // that here full token names are compared.
        let curr_asset =
          utils.get_single_asset_from_value_apart_from_ada(curr_value)
        let (curr_asset_policy, curr_asset_tn, _) = curr_asset
        expect and {
            curr_asset_policy == own_policy,
            bytearray.compare(curr_asset_tn, entrys_token_name) == Less,
          }?

        expect Entry { next_username } = prev_entry_data
        let updated_datum = Entry { next_username: Some(username) }

        // New username must be smaller than a potential next user. Note that
        // only usernames are compared.
        expect
          when next_username is {
            None -> True
            Some(prev_next_user) ->
              bytearray.compare(username, prev_next_user) == Less
          }?

        // First 2 outputs are expected to be produced at the script address,
        // 3rd one has to be produced somewhere else (presumably user's
        // instantiation of the `account` script).
        // 1. Updated previous entry input ------> (this script)
        // 2. New entry -------------------------> (this script)
        // 3. User's account UTxO ---------------> (outside)
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

        let entrys_datum = Entry { next_username }
        let (entrys_asset_policy, entrys_asset_name, entrys_asset_quantity) =
          utils.get_single_asset_from_value_apart_from_ada(o1_value)

        expect Account {
          pubkey: specified_pubkey,
          nonce: specified_nonce,
          latest_activity: specified_latest_activity,
        } = o2_datum_data

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
          specified_latest_activity == utils.get_upper_bound(validity_range),
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
      CloseStaleAccount { prev_entrys_out_ref, entrys_out_ref } -> {
        // Accounts older than 5 years are up for grabs. This is meant as a
        // measure to prevent permanent locking of funds.
        // 1. Three UTxOs are expected to be spent such that one of them points
        //    to the closing account's username, and the other two are closing
        //    account's entry and "info" UTxOs
        // 2. Both closing account's NFTs must be getting burnt
        // 3. Datum of the previous account must be updated so that it points to
        //    the (potential) account that the closing account points to

        // Only 3 UTxOs must be spent from the script:
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
                ScriptCredential(_) -> True
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
            !(accounts_script_hash == own_policy),
          }?

        let (prev_entrys_policy, prev_entrys_token_name, prev_entrys_qty) =
          utils.get_single_asset_from_value_apart_from_ada(prev_value)
        let (entrys_policy, entrys_token_name, entrys_qty) =
          utils.get_single_asset_from_value_apart_from_ada(entrys_value)
        let (accounts_policy, accounts_token_name, accounts_qty) =
          utils.get_single_asset_from_value_apart_from_ada(accounts_value)

        // Spent tokens must be authentic.
        expect and {
            prev_entrys_policy == own_policy,
            entrys_policy == own_policy,
            accounts_policy == own_policy,
            bytearray.take(prev_entrys_token_name, 1) == entrys_token_name_byte,
            bytearray.take(entrys_token_name, 1) == entrys_token_name_byte,
            bytearray.take(accounts_token_name, 1) == accounts_token_name_byte,
            prev_entrys_qty == 1,
            entrys_qty == 1,
            accounts_qty == 1,
          }?

        // Usernames and token names must match properly.
        let closing_username = bytearray.drop(accounts_token_name, 1)
        expect (bytearray.drop(entrys_token_name, 1) == closing_username)?
        expect Entry{next_username: Some(stored_closing_username)} = prev_datum
        expect (stored_closing_username == closing_username)?
        expect Entry { next_username: closing_entrys_next_username } =
          entrys_datum
        expect Account { pubkey: accounts_pubkey, .. }: AccountDatum =
          accounts_datum
        let prev_entrys_updated_datum: Data =
          Entry { next_username: closing_entrys_next_username }

        // First produced UTxO must go back to the script.
        expect [
          Output {
            datum: InlineDatum(cont_prev_datum),
            value: cont_prev_value,
            address: Address {
              payment_credential: ScriptCredential(cont_prev_script_hash),
              ..
            },
            reference_script: None,
          },
          ..
        ] = outputs

        // Exactly two assets must be burnt for `closing_username`.
        expect [
          (entrys_burn_policy, entrys_mint_name, -1),
          (accounts_burn_policy, accounts_mint_name, -1),
        ] =
          mint
            |> value.from_minted_value
            |> value.flatten

        let entrys_token_name =
          closing_username |> bytearray.push(entrys_token_name_byte_value)

        let accounts_token_name =
          closing_username |> bytearray.push(accounts_token_name_byte_value)

        and {
          // Both burnt tokens belong to the closing username.
          entrys_burn_policy == own_policy,
          accounts_burn_policy == own_policy,
          entrys_mint_name == entrys_token_name,
          accounts_mint_name == accounts_token_name,
          // Previous entry in the list is reproduced unchanged, except for its
          // datum, which must point to the closing entry's (potential) next
          // username.
          cont_prev_datum == prev_entrys_updated_datum,
          cont_prev_value == prev_value,
          cont_prev_script_hash == prev_entrys_script_hash,
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
