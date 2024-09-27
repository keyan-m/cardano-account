// === IMPORTS =================================================================
use aiken/cbor
use aiken/collection/list
use aiken/primitive/bytearray
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{
  InlineDatum, Input, Output, OutputReference, Transaction,
}
use cardano_account/constants as constants
use cardano_account/types.{
  Account, CloseStaleAccount, Contributor, DeployedScript, Entry,
  InitiateRecord, MintNewAccount, RecordDatum, RecordMintAction,
} as types
use cardano_account/utils as utils

// === DATATYPES ===============================================================

pub type SpendAction {
  AppendToNewAccount { input_index: Int }
  DepleteAccount { input_index: Int }
}

// === THE VALIDATOR ===========================================================
validator record(utxo_ref: OutputReference) {
  mint(action: RecordMintAction, own_policy: PolicyId, tx: Transaction) {
    let Transaction {
      extra_signatories,
      inputs,
      outputs,
      mint,
      validity_range,
      ..
    } = tx

    when action is {
      InitiateRecord -> {
        // Initial endpoint for starting the linked list. Requirements are:
        // 1. Specified UTxO must be getting spent
        // 2. Exactly two nameless tokens are minted at the script address
        // 3. Two UTxOs are produced at the script: list head at index 0, record
        //    validator's deployed script at index 1
        // 4. List head's output datum is
        //      `Entry { next_username: None, contributor }`
        //    where the contributor can be set arbitrarily
        // 5. Reference UTxO has a `DeployedScript` datum
        // 6. Each of the two produced UTxOs carry one of the nameless tokens

        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted, with a quantity of 2,
        // 1 for the linked list head, and the other for the deployed script.
        expect [mint_triplet] =
          mint
            |> assets.flatten
        expect (_, mint_name, 2) = mint_triplet

        // First 2 produced UTxOs must go to the script.
        expect [
          Output {
            address: Address {
              payment_credential: Script(list_head_script_hash),
              ..
            },
            value: list_head_value,
            datum: InlineDatum(list_head_datum_data),
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: Script(records_ref_script_script_hash),
              ..
            },
            value: records_ref_script_value,
            datum: InlineDatum(records_ref_script_datum_data),
            reference_script: Some(_),
          },
          ..
        ] = outputs

        // Linked list must be empty at initiation.
        expect Entry { next_username: None, .. } = list_head_datum_data

        // Proper datum must be attached to the reference script's UTxO.
        expect DeployedScript = records_ref_script_datum_data

        // List head UTxO must contain only one other asset apart from ADA.
        let (list_head_asset_symbol, list_head_asset_name, list_head_asset_qty) =
          utils.get_single_asset_from_value_apart_from_ada(list_head_value)

        // Record's reference script UTxO must contain only one other asset
        // apart from ADA.
        let (records_ref_script_asset_symbol, records_ref_script_asset_name, records_ref_script_asset_qty) =
          utils.get_single_asset_from_value_apart_from_ada(records_ref_script_value)
        expect and {
          list_head_script_hash == own_policy,
          records_ref_script_script_hash == own_policy,
          mint_name == #"",
          list_head_asset_symbol == own_policy,
          list_head_asset_name == mint_name,
          list_head_asset_qty == 1,
          records_ref_script_asset_symbol == own_policy,
          records_ref_script_asset_name == mint_name,
          records_ref_script_asset_qty == 1,
        }?
      }
      MintNewAccount { username, signature } -> {
        // Requires the proper entry in the list to be spent so that its datum
        // correctly points to the new account's username. The proper entry is
        // a previously created entry such that:
        // 1. Its own token name (i.e. username) is smaller than the new
        //    account's entry token name
        // 2. The account it (potentially) points to as its `next_username` has
        //    a username that is larger than the new account's
        // Note that token names are NOT labeled, as none of them can leave the
        // record script.

        // Security measure to prevent raw username submissions.
        expect (bytearray.length(username) == 32)?

        // Exactly one asset must be minted for `username`, with a quantity of
        // three. No need to validate the minted asset's policy.
        let [(_, mint_name, mint_qty)] = mint |> assets.flatten
        expect and {
            mint_username == username,
            mint_qty == 3,
          }?

        let own_script = Script(own_policy)

        // Only 1 UTxO must be spent from the script address.
        expect [
          Input {
            output: Output {
              address: prev_entrys_address,
              datum: InlineDatum(prev_entry_data),
              value: prev_entrys_value,
              ..
            },
            output_reference: own_out_ref,
          },
        ] =
          list.filter(
            inputs,
            fn(i) { i.output.address.payment_credential == own_script },
          )

        // Only Ada and previous entry's token must be carried in the UTxO.
        let prev_entrys_beacon =
          utils.get_single_asset_from_value_apart_from_ada(prev_entrys_value)
        expect (prev_entrys_beacon_policy, prev_entrys_beacon_name, 1) = prev_entrys_beacon
        expect and {
            prev_entrys_beacon_policy == own_policy,
            bytearray.compare(prev_entrys_beacon_name, username) == Less,
          }?

        expect Entry {
          next_username: prev_entrys_next_username,
          contributor: prev_entrys_contributor
        }: RecordDatum = prev_entry_data
        let updated_datum =
          Entry {
            next_username: Some(username),
            contributor: prev_entrys_contributor,
          }

        // New username must be smaller than a potential next user. Note that
        // only usernames are compared.
        expect
          when prev_entrys_next_username is {
            None -> True
            Some(prev_next_user) ->
              bytearray.compare(username, prev_next_user) == Less
          }?

        // Four outputs are expected to be produced at the script address:
        // 1. Updated previous entry input
        // 2. New entry
        // 3. User's account UTxO
        // 4. User's account reference script
        //
        // Here we don't care about the staking parts. However, if the funds are
        // being provided by the `treasury` contract, it'll stipulate that the
        // staking parts of all 3 new UTxOs (since the first one is just getting
        // an updated datum) match the contributor's.
        expect [
          Output {
            address: o0_address,
            value: o0_value,
            datum: o0_datum,
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: Script(o1_pay_cred_hash),
              ..
            },
            value: o1_value,
            datum: InlineDatum(o1_datum_data),
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: Script(o2_pay_cred_hash),
              ..
            },
            value: o2_value,
            datum: InlineDatum(o2_datum_data),
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: Script(o3_pay_cred_hash),
              ..
            },
            value: o3_value,
            datum: InlineDatum(o3_datum_data),
            reference_script: Some(_),
          },
          ..
        ] = outputs

        // We don't care about Lovelace fluctuations, since in case previous
        // entry's datum goes from a `None` to a `Some`, its minimum required
        // Lovelaces increases.
        let updated_prev_entrys_beacon =
          utils.get_single_asset_from_value_apart_from_ada(o0_value)

        expect Entry {
          next_username: entrys_next_username,
          ..
        }: RecordDatum = o1_datum_data
        let (
          entrys_output_asset_policy,
          entrys_output_asset_name,
          entrys_output_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o1_value)

        expect AccountDatum {
          pubkey: specified_pubkey,
          nonce: specified_nonce,
          latest_activity: specified_latest_activity,
        }: RecordDatum = o2_datum_data
        let (
          accounts_output_asset_policy,
          accounts_output_asset_name,
          accounts_output_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o2_value)

        expect DeployedScript: RecordDatum = o3_datum_data
        let (
          accounts_script_asset_policy,
          accounts_script_asset_name,
          accounts_script_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o3_value)

        and {
          // Address validations
          o0_address == prev_entrys_address,
          o1_pay_cred_hash == own_policy,
          o2_pay_cred_hash == own_policy,
          o3_pay_cred_hash == own_policy,
          // Value validations
          updated_prev_entrys_beacon == prev_entrys_beacon,
          entrys_output_asset_policy == own_policy,
          entrys_output_asset_name == username,
          entrys_output_asset_quantity == 1,
          accounts_output_asset_policy == own_policy,
          accounts_output_asset_name == username,
          accounts_output_asset_quantity == 1,
          accounts_script_asset_policy == own_policy,
          accounts_script_asset_name == username,
          accounts_script_asset_quantity == 1,
          // Datum validations
          o0_datum == InlineDatum(updated_datum),
          entrys_next_username == prev_entrys_next_username,
          specified_nonce == cbor.serialise(own_out_ref),
          specified_latest_activity == utils.get_upper_bound(validity_range),
          utils.outputs_signed_by_ed25519_key(
            specified_pubkey,
            outputs,
            signature,
          ),
        }?
      }
      CloseStaleAccount { prev_entrys_out_ref, entrys_out_ref } -> {
        // Accounts older than 6 years are up for grabs (it'll be 5 years for
        // the contributor). This is meant as a measure to prevent permanent
        // locking of funds.
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
              when i.output.address.payment_credential is {
                Script(_) -> True
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
              payment_credential: Script(prev_entrys_script_hash),
              ..
            } as prev_entrys_address,
            datum: InlineDatum(prev_datum),
            value: prev_value,
            ..
          },
          Output {
            address: Address {
              payment_credential: Script(closing_entrys_script_hash),
              ..
            },
            datum: InlineDatum(entrys_datum),
            value: entrys_value,
            ..
          },
          Output {
            address: Address {
              payment_credential: Script(accounts_script_hash),
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
            fail @"Given out refs don't match found inputs properly"
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
            or {
              bytearray.take(prev_entrys_token_name, 1) == constants.entrys_token_name_byte,
              prev_entrys_token_name == #"",
            },
            bytearray.take(entrys_token_name, 1) == constants.entrys_token_name_byte,
            bytearray.take(accounts_token_name, 1) == constants.accounts_token_name_byte,
            prev_entrys_qty == 1,
            entrys_qty == 1,
            accounts_qty == 1,
          }?

        // Usernames and token names must match properly.
        let closing_username = bytearray.drop(accounts_token_name, 1)
        expect (bytearray.drop(entrys_token_name, 1) == closing_username)?
        expect Entry {
          next_username: Some(stored_closing_username),
          contributor: prev_entrys_contributor,
        }: Entry = prev_datum
        expect (stored_closing_username == closing_username)?
        expect Entry {
          next_username: closing_entrys_next_username,
          contributor: Contributor {
            payment_credential: closing_entrys_contributor,
            ..
          },
        }: Entry = entrys_datum
        let prev_entrys_updated_datum: Data =
          Entry {
            next_username: closing_entrys_next_username,
            contributor: prev_entrys_contributor,
          }

        // Exactly two assets must be burnt for `closing_username`.
        let (burn_username, burn_qty) =
          mint
            |> utils.get_entry_and_account_mint_username_and_quantity_of(
                own_policy,
              )
        expect and {
            burn_username == closing_username,
            burn_qty == -1,
          }?

        // Closing account must be considered stale.
        expect AccountDatum { latest_activity, .. } = accounts_datum
        expect
          utils.account_is_stale(
            latest_activity,
            closing_entrys_contributor,
            extra_signatories,
            validity_range,
          )?

        // First produced UTxO must go back to the script.
        expect [
          Output {
            address: cont_prev_address,
            datum: InlineDatum(cont_prev_datum),
            value: cont_prev_value,
            reference_script: None,
          },
          ..
        ] = outputs

        // Previous entry in the list is reproduced unchanged, except for its
        // datum, which must point to the closing entry's (potential) next
        // username.
        and {
          cont_prev_address == prev_entrys_address,
          cont_prev_datum == prev_entrys_updated_datum,
          cont_prev_value == prev_value,
        }?
      }
    }
  }

  spend(
    datum: Option<Entry>,
    action: SpendAction,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    expect Some(_) = datum

    let Transaction { inputs, mint, .. } = tx

    when action is {
      AppendToNewAccount { input_index } ->
        // This only needs to make sure the minting endpoint is invoked with two
        // NFTs minted with own script hash.
        validate_mint(input_index, 1, own_out_ref, inputs, mint)?
      DepleteAccount { input_index } ->
        // This only needs to make sure the minting endpoint is invoked with two
        // NFTs minted with own script hash.
        validate_mint(input_index, -1, own_out_ref, inputs, mint)?
    }
  }

  else(_) {
    fail
  }
}

fn validate_mint(
  input_index: Int,
  expected_mint_quantity: Int,
  own_out_ref: OutputReference,
  inputs: List<Input>,
  mint: Value,
) -> Bool {
  expect Output {
    address: Address { payment_credential: Script(own_script_hash), .. },
    ..
  } = utils.get_own_input_at(inputs, own_out_ref, input_index)

  let mint_qty = mint |> utils.get_two_mint_nfts_of(own_script_hash)

  mint_qty == expected_mint_quantity
}
