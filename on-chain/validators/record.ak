// === IMPORTS =================================================================
use aiken/cbor
use aiken/collection/list
use aiken/primitive/bytearray
use aiken_scott_utils/list.{foldl6} as scott_list
use cardano/address.{Address, Script}
use cardano/assets.{PolicyId, Value}
use cardano/transaction.{
  InlineDatum, Input, NoDatum, Output, OutputReference, Transaction,
}
use cardano_account/types.{
  Account, AppendToNewAccount, AuthorizedSpend, BurnAccount, CloseAccount,
  ContributionReturn, Contributor, Entry, InitiateRecord, MintNewAccount,
  RecordDatum, RecordMintAction, RecordSpendAction, UpdatePubkey,
} as types
use cardano_account/utils as utils

// === THE VALIDATOR ===========================================================
validator record(utxo_ref: OutputReference) {
  mint(action: RecordMintAction, own_policy: PolicyId, tx: Transaction) {
    let Transaction { inputs, outputs, mint, .. } = tx

    let own_script = Script(own_policy)

    when action is {
      InitiateRecord -> {
        // {{{
        // Initial endpoint for starting the linked list. Requirements are:
        // 1. Specified UTxO must be getting spent
        // 2. Exactly two nameless tokens are minted at the script address
        // 3. Two UTxOs are produced at the script: list head at index 0, record
        //    validator's deployed script at index 1
        // 4. List head's output datum is
        //      `Entry { next_username: None }`
        //    where the contributor can be set arbitrarily
        // 5. Reference UTxO has no datum attached
        // 6. Each of the two produced UTxOs carry one of the nameless tokens

        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted, with a quantity of 2,
        // 1 for the linked list head, and the other for the deployed script.
        expect [(_, mint_name, 2)] = assets.flatten(mint)

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
            datum: NoDatum,
            reference_script: Some(_),
          },
          ..
        ] = outputs

        // Linked list must be empty at initiation.
        expect Entry { next_username: None } = list_head_datum_data

        // List head UTxO must contain only one other asset apart from ADA.
        let (list_head_asset_symbol, list_head_asset_name, list_head_asset_qty) =
          utils.get_single_asset_from_value_apart_from_ada(list_head_value)

        // Record's reference script UTxO must contain only one other asset
        // apart from ADA.
        let (
          records_ref_script_asset_symbol,
          records_ref_script_asset_name,
          records_ref_script_asset_qty,
        ) =
          utils.get_single_asset_from_value_apart_from_ada(
            records_ref_script_value,
          )
        and {
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
      // }}}
      MintNewAccount { username, signature } -> {
        // {{{
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
        // four. No need to validate the minted asset's policy.
        expect [(_, mint_name, mint_qty)] = assets.flatten(mint)
        expect and {
            mint_name == username,
            mint_qty == 4,
          }?

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
        ] = utils.keep_only_inputs_from_credential(inputs, own_script)

        // Only Ada and previous entry's token must be carried in the UTxO.
        let prev_entrys_beacon =
          utils.get_single_asset_from_value_apart_from_ada(prev_entrys_value)
        expect (prev_entrys_beacon_policy, prev_entrys_beacon_name, 1) =
          prev_entrys_beacon
        expect and {
            prev_entrys_beacon_policy == own_policy,
            bytearray.compare(prev_entrys_beacon_name, username) == Less,
          }?

        expect Entry { next_username: prev_entrys_next_username }: RecordDatum =
          prev_entry_data

        // New username must be smaller than a potential next user. Note that
        // only usernames are compared.
        expect
          when prev_entrys_next_username is {
            None -> True
            Some(prev_next_user) ->
              bytearray.compare(username, prev_next_user) == Less
          }?

        // Five outputs are expected to be produced at the script address:
        // 1. Updated previous entry input
        // 2. New entry
        // 3. User's account UTxO
        // 4. User's account reference script
        // 5. User's staking reference script
        //
        // Here we don't care about the staking parts. However, if the funds are
        // being provided by the `treasury` contract, it'll stipulate that the
        // staking parts of all 4 new UTxOs (since the first one is just getting
        // an updated datum) match the contributor's.
        expect [
          Output {
            address: o0_address,
            value: o0_value,
            datum: InlineDatum(o0_datum_data),
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
            datum: NoDatum,
            reference_script: Some(_),
          },
          Output {
            address: Address {
              payment_credential: Script(o4_pay_cred_hash),
              ..
            },
            value: o4_value,
            datum: NoDatum,
            reference_script: Some(_),
          },
          ..
        ] = outputs

        expect Entry{next_username: Some(prev_entrys_updated_next_username)}: RecordDatum =
          o0_datum_data

        // We don't care about Lovelace fluctuations, since in case previous
        // entry's datum goes from a `None` to a `Some`, its minimum required
        // Lovelaces increases.
        let updated_prev_entrys_beacon =
          utils.get_single_asset_from_value_apart_from_ada(o0_value)

        expect Entry { next_username: entrys_next_username }: RecordDatum =
          o1_datum_data
        let (
          entrys_output_asset_policy,
          entrys_output_asset_name,
          entrys_output_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o1_value)

        // `contributor` and `treasury_address` can be set arbitrarily. If
        // funded by treasury, its own contract will validate these.
        expect Account { pubkey: specified_pubkey, salt: specified_salt, .. }: RecordDatum =
          o2_datum_data
        let (
          accounts_output_asset_policy,
          accounts_output_asset_name,
          accounts_output_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o2_value)

        let (
          accounts_script_asset_policy,
          accounts_script_asset_name,
          accounts_script_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o3_value)

        let (
          accounts_staking_script_asset_policy,
          accounts_staking_script_asset_name,
          accounts_staking_script_asset_quantity,
        ) = utils.get_single_asset_from_value_apart_from_ada(o4_value)

        and {
          // --- Address validations -------------------------------------------
          o0_address == prev_entrys_address,
          o1_pay_cred_hash == own_policy,
          o2_pay_cred_hash == own_policy,
          o3_pay_cred_hash == own_policy,
          o4_pay_cred_hash == own_policy,
          // --- Value validations ---------------------------------------------
          updated_prev_entrys_beacon == prev_entrys_beacon,
          //
          entrys_output_asset_policy == own_policy,
          entrys_output_asset_name == username,
          entrys_output_asset_quantity == 1,
          //
          accounts_output_asset_policy == own_policy,
          accounts_output_asset_name == username,
          accounts_output_asset_quantity == 1,
          //
          accounts_script_asset_policy == own_policy,
          accounts_script_asset_name == username,
          accounts_script_asset_quantity == 1,
          //
          accounts_staking_script_asset_policy == own_policy,
          accounts_staking_script_asset_name == username,
          accounts_staking_script_asset_quantity == 1,
          // --- Datum validations ---------------------------------------------
          prev_entrys_updated_next_username == username,
          entrys_next_username == prev_entrys_next_username,
          specified_salt == cbor.serialise(own_out_ref),
          utils.outputs_signed_by_ed25519_key(
            specified_pubkey,
            outputs,
            signature,
          ),
        }?
      }
      // }}}
      BurnAccount {
        signature,
        prev_entrys_index,
        closing_entrys_index,
        closing_accounts_index,
        closing_accounts_ref_script_index,
        closing_accounts_staking_ref_script_index,
      } -> {
        // {{{
        // Users will have the right to close their accounts. The only
        // requirement is to pay all the deployment funds back to their
        // designated treasury.
        // 1. Five UTxOs are expected to be spent such that one of them points
        //    to the closing account's username, and the other four are closing
        //    account's entry, "info," and two reference script UTxOs
        // 2. All four closing account's tokens must be getting burnt
        // 3. Datum of the previous account must be updated so that it points to
        //    the (potential) account that the closing account points to (note
        //    that unlike `MintNewAccount` endpoint, here we won't allow value
        //    of previous entry's UTxO to change, since its datum can only
        //    decrease in size)
        // 4. If there is contribution return info attached to the closing
        //    account's UTxO (i.e. its deployment costs were covered by the
        //    treasury), all Lovelaces next to authentication tokens must go
        //    back to the designated treasury

        let
          m_prev_entrys_output,
          m_closing_entrys_output,
          m_closing_accounts_output,
          m_ref_scripts_output,
          m_staking_ref_scripts_output,
          _last_index,
        <-
          foldl6(
            inputs,
            None,
            None,
            None,
            None,
            None,
            0,
            fn(
              i,
              m_prev_entry,
              m_closing_entry,
              m_closing_account,
              m_ref_script,
              m_staking_ref_script,
              curr_index,
              return,
            ) {
              let next_index = curr_index + 1
              let Input {
                output: Output {
                  address: Address { payment_credential, .. },
                  ..
                } as o,
                ..
              } = i
              when payment_credential is {
                Script(inputs_script_hash) -> {
                  expect (inputs_script_hash == own_policy)?
                  if curr_index == prev_entrys_index {
                    return(
                      Some(o),
                      m_closing_entry,
                      m_closing_account,
                      m_ref_script,
                      m_staking_ref_script,
                      next_index,
                    )
                  } else if curr_index == closing_entrys_index {
                    return(
                      m_prev_entry,
                      Some(o),
                      m_closing_account,
                      m_ref_script,
                      m_staking_ref_script,
                      next_index,
                    )
                  } else if curr_index == closing_accounts_index {
                    return(
                      m_prev_entry,
                      m_closing_entry,
                      Some(o),
                      m_ref_script,
                      m_staking_ref_script,
                      next_index,
                    )
                  } else if curr_index == closing_accounts_ref_script_index {
                    return(
                      m_prev_entry,
                      m_closing_entry,
                      m_closing_account,
                      Some(o),
                      m_staking_ref_script,
                      next_index,
                    )
                  } else if curr_index == closing_accounts_staking_ref_script_index {
                    return(
                      m_prev_entry,
                      m_closing_entry,
                      m_closing_account,
                      m_ref_script,
                      Some(o),
                      next_index,
                    )
                  } else {
                    fail @"Invalid input index encountered"
                  }
                }
                _ ->
                  return(
                    m_prev_entry,
                    m_closing_entry,
                    m_closing_account,
                    m_ref_script,
                    m_staking_ref_script,
                    next_index,
                  )
              }
            },
          )
        // Only 5 UTxOs must be spent from the record script:
        // 1. Previous entry
        // 2. Closing entry
        // 3. Closing account
        // 4. Closing account's reference script
        // 5. Closing account's staking reference script
        expect Some(Output {
          address: prev_entrys_address,
          value: prev_entrys_value,
          datum: InlineDatum(prev_entrys_datum),
          ..
        }) = m_prev_entrys_output
        expect Some(Output {
          value: closing_entrys_value,
          datum: InlineDatum(closing_entrys_datum),
          ..
        }) = m_closing_entrys_output
        expect Some(Output {
          value: closing_accounts_value,
          datum: InlineDatum(closing_accounts_datum),
          ..
        }) = m_closing_accounts_output
        expect Some(Output {
          value: ref_scripts_value,
          datum: NoDatum,
          reference_script: Some(_),
          ..
        }) = m_ref_scripts_output
        expect Some(Output {
          value: staking_ref_scripts_value,
          datum: NoDatum,
          reference_script: Some(_),
          ..
        }) = m_staking_ref_scripts_output

        let (prev_entrys_policy, _prev_entrys_token_name, prev_entrys_qty) =
          utils.get_single_asset_from_value_apart_from_ada(prev_entrys_value)
        let
          closing_entrys_lovelace,
          closing_entrys_policy,
          closing_username,
          closing_entrys_qty,
        <- utils.get_lovelace_quantity_and_single_asset(closing_entrys_value)
        let
          closing_accounts_lovelace,
          closing_accounts_policy,
          closing_accounts_token_name,
          closing_accounts_qty,
        <- utils.get_lovelace_quantity_and_single_asset(closing_accounts_value)
        let
          ref_scripts_lovelace,
          ref_scripts_policy,
          ref_scripts_token_name,
          ref_scripts_qty,
        <- utils.get_lovelace_quantity_and_single_asset(ref_scripts_value)
        let
          staking_ref_scripts_lovelace,
          staking_ref_scripts_policy,
          staking_ref_scripts_token_name,
          staking_ref_scripts_qty,
        <-
          utils.get_lovelace_quantity_and_single_asset(
            staking_ref_scripts_value,
          )

        // Spent tokens must be authentic.
        expect and {
            own_policy == prev_entrys_policy,
            own_policy == closing_entrys_policy,
            own_policy == closing_accounts_policy,
            own_policy == ref_scripts_policy,
            own_policy == staking_ref_scripts_policy,
            closing_username == closing_accounts_token_name,
            closing_username == ref_scripts_token_name,
            closing_username == staking_ref_scripts_token_name,
            prev_entrys_qty == 1,
            closing_entrys_qty == 1,
            closing_accounts_qty == 1,
            ref_scripts_qty == 1,
            staking_ref_scripts_qty == 1,
          }?

        // Usernames and token names must match properly.
        expect Entry{next_username: Some(stored_closing_username)}: RecordDatum =
          prev_entrys_datum
        expect (stored_closing_username == closing_username)?
        expect Entry { next_username: closing_entrys_next_username }: RecordDatum =
          closing_entrys_datum
        let prev_entrys_updated_datum: Data =
          Entry { next_username: closing_entrys_next_username }

        // Exactly one asset must be burnt for `closing_username`, with a
        // quantity of -4. Here too there is no need to validate the burnt
        // asset's policy.
        expect [(_, burn_username, burn_qty)] = assets.flatten(mint)
        expect and {
            burn_username == closing_username,
            burn_qty == -4,
          }?

        // - First produced UTxO must go back to the script.
        // - We're also expecting a second produced UTxO here so that further
        //   down we can validate it against a possible reimbursement of its
        //   contributor (this is alright as spent UTxOs validated here can't
        //   cover transaction fees)
        expect [
          Output {
            address: cont_prev_address,
            datum: InlineDatum(cont_prev_datum),
            value: cont_prev_value,
            reference_script: None,
          },
          o2,
          ..
        ] = outputs

        expect Account {
          pubkey: closing_accounts_pubkey,
          contribution_return: closing_accounts_contribution_return,
          ..
        }: RecordDatum = closing_accounts_datum

        // Previous entry in the list is reproduced unchanged, except for its
        // datum, which must point to the closing entry's (potential) next
        // username.
        and {
          cont_prev_address == prev_entrys_address,
          cont_prev_datum == prev_entrys_updated_datum,
          cont_prev_value == prev_entrys_value,
          utils.outputs_signed_by_ed25519_key(
            closing_accounts_pubkey,
            outputs,
            signature,
          ),
          // If there are contribution info stored in the closing account, it
          // means this account has not paid back the deployment costs yet, and
          // it can only close the account by paying the funds back to the
          // treasury, ensuring the contributor's info are preserved.
          when closing_accounts_contribution_return is {
            None -> True
            Some(ContributionReturn {
              treasury_address: closing_accounts_treasury_address,
              contributor: closing_accounts_contributor,
            }) -> {
              expect Output {
                address: treasurys_address,
                datum: InlineDatum(treasurys_datum_data),
                value: treasurys_value,
                reference_script: None,
              } = o2

              expect treasurys_contributor: Contributor = treasurys_datum_data

              and {
                treasurys_address == closing_accounts_treasury_address,
                treasurys_value == assets.from_lovelace(
                  closing_entrys_lovelace + closing_accounts_lovelace + ref_scripts_lovelace + staking_ref_scripts_lovelace,
                ),
                treasurys_contributor == closing_accounts_contributor,
              }
            }
          },
        }?
      }
    }
    // }}}
  }

  spend(
    datum: Option<RecordDatum>,
    action: RecordSpendAction,
    own_out_ref: OutputReference,
    tx: Transaction,
  ) {
    let Transaction { inputs, outputs, mint, .. } = tx

    when action is {
      AppendToNewAccount { input_index } ->
        // This only needs to make sure the minting endpoint is invoked with a
        // single asset of own script hash.
        validate_mint(input_index, 4, own_out_ref, inputs, mint)?
      CloseAccount { input_index } ->
        // This only needs to make sure the minting endpoint is invoked with a
        // single asset of own script hash.
        validate_mint(input_index, -4, own_out_ref, inputs, mint)?
      AuthorizedSpend { signature, accounts_input_index, intent } -> {
        expect Some(input_datum) = datum

        expect Account { pubkey, contribution_return, .. }: RecordDatum =
          input_datum

        expect Output {
          address: Address { payment_credential: Script(own_script_hash), .. } as own_address,
          value: own_value,
          reference_script: None,
          ..
        } = utils.get_own_input_at(inputs, own_out_ref, accounts_input_index)

        let (accounts_policy, _username, accounts_qty) =
          utils.get_single_asset_from_value_apart_from_ada(own_value)

        expect [
          Output {
            address: cont_address,
            datum: InlineDatum(cont_datum_data),
            value: cont_value,
            reference_script: None,
          },
          ..
        ] = outputs

        expect Account {
          pubkey: cont_pubkey,
          salt: cont_salt,
          contribution_return: cont_contribution_return,
        }: RecordDatum = cont_datum_data
        let UpdatePubkey { signature_with_new_key } = intent

        // 1. Input account UTxO must be authentic
        // 2. Outputs must be signed by input account's stored `pubkey`
        // 3. Account UTxO must go back to the script
        // 4. Account's value must remain unchanged (this is fine as the
        //    datum size won't change)
        // 6. If the intent is to update pubkey, both pubkey and salt need to be
        //    updated, and the outputs must also be signed by the new `pubkey`
        and {
          accounts_policy == own_script_hash,
          accounts_qty == 1,
          utils.outputs_signed_by_ed25519_key(pubkey, outputs, signature),
          cont_address == own_address,
          cont_value == own_value,
          cont_contribution_return == contribution_return,
          // Validations for updating the pubkey
          !(cont_pubkey == pubkey),
          cont_salt == cbor.serialise(own_out_ref),
          utils.outputs_signed_by_ed25519_key(
            cont_pubkey,
            outputs,
            signature_with_new_key,
          ),
        }?
      }
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

  let mint_qty = utils.get_single_mint_quantity_of(mint, own_script_hash)

  mint_qty == expected_mint_quantity
}
