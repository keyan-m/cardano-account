// IMPORTS
use aiken/bytearray
use aiken/cbor
use aiken/dict
use aiken/hash.{Blake2b_224, Hash}
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, ScriptContext, Spend,
  Transaction,
}
use aiken/transaction/credential.{
  Address, Script, ScriptCredential, StakeCredential,
}
use aiken/transaction/value.{MintedValue, Value}
use cardano_account/utils as utils

// DATATYPES
type Datum {
  RecordHead { next_username: Option<ByteArray> }
  Account {
    password_hash: ByteArray,
    nonce: ByteArray,
    next_username: Option<ByteArray>,
  }
}

type MintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, password_hash: ByteArray }
  CloseAccount {
    prev_elements_out_ref: OutputReference,
    accounts_out_ref: OutputReference,
    presalt_password: ByteArray,
  }
}

type SpendAction {
  AppendToNewAccount { input_index: Int }
  Deposit { input_index: Int, deposit_value: Value }
  Withdraw {
    input_index: Int,
    presalt_password: ByteArray,
    new_password_hash: ByteArray,
  }
  DepleteAccount { input_index: Int }
}

// THE VALIDATOR
validator(utxo_ref: OutputReference, providers_stake_cred: StakeCredential) {
  fn mint(action: MintAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Mint(own_policy) } = ctx

    let Transaction { inputs, outputs, mint, .. } = tx

    expect [mint_triplet] =
      mint
        |> value.from_minted_value
        |> value.flatten

    let (mint_policy, mint_name, mint_quantity) = mint_triplet

    expect (mint_policy == own_policy)?

    let own_script_cred = ScriptCredential(own_policy)

    when action is {
      InitiateRecord -> {
        // Initial endpoint for starting the linked list. Requirements are:
        // 1. Specified UTxO must be getting spent
        // 2. A single, nameless NFT is minted at the script address, such that
        //    its staking part is the same as the frontend provider's staking
        //    credential
        // 3. Output datum is `RecordHead { next_username: None }`

        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted.
        expect (mint_name == #"")?
        expect (mint_quantity == 1)?

        // First produced UTxO must go to the script, and providers stake
        // credential.
        expect [
          Output {
            datum: InlineDatum(list_head_datum),
            value: list_head_value,
            address: Address {
              payment_credential: dest_script_cred,
              stake_credential: Some(dest_stake_cred),
            },
            reference_script: None,
          },
          ..
        ] = outputs
        expect (dest_script_cred == own_script_cred)?
        expect (dest_stake_cred == providers_stake_cred)?

        // Linked list must be empty at initiation.
        expect RecordHead { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from
        // Lovelaces.
        let list_head_asset = utils.get_single_asset_from_value(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      MintNewAccount { username, password_hash } -> {
        // Requires the proper link in the list to be spent so that its datum
        // correctly points to the new account's username. The proper link is
        // a previously created account (or the head of the list) such that:
        // 1. Its username is smaller than the new account's
        // 2. The account it (potentially) points to as its `next_username` has
        //    a username that is larger than the new account's
        // TODO: Note that this is flawed as addition/removal of an account can
        //       disrupt the account UTxO of another user. A more proper
        //       approach is to decouple the username UTxOs from balance UTxOs.

        // A signle asset must be minted for `username`.
        expect (username == mint_name)?
        expect (mint_quantity == 1)?

        // Only 1 UTxO must be getting spent from the script address.
        expect [
          Input {
            output: Output {
              datum: InlineDatum(head_or_prev_user_datum),
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
        let curr_asset = utils.get_single_asset_from_value(curr_value)
        let (curr_asset_policy, curr_asset_tn, _) = curr_asset
        expect and {
            curr_asset_policy == own_policy,
            bytearray.compare(curr_asset_tn, username) == Less,
          }?

        expect d: Datum = head_or_prev_user_datum
        let (next_username, updated_datum) =
          when d is {
            RecordHead { next_username } ->
              (next_username, RecordHead(Some(username)))
            Account { password_hash, nonce, next_username } ->
              (next_username, Account(password_hash, nonce, Some(username)))
          }

        // New username must be smaller than a potential next user.
        expect
          when next_username is {
            None -> True
            Some(prev_next_user) ->
              bytearray.compare(username, prev_next_user) == Less
          }?

        // First 2 outputs are expected to be produced at the script address.
        expect [
          Output {
            address: Address {
              payment_credential: o0_pay_cred,
              stake_credential: Some(o0_stake_cred),
            },
            value: o0_value,
            datum: o0_datum,
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: o1_pay_cred,
              stake_credential: Some(o1_stake_cred),
            },
            value: o1_value,
            datum: o1_datum,
            reference_script: None,
          },
          ..
        ] = outputs

        let account_datum: Datum =
          Account {
            password_hash,
            nonce: cbor.serialise(own_out_ref),
            next_username,
          }
        let (
          accounts_asset_policy,
          accounts_asset_name,
          accounts_asset_quantity,
        ) = utils.get_single_asset_from_value(o1_value)

        and {
          o0_pay_cred == own_script_cred,
          o1_pay_cred == own_script_cred,
          o0_stake_cred == providers_stake_cred,
          o1_stake_cred == providers_stake_cred,
          o0_datum == InlineDatum(updated_datum),
          o1_datum == InlineDatum(account_datum),
          o0_value == curr_value,
          accounts_asset_policy == own_policy,
          accounts_asset_name == username,
          accounts_asset_quantity == 1,
        }?
      }
      CloseAccount { prev_elements_out_ref, accounts_out_ref, presalt_password } -> {
        // This is essentially a combination of the account creation and the
        // withdrawal endpoints.
        // 1. Two UTxOs are expected to be spent such that one of them points to
        //    the closing account's username
        // 2. The closing account's NFT must be getting burnt
        // 3. Datum of the previous account must be updated so that it points to
        //    the (potential) account that the closing account points to

        expect [
          Input { output: o0, output_reference: o0_out_ref },
          Input { output: o1, output_reference: o1_out_ref },
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
        expect (
          Output {
            datum: InlineDatum(prev_datum),
            value: prev_value,
            address: prev_address,
            ..
          },
          Output {
            datum: InlineDatum(accounts_datum),
            value: accounts_value,
            ..
          },
        ) =
          if
          o0_out_ref == prev_elements_out_ref && o1_out_ref == accounts_out_ref{
          
            (o0, o1)
          } else if o1_out_ref == prev_elements_out_ref && o0_out_ref == accounts_out_ref {
            (o1, o0)
          } else {
            fail @"Given out refs don't match with found inputs properly"
          }
        expect [(closing_username, _)] =
          accounts_value
            |> value.tokens(own_policy)
            |> dict.to_list
        expect Account {
          password_hash: accounts_password_hash,
          nonce: accounts_nonce,
          next_username: prevs_new_next_username,
        }: Datum = accounts_datum
        expect prev_datum_coerced: Datum = prev_datum
        let prev_accounts_updated_datum: Data =
          when prev_datum_coerced is {
            RecordHead{next_username: Some(stored_closing_username)} -> {
              // Closing account's username must match with the previous UTxO's
              // datum.
              expect (closing_username == stored_closing_username)?
              RecordHead { next_username: prevs_new_next_username }
            }
            Account {
              password_hash: pw,
              nonce: n,
              next_username: Some(stored_closing_username),
            } -> {
              expect (closing_username == stored_closing_username)?
              Account {
                password_hash: pw,
                nonce: n,
                next_username: prevs_new_next_username,
              }
            }
            _ -> fail @"Invalid account configuration encountered"
          }

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
        and {
          mint_name == closing_username,
          mint_quantity == -1,
          password_is_valid(
            accounts_password_hash,
            accounts_nonce,
            presalt_password,
          ),
          cont_prev_datum == prev_accounts_updated_datum,
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
        } = get_own_input_at(inputs, own_out_ref, input_index)

        let mint_quantity = get_single_mint_quantity_of(mint, own_script)
        mint_quantity == 1
      }
      Deposit { input_index, deposit_value } -> {
        // Allows anyone to "charge" an account. However this puts accounts in
        // danger of the token dust attacks.
        // TODO: Limit the maximum number of tokens an account can hold—perhaps
        //       even limit it to only Ada.

        // Always `True` to avoid perfoming a boolean operation on the
        // accumulator.
        let positive_deposits =
          value.reduce(
            deposit_value,
            True,
            fn(_, _, q: Int, _) -> Bool {
              expect (q > 0)?
              True
            },
          )

        let Output {
          address: in_address,
          value: in_value,
          datum: in_inline_datum,
          ..
        } = get_own_input_at(inputs, own_out_ref, input_index)

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
          positive_deposits,
          in_address == out_address,
          in_inline_datum == out_datum,
          value.merge(in_value, deposit_value) == out_value,
        }?
      }
      Withdraw { input_index, presalt_password, new_password_hash } -> {
        // Allows withdraw iff:
        // 1. Concatenation of the nonce with the provided password hashes to
        //    the stored hash
        // 2. The UTxO is reproduced at the incoming address (i.e. script
        //    address, with provider's staking credential)
        // 3. As a slight security measure, prevents the new password to be
        //    identical with the old one

        expect Output {
          address: Address {
            payment_credential: ScriptCredential(own_script),
            ..
          } as in_address,
          value: in_value,
          ..
        } = get_own_input_at(inputs, own_out_ref, input_index)

        // Validate the password.
        expect Account { password_hash, nonce, next_username }: Datum = in_datum
        expect password_is_valid(password_hash, nonce, presalt_password)?

        // Protection layer to prevent resubmitting the same password.
        expect !(password_hash == new_password_hash)?

        let new_datum: Datum =
          Account {
            password_hash: new_password_hash,
            nonce: cbor.serialise(own_out_ref),
            next_username,
          }

        expect [
          Output {
            address: out_address,
            value: out_value,
            datum: out_datum,
            reference_script: None,
          },
          ..
        ] = outputs

        // Only requirement is that username's NFT is not leaving the UTxO. No
        // need to check the quantities here.
        expect [(in_username, _)] =
          in_value
            |> value.tokens(own_script)
            |> dict.to_list
        expect [(out_username, _)] =
          out_value
            |> value.tokens(own_script)
            |> dict.to_list

        and {
          in_address == out_address,
          out_datum == InlineDatum(new_datum),
          in_username == out_username,
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
        } = get_own_input_at(inputs, own_out_ref, input_index)

        let mint_quantity = get_single_mint_quantity_of(mint, own_script)
        mint_quantity == -1
      }
    }
  }
}

// HELPER FUNCTIONS
fn get_own_input_at(
  inputs: List<Input>,
  own_out_ref: OutputReference,
  input_index: Int,
) -> Output {
  expect Some(Input { output: own_utxo, output_reference: spent_own_out_ref }) =
    list.at(inputs, input_index)
  expect (own_out_ref == spent_own_out_ref)?
  own_utxo
}

fn get_single_mint_quantity_of(
  mint: MintedValue,
  target_policy: Hash<Blake2b_224, Script>,
) -> Int {
  expect [(mint_policy, _, mint_quantity)] =
    mint
      |> value.from_minted_value
      |> value.flatten
  expect (mint_policy == target_policy)?
  mint_quantity
}

fn password_is_valid(
  password_hash: ByteArray,
  nonce: ByteArray,
  presalt_password: ByteArray,
) -> Bool {
  let hashed_salted_pass =
    bytearray.concat(nonce, presalt_password)
      |> hash.blake2b_256
  hashed_salted_pass == password_hash
}
