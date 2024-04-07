// IMPORTS
use aiken/bytearray
use aiken/cbor
use aiken/hash
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, ScriptContext, Spend,
  Transaction,
}
use aiken/transaction/credential.{Address, ScriptCredential, StakeCredential}
use aiken/transaction/value
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
  CloseAccount { prev_elements_input_index: Int, accounts_input_index: Int }
}

type SpendAction {
  AppendToNewAccount { input_index: Int }
  Deposit { input_index: Int }
  Withdraw {
    input_index: Int,
    presalt_password: ByteArray,
    new_password_hash: ByteArray,
  }
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
    expect (mint_quantity == 1)?

    let own_script_cred = ScriptCredential(own_policy)

    when action is {
      InitiateRecord -> {
        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted.
        expect (mint_name == #"")?

        // First produced UTxO must go to the script, and providers stake
        // credential.
        expect [
          Output {
            datum: InlineDatum(list_head_datum),
            value: list_head_value,
            address: Address {
              payment_credential: script_cred,
              stake_credential: Some(dest_stake_cred),
            },
            reference_script: None,
          },
          ..
        ] = outputs
        expect (script_cred == own_script_cred)?
        expect (dest_stake_cred == providers_stake_cred)?

        // Linked list must be empty at initiation.
        expect RecordHead { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from Lovelaces.
        let list_head_asset = utils.get_single_asset_from_value(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      MintNewAccount { username, password_hash } -> {
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
        expect d: Datum = head_or_prev_user_datum
        let curr_asset = utils.get_single_asset_from_value(curr_value)
        let (curr_asset_policy, curr_asset_tn, _) = curr_asset
        expect and {
            curr_asset_policy == own_policy,
            username == mint_name,
            bytearray.compare(curr_asset_tn, username) == Less,
          }?
        let (next_username, updated_datum) =
          when d is {
            RecordHead { next_username } ->
              (next_username, RecordHead(Some(username)))
            Account { password_hash, nonce, next_username } ->
              (next_username, Account(password_hash, nonce, Some(username)))
          }
        expect validate_proper_placement(username, next_username)?
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
      CloseAccount { prev_elements_input_index, accounts_input_index } -> todo
    }
  }

  fn spend(datum: Datum, action: SpendAction, ctx: ScriptContext) {
    expect ScriptContext { transaction: tx, purpose: Spend(own_out_ref) } = ctx

    let Transaction { inputs, outputs, mint, .. } = tx

    when action is {
      // Only ensures that the minting endpoint is invoked.
      AppendToNewAccount { input_index } -> {
        expect Some(Input {
          output: Output {
            address: Address {
              payment_credential: ScriptCredential(own_script),
              ..
            },
            ..
          },
          output_reference,
        }) = list.at(inputs, input_index)
        expect (output_reference == own_out_ref)?

        expect [(mint_policy, _, mint_quantity)] =
          mint
            |> value.from_minted_value
            |> value.flatten

        and {
          mint_policy == own_script,
          mint_quantity == 1,
        }
      }
      Deposit { input_index } -> todo
      Withdraw { input_index, presalt_password, new_password_hash } -> {
        expect Some(Input {
          output: Output {
            address: Address {
              payment_credential: ScriptCredential(own_script),
              ..
            },
            datum: InlineDatum(own_datum),
            value: own_value,
            ..
          },
          output_reference: spent_own_out_ref,
        }) = list.at(inputs, input_index)
        expect (own_out_ref == spent_own_out_ref)?
        expect Account { password_hash, nonce, next_username }: Datum =
          own_datum
        expect password_is_valid(password_hash, nonce, presalt_password)?
        let new_datum: Datum =
          Account {
            password_hash: new_password_hash,
            nonce: cbor.serialise(own_out_ref),
            next_username,
          }
        expect [
          Output {
            address: Address {
              payment_credential: o_pay_cred,
              stake_credential: Some(o_stake_cred),
            },
            value: o_value,
            datum: o_datum,
            reference_script: None,
          },
          ..
        ] = outputs
        and {
          o_pay_cred == ScriptCredential(own_script),
          o_stake_cred == providers_stake_cred,
          o_datum == InlineDatum(new_datum),
          value.without_lovelace(o_value) == value.without_lovelace(own_value),
        }
      }
    }
  }
}

// HELPER FUNCTIONS
fn validate_proper_placement(
  new_elem: ByteArray,
  m_next_elem: Option<ByteArray>,
) -> Bool {
  when m_next_elem is {
    None -> True
    Some(next_elem) -> bytearray.compare(new_elem, next_elem) == Less
  }
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
