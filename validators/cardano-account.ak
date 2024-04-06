use aiken/bytearray 
use aiken/cbor 
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Redeemer, ScriptContext,
  Transaction,
}
use aiken/transaction/credential.{Address, ScriptCredential, StakeCredential}
use aiken/transaction/value
use cardano_account/utils as utils

type Datum {
  RecordHead { next_username: Option<ByteArray> }
  Account {
    password_hash: ByteArray,
    nonce: ByteArray,
    next_username: Option<ByteArray>,
  }
}

type MintAction {
  Initiate
  NewAccount {
    username: ByteArray,
    password_hash: ByteArray,
    initial_balance: Int,
  }
}

validator(utxo_ref: OutputReference, providers_stake_cred: Option<StakeCredential>) {
  fn mint(action: MintAction, ctx: ScriptContext) {
    let ScriptContext { transaction: tx, purpose } = ctx

    expect Mint(own_policy) = purpose

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
      Initiate -> {
        // To enforce a single initiation, the specified UTxO must be spent.
        expect
          list.any(inputs, fn(input) { input.output_reference == utxo_ref })?

        // Only a single, nameless token must be minted.
        expect (mint_name == #"")?

        // Only one UTxO must be produced at the script address.
        expect [
          Output {
            datum: InlineDatum(list_head_datum),
            value: list_head_value,
            ..
          },
        ] =
          list.filter(
            outputs,
            fn(output) { output.address.payment_credential == own_script_cred },
          )

        // Linked list must be empty at initiation.
        expect RecordHead { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from Lovelaces.
        let list_head_asset = utils.get_single_asset_from_value(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      NewAccount { username, password_hash, initial_balance } -> {
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
              stake_credential: o0_stake_cred,
            },
            value: o0_value,
            datum: o0_datum,
            reference_script: None,
          },
          Output {
            address: Address {
              payment_credential: o1_pay_cred,
              stake_credential: o1_stake_cred,
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
        and {
          o0_pay_cred == own_script_cred,
          o1_pay_cred == own_script_cred,
          o0_stake_cred == providers_stake_cred,
          o1_stake_cred == providers_stake_cred,
          o0_datum == InlineDatum(updated_datum),
          o1_datum == InlineDatum(account_datum),
          o0_value == curr_value,
          o1_value == value.from_lovelace(initial_balance),
        }?
      }
    }
  }

  fn spend(_datum: Datum, _redeemer: Redeemer, _ctx: ScriptContext) {
    True
  }
}

fn validate_proper_placement(
  new_elem: ByteArray,
  m_next_elem: Option<ByteArray>,
) -> Bool {
  when m_next_elem is {
    None -> True
    Some(next_elem) -> bytearray.compare(new_elem, next_elem) == Less
  }
}
