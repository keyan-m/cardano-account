use aiken/bytearray
use aiken/list
use aiken/transaction.{
  InlineDatum, Input, Mint, Output, OutputReference, Redeemer, ScriptContext,
  Transaction,
}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value
use cardano_walletless_onboarding/utils as utils

type Datum {
  RecordHead { next_username: Option<ByteArray> }
  Account {
    hashed_salted_password_hash: ByteArray,
    nonce: ByteArray,
    next_username: Option<ByteArray>,
  }
}

type MintAction {
  Initiate
  NewAccount { username: ByteArray, password_hash: ByteArray, input_index: Int }
}

validator(utxo_ref: OutputReference) {
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
            fn(output) {
              output.address.payment_credential == ScriptCredential(own_policy)
            },
          )

        // Linked list must be empty at initiation.
        expect RecordHead { next_username: None }: Datum = list_head_datum

        // List head UTxO must contain only one other asset apart from Lovelaces.
        let list_head_asset = utils.get_single_asset_from_value(list_head_value)

        // List head's asset must match the minted asset.
        (list_head_asset == mint_triplet)?
      }
      NewAccount { username, password_hash, input_index } -> {
        // Specified UTxO must be getting spent from the spending endpoint.
        expect Some(Input {
          output: Output {
            datum: InlineDatum(head_or_prev_user_datum),
            value: curr_value,
            ..
          },
          ..
        }) = list.at(inputs, input_index)
        expect d: Datum = head_or_prev_user_datum
        let curr_asset = utils.get_single_asset_from_value(curr_value)
        let (curr_asset_policy, curr_asset_tn, _) = curr_asset
        expect and {
            curr_asset_policy == own_policy,
            username == mint_name,
            bytearray.compare(curr_asset_tn, username) == Less,
          }?
        when d is {
          RecordHead { next_username } -> {
            expect validate_proper_placement(username, next_username)?
            expect [
              Output {
                address: Address {
                  payment_credential: o0PKH,
                  stake_credential: o0StakeCred,
                },
                value: o0Value,
                datum: o0Datum,
                reference_script: None,
              },
              Output {
                address: Address {
                  payment_credential: o1PKH,
                  stake_credential: o1StakeCred,
                },
                value: o1Value,
                datum: o1Datum,
                reference_script: None,
              },
              ..
            ] = outputs
            True
          }
          Account { hashed_salted_password_hash, nonce, next_username } ->
            validate_proper_placement(username, next_username)
        }
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
