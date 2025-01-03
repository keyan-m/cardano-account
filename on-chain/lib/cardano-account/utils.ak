use aiken/builtin
use aiken/cbor
use aiken/collection/list
use aiken/crypto.{ScriptHash, Signature, VerificationKeyHash}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken_scott_utils/common.{Scott4}
use cardano/address.{Address, Credential, Script}
use cardano/assets.{AssetName, PolicyId, Value}
use cardano/transaction.{Input, Output, OutputReference, ValidityRange}
use cardano/transaction/output_reference as output_reference

pub type PubKeyHash =
  VerificationKeyHash

pub fn sort_inputs(inputs: List<Input>) -> List<Input> {
  inputs
    |> list.sort(
        fn(i0: Input, i1: Input) {
          output_reference.compare(i0.output_reference, i1.output_reference)
        },
      )
}

// This functions assumes the "first" asset is ADA.
pub fn get_single_asset_from_value_apart_from_ada(
  v: Value,
) -> (PolicyId, AssetName, Int) {
  // Exactly two assets are expected.
  expect [_,
    triplet] =
    v
      |> assets.flatten
  triplet
}

pub fn get_lovelace_quantity_and_single_asset(
  v: Value,
  return: Scott4<Int, PolicyId, AssetName, Int, result>,
) -> result {
  expect [(_, _, lovelace_qty),
    (policy_id, token_name, qty)] = v |> assets.flatten
  return(lovelace_qty, policy_id, token_name, qty)
}

pub fn get_single_mint_quantity_of(
  mint: Value,
  target_policy: ScriptHash,
) -> Int {
  expect [(mint_policy, _, mint_quantity)] =
    mint
      |> assets.flatten
  expect (mint_policy == target_policy)?
  mint_quantity
}

pub fn get_own_input_at(
  inputs: List<Input>,
  own_out_ref: OutputReference,
  input_index: Int,
) -> Output {
  expect Some(Input { output: own_utxo, output_reference: spent_own_out_ref }) =
    list.at(inputs, input_index)
  expect (own_out_ref == spent_own_out_ref)?
  own_utxo
}

pub fn get_authentic_input_of_at(
  reference_inputs: List<Input>,
  address_script_hash: ScriptHash,
  nft_token_name: ByteArray,
  input_index: Int,
) -> Input {
  expect Some(
    Input {
      output: Output {
        address: Address { payment_credential: Script(refs_script_hash), .. },
        value: refs_value,
        ..
      },
      ..
    } as found_ref_input,
  ) = list.at(reference_inputs, input_index)

  let (refs_nft_policy, refs_nft_token_name, refs_nft_qty) =
    get_single_asset_from_value_apart_from_ada(refs_value)

  expect and {
      refs_script_hash == address_script_hash,
      refs_nft_policy == address_script_hash,
      refs_nft_token_name == nft_token_name,
      refs_nft_qty == 1,
    }?

  found_ref_input
}

pub fn get_single_script_input(inputs: List<Input>) -> Input {
  expect [script_input] =
    list.filter(
      inputs,
      fn(i) {
        when i.output.address.payment_credential is {
          Script(_) -> True
          _ -> False
        }
      },
    )
  script_input
}

pub fn keep_only_inputs_from_credential(
  inputs: List<Input>,
  cred: Credential,
) -> List<Input> {
  inputs |> list.filter(fn(i) { i.output.address.payment_credential == cred })
}

pub fn get_upper_bound(validity_range: ValidityRange) -> Int {
  expect Interval {
    upper_bound: IntervalBound { bound_type: Finite(upper_int), .. },
    ..
  } = validity_range
  upper_int
}

// Copied over from the Fortuna repo:
// https://github.com/cardano-miners/fortuna/blob/32a5edf5b56c8d8a97c45eae254a70d1c66bd972/lib/fortuna/utils.ak#L6-L17
pub fn resolve_output_reference(
  inputs: List<Input>,
  output_ref: OutputReference,
) -> Output {
  expect [input, ..] = inputs
  if input.output_reference == output_ref {
    input.output
  } else {
    resolve_output_reference(builtin.tail_list(inputs), output_ref)
  }
}

pub fn outputs_signed_by_ed25519_key(
  verification_key: ByteArray,
  outputs: List<Output>,
  signature: Signature,
) -> Bool {
  builtin.verify_ed25519_signature(
    verification_key,
    cbor.serialise(outputs),
    signature,
  )
}
