use aiken/builtin
use aiken/cbor
use aiken/transaction.{Output}
use aiken/transaction/value.{AssetName, PolicyId, Value}

pub fn get_single_asset_from_value_apart_from_ada(
  v: Value,
) -> (PolicyId, AssetName, Int) {
  // A single asset was expected.
  expect [_, triplet] =
    v
      |> value.flatten
  triplet
}

pub fn outputs_signed_by_ed25519_key(
  verification_key: ByteArray,
  outputs: List<Output>,
  signature: ByteArray,
) -> Bool {
  builtin.verify_ed25519_signature(
    verification_key,
    cbor.serialise(outputs),
    signature,
  )
}
