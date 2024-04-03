use aiken/transaction/value.{AssetName, PolicyId, Value}

pub fn get_single_asset_from_value(v: Value) -> (PolicyId, AssetName, Int) {
  // A single asset was expected.
  expect [triplet] =
    v
      |> value.without_lovelace
      |> value.flatten
  triplet
}
