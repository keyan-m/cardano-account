use aiken/builtin
use aiken/collection/list
use aiken/crypto.{ScriptHash, blake2b_256}
use aiken/fuzz.{and_then}
use cardano/address.{Address, Inline, Script, VerificationKey}
use cardano/assets.{Value}
use cardano/transaction.{Datum, Input, NoDatum, Output, OutputReference}
use cardano_account/utils as utils

/// A fuzzer for `Value` with a single asset. Unsafely expects 28 bytes long
/// policy ID to be provided.
pub fn single_specific_asset_value_fuzzer(policyId: ByteArray) -> Fuzzer<Value> {
  let token_name <- and_then(fuzz.bytearray_between(0, 32))
  let quantity <- and_then(fuzz.int_at_least(1))
  fuzz.constant(assets.from_asset(policyId, token_name, quantity))
}

/// A `Value` fuzzer with a single asset. Randomly generates the policy ID.
pub fn single_asset_value_fuzzer() -> Fuzzer<Value> {
  let policyId <- and_then(fuzz.bytearray_fixed(28))
  single_specific_asset_value_fuzzer(policyId)
}

/// A `Value` fuzzer without any lovelaces.
pub fn mint_fuzzer() -> Fuzzer<Value> {
  let other_assets_values <-
    and_then(fuzz.list_between(single_asset_value_fuzzer(), 1, 10))
  fuzz.constant(
    list.foldl(
      other_assets_values,
      assets.zero,
      fn(v, acc) { assets.merge(v, acc) },
    ),
  )
}

/// A `Value` fuzzer, guaranteed to include some amount of ADA (minimum must be
/// specified).
pub fn value_fuzzer(min_lovelaces: Int) -> Fuzzer<Value> {
  let lovelace_count <- and_then(fuzz.int_at_least(min_lovelaces))
  let lovelace_value = assets.from_lovelace(lovelace_count)
  let other_assets_values <-
    and_then(fuzz.list_at_most(single_asset_value_fuzzer(), 10))
  fuzz.constant(
    list.foldl(
      other_assets_values,
      lovelace_value,
      fn(v, acc) { assets.merge(v, acc) },
    ),
  )
}

/// Output reference fuzzer, transaction ID with 32 bytes, and output index
/// between 0 and 512.
pub fn output_reference_fuzzer() -> Fuzzer<OutputReference> {
  let ref_bytes <- and_then(fuzz.bytearray_fixed(32))
  let output_index <- and_then(fuzz.int_between(0, 512))
  fuzz.constant(OutputReference { transaction_id: ref_bytes, output_index })
}

/// Simple wallet UTxO fuzzer, with a random number of tokens/NFTs.
pub fn user_output_fuzzer() -> Fuzzer<Output> {
  let pkh <- and_then(fuzz.bytearray_fixed(28))
  let skh <- and_then(fuzz.bytearray_fixed(28))
  let v <- and_then(value_fuzzer(2_000_000))
  fuzz.constant(
    Output {
      address: Address {
        payment_credential: VerificationKey(pkh),
        stake_credential: Some(Inline(VerificationKey(skh))),
      },
      value: v,
      datum: NoDatum,
      reference_script: None,
    },
  )
}

/// Simple wallet UTxO fuzzer, with a random reference output and a random
/// number of tokens/NFTs.
pub fn user_input_fuzzer() -> Fuzzer<Input> {
  let output_reference <- and_then(output_reference_fuzzer())
  let output <- and_then(user_output_fuzzer())
  fuzz.constant(Input { output_reference, output })
}

/// Given a script hash and datum, this fuzzer generates a UTxO at an address
/// which its payment part is the same as the given script hash.
pub fn specific_script_output_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Output> {
  let v <- and_then(value_fuzzer(2_000_000))
  fuzz.constant(
    Output {
      address: Address {
        payment_credential: Script(script_hash),
        stake_credential: None,
      },
      value: v,
      datum,
      reference_script: None,
    },
  )
}

/// Returns a tuple where its first element is the random script hash (payment
/// part of the UTxO's address). UTxO value is also random, with 2 ADA.
pub fn script_output_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(fuzz.bytearray_fixed(28))
  let utxo <- and_then(specific_script_output_fuzzer(script_hash, datum))
  fuzz.constant((script_hash, utxo))
}

/// UTxO fuzzer, where the value is composed of 2 ADA and a beacon NFT, such
/// that its policy ID is equal to the script credential of the payment part of
/// UTxO's address. This script hash is also returned.
pub fn authentic_script_output_fuzzer(
  datum: Datum,
) -> Fuzzer<(ByteArray, Output)> {
  let script_hash <- and_then(fuzz.bytearray_fixed(28))
  let tn <- and_then(fuzz.bytearray_between(0, 32))
  let lovelace_value = assets.from_lovelace(2_000_000)
  let beacon = assets.from_asset(script_hash, tn, 1)
  let v = assets.merge(lovelace_value, beacon)
  fuzz.constant(
    (
      script_hash,
      Output {
        address: Address {
          payment_credential: Script(script_hash),
          stake_credential: None,
        },
        value: v,
        datum,
        reference_script: None,
      },
    ),
  )
}

/// Similar to [`specific_script_output_fuzzer`](#specific_script_output_fuzzer),
/// with an additional randomized wrapper for output reference.
pub fn specific_script_input_fuzzer(
  script_hash: ScriptHash,
  datum: Datum,
) -> Fuzzer<Input> {
  let output_reference <- and_then(output_reference_fuzzer())
  let output <- and_then(specific_script_output_fuzzer(script_hash, datum))
  fuzz.constant(Input { output_reference, output })
}

/// Similar to [`script_output_fuzzer`](#script_output_fuzzer), with an
/// additional randomized wrapper for output reference.
pub fn script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(script_output_fuzzer(datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Similar to [`authentic_script_output_fuzzer`](#script_output_fuzzer), with
/// and additional randomized wrapper for output reference.
pub fn authentic_script_input_fuzzer(datum: Datum) -> Fuzzer<(ByteArray, Input)> {
  let output_reference <- and_then(output_reference_fuzzer())
  let (script_hash, output) <- and_then(authentic_script_output_fuzzer(datum))
  fuzz.constant((script_hash, Input { output_reference, output }))
}

/// Simple (non-script) outputs fuzzer.
pub fn user_outputs_fuzzer() -> Fuzzer<List<Output>> {
  fuzz.list_between(user_output_fuzzer(), 1, 10)
}

/// Simple (non-script) inputs fuzzer.
pub fn user_inputs_fuzzer() -> Fuzzer<List<Input>> {
  fuzz.list_between(user_input_fuzzer(), 1, 10)
}

/// Fuzzer for a sorted list of user/wallet inputs, with the addition of one
/// authentic script input.
pub fn inputs_with_an_authentic_script_input_fuzzer(
  datum: Datum,
) -> Fuzzer<(ByteArray, Input, List<Input>)> {
  let wallet_inputs <- and_then(user_inputs_fuzzer())
  let (spend_script_hash, script_input) <-
    and_then(authentic_script_input_fuzzer(datum))
  fuzz.constant(
    (
      spend_script_hash,
      script_input,
      [script_input, ..wallet_inputs] |> utils.sort_inputs,
    ),
  )
}

const sample_outputs =
  #"9fd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e01d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e02d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e07d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e01d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e02d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e03d87b9f01ffd87a80ffff"

// const sample_outputs_blake2b_256 =
//   #"e5a57915afbc4ca6a65e170c05c11ae6f19516efabc3cc13298d0ea61c3a2d32"

// // from: https://cyphr.me/ed25519_tool/ed.html
// const ed25519_seed = #"329759e0c67991b1e9b8b9b212a1ebbab2d85e9dd93a457d0640a824ece3aea8"
const ed25519_pubkey =
  #"3e05b475fa1e873b587b1ac971d9db1a6a2e111413c45c81df76472d1be2808d"

const signed_sample_outputs =
  #"d53672e11ecb943f8b573c1c2e65f9a466f2f85cb1c159de2ee8660862d1ec629879c43c17341a81d05f04a50b51c898e21d9c36211c92ef759608cea1f0c501"

const signed_sample_outputs_blake2b_256 =
  #"d8be4d9d42a123c4e748b17bfc031b5a3b24c8712a3854c73202da8bf1284e8d0825ff7e0e3ebcb36764d6cc79be53b9f34ea06858bbc854d16c5ceaffbf7d00"

test unit_verify_raw_outputs() {
  builtin.verify_ed25519_signature(
    ed25519_pubkey,
    sample_outputs,
    signed_sample_outputs,
  )
}

test unit_verify_hashed_outputs() {
  let hashed = blake2b_256(sample_outputs)
  builtin.verify_ed25519_signature(
    ed25519_pubkey,
    hashed,
    signed_sample_outputs_blake2b_256,
  )
}
