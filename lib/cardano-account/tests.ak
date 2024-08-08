use aiken/builtin
use aiken/bytearray
use aiken/cbor
use aiken/fuzz.{and_then}
use aiken/list
use aiken/transaction.{InlineDatum, Output}
use aiken/transaction/credential.{Address, ScriptCredential}
use aiken/transaction/value.{Value}

const sample_outputs = #"9fd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e01d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e02d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e07d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e01d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e02d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa140a1401a00030d40d87b9f01ffd87a80ffd8799fd8799fd87a9f581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616ffd87a80ffa240a1401a00030d40581c9ee6dfb61a2fb903df487c401663825643bb825d41695e63df8af616a1419e03d87b9f01ffd87a80ffff"
const sample_outputs_blake2b_256 = #"e5a57915afbc4ca6a65e170c05c11ae6f19516efabc3cc13298d0ea61c3a2d32"
// // from: https://cyphr.me/ed25519_tool/ed.html
// const ed25519_seed = #"329759e0c67991b1e9b8b9b212a1ebbab2d85e9dd93a457d0640a824ece3aea8"
const ed25519_pubkey = #"3e05b475fa1e873b587b1ac971d9db1a6a2e111413c45c81df76472d1be2808d"
const signed_sample_outputs = #"d53672e11ecb943f8b573c1c2e65f9a466f2f85cb1c159de2ee8660862d1ec629879c43c17341a81d05f04a50b51c898e21d9c36211c92ef759608cea1f0c501"
const signed_sample_outputs_blake2b_256 = #"d8be4d9d42a123c4e748b17bfc031b5a3b24c8712a3854c73202da8bf1284e8d0825ff7e0e3ebcb36764d6cc79be53b9f34ea06858bbc854d16c5ceaffbf7d00"

fn generate_28_bytes() -> Fuzzer<ByteArray> {
  let src <- and_then(fuzz.bytearray())
  fuzz.constant(bytearray.take(src, 28))
}

fn generate_one_asset_as_value() -> Fuzzer<Value> {
  let b28 <- and_then(generate_28_bytes())
  let b32 <- and_then(fuzz.bytearray())
  let token_name_length <- and_then(fuzz.int_at_least(1))
  let token_count <- and_then(fuzz.int_at_least(1))
  fuzz.constant(value.from_asset(b28, bytearray.take(b32, token_name_length), token_count))
}

fn generate_value() -> Fuzzer<Value> {
  let lovelace_count <- and_then(fuzz.int_at_least(2_000_00))
  let lovelace_value = value.from_lovelace(lovelace_count)
  let other_assets_values <- and_then(fuzz.list_at_most(generate_one_asset_as_value(), 50))
  fuzz.constant(list.foldl(other_assets_values, lovelace_value, fn(v, acc) {value.merge(v, acc)}))
}

fn generate_sample_utxo() -> Fuzzer<Output> {
  let b28 <- and_then(generate_28_bytes())
  let v <- and_then(generate_value())
  fuzz.constant(Output {
    address: Address {
      payment_credential: ScriptCredential(b28),
      stake_credential: None,
    },
    value: v,
    datum: InlineDatum(1),
    reference_script: None,
  })
}

fn generate_outputs() -> Fuzzer<List<Output>> {
  fuzz.list_at_least(generate_sample_utxo(), 1)
}

test prop_outputs(outs via generate_outputs()) {
  fuzz.label(@"TEST")
  trace cbor.serialise(outs)
  list.length(outs) < 40
}

test unit_verify_raw_outputs() {
  builtin.verify_ed25519_signature(
    ed25519_pubkey,
    sample_outputs,
    signed_sample_outputs,
  )
}

test unit_verify_hashed_outputs() {
  builtin.verify_ed25519_signature(
    ed25519_pubkey,
    sample_outputs_blake2b_256,
    signed_sample_outputs_blake2b_256,
  )
}
