use aiken/builtin
use aiken/bytearray
use aiken/cbor
use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken/list
use aiken/time.{PosixTime}
use aiken/transaction.{
  InlineDatum, Input, Output, OutputReference, ValidityRange,
}
use aiken/transaction/credential.{
  Address, Script, ScriptCredential, VerificationKey,
}
use aiken/transaction/value.{AssetName, MintedValue, PolicyId, Value}
use cardano_account/constants.{accounts_token_name_byte, entrys_token_name_byte}

pub type PubKeyHash =
  Hash<Blake2b_224, VerificationKey>

pub type ScriptHash =
  Hash<Blake2b_224, Script>

// This functions assumes the "first" asset is ADA.
pub fn get_single_asset_from_value_apart_from_ada(
  v: Value,
) -> (PolicyId, AssetName, Int) {
  // Exactly two assets are expected.
  expect [_, triplet] =
    v
      |> value.flatten
  triplet
}

pub fn get_single_mint_quantity_of(
  mint: MintedValue,
  target_policy: ScriptHash,
) -> Int {
  expect [(mint_policy, _, mint_quantity)] =
    mint
      |> value.from_minted_value
      |> value.flatten
  expect (mint_policy == target_policy)?
  mint_quantity
}

pub fn get_two_mint_nfts_of(mint: MintedValue, script_hash: ScriptHash) -> Int {
  expect [(mint_policy_0, _, mint_qty_0), (mint_policy_1, _, mint_qty_1)] =
    mint
      |> value.from_minted_value
      |> value.flatten

  // Exactly two NFTs must be minted with the same script hash.
  expect and {
      mint_policy_0 == script_hash,
      mint_policy_1 == script_hash,
      mint_qty_0 == mint_qty_1,
    }?

  mint_qty_0
}

// Validates only 2 tokens are minted/burnt such that:
// 1. Both have the same policy as `target_policy`
// 2. First one has an "entry label"
// 3. Second one has an "account label"
// 4. Both token names are identical apart from their labels
// 5. Quantities of both are equal
// And returns the "username," along with the mint/burn quantity.
pub fn get_entry_and_account_mint_username_and_quantity_of(
  mint: MintedValue,
  target_policy: ScriptHash,
) -> (ByteArray, Int) {
  expect [
    (entrys_policy, entrys_mint_name, entrys_mint_qty),
    (accounts_policy, accounts_mint_name, accounts_mint_qty),
  ] =
    mint
      |> value.from_minted_value
      |> value.flatten
  let username = entrys_mint_name |> bytearray.drop(1)
  expect and {
      entrys_policy == target_policy,
      accounts_policy == target_policy,
      bytearray.take(entrys_mint_name, 1) == entrys_token_name_byte,
      bytearray.take(accounts_mint_name, 1) == accounts_token_name_byte,
      bytearray.drop(accounts_mint_name, 1) == username,
      entrys_mint_qty == accounts_mint_qty,
    }?
  (username, entrys_mint_qty)
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

pub fn get_authentic_input_at(
  reference_inputs: List<Input>,
  address_script_hash: ScriptHash,
  nft_policy: ScriptHash,
  nft_token_name: ByteArray,
  input_index: Int,
) -> Input {
  expect Some(
    Input {
      output: Output {
        address: Address {
          payment_credential: ScriptCredential(refs_script_hash),
          ..
        },
        datum: InlineDatum(_),
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
      refs_nft_policy == nft_policy,
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
        let Input {
          output: Output { address: Address { payment_credential, .. }, .. },
          ..
        } = i
        when payment_credential is {
          ScriptCredential(_) -> True
          _ -> False
        }
      },
    )
  script_input
}

pub fn get_upper_bound(validity_range: ValidityRange) -> PosixTime {
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
  signature: ByteArray,
) -> Bool {
  builtin.verify_ed25519_signature(
    verification_key,
    cbor.serialise(outputs),
    signature,
  )
}

pub fn account_is_stale(
  latest_activity: PosixTime,
  accounts_contributor: PubKeyHash,
  extra_signatories: List<PubKeyHash>,
  validity_range: ValidityRange,
) -> Bool {
  // An account must be considered stale to allow its removal. There is a 2-tier
  // staleness.
  //
  // The contributor who had provided the initial funds for creating the account
  // has the right to claim all the funds earlier than public.
  //
  // Therefore if contributor's signature is present, the shorter allowed
  // inactivity is used to validate staleness.
  let allowed_inactivity_period =
    if list.has(extra_signatories, accounts_contributor) {
      constants.allowed_inactivity_period_before_contributor_can_claim
    } else {
      constants.allowed_inactivity_period_before_open_claim
    }
  let elapsed_since_inactivity =
    get_upper_bound(validity_range) - latest_activity
  elapsed_since_inactivity > allowed_inactivity_period
}
