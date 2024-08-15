// NOTE: Lexicographic order of these constants matter as the contract logic
//       relies on it.

pub const entrys_token_name_byte_value = 0

pub const entrys_token_name_byte = #"00"

pub const accounts_token_name_byte_value = 1

pub const accounts_token_name_byte = #"01"

// 5 years of inactivity allowed, after which the contributor who had provided
// the initial required funds for creating an acount can deplete the account,
// and burn the NFTs.
pub const allowed_inactivity_period_before_contributor_can_claim =
  157_800_000_000_000

// 6 years of inactivity allowed, after which anyone can claim all funds of an
// account and burn its beacon NFTs.
pub const allowed_inactivity_period_before_open_claim = 189_300_000_000_000
