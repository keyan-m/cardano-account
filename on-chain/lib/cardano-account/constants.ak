// NOTE: Lexicographic order of these constants matter as the contract logic
//       relies on it.

pub const entrys_token_name_byte_value = 0

pub const entrys_token_name_byte = #"00"

pub const accounts_token_name_byte_value = 1

pub const accounts_token_name_byte = #"01"

// 1 year / 366 days of inactivity allowed, after which the contributor who had
// provided the initial required funds for creating an acount can deplete the
// account, and burn the NFTs.
pub const allowed_inactivity_period_before_contributor_can_claim =
  31_622_400_000

// 2 years of inactivity allowed, after which anyone can claim all funds of an
// account and burn its beacon NFTs.
pub const allowed_inactivity_period_before_open_claim = 63_244_800_000
