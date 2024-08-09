// NOTE: Lexicographic order of these constants matter as the contract logic
//       relies on it.

pub const entrys_token_name_byte_value = 0

pub const entrys_token_name_byte = #"00"

pub const accounts_token_name_byte_value = 1

pub const accounts_token_name_byte = #"01"

// 5 years of inactivity allowed, after which anyone can deplete the account,
// but only the initial fund provider can burn the NFTs.
pub const allowed_inactivity_period = 157_800_000_000_000
