use cardano/address.{Credential}

pub type AccountDatum {
  pubkey: ByteArray,
  nonce: ByteArray,
  latest_activity: Int,
}

pub type Contributor {
  payment_credential: Credential,
  stake_credential: Credential,
}

pub type Entry {
  next_username: Option<ByteArray>,
  contributor: Contributor,
}
