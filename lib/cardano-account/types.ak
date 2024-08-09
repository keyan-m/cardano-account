use aiken/time.{PosixTime}

pub type AccountDatum {
  NoDatum
  Account { pubkey: ByteArray, nonce: ByteArray, latest_activity: PosixTime }
}
