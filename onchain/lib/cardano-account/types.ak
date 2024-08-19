use aiken/time.{PosixTime}
use aiken/transaction/credential.{Address}

pub type AccountDatum {
  NoDatum
  Account { pubkey: ByteArray, nonce: ByteArray, latest_activity: PosixTime }
}

pub type Entry {
  next_username: Option<ByteArray>,
  contributor: Address,
}
