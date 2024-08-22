use cardano/transaction.{PosixTime}
use cardano/credential.{Address}

pub type AccountDatum {
  pubkey: ByteArray, nonce: ByteArray, latest_activity: PosixTime
}

pub type Entry {
  next_username: Option<ByteArray>,
  contributor: Address,
}
