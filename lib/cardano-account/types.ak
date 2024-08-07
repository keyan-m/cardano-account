pub type AccountDatum {
  NoDatum
  Account { pubkey: ByteArray, nonce: ByteArray }
}
