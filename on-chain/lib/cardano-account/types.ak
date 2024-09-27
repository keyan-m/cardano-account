use cardano/address.{Credential}
use cardano/transaction.{OutputReference}

pub type Contributor {
  verification_key_hash: ByteArray,
  stake_credential: Credential,
}

pub type RecordDatum {
  Entry {
    next_username: Option<ByteArray>,
    contributor: Contributor,
  }
  Account {
    pubkey: ByteArray,
    nonce: ByteArray,
    latest_activity: Int,
  }
  DeployedScript
}

pub type RecordMintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: ByteArray }
  CloseStaleAccount {
    prev_entrys_out_ref: OutputReference,
    entrys_out_ref: OutputReference,
  }
}
