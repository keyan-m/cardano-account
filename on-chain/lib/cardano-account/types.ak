use aiken/crypto.{Signature}
use cardano/address.{Credential}

pub type Contributor {
  verification_key_hash: ByteArray,
  stake_credential: Credential,
}

pub type RecordDatum {
  Entry { next_username: Option<ByteArray>, contributor: Contributor }
  Account { pubkey: ByteArray, salt: ByteArray, m_latest_activity: Option<Int> }
  DeployedScript
}

pub type RecordMintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: Signature }
  CloseStaleAccount {
    prev_entrys_index: Int,
    closing_entrys_index: Int,
    closing_accounts_index: Int,
    closing_accounts_ref_script_index: Int,
  }
}

pub type RecordSpendAction {
  AppendToNewAccount { input_index: Int }
  DepleteAccount { input_index: Int }
  AuthorizedSpend {
    signature: Signature,
    accounts_input_index: Int,
    intent: Intent,
  }
}

pub type Intent {
  ProveActivity
  UpdatePubkey { signature_with_new_key: Signature }
}
