use aiken/crypto.{Signature}
use cardano/address.{Credential}

pub type Contributor {
  verification_key_hash: ByteArray,
  stake_credential: Credential,
}

pub type RecordDatum {
  Entry { next_username: Option<ByteArray>, contributor: Contributor }
  Account { pubkey: ByteArray, salt: ByteArray }
  DeployedScript
}

pub type RecordMintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: Signature }
  BurnAccount {
    prev_entrys_index: Int,
    closing_entrys_index: Int,
    closing_accounts_index: Int,
    closing_accounts_ref_script_index: Int,
  }
}

pub type RecordSpendAction {
  AppendToNewAccount { input_index: Int }
  CloseAccount
  AuthorizedSpend {
    signature: Signature,
    accounts_input_index: Int,
    intent: Intent,
  }
}

pub type Intent {
  UpdatePubkey { signature_with_new_key: Signature }
}
