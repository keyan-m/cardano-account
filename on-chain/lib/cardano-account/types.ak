use aiken/crypto.{Signature}
use cardano/address.{Address, Credential}

pub type Contributor {
  verification_key_hash: ByteArray,
  stake_credential: Credential,
}

pub type RecordDatum {
  Entry {
    next_username: Option<ByteArray>,
    contributor: Contributor,
    treasury_address: Address,
  }
  Account { pubkey: ByteArray, salt: ByteArray }
}

pub type RecordMintAction {
  InitiateRecord
  MintNewAccount { username: ByteArray, signature: Signature }
  BurnAccount {
    signature: Signature,
    prev_entrys_index: Int,
    closing_entrys_index: Int,
    closing_accounts_index: Int,
    closing_accounts_ref_script_index: Int,
    closing_accounts_staking_ref_script_index: Int,
  }
}

pub type RecordSpendAction {
  AppendToNewAccount { input_index: Int }
  CloseAccount { input_index: Int }
  AuthorizedSpend {
    signature: Signature,
    accounts_input_index: Int,
    intent: Intent,
  }
}

pub type Intent {
  UpdatePubkey { signature_with_new_key: Signature }
}
