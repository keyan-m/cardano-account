# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Cardano Account: A Wallet-less Solution](#cardano-account-a-wallet-less-solution)
    * [How does it work?](#how-does-it-work)
    * [Technical Details](#technical-details)
        * [Account Contract](#account-contract)
        * [Record Contract](#record-contract)
        * [Support for Open Claim of Stale Accounts](#support-for-open-claim-of-stale-accounts)
    * [User Experience](#user-experience)
        * [Account Creation](#account-creation)
        * [Deposits](#deposits)
        * [Withdrawals](#withdrawals)
    * [Disclaimer](#disclaimer)

<!-- vim-markdown-toc -->

# Cardano Account: A Wallet-less Solution

An alternate solution to Cardano wallets for simplifying the adoption by
allowing users to take custody of their Cardano funds with a username and
password—similar to web2 conventions.

## How does it work?

By allocating a UTxO for each username, withdrawals can be unlocked using an
ED25519 signature, where its key pair is generated using a nonce stored in the
datum (which comes from a spent UTxO in order to satisfy uniqueness and, to some
extent, randomness).

The contract only verifies the signature and doesn't care about the underlying
seed of the key pair. However, the following hash can be used as seed:
```
[ nonce, [ raw_username ], [ raw_password ] ]
```

Where `,` has been used to notate concatenation, and `[ ]` indicates hashing.

For the user to withdraw their funds, they should provide their username and
password to the frontend provider, after which their account UTxO will be
fetched, their account seed constructed, and their key pair generated.

Using the private key of this pair, users can now sign any withdrawal
transactions.

With this solution, users can utilize all the password management solutions
already existing, and therefore offers a smoother onboarding process for less
experienced users.

## Technical Details

### Account Contract

The `account` contract relies on the `record` contract, where all registered
accounts are stored in order to guarantee uniqueness of usernames.

`account` works by requiring its info UTxO to be spent, so that its latest
activity field can be
updated (see [Support for Open Claim of Stale Accounts](#support-for-open-claim-of-stale-accounts)). To
allow multiple datum-less UTxOs to be spent with minimal execution budgets, this
contract also supports reward withdrawals that, depending on whether the account
is considered stale or not, will either look for the account UTxO in the inputs,
or simply as a reference input.

The "account UTxO" (meaning the UTxO carrying account's info), is authenticated
by an NFT from the `record` validator, and a token name identical to
the `username` parameter of the contract, prefixed with a single byte to
distinguish it from the NFT stored in the linked list.

Information stored in account UTxO's datum consist of:
- User's ED25519 public key
- The nonce that was presumably used to generate the key pair
- Account's latest activity in POSIX milliseconds
```rs
type Account {
  pubkey: ByteArray,
  nonce: ByteArray,
  latest_activity: PosixTime,
}
```

### Record Contract

The purpose of this contract is to provide beacon NFTs for UTxOs, and also to
keep track of registered usernames using a linked list to ensure uniqueness.

### Support for Open Claim of Stale Accounts

The account datum carries a `latest_activity` field which has to be updated
whenever the user wants to withdraw datum-less UTxOs (or update their public
key).

With a hardcoded 5-year period, if an account has been inactive for more than
that, anyone will be free to:
- Claim all the funds (i.e. datum-less UTxOs sitting at
  user's `cardano-account` address)
- Burn the NFTs and get ADA of account's UTxOs
- De-register `account`'s staking script and claim its registration deposit

Note that currently there is no prevention of claiming the account UTxO before
claiming all funds in the contract. If NFTs are burnt first, remaining funds
will be locked permanently.

## User Experience

### Account Creation

1. User provides a username and password, quite like any web2 login page
2. If the username is not already occupied (enforced by an on-chain linked
   list), the platform builds the transaction that consumes the previous
   link/UTxO in the list
3. It uses the output reference of link's UTxO as nonce, concatenates it to the
   hashes of the provided raw username and raw password, and hashes the result
4. It uses this hash as the seed for generating an ED25519 key pair
5. Store the nonce alongside the verification/public key of the generated pair
6. With the outputs of the transaction now determined, the platform uses the
   acquired private key to sign the outputs, and provide it as the redeemer
7. Submit the transaction

Here it's assumed the platform that's providing this service also provides the
required fee, minimum required ADA for both the account UTxO and list entry
UTxO, and also collateral UTxO(s).

### Deposits

Since each account UTxO is meant to be stored in a dedicated script address,
this address can be used for arbitrary deposits, identical to a simple wallet.

The frontend can either provide a payment platform, a standard for other wallets
to implement, or simply allow users to query their address so that they can
share it with others.

### Withdrawals

1. User types in their username and password, and the funds they want to
   withdraw
2. System hashes the raw username, drops its first byte (since the first byte
   is used to distinguish the list entry's and account's token names), and looks
   to find the UTxO which stores an NFT with this token name
3. The platform uses the stored nonce, along with username and password of the
   user to generate the ED25519 key pair
4. Builds the transaction with proper outputs
5. Using user's private key, signs the outputs of this transaction
4. And finalizes the transaction such that the redeemer contains the signature
   that can be verified on-chain using the user's stored public key

## Disclaimer

In its current form, this is primarily intended as a proof of concept and not
meant to be used in production.

Plutus V3 is also not yet supported, and handling of datum-less UTxOs is
emulated by defining `AccountDatum` as a sum type.
