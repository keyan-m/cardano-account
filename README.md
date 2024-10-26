# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Cardano Account: A Wallet-less Solution](#cardano-account-a-wallet-less-solution)
    * [How does it work?](#how-does-it-work)
    * [Technical Details](#technical-details)
        * [Account Contract](#account-contract)
        * [Record Contract](#record-contract)
        * [Treasury](#treasury)
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

By storing each username in a linked list, along with a public key and a salt,
each account can be uniquely identified, and a provided signature (ED25519) can
be verified.

The contract only verifies the signature and doesn't care about the underlying
seed of the key pair. However, the following hash can be used as seed:
```
[ salt, [ raw_username ], [ raw_password ] ]
```

Where `,` has been used to notate concatenation, and `[ ]` indicates hashing.

For the user to withdraw their funds, they should provide their username and
password to the frontend provider, after which their linked list entry UTxO will
be fetched, their account seed constructed, and their key pair generated.

Using the private key of this pair, users can now sign any withdrawal
transactions.

With this solution, users can utilize all the password management solutions
already existing, and therefore offers a smoother onboarding process for less
experienced users.

## Technical Details

### Account Contract

The `account` contract relies on the `record` contract, where all registered
accounts are stored in order to guarantee uniqueness of usernames.

`account`'s spend endpoint is very minimal. It only validates a withdrawal is
present in the transaction, invoking the script it is parameterized by.

The staking script (parameterized by a username, and script hash of the contract
responsible for managing the linked list), is also somewhat minimal: it works by
requiring an account's info UTxO to be present in the transaction as a reference
input, so that it can verify provided signatures against users' stored public
keys.

This design keeps transaction costs low for users, and also allows multiple
UTxOs to be spent with minimal execution budgets.

The "account UTxO" (meaning the UTxO carrying account's info), is authenticated
by an NFT from the `record` validator, and a token name identical to
the `username` parameter of the contract.

Information stored in account UTxO's datum consist of:
- User's ED25519 public key
- The salt that was presumably used to generate the key pair
- If the account registration was funded by a contributor, reimbursement info
  are also included
```rs
type Account {
  pubkey: ByteArray,
  salt: ByteArray,
  constribution_return: Option<ContributionReturn>,
}
```

### Record Contract

The purpose of this contract is to provide beacon NFTs for UTxOs, and also to
keep track of registered usernames using a linked list to ensure uniqueness.

### Treasury

To allow free registrations, there is also a treasury contract where
contributors can permanently lock their funds, which can later be used for new
accounts.

These funds will be marked with contributors' credentials so that they preserve
staking rights, and therefore continue supporting the chain.

## User Experience

### Account Creation

1. User provides a username and password, quite like any web2 login page
2. If the username is not already occupied (enforced by an on-chain linked
   list), the platform builds the transaction that consumes the previous
   link/UTxO in the list
3. It uses the output reference of link's UTxO as salt, concatenates it to the
   hashes of the provided raw username and raw password, and hashes the result
4. It uses this hash as the seed for generating an ED25519 key pair
5. Store the salt alongside the verification/public key of the generated pair
6. With the outputs of the transaction now determined, the platform uses the
   acquired private key to sign the outputs, and provide it as the redeemer
7. Submit the transaction

All the required funds (transaction fee, minimum required ADA for beacon UTxOs
and deployed scripts) are provided by the treasury.

### Deposits

Since each account UTxO is meant to be stored in a dedicated script address,
this address can be used for arbitrary deposits, identical to a simple wallet.

The frontend can either provide a payment platform, a standard for other wallets
to implement, or simply allow users to query their address so that they can
share it with others.

### Withdrawals

1. User types in their username and password, and the funds they want to
   withdraw
2. System hashes the raw username, and looks to find the UTxO which stores an
   NFT with this token name
3. The platform uses the stored salt, along with username and password of the
   user to generate the ED25519 key pair
4. Builds the transaction with proper outputs
5. Using user's private key, signs the outputs of this transaction
4. And finalizes the transaction such that the redeemer contains the signature
   that can be verified on-chain using the user's stored public key

## Disclaimer

This is currently a prototype, and it's primarily intended as a proof of
concept.
