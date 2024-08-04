# Table of Contents

<!-- vim-markdown-toc GFM -->

* [Cardano Account: A Wallet-less Solution](#cardano-account-a-wallet-less-solution)
    * [How does it work?](#how-does-it-work)
    * [Compromises and Issues](#compromises-and-issues)
        * [Front Running](#front-running)
        * [Ecosystem Participation](#ecosystem-participation)
    * [A More Detailed Walkthrough](#a-more-detailed-walkthrough)
        * [Account Creation](#account-creation)
        * [Deposits](#deposits)
        * [Withdrawals](#withdrawals)
    * [Disclaimer](#disclaimer)

<!-- vim-markdown-toc -->

# Cardano Account: A Wallet-less Solution

An alternate solution to Cardano wallets for simplifying the adoption by
allowing users to take custody of their ADA with a username and password—similar
to web2 conventions.

## How does it work?

By allocating a UTxO for each username, withdrawals can be unlocked using an
ED25519 signature, where its key pair is generated using a nonce stored in the
datum (which comes from a spent UTxO in order to satisfy uniqueness and, to some
extent, randomness).

The contract only verifies the signature and doesn't care about the underlying
seed of the key pair. However, this seed can be generated using the following
hash:
```
[ nonce, raw_username, raw_password ]
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

## Compromises and Issues

### Ecosystem Participation

In this approach where all users share the same address, it becomes impossible
for them to use most Cardano DApps (since user signature is a common
requirement).

One solution is to dedicate an address for each user, where the differing
parameter is their usernames. This, along with passing
of [CIP-112](https://github.com/cardano-foundation/CIPs/pull/749) will
allow `cardano-account` users participate in the ecosystem similar to wallet
owners.

## A More Detailed Walkthrough

### Account Creation

1. User provides a username and password, quite like any web2 login page
2. If the username is not already occupied (enforced by an on-chain linked
   list), the platform builds the transaction that consumes the previous
   link/UTxO in the list
3. It uses the output reference of link's UTxO as nonce, concatenates it to the
   provided raw username and raw password, and hashes the result
4. It uses this hash as the seed for generating an ED25519 key pair
5. Store the nonce alongside the verification/public key of the pair
6. With the outputs of the transaction now determined, the platform uses the
   acquired private key to sign the outputs, and provide it as the redeemer
7. Submit the transaction

Here it's assumed the the platform that's providing this service also provides
the required fee, minimum required ADA for the account UTxO, and collateral
UTxO(s).

### Deposits

Currently, the contract allows anyone to increase ADA of any account UTxOs.
Idealy, payments should be possible with any tokens, but this puts the UTxO at
the risk of [token dust attack](https://plutonomicon.github.io/plutonomicon/vulnerabilities#utxo-value-size-spam-aka-token-dust-attack).

One solution would be limiting the policy IDs an account is willing to accept,
which expands this limit with consent of the account's owner.

Another limitation would be deposits from outside frontend providers (e.g.
from CEXes). This is something that requires the separate address solution
mentioned [earlier](#ecosystem-participation), and also passing of [CIP-69](https://github.com/cardano-foundation/CIPs/pull/321) which
allows scripts to spend datum-less UTxOs.

### Withdrawals

1. User types in their username and password, and the funds they want to
   withdraw
2. System hashes the raw username, drops its first byte (since the first byte
   is used to distinguish the list entry's and account's token names), and looks
   to find the UTxO which stores an NFT with this token name
3. The platform uses the stored nonce, along with raw username and password of
   the user to generate the ED25519 key pair
4. Builds the transaction with proper outputs
5. Using user's private key, signs the outputs of this transaction
4. And finalizes the transaction such that the redeemer contains the signature
   that can be verified on-chain using the user's stored public key

## Disclaimer

In its current form, this is primarily intended as a proof of concept and not
meant to be used in production.
