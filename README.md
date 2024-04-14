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

An alternative solution to Cardano wallets to simplify the adoption by allowing
users to take custody of their Ada with a username and password—similar to web2
conventions.

## How does it work?

By allocating a UTxO for each username, withdrawals can be locked behind a
twice salted and hashed password, where its nonce comes from a spent UTxO (which
satisfies randomness and uniqueness required for a nonce).

For the user to withdraw their funds, they can provide the hash of their salted
raw password. This way, the redeemer (which will publicly be available on-chain)
won't reveal user's password, yet it securely allows the contract to validate
its correctness.

The validator performs the salting and hashing once again to make sure it'll
match the stored hash in the datum.

With this solution, users can utilize all the password management solutions
already existing, and therefore offers a smoother onboarding process for less
experienced users.

## Compromises and Issues

### Front Running

Implemented as is, the script is parametrized by a list of "providers" (i.e.
frontend providers), so that it can validate one of them has signed the
transaction.

If this requirement was not put in place, a node validator would be free to
avoid submitting the transaction honestly, but rather remove the transaction,
use the provided redeemer, and withdraw the account in its own favor.

This is an issue that is likely not solvable without changes to Cardano's
infrastructure.

While this is not an ideal solution, it mitigates the required centralization by
allowing users to use any of the providers.

### Ecosystem Participation

In this approach where all users share the same address, it becomes impossible
for them to use most Cardano DApps (since user signature is a common
requirement).

One solution is to dedicate an address for each user, where the differing
parameter is their usernames. This, along with the dual-NFT minting solution
mentioned earlier (where the second NFT is sent to user's dedicated address),
and passing of [CIP-112](https://github.com/cardano-foundation/CIPs/pull/749) will
allow `cardano-account` users participate in the ecosystem similar to wallet
owners.

## A More Detailed Walkthrough

### Account Creation

1. User provides a username and password, quite like any web2 login page
2. If the username is not already occupied (enforced by an on-chain linked
   list), the platform builds the transaction that consumes the previous
   link/UTxO in the list
3. It uses the output reference of link's UTxO as nonce, concatenates it to the
   provided raw password and hashes the result
4. Repeats step 3 to achieve the password hash that should be stored in the
   user's account datum
5. Store the nonce alongside the password hash
6. Submit the transaction

Here it's assumed the the platform that's providing this service also provides
the required fee and collateral UTxO(s).

### Deposits

Currently, the contract allows anyone to increase the Lovelace count of any
account UTxOs. Idealy, payments should be possible with any tokens, but this
puts the UTxO at the risk of [token dust attack](https://plutonomicon.github.io/plutonomicon/vulnerabilities#utxo-value-size-spam-aka-token-dust-attack).

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
3. Ensures that double salt-and-hashing the raw password corresponds to the one
   stored on-chain
4. And builds the transaction such that the redeemer contains first iteration of
   salt-and-hashing of the password

## Disclaimer

In its current form, this is primarily intended as a proof of concept and not
meant to be used in production.
