# Cardano Account: A Wallet-less Solution

An alternative solution to Cardano wallets to simplify the adoption by allowing
users to take custody of their digital assets with a username and
password—similar to web2 conventions.

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
already existing, and therefore offers an easier onboarding solution for less
experienced users.

## Compromises and Issues

### Front Running

Implemented as is, the script is parametrized by a list of "providers" (i.e. a
frontend provider), so that it can validate one of them has signed the
transaction.

If this requirement was not put in place, a node validator would be free to
avoid submitting the transaction honestly, but rather remove the transaction,
use the provided redeemer, and withdraw the account in its own favor.

This is an issue that is likely not solvable without changes to Cardano's
infrastructure.

While this is not an ideal solution, it mitigates the required centralization by
allowing users to use any of the providers.

### Interrupted User Experience

Current design where account UTxOs are also links in the on-chain association
list leads to an interrupted user experience when another user creates a new
accounts or closes their existing account, since it might be the account ahead
of the interrupted user (who might be in the middle of signing a transaction).

A straightforward solution is to create 2 UTxOs for every account such that one
corresponds to user's place in the association list, while the other is free
from disturbances, dedicate for user deposits/withdrawals.

### Ecosystem Participation

In this approach where all users share the same address, it becomes impossible
for them to use most Cardano DApps (since user signature is a common
requirement).

One solution is to dedicate an address for each user, where the differing
parameter is their usernames. This, along with the dual-NFT minting solution
mentioned earlier (where the second NFT is sent to user's dedicated address),
and passing of [CIP-0112]() will allow `cardano-account` users participate in
the ecosystem similar to wallet owners.

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

Currently, the contract allows anyone to add arbitrary tokens to an account's
UTxO. However, this is flawed since it has the risk of "token dust attack,"
where the attacker can fill a UTxO with random tokens in order to make the UTxO
so big such that it can not fit in any future transactions, consequently locking
all its funds.

Please read the [Compromises and Issues](#compromises-and-issues) section to
learn how a more proper logic can be implemented.

### Withdrawals

1. User types in their username and password, and the funds they want to
   withdraw
2. System finds the UTxO by hashing the raw username (which is how it was stored
   in the first place)
3. Ensures that double salt-and-hashing the raw password corresponds to the one
   stored on-chain
4. And builds the transaction such that the redeemer contains first iteration of
   salt-and-hashing of the password

## Future
