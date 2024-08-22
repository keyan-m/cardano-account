// -- IMPORTS ------------------------------------------------------------------
// {{{
import {Data} from "@lucid-evolution/lucid";
// }}}
// -----------------------------------------------------------------------------

// -- OFF-CHAIN DATATYPES ------------------------------------------------------
// {{{
export type Result<T> =
  | { type: "ok"; data: T }
  | { type: "error"; error: Error };

export type TokenName = string;
// }}}
// -----------------------------------------------------------------------------

// -- ON-CHAIN DATATYPES -------------------------------------------------------
// {{{
export const TokenNameDataSchema = Data.Bytes();
export type TokenNameData = Data.Static<typeof TokenNameDataSchema>;
export const TokenNameData = TokenNameDataSchema as unknown as TokenNameData;

export const OutputReferenceSchema = Data.Object({
  txHash: Data.Object({ hash: Data.Bytes({ minLength: 32, maxLength: 32 }) }),
  outputIndex: Data.Integer(),
});
export type OutputReference = Data.Static<typeof OutputReferenceSchema>;
export const OutputReference =
  OutputReferenceSchema as unknown as OutputReference;

export const CredentialSchema = Data.Enum([
  Data.Object({
    PublicKeyCredential: Data.Tuple([
      Data.Bytes({ minLength: 28, maxLength: 28 }),
    ]),
  }),
  Data.Object({
    ScriptCredential: Data.Tuple([
      Data.Bytes({ minLength: 28, maxLength: 28 }),
    ]),
  }),
]);
export type CredentialData = Data.Static<typeof CredentialSchema>;
export const CredentialData = CredentialSchema as unknown as CredentialData;

export const AddressSchema = Data.Object({
  paymentCredential: CredentialSchema,
  stakeCredential: Data.Nullable(
    Data.Enum([
      Data.Object({ Inline: Data.Tuple([CredentialSchema]) }),
      Data.Object({
        Pointer: Data.Tuple([
          Data.Object({
            slotNumber: Data.Integer(),
            transactionIndex: Data.Integer(),
            certificateIndex: Data.Integer(),
          }),
        ]),
      }),
    ])
  ),
});
export type AddressData = Data.Static<typeof AddressSchema>;
export const AddressData = AddressSchema as unknown as AddressData;

export const AccountDatumSchema = Data.Object({
  pubkey: Data.Bytes(),
  nonce: Data.Bytes(),
  latest_activity: Data.Integer(),
});
export type AccountDatum = Data.Static<typeof AccountDatumSchema>;
export const AccountDatum = AccountDatumSchema as unknown as AccountDatum;

export const EntrySchema = Data.Object({
  next_username: Data.Nullable(Data.Bytes()),
  contributor: AddressSchema,
});
export type Entry = Data.Static<typeof EntrySchema>;
export const Entry = EntrySchema as unknown as Entry;

export const ContributorSchema = Data.Object({
  address: AddressSchema,
});
export type Contributor = Data.Static<typeof ContributorSchema>;
export const Contributor = ContributorSchema as unknown as Contributor;
// }}}
// -----------------------------------------------------------------------------
