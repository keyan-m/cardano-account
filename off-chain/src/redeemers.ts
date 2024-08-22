import {CBORHex, Constr, Data, TxOutput} from "@lucid-evolution/lucid";
import {hash} from "crypto";

const RecordMint = {
  InitiateRecord: Data.to(new Constr(0, [])) as CBORHex,
  MintNewAccount: (rawUsername: string, rawPassword: string, outputs: TxOutput[]): CBORHex => {
    // Hash the raw username.
    const usernameHashHex = hash("sha256", rawUsername, "buffer").toString("hex");
    // Dropping the first byte as its meant to be replaced with a label byte.
    const finalUsername: Data = usernameHashHex.slice(2);
    const x: TxOut
    new Constr(1, [])
  },
};
