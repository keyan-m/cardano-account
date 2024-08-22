import {Assets, PolicyId, fromUnit} from "@lucid-evolution/lucid";
import {Result, TokenName} from "./types";

export function errorToString(error: any): string {
  return error.message ?? JSON.stringify(error);
}

export function genericCatch(error: any): Result<any> {
  if (error instanceof Error) return { type: "error", error: error };
  return {
    type: "error",
    error: new Error(errorToString(error)),
  };
}

export function flattenAssets(assets: Assets): [PolicyId, TokenName, bigint][] {
  const unitsAndQuantities = Object.entries(assets);
  return unitsAndQuantities.map(([u, qty]) => {
    const splitUnit = fromUnit(u);
    return [splitUnit.policyId, splitUnit.assetName ?? "", qty];
  });
}
