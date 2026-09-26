export interface CircuitProfile {
  profile: string;
  main: string;
  template: string;
  publicSignals: string[];
}

export declare const dir: string;
export declare const pilot: CircuitProfile & {
  profile: "pilot-transfer-v3";
  treeDepths: { issuance: number; authorizedIssuers: number; sanctions: number };
};
export declare const legacy: CircuitProfile & { profile: "legacy-compliance-16" };
export declare const includePath: string;
