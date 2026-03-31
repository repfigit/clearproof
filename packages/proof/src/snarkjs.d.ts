declare module 'snarkjs' {
  export namespace groth16 {
    function fullProve(
      input: Record<string, string | string[]>,
      wasmFile: string,
      zkeyFile: string,
    ): Promise<{ proof: object; publicSignals: string[] }>;

    function verify(
      vkey: object,
      publicSignals: string[],
      proof: object,
    ): Promise<boolean>;
  }

  export namespace zKey {
    function exportSolidityVerifier(
      zkeyName: string,
      templates: object,
    ): Promise<string>;

    function exportVerificationKey(zkeyName: string): Promise<object>;
  }
}
