import { ethers, network } from "hardhat";
import { prepareLegacyVerifier } from "./legacy-verifier";
import thresholds from "../../../config/jurisdiction_thresholds.json";

async function main() {
  if (network.name !== "hardhat") throw new Error("Gas benchmark requires the ephemeral Hardhat network");
  const [deployer] = await ethers.getSigners();

  // Deploy SanctionsOracle
  const Oracle = await ethers.getContractFactory("SanctionsOracle");
  const oracle = await Oracle.deploy(
    deployer.address,
    ethers.keccak256(ethers.toUtf8Bytes("root")),
    100,
  );
  const oracleDeployed = await oracle.waitForDeployment();
  const r1 = await oracleDeployed.deploymentTransaction()!.wait();
  console.log("SanctionsOracle deploy gas:", r1!.gasUsed.toString());

  // Deploy VASPRegistry
  const VASP = await ethers.getContractFactory("VASPRegistry");
  const vasp = await VASP.deploy(deployer.address);
  const vaspDeployed = await vasp.waitForDeployment();
  const r2 = await vaspDeployed.deploymentTransaction()!.wait();
  console.log("VASPRegistry deploy gas:", r2!.gasUsed.toString());

  // Deploy ComplianceRegistry
  const { router, selector } = await prepareLegacyVerifier();
  const Compliance = await ethers.getContractFactory("ComplianceRegistry");
  const comp = await Compliance.deploy(
    await router.getAddress(), selector, await vasp.getAddress(), await oracle.getAddress(),
    thresholds.default.tier2, thresholds.default.tier3, thresholds.default.tier4,
  );
  const compDeployed = await comp.waitForDeployment();
  const r3 = await compDeployed.deploymentTransaction()!.wait();
  console.log("ComplianceRegistry deploy gas:", r3!.gasUsed.toString());

  // Test a revert path: VASPRegistry.registerVASP with zero admin (constructor already tested above)
  // Test registerVASP revert (unauthorized caller)
  const [, other] = await ethers.getSigners();
  const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:test:123"));
  try {
    await vasp
      .connect(other)
      .registerVASP(didHash, other.address, "US", "https://example.com/.well-known/clearproof");
  } catch (e: any) {
    // This will revert — we can't easily get gas from a reverted tx in hardhat
    console.log("VASPRegistry.registerVASP revert (expected): custom error thrown");
  }

  // Test successful register + gas
  const registrarRole = ethers.id("REGISTRAR_ROLE");
  await vasp.grantRole(registrarRole, deployer.address);
  const tx = await vasp.registerVASP(
    didHash,
    deployer.address,
    "US",
    "https://example.com/.well-known/clearproof",
  );
  const receipt = await tx.wait();
  console.log("VASPRegistry.registerVASP gas:", receipt!.gasUsed.toString());
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
