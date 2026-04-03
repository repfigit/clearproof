import { expect } from "chai";
import { ethers } from "hardhat";

describe("VASPRegistry Discovery", function () {
  async function deployVASPRegistry() {
    const [admin, other] = await ethers.getSigners();
    const VASPRegistry = await ethers.getContractFactory("VASPRegistry");
    const registry = await VASPRegistry.deploy(admin.address);
    await registry.waitForDeployment();
    return { registry, admin, other };
  }

  it("registerVASP stores discoveryEndpoint correctly", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:alpha.example"));
    const wallet = ethers.Wallet.createRandom().address;
    const endpoint = "https://alpha.example/.well-known/clearproof";

    await registry.registerVASP(didHash, wallet, "US", endpoint);

    const vasp = await registry.vasps(didHash);
    expect(vasp.discoveryEndpoint).to.equal(endpoint);
  });

  it("getDiscoveryEndpoint returns the URL", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:beta.example"));
    const wallet = ethers.Wallet.createRandom().address;
    const endpoint = "https://beta.example/.well-known/clearproof";

    await registry.registerVASP(didHash, wallet, "SG", endpoint);

    expect(await registry.getDiscoveryEndpoint(didHash)).to.equal(endpoint);
  });

  it("updateDiscoveryEndpoint changes the URL and emits event", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:gamma.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "JP", "https://old.gamma.example/.well-known/clearproof");

    const newEndpoint = "https://new.gamma.example/.well-known/clearproof";
    await expect(registry.updateDiscoveryEndpoint(didHash, newEndpoint))
      .to.emit(registry, "DiscoveryEndpointUpdated")
      .withArgs(didHash, newEndpoint);

    expect(await registry.getDiscoveryEndpoint(didHash)).to.equal(newEndpoint);
  });

  it("updateDiscoveryEndpoint rejects for inactive VASP", async function () {
    const { registry } = await deployVASPRegistry();
    const didHash = ethers.keccak256(ethers.toUtf8Bytes("did:web:revoked.example"));
    const wallet = ethers.Wallet.createRandom().address;

    await registry.registerVASP(didHash, wallet, "UK", "https://revoked.example/.well-known/clearproof");
    await registry.revokeVASP(didHash);

    await expect(
      registry.updateDiscoveryEndpoint(didHash, "https://new.revoked.example/.well-known/clearproof")
    ).to.be.revertedWith("Not active");
  });

  it("Can enumerate vaspIds and fetch each endpoint", async function () {
    const { registry } = await deployVASPRegistry();

    const vasps = [
      { did: "did:web:one.example", jurisdiction: "US", endpoint: "https://one.example/.well-known/clearproof" },
      { did: "did:web:two.example", jurisdiction: "SG", endpoint: "https://two.example/.well-known/clearproof" },
      { did: "did:web:three.example", jurisdiction: "DE", endpoint: "https://three.example/.well-known/clearproof" },
    ];

    for (const v of vasps) {
      const didHash = ethers.keccak256(ethers.toUtf8Bytes(v.did));
      const wallet = ethers.Wallet.createRandom().address;
      await registry.registerVASP(didHash, wallet, v.jurisdiction, v.endpoint);
    }

    expect(await registry.vaspCount()).to.equal(3);

    for (let i = 0; i < vasps.length; i++) {
      const id = await registry.vaspIds(i);
      const expectedHash = ethers.keccak256(ethers.toUtf8Bytes(vasps[i].did));
      expect(id).to.equal(expectedHash);

      const endpoint = await registry.getDiscoveryEndpoint(id);
      expect(endpoint).to.equal(vasps[i].endpoint);
    }
  });
});
