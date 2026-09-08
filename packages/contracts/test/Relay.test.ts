import { expect } from "chai";
import { ethers } from "hardhat";
import { time } from "@nomicfoundation/hardhat-network-helpers";

describe("SanctionsRootRelay", function () {
  async function deployRelay() {
    const [admin, relayer, other] = await ethers.getSigners();

    // Deploy oracle first (relay needs its address)
    const initialRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-v0"));
    const SanctionsOracle = await ethers.getContractFactory("SanctionsOracle");
    const oracle = await SanctionsOracle.deploy(admin.address, initialRoot, 100);
    await oracle.waitForDeployment();

    // Deploy relay with admin
    const SanctionsRootRelay = await ethers.getContractFactory("SanctionsRootRelay");
    const relay = await SanctionsRootRelay.deploy(admin.address, await oracle.getAddress());
    await relay.waitForDeployment();

    // Grant ORACLE_ROLE on the oracle to the relay contract
    const ORACLE_ROLE = await oracle.ORACLE_ROLE();
    await oracle.grantRole(ORACLE_ROLE, await relay.getAddress());

    // Grant RELAYER_ROLE on the relay to the relayer signer
    const RELAYER_ROLE = await relay.RELAYER_ROLE();
    await relay.grantRole(RELAYER_ROLE, relayer.address);

    return { oracle, relay, admin, relayer, other, initialRoot, ORACLE_ROLE, RELAYER_ROLE };
  }

  it("rejects zero constructor authorities and binds the intended oracle", async function () {
    const { oracle, relay, admin } = await deployRelay();
    const Factory = await ethers.getContractFactory("SanctionsRootRelay");
    await expect(Factory.deploy(ethers.ZeroAddress, await oracle.getAddress()))
      .to.be.revertedWithCustomError(Factory, "ZeroAdmin");
    await expect(Factory.deploy(admin.address, ethers.ZeroAddress))
      .to.be.revertedWithCustomError(Factory, "ZeroOracle");
    expect(await relay.oracle()).to.equal(await oracle.getAddress());
    expect(await relay.hasRole(await relay.DEFAULT_ADMIN_ROLE(), admin.address)).to.equal(true);
  });

  it("leaves oracle history unchanged through paused, rejected and revoked-authority attempts", async function () {
    const { oracle, relay, relayer, initialRoot, ORACLE_ROLE, RELAYER_ROLE } = await deployRelay();
    const relayAddress = await relay.getAddress();
    const nextRoot = ethers.id("synthetic-retry-root");
    const originalTime = await oracle.lastUpdated();
    await time.increase(3600);
    async function unchanged() {
      expect(await oracle.currentRoot()).to.equal(initialRoot);
      expect(await oracle.lastUpdated()).to.equal(originalTime);
      expect(await oracle.leafCount()).to.equal(100);
      expect(await oracle.historyLength()).to.equal(1);
      expect(await relay.queryFilter(relay.filters.RootRelayed())).to.have.length(0);
    }
    await oracle.pause();
    await expect(relay.connect(relayer).receiveRoot(nextRoot, 100))
      .to.be.revertedWithCustomError(oracle, "EnforcedPause");
    await unchanged();
    await oracle.unpause();
    await expect(relay.connect(relayer).receiveRoot(nextRoot, 49))
      .to.be.revertedWithCustomError(oracle, "LeafCountDecreasedTooMuch");
    await unchanged();
    await oracle.revokeRole(ORACLE_ROLE, relayAddress);
    await expect(relay.connect(relayer).receiveRoot(nextRoot, 100))
      .to.be.revertedWithCustomError(oracle, "AccessControlUnauthorizedAccount").withArgs(relayAddress, ORACLE_ROLE);
    await unchanged();
    await oracle.grantRole(ORACLE_ROLE, relayAddress);
    await relay.revokeRole(RELAYER_ROLE, relayer.address);
    await expect(relay.connect(relayer).receiveRoot(nextRoot, 100))
      .to.be.revertedWithCustomError(relay, "AccessControlUnauthorizedAccount").withArgs(relayer.address, RELAYER_ROLE);
    await unchanged();
    await relay.grantRole(RELAYER_ROLE, relayer.address);
    await expect(relay.connect(relayer).receiveRoot(nextRoot, 100))
      .to.emit(relay, "RootRelayed").withArgs(nextRoot, 100, relayer.address);
    expect(await oracle.currentRoot()).to.equal(nextRoot);
    expect(await oracle.historyLength()).to.equal(2);
    expect((await oracle.rootHistory(1)).root).to.equal(nextRoot);
    expect(await relay.queryFilter(relay.filters.RootRelayed())).to.have.length(1);
  });

  it("receiveRoot forwards to oracle successfully (after cooldown)", async function () {
    const { oracle, relay, relayer } = await deployRelay();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("sanctions-root-v1"));

    // Advance past the 1-hour cooldown
    await time.increase(3601);

    await relay.connect(relayer).receiveRoot(newRoot, 150);

    expect(await oracle.currentRoot()).to.equal(newRoot);
    expect(await oracle.leafCount()).to.equal(150);
  });

  it("receiveRoot respects RELAYER_ROLE (unauthorized caller reverts)", async function () {
    const { relay, other } = await deployRelay();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("unauthorized-root"));

    await time.increase(3601);

    await expect(
      relay.connect(other).receiveRoot(newRoot, 200)
    ).to.be.reverted;
  });

  it("receiveRoot propagates oracle errors (zero root)", async function () {
    const { oracle, relay, relayer } = await deployRelay();

    await time.increase(3601);

    await expect(
      relay.connect(relayer).receiveRoot(ethers.ZeroHash, 0)
    ).to.be.revertedWithCustomError(oracle, "ZeroRoot");
  });

  it("receiveRoot propagates oracle errors (cooldown)", async function () {
    const { oracle, relay, relayer } = await deployRelay();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("too-fast-root"));

    // Do NOT advance time — oracle cooldown should reject
    await expect(
      relay.connect(relayer).receiveRoot(newRoot, 100)
    ).to.be.revertedWithCustomError(oracle, "CooldownActive");
  });

  it("RootRelayed event emitted with correct args", async function () {
    const { relay, relayer } = await deployRelay();
    const newRoot = ethers.keccak256(ethers.toUtf8Bytes("event-root"));

    await time.increase(3601);

    await expect(relay.connect(relayer).receiveRoot(newRoot, 250))
      .to.emit(relay, "RootRelayed")
      .withArgs(newRoot, 250, relayer.address);
  });

  it("Relay holds ORACLE_ROLE on the oracle", async function () {
    const { oracle, relay, ORACLE_ROLE } = await deployRelay();

    expect(await oracle.hasRole(ORACLE_ROLE, await relay.getAddress())).to.equal(true);
  });
});
