import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, setCode, time } from "@nomicfoundation/hardhat-network-helpers";
import type { PilotCurrentRegistry } from "../typechain-types/contracts/PilotCurrentRegistry";

// Registry logic with a test-only mock pairing verifier. These run in the default
// `npx hardhat test` job; real pairing is covered by PilotCurrentRegistry.test.ts
// when CLEARPROOF_PILOT_TEST_ARTIFACTS points at development artifacts.
describe("PilotCurrentRegistry logic (mock pairing verifier)", function () {
  const ADMIN_DELAY = 2n * 24n * 3600n;
  const proof = {
    a: [1n, 2n] as [bigint, bigint],
    b: [[3n, 4n], [5n, 6n]] as [[bigint, bigint], [bigint, bigint]],
    c: [7n, 8n] as [bigint, bigint],
  };

  async function fixture() {
    const [admin, publisher, consumer, outsider, successor] = await ethers.getSigners();
    const verifier = await (await ethers.getContractFactory("MockPilotVerifier")).deploy(ethers.id("synthetic-manifest"));
    const registry = await (await ethers.getContractFactory("PilotCurrentRegistry"))
      .deploy(admin.address, await verifier.getAddress());
    const tenant = ethers.id("synthetic-tenant-a");
    await registry.setPublisher(tenant, publisher.address);
    const evaluatedAt = BigInt(await time.latest());
    const validUntil = evaluatedAt + 300n;
    const contextDigest = ethers.id("synthetic-context");
    const receiptId = ethers.id("synthetic-receipt");
    const issuerRoot = 1001n, sanctionsRoot = 1002n, projection = 1003n, nullifier = 1004n;
    const values = [1000n, issuerRoot, sanctionsRoot, 0n, 0n, 0n, 0n];
    const pins = Array.from({ length: 8 }, (_, i) => ({
      scope: i === 7 ? contextDigest : ethers.id(`synthetic-scope-${i}`),
      digest: i === 7 ? receiptId : ethers.id(`synthetic-digest-${i}`),
      revision: 1n,
    })) as PilotCurrentRegistry.StatementStruct["pins"];
    for (let i = 0; i < 7; i++) {
      await registry.connect(publisher).publishHead(tenant, i, pins[i].scope, pins[i].digest, values[i], 0,
        evaluatedAt, validUntil, true);
    }
    const statement: PilotCurrentRegistry.StatementStruct = {
      contextDigest, transferDigest: ethers.id("synthetic-transfer"), projectionCommitment: projection,
      evaluatedAt, validUntil, consumer: consumer.address, pins,
    };
    const id = await registry.statementId(tenant, statement);
    await registry.connect(publisher).publishStatement(tenant, statement);
    await registry.connect(publisher).publishHead(tenant, 7, contextDigest, receiptId, 1, 0, evaluatedAt, validUntil, true);
    const signals = [projection, issuerRoot, sanctionsRoot, nullifier, evaluatedAt, validUntil, 31337n,
      BigInt(await registry.getAddress())];
    const sig = (changes: Record<number, bigint> = {}) =>
      signals.map((value, i) => (i in changes ? changes[i] : value)) as [
        bigint, bigint, bigint, bigint, bigint, bigint, bigint, bigint];
    const inspect = (s = sig()) => registry.inspect(tenant, id, proof.a, proof.b, proof.c, s);
    const mirror = (s = sig()) =>
      registry.connect(consumer).mirror(tenant, id, receiptId, proof.a, proof.b, proof.c, s);
    return {
      registry, verifier, admin, publisher, consumer, outsider, successor, tenant, statement, id, pins, values,
      evaluatedAt, validUntil, receiptId, sig, inspect, mirror,
    };
  }

  describe("construction and default-admin rules", function () {
    it("rejects a zero admin, a codeless verifier and an empty manifest", async function () {
      const { verifier, admin, outsider } = await loadFixture(fixture);
      const Factory = await ethers.getContractFactory("PilotCurrentRegistry");
      await expect(Factory.deploy(ethers.ZeroAddress, await verifier.getAddress()))
        .to.be.revertedWithCustomError(Factory, "AccessControlInvalidDefaultAdmin").withArgs(ethers.ZeroAddress);
      for (const target of [ethers.ZeroAddress, outsider.address]) {
        await expect(Factory.deploy(admin.address, target)).to.be.revertedWithCustomError(Factory, "InvalidScope");
      }
      const empty = await (await ethers.getContractFactory("MockPilotVerifier")).deploy(ethers.ZeroHash);
      await expect(Factory.deploy(admin.address, await empty.getAddress()))
        .to.be.revertedWithCustomError(Factory, "InvalidScope");
    });

    it("pins the verifier, grants admin and pauser roles and sets a two-day admin delay", async function () {
      const { registry, verifier, admin } = await loadFixture(fixture);
      expect(await registry.verifier()).to.equal(await verifier.getAddress());
      expect(await registry.artifactManifestDigest()).to.equal(ethers.id("synthetic-manifest"));
      expect(await registry.owner()).to.equal(admin.address);
      expect(await registry.defaultAdmin()).to.equal(admin.address);
      expect(await registry.hasRole(await registry.PAUSER_ROLE(), admin.address)).to.equal(true);
      expect(await registry.defaultAdminDelay()).to.equal(ADMIN_DELAY);
      expect(await registry.INITIAL_ADMIN_DELAY()).to.equal(ADMIN_DELAY);
      expect(await registry.consumptionOwner()).to.equal("postgresql");
    });

    it("transfers the default admin only in two steps after the delay", async function () {
      const { registry, admin, outsider, successor, tenant } = await loadFixture(fixture);
      const role = await registry.DEFAULT_ADMIN_ROLE();
      await expect(registry.grantRole(role, successor.address))
        .to.be.revertedWithCustomError(registry, "AccessControlEnforcedDefaultAdminRules");
      await expect(registry.connect(outsider).beginDefaultAdminTransfer(outsider.address))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount");
      await registry.beginDefaultAdminTransfer(successor.address);
      await expect(registry.connect(outsider).acceptDefaultAdminTransfer())
        .to.be.revertedWithCustomError(registry, "AccessControlInvalidDefaultAdmin").withArgs(outsider.address);
      const [, schedule] = await registry.pendingDefaultAdmin();
      await expect(registry.connect(successor).acceptDefaultAdminTransfer())
        .to.be.revertedWithCustomError(registry, "AccessControlEnforcedDefaultAdminDelay").withArgs(schedule);
      expect(await registry.defaultAdmin()).to.equal(admin.address);
      await time.increaseTo(schedule + 1n);
      await registry.connect(successor).acceptDefaultAdminTransfer();
      expect(await registry.defaultAdmin()).to.equal(successor.address);
      expect(await registry.hasRole(role, admin.address)).to.equal(false);
      await expect(registry.setPublisher(tenant, admin.address))
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount").withArgs(admin.address, role);
      await expect(registry.connect(successor).setPublisher(tenant, successor.address))
        .to.emit(registry, "PublisherChanged").withArgs(tenant, successor.address, 2);
    });
  });

  describe("pause", function () {
    it("restricts pause to PAUSER_ROLE and unpause to the default admin", async function () {
      const { registry, admin, outsider } = await loadFixture(fixture);
      const pauser = await registry.PAUSER_ROLE();
      await expect(registry.connect(outsider).pause())
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount").withArgs(outsider.address, pauser);
      await registry.grantRole(pauser, outsider.address);
      await expect(registry.connect(outsider).pause()).to.emit(registry, "Paused").withArgs(outsider.address);
      await expect(registry.connect(outsider).unpause())
        .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
        .withArgs(outsider.address, await registry.DEFAULT_ADMIN_ROLE());
      await expect(registry.unpause()).to.emit(registry, "Unpaused").withArgs(admin.address);
      expect(await registry.paused()).to.equal(false);
    });

    it("halts every publication and mirror path while views and publisher control remain available", async function () {
      const { registry, publisher, tenant, statement, pins, values, evaluatedAt, validUntil, inspect, mirror } =
        await loadFixture(fixture);
      await registry.pause();
      await expect(registry.connect(publisher).publishHead(tenant, 0, pins[0].scope, pins[0].digest, values[0], 1,
        evaluatedAt, validUntil, true)).to.be.revertedWithCustomError(registry, "EnforcedPause");
      await expect(registry.connect(publisher).publishStatement(tenant, statement))
        .to.be.revertedWithCustomError(registry, "EnforcedPause");
      const updates = pins.map((pin, i) => ({
        scope: pin.scope, digest: pin.digest, value: i === 7 ? 1n : values[i], expectedRevision: 1n,
        validFrom: evaluatedAt, validUntil, enabled: true, replace: false,
      })) as PilotCurrentRegistry.HeadUpdateStruct[];
      await expect(registry.connect(publisher).publishBatch(tenant, 1, updates as any, statement))
        .to.be.revertedWithCustomError(registry, "EnforcedPause");
      await expect(mirror()).to.be.revertedWithCustomError(registry, "EnforcedPause");
      expect(await inspect()).to.equal(true);
      expect((await registry.head(tenant, 2, pins[2].scope)).revision).to.equal(1);
      await registry.unpause();
      await expect(mirror()).to.emit(registry, "AuthorizationMirrored");
      // setPublisher is deliberately unpausable so a compromised publisher can be cut off.
      await registry.pause();
      await expect(registry.setPublisher(tenant, ethers.ZeroAddress)).to.emit(registry, "PublisherChanged");
    });
  });

  describe("events", function () {
    it("emits complete head, statement and indexed publisher events", async function () {
      const { registry, publisher, consumer, tenant, statement, id, pins, evaluatedAt, validUntil } =
        await loadFixture(fixture);
      const heads = await registry.queryFilter(registry.filters.HeadPublished(tenant, 2));
      expect(heads).to.have.length(1);
      expect(heads[0].args.scope).to.equal(pins[2].scope);
      expect(heads[0].args.revision).to.equal(1);
      expect(heads[0].args.digest).to.equal(pins[2].digest);
      expect(heads[0].args.value).to.equal(1002n);
      expect(heads[0].args.validFrom).to.equal(evaluatedAt);
      expect(heads[0].args.validUntil).to.equal(validUntil);
      expect(heads[0].args.enabled).to.equal(true);
      expect(heads[0].args.publisherEpoch).to.equal(1);
      await expect(registry.connect(publisher).publishHead(tenant, 2, pins[2].scope, ethers.id("replacement"), 77, 1,
        evaluatedAt, validUntil, false)).to.emit(registry, "HeadPublished")
        .withArgs(tenant, 2, pins[2].scope, 2, ethers.id("replacement"), 77, evaluatedAt, validUntil, false, 1);
      const statements = await registry.queryFilter(registry.filters.StatementPublished(tenant, id));
      expect(statements).to.have.length(1);
      expect(statements[0].args.contextDigest).to.equal(statement.contextDigest);
      expect(statements[0].args.consumer).to.equal(consumer.address);
      expect(statements[0].args.projectionCommitment).to.equal(statement.projectionCommitment);
      const byPublisher = await registry.queryFilter(registry.filters.PublisherChanged(undefined, publisher.address));
      expect(byPublisher.map((event) => [event.args.tenant, event.args.epoch])).to.deep.equal([[tenant, 1n]]);
    });
  });

  describe("publisher epochs", function () {
    it("invalidates inspection and mirroring when the publisher is disabled", async function () {
      const { registry, tenant, inspect, mirror } = await loadFixture(fixture);
      expect(await inspect()).to.equal(true);
      await expect(registry.setPublisher(tenant, ethers.ZeroAddress))
        .to.emit(registry, "PublisherChanged").withArgs(tenant, ethers.ZeroAddress, 2);
      await expect(inspect()).to.be.revertedWithCustomError(registry, "InvalidStatement");
      await expect(mirror()).to.be.revertedWithCustomError(registry, "InvalidStatement");
    });

    it("supersedes existing heads when the same publisher is reassigned", async function () {
      const { registry, publisher, tenant, statement, inspect } = await loadFixture(fixture);
      await registry.setPublisher(tenant, publisher.address);
      expect(await registry.publisherEpochs(tenant)).to.equal(2);
      await expect(inspect()).to.be.revertedWithCustomError(registry, "InvalidStatement");
      const fresh = { ...statement, transferDigest: ethers.id("fresh-transfer") };
      await expect(registry.connect(publisher).publishStatement(tenant, fresh))
        .to.be.revertedWithCustomError(registry, "InvalidState");
    });
  });

  describe("inspection, domain binding and mirroring", function () {
    it("binds the proof to this chain and this registry address", async function () {
      const { registry, sig, inspect, mirror } = await loadFixture(fixture);
      await expect(inspect(sig({ 6: 1n }))).to.be.revertedWithCustomError(registry, "InvalidStatement");
      await expect(inspect(sig({ 7: BigInt(await registry.getAddress()) + 1n })))
        .to.be.revertedWithCustomError(registry, "InvalidStatement");
      await expect(mirror(sig({ 6: 1n }))).to.be.revertedWithCustomError(registry, "InvalidStatement");
    });

    it("checks the pinned issuer and sanctions roots and the statement fields", async function () {
      const { registry, sig, inspect } = await loadFixture(fixture);
      for (const changes of <Record<number, bigint>[]>[{ 0: 1n }, { 1: 1n }, { 2: 1n }, { 3: 0n }, { 4: 1n }, { 5: 1n }]) {
        await expect(inspect(sig(changes))).to.be.revertedWithCustomError(registry, "InvalidStatement");
      }
    });

    it("mirrors the approved receipt once, then rejects replay, wrong callers and failed pairing", async function () {
      const { registry, verifier, outsider, tenant, id, receiptId, sig, mirror } = await loadFixture(fixture);
      await expect(registry.connect(outsider).mirror(tenant, id, receiptId, proof.a, proof.b, proof.c, sig()))
        .to.be.revertedWithCustomError(registry, "UnauthorizedConsumer");
      await verifier.setResult(false);
      await expect(mirror()).to.be.revertedWithCustomError(registry, "InvalidProof");
      await verifier.setResult(true);
      await expect(mirror()).to.emit(registry, "AuthorizationMirrored").withArgs(tenant, id, receiptId, 1004n);
      expect(await registry.mirroredReceipts(tenant, 1004n)).to.equal(receiptId);
      await expect(mirror()).to.be.revertedWithCustomError(registry, "AlreadyMirrored");
    });

    it("fails closed when the pinned verifier code changes", async function () {
      const { registry, verifier, inspect } = await loadFixture(fixture);
      await setCode(await verifier.getAddress(), "0x00");
      await expect(inspect()).to.be.revertedWithCustomError(registry, "InvalidStatement");
    });
  });
});
