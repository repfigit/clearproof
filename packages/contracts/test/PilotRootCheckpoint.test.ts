import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, takeSnapshot, time } from "@nomicfoundation/hardhat-network-helpers";

describe("PilotRootCheckpoint", function () {
  async function fixture() {
    const [admin, publisher, outsider] = await ethers.getSigners();
    const registry = await (await ethers.getContractFactory("PilotRootCheckpoint")).deploy(admin.address);
    const tenant = ethers.id("synthetic-tenant-a");
    const scope = ethers.id("synthetic-issuer-scope");
    await registry.setPublisher(tenant, publisher.address);
    const now = await time.latest();
    return { registry, publisher, outsider, tenant, scope, now };
  }

  it("rejects zero admin, tenant and root scope", async function () {
    const Factory = await ethers.getContractFactory("PilotRootCheckpoint");
    await expect(Factory.deploy(ethers.ZeroAddress))
      .to.be.revertedWithCustomError(Factory, "AccessControlInvalidDefaultAdmin").withArgs(ethers.ZeroAddress);
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    await expect(registry.setPublisher(ethers.ZeroHash, publisher.address))
      .to.be.revertedWithCustomError(registry, "InvalidScope");
    for (const [candidateTenant, candidateScope] of [[ethers.ZeroHash, scope], [tenant, ethers.ZeroHash]]) {
      await expect(registry.connect(publisher).publish(
        candidateTenant, candidateScope, ethers.id("synthetic-approval"), 123, 0, 1, now, now + 300,
      )).to.be.revertedWithCustomError(registry, "InvalidScope");
    }
    expect((await registry.head(tenant, scope)).revision).to.equal(0);
  });

  it("rejects missing digests and unsafe revisions without retaining a head", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    for (const [digest, revision] of [[ethers.ZeroHash, 1n], [ethers.id("unsafe"), 9007199254740992n]] as const) {
      await expect(registry.connect(publisher).publish(tenant, scope, digest, 123, 0, revision, now, now + 300))
        .to.be.revertedWithCustomError(registry, "InvalidApproval");
      expect((await registry.head(tenant, scope)).revision).to.equal(0);
    }
    expect(await registry.queryFilter(registry.filters.RootCheckpointPublished())).to.have.length(0);
  });

  it("accepts field and validity limits and preserves a prior head on malformed replacement", async function () {
    const { registry, publisher, tenant, scope } = await loadFixture(fixture);
    const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const from = (await time.latest()) + 1;
    await time.setNextBlockTimestamp(from);
    await registry.connect(publisher).publish(tenant, scope, ethers.id("boundary"), field - 1n, 0, 1, from, from + 86400);
    const before = await registry.head(tenant, scope);
    expect(before.validFrom).to.equal(from);
    expect(before.validUntil).to.equal(from + 86400);
    expect(before.root).to.equal(field - 1n);
    // Equal/reversed validity windows reject even when other metadata is valid.
    for (const until of [from, from - 1]) {
      await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("reversed"), 0, 1, 2, from, until))
        .to.be.revertedWithCustomError(registry, "InvalidApproval");
      expect(await registry.head(tenant, scope)).to.deep.equal(before);
    }
    await registry.connect(publisher).publish(tenant, scope, ethers.id("zero-root"), 0, 1, 2, from, from + 86400);
    expect((await registry.head(tenant, scope)).root).to.equal(0);
  });

  it("enforces the interoperable timestamp ceiling with a short valid window", async function () {
    const { registry, publisher, tenant, scope } = await loadFixture(fixture);
    const snapshot = await takeSnapshot();
    const limit = 9007199254740991n;
    try {
      await time.setNextBlockTimestamp(limit - 100n);
      await expect(registry.connect(publisher).publish(
        tenant, scope, ethers.id("unsafe-time"), 123, 0, 1, limit - 100n, limit + 1n,
      )).to.be.revertedWithCustomError(registry, "InvalidApproval");
      expect((await registry.head(tenant, scope)).revision).to.equal(0);
      await registry.connect(publisher).publish(
        tenant, scope, ethers.id("safe-time"), 123, 0, limit, limit - 100n, limit,
      );
      const head = await registry.head(tenant, scope);
      expect(head.validUntil).to.equal(limit);
      expect(head.revision).to.equal(limit);
    } finally {
      await snapshot.restore();
    }
  });

  it("publishes scoped heads and historical events", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    const digest = ethers.id("approval-one");
    await expect(registry.connect(publisher).publish(tenant, scope, digest, 123, 0, 1, now, now + 300))
      .to.emit(registry, "RootCheckpointPublished").withArgs(tenant, scope, digest, 123, 1, now, now + 300, 1);
    const head = await registry.head(tenant, scope);
    expect(head.snapshotDigest).to.equal(digest);
    expect(head.revision).to.equal(1);
    expect(head.root).to.equal(123);
    expect(head.publishedAt).to.be.greaterThanOrEqual(now);
    expect(head.publisherEpoch).to.equal(1);
    expect(await registry.isCurrent(tenant, scope)).to.equal(true);
    expect((await registry.head(ethers.id("tenant-b"), scope)).revision).to.equal(0);
    expect((await registry.head(tenant, ethers.id("other-scope"))).revision).to.equal(0);
  });

  it("rejects outsiders, cross-tenant and disabled publishers", async function () {
    const { registry, publisher, outsider, tenant, scope, now } = await loadFixture(fixture);
    const digest = ethers.id("approval");
    await expect(registry.connect(outsider).publish(tenant, scope, digest, 123, 0, 1, now, now + 300))
      .to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.connect(publisher).publish(ethers.id("tenant-b"), scope, digest, 123, 0, 1, now, now + 300))
      .to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.connect(outsider).setPublisher(tenant, outsider.address)).to.be.reverted;
    await registry.setPublisher(tenant, ethers.ZeroAddress);
    await expect(registry.connect(publisher).publish(tenant, scope, digest, 123, 0, 1, now, now + 300))
      .to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
  });

  it("rejects forks/rollback and permits skipped unpublished revisions", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    await registry.connect(publisher).publish(tenant, scope, ethers.id("one"), 123, 0, 1, now, now + 300);
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("fork"), 124, 0, 2, now, now + 300))
      .to.be.revertedWithCustomError(registry, "StaleRevision");
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("rollback"), 123, 1, 1, now, now + 300))
      .to.be.revertedWithCustomError(registry, "StaleRevision");
    await registry.connect(publisher).publish(tenant, scope, ethers.id("three"), 125, 1, 3, now, now + 300);
    expect((await registry.head(tenant, scope)).revision).to.equal(3);
  });

  it("enforces field bounds, validity and monotonic approval time", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    for (const [root, from, until] of [[field, now, now + 300], [123n, now + 100, now + 300],
      [123n, now, now], [123n, now, now + 86401]] as const) {
      await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("bad"), root, 0, 1, from, until))
        .to.be.revertedWithCustomError(registry, "InvalidApproval");
    }
    await registry.connect(publisher).publish(tenant, scope, ethers.id("good"), 123, 0, 1, now, now + 300);
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("backdated"), 123, 1, 2, now - 1, now + 300))
      .to.be.revertedWithCustomError(registry, "InvalidApproval");
  });

  it("supersedes current heads whenever the tenant publisher changes", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    await registry.connect(publisher).publish(tenant, scope, ethers.id("one"), 123, 0, 1, now, now + 300);
    expect(await registry.isCurrent(tenant, ethers.id("unpublished"))).to.equal(false);
    await expect(registry.setPublisher(tenant, ethers.ZeroAddress))
      .to.emit(registry, "PublisherChanged").withArgs(tenant, ethers.ZeroAddress, 2);
    expect(await registry.isCurrent(tenant, scope)).to.equal(false);
    // Reassigning the same publisher still leaves the old head under a stale epoch.
    await registry.setPublisher(tenant, publisher.address);
    expect(await registry.publisherEpochs(tenant)).to.equal(3);
    expect(await registry.isCurrent(tenant, scope)).to.equal(false);
    expect((await registry.head(tenant, scope)).publisherEpoch).to.equal(1);
    // Revisions stay monotonic: only a newer approval revision restores a current head.
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("one"), 123, 1, 1, now, now + 300))
      .to.be.revertedWithCustomError(registry, "StaleRevision");
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("two"), 123, 1, 2, now, now + 300))
      .to.emit(registry, "RootCheckpointPublished").withArgs(tenant, scope, ethers.id("two"), 123, 2, now, now + 300, 3);
    expect(await registry.isCurrent(tenant, scope)).to.equal(true);
    const changes = await registry.queryFilter(registry.filters.PublisherChanged(undefined, publisher.address));
    expect(changes.map((event) => event.args.epoch)).to.deep.equal([1n, 3n]);
  });

  it("pauses publication without hiding heads and keeps publisher control available", async function () {
    const { registry, publisher, outsider, tenant, scope, now } = await loadFixture(fixture);
    const [admin] = await ethers.getSigners();
    await registry.connect(publisher).publish(tenant, scope, ethers.id("one"), 123, 0, 1, now, now + 300);
    await expect(registry.connect(outsider).pause())
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(outsider.address, await registry.PAUSER_ROLE());
    await expect(registry.pause()).to.emit(registry, "Paused").withArgs(admin.address);
    await expect(registry.connect(publisher).publish(tenant, scope, ethers.id("two"), 124, 1, 2, now, now + 300))
      .to.be.revertedWithCustomError(registry, "EnforcedPause");
    expect((await registry.head(tenant, scope)).revision).to.equal(1);
    expect(await registry.isCurrent(tenant, scope)).to.equal(true);
    await registry.grantRole(await registry.PAUSER_ROLE(), outsider.address);
    await expect(registry.connect(outsider).unpause())
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(outsider.address, await registry.DEFAULT_ADMIN_ROLE());
    await registry.setPublisher(tenant, publisher.address);
    await registry.unpause();
    await registry.connect(publisher).publish(tenant, scope, ethers.id("two"), 124, 1, 2, now, now + 300);
    expect(await registry.isCurrent(tenant, scope)).to.equal(true);
  });

  it("transfers the default admin in two steps after a two-day delay", async function () {
    const { registry, outsider, tenant } = await loadFixture(fixture);
    const [admin, , , successor] = await ethers.getSigners();
    const role = await registry.DEFAULT_ADMIN_ROLE();
    expect(await registry.defaultAdminDelay()).to.equal(2 * 24 * 3600);
    expect(await registry.hasRole(await registry.PAUSER_ROLE(), admin.address)).to.equal(true);
    await expect(registry.grantRole(role, successor.address))
      .to.be.revertedWithCustomError(registry, "AccessControlEnforcedDefaultAdminRules");
    await registry.beginDefaultAdminTransfer(successor.address);
    const [pending, schedule] = await registry.pendingDefaultAdmin();
    expect(pending).to.equal(successor.address);
    await expect(registry.connect(successor).acceptDefaultAdminTransfer())
      .to.be.revertedWithCustomError(registry, "AccessControlEnforcedDefaultAdminDelay");
    await time.increaseTo(schedule + 1n);
    await registry.connect(successor).acceptDefaultAdminTransfer();
    expect(await registry.defaultAdmin()).to.equal(successor.address);
    await expect(registry.setPublisher(tenant, outsider.address))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount").withArgs(admin.address, role);
    await registry.connect(successor).setPublisher(tenant, outsider.address);
    expect(await registry.publishers(tenant)).to.equal(outsider.address);
  });
});
