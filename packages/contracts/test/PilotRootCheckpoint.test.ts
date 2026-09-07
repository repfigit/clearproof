import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";

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

  it("publishes scoped heads and historical events", async function () {
    const { registry, publisher, tenant, scope, now } = await loadFixture(fixture);
    const digest = ethers.id("approval-one");
    await expect(registry.connect(publisher).publish(tenant, scope, digest, 123, 0, 1, now, now + 300))
      .to.emit(registry, "RootCheckpointPublished").withArgs(tenant, scope, digest, 123, 1, now, now + 300);
    const head = await registry.head(tenant, scope);
    expect(head.snapshotDigest).to.equal(digest);
    expect(head.revision).to.equal(1);
    expect(head.root).to.equal(123);
    expect(head.publishedAt).to.be.greaterThanOrEqual(now);
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
});
