import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, setCode, time } from "@nomicfoundation/hardhat-network-helpers";
import fs from "node:fs";
import path from "node:path";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { PilotGroth16Verifier } from "../typechain-types/contracts/PilotGroth16Verifier";
import type { PilotCurrentRegistry } from "../typechain-types/contracts/PilotCurrentRegistry";

const location = process.env.CLEARPROOF_PILOT_TEST_ARTIFACTS;
type G1 = [string, string];
const g1 = (p: string[]): G1 => [p[0], p[1]];
const g2 = (p: string[][]): [G1, G1] => [[p[0][1], p[0][0]], [p[1][1], p[1][0]]];
(location ? describe : describe.skip)("PilotCurrentRegistry real development checkpoints", function () {
  this.timeout(180000);
  async function fixture() {
    const directory = path.resolve(location!);
    const root = path.resolve(__dirname, "../../..");
    const [admin, publisher, consumer, outsider] = await ethers.getSigners();
    const vk = JSON.parse(fs.readFileSync(path.join(directory, "verification-key.json"), "utf8"));
    const pin = fs.readFileSync(path.join(directory, "development-manifest-pin.txt"), "utf8").trim();
    const pairing = await (await ethers.getContractFactory("PilotGroth16Verifier")).deploy({
      alpha: g1(vk.vk_alpha_1), beta: g2(vk.vk_beta_2), gamma: g2(vk.vk_gamma_2), delta: g2(vk.vk_delta_2),
      ic: vk.IC.map(g1) as PilotGroth16Verifier.VerificationKeyStruct["ic"],
    }, "0x" + pin);
    const registry = await (await ethers.getContractFactory("PilotCurrentRegistry")).deploy(admin.address, await pairing.getAddress());
    const tenant = ethers.id("synthetic-tenant-a");
    await registry.setPublisher(tenant, publisher.address);
    const evaluatedAt = await time.latest();
    const python = process.env.CLEARPROOF_TEST_PYTHON || path.join(root, ".venv/bin/python");
    const { stdout } = await promisify(execFile)(python, [path.join(root, "scripts/pilot_contract_fixture.py"),
      directory, (await registry.getAddress()).toLowerCase(), String(evaluatedAt)],
      { cwd: root, timeout: 150000, maxBuffer: 1024 * 1024 });
    const bundle = JSON.parse(stdout);
    expect(bundle.scope).to.equal("synthetic-contract-checkpoints");
    expect(bundle.assurance).to.equal("development-unapproved");
    expect(bundle.python_current_valid).to.equal(true);
    expect(bundle.signals[6]).to.equal("31337");
    expect(BigInt(bundle.signals[7])).to.equal(BigInt(await registry.getAddress()));
    const pins = bundle.heads.map((head: any, i: number) => ({
      scope: i === 7 ? "0x" + bundle.context_digest : ethers.id(`synthetic-scope-${i}`),
      digest: "0x" + head.digest, revision: 1,
    })) as PilotCurrentRegistry.StatementStruct["pins"];
    for (let i = 0; i < 7; i++) {
      await registry.connect(publisher).publishHead(tenant, i, pins[i].scope, pins[i].digest,
        bundle.heads[i].value, 0, evaluatedAt, bundle.valid_until, true);
    }
    const statement: PilotCurrentRegistry.StatementStruct = {
      contextDigest: "0x" + bundle.context_digest, transferDigest: "0x" + bundle.transfer_digest,
      projectionCommitment: bundle.signals[0], evaluatedAt, validUntil: bundle.valid_until,
      consumer: consumer.address, pins,
    };
    const id = await registry.statementId(tenant, statement);
    await registry.connect(publisher).publishStatement(tenant, statement);
    const a = g1(bundle.proof.pi_a), b = g2(bundle.proof.pi_b), c = g1(bundle.proof.pi_c);
    const signals: string[] = bundle.signals;
    const receiptId = pins[7].digest;
    const approve = (allow = true) => registry.connect(publisher).publishHead(tenant, 7, pins[7].scope,
      pins[7].digest, allow ? 1 : 0, 0, evaluatedAt, bundle.valid_until, true);
    return { registry, pairing, tenant, publisher, consumer, outsider, statement, id, pins, bundle, a, b, c, signals, approve, receiptId };
  }

  it("rejects invalid constructor dependencies and unauthorized publisher configuration", async function () {
    const { registry, pairing, tenant, publisher, outsider } = await loadFixture(fixture);
    const [admin] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("PilotCurrentRegistry");
    for (const [authority, target] of [
      [ethers.ZeroAddress, await pairing.getAddress()],
      [admin.address, ethers.ZeroAddress],
      [admin.address, outsider.address],
    ]) {
      await expect(Factory.deploy(authority, target)).to.be.revertedWithCustomError(Factory, "InvalidScope");
    }
    await expect(registry.setPublisher(ethers.ZeroHash, publisher.address))
      .to.be.revertedWithCustomError(registry, "InvalidScope");
    await expect(registry.connect(outsider).setPublisher(tenant, outsider.address))
      .to.be.revertedWithCustomError(registry, "AccessControlUnauthorizedAccount")
      .withArgs(outsider.address, await registry.DEFAULT_ADMIN_ROLE());
    expect(await registry.publishers(tenant)).to.equal(publisher.address);
    expect(await registry.publisherEpochs(tenant)).to.equal(1);
  });

  it("rejects an empty manifest and fails closed when pinned verifier code changes", async function () {
    const { registry, pairing, tenant, consumer, outsider, id, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    const [admin] = await ethers.getSigners();
    const Factory = await ethers.getContractFactory("PilotCurrentRegistry");
    // Dependency fault injection: this runtime returns a zero word for every call.
    // No registry storage or proof inputs are altered.
    const zeroReturn = "0x600060005260206000f3";
    const outsiderCode = await ethers.provider.getCode(outsider.address);
    try {
      await setCode(outsider.address, zeroReturn);
      await expect(Factory.deploy(admin.address, outsider.address))
        .to.be.revertedWithCustomError(Factory, "InvalidScope");
    } finally {
      await setCode(outsider.address, outsiderCode);
    }
    await approve();
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    const target = await pairing.getAddress();
    const originalCode = await ethers.provider.getCode(target);
    expect(await registry.verifierCodeHash()).to.equal(ethers.keccak256(originalCode));
    try {
      await setCode(target, zeroReturn);
      await expect(registry.inspect(tenant, id, a, b, c, signals))
        .to.be.revertedWithCustomError(registry, "InvalidStatement");
      await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals))
        .to.be.revertedWithCustomError(registry, "InvalidStatement");
      expect((await registry.statementPublication(id)).exists).to.equal(true);
      expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
      expect(await registry.queryFilter(registry.filters.AuthorizationMirrored())).to.have.length(0);
    } finally {
      await setCode(target, originalCode);
    }
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(receiptId);
    expect(await registry.queryFilter(registry.filters.AuthorizationMirrored())).to.have.length(1);
  });

  it("rejects malformed head updates without altering existing checkpoints", async function () {
    const { registry, tenant, publisher, outsider } = await loadFixture(fixture);
    const now = BigInt(await time.latest());
    const base = {
      kind: 0, scope: ethers.id("synthetic-boundary-scope"), digest: ethers.id("synthetic-boundary-digest"),
      value: 123n, expected: 0n, from: now, until: now + 300n,
    };
    const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const invalid = [
      { ...base, scope: ethers.ZeroHash }, { ...base, digest: ethers.ZeroHash },
      { ...base, from: now + 10000n }, { ...base, until: now },
      { ...base, until: 9007199254740992n }, { ...base, until: now + 86401n },
      { ...base, value: field }, { ...base, expected: 1n },
      ...[3, 4, 5, 6].map(kind => ({ ...base, kind, value: 1n })),
      { ...base, kind: 7, value: 2n },
    ];
    const before = await registry.queryFilter(registry.filters.HeadPublished());
    for (const candidate of invalid) {
      await expect(registry.connect(publisher).publishHead(
        tenant, candidate.kind, candidate.scope, candidate.digest, candidate.value,
        candidate.expected, candidate.from, candidate.until, true,
      )).to.be.revertedWithCustomError(registry, "InvalidState");
      expect((await registry.head(tenant, candidate.kind, candidate.scope)).revision).to.equal(0);
    }
    await expect(registry.connect(outsider).publishHead(
      tenant, 0, base.scope, base.digest, 123, 0, now, now + 300n, true,
    )).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    expect(await registry.queryFilter(registry.filters.HeadPublished())).to.have.length(before.length);
    await registry.connect(publisher).publishHead(tenant, 0, base.scope, base.digest, field - 1n, 0, now, now + 300n, true);
    const retained = await registry.head(tenant, 0, base.scope);
    expect(retained.value).to.equal(field - 1n);
    await expect(registry.connect(publisher).publishHead(
      tenant, 0, base.scope, ethers.id("backdated"), 0, 1, now - 1n, now + 300n, true,
    )).to.be.revertedWithCustomError(registry, "InvalidState");
    expect(await registry.head(tenant, 0, base.scope)).to.deep.equal(retained);
    await registry.connect(publisher).publishHead(tenant, 0, base.scope, base.digest, 0, 1, now, now + 300n, false);
    const disabled = await registry.head(tenant, 0, base.scope);
    expect(disabled.value).to.equal(0);
    expect(disabled.revision).to.equal(2);
    expect(disabled.enabled).to.equal(false);
  });

  it("rejects invalid statement metadata without publishing an approval", async function () {
    const { registry, tenant, publisher, outsider, statement } = await loadFixture(fixture);
    const base = { ...statement, consumer: outsider.address };
    const evaluated = BigInt(statement.evaluatedAt.toString());
    const now = BigInt(await time.latest());
    const field = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
    const invalid = [
      { ...base, contextDigest: ethers.ZeroHash }, { ...base, transferDigest: ethers.ZeroHash },
      { ...base, projectionCommitment: 0 }, { ...base, projectionCommitment: field },
      { ...base, consumer: ethers.ZeroAddress }, { ...base, evaluatedAt: now + 10000n },
      { ...base, validUntil: now }, { ...base, validUntil: 9007199254740992n },
      { ...base, validUntil: evaluated + 301n },
      { ...base, pins: base.pins.map((pin, i) => i === 7 ? { ...pin, scope: ethers.id("wrong-context") } : pin) },
    ];
    const events = await registry.queryFilter(registry.filters.StatementPublished());
    for (const candidate of invalid) {
      const id = await registry.statementId(tenant, candidate);
      await expect(registry.connect(publisher).publishStatement(tenant, candidate))
        .to.be.revertedWithCustomError(registry, "InvalidStatement");
      expect((await registry.statementPublication(id)).exists).to.equal(false);
    }
    expect(await registry.queryFilter(registry.filters.StatementPublished())).to.have.length(events.length);
    const id = await registry.statementId(tenant, base);
    await registry.connect(publisher).publishStatement(tenant, base);
    expect((await registry.statementPublication(id)).exists).to.equal(true);
  });

  it("rejects malformed or mismatched pins for each current head without retaining approval", async function () {
    const { registry, tenant, publisher, outsider, statement, a, b, c, signals } = await loadFixture(fixture);
    const base = { ...statement, consumer: outsider.address };
    const events = await registry.queryFilter(registry.filters.StatementPublished());
    for (let index = 0; index < 7; index++) {
      const original = base.pins[index];
      const head = await registry.head(tenant, index, original.scope);
      for (const changed of [
        { ...original, scope: ethers.ZeroHash }, { ...original, digest: ethers.ZeroHash },
        { ...original, revision: 0 }, { ...original, scope: ethers.id("absent-scope") },
        { ...original, digest: ethers.id("wrong-digest") }, { ...original, revision: 2 },
      ]) {
        const candidate = { ...base, pins: base.pins.map((pin, i) => i === index ? changed : pin) };
        const id = await registry.statementId(tenant, candidate);
        await expect(registry.connect(publisher).publishStatement(tenant, candidate))
          .to.be.revertedWithCustomError(registry, "InvalidState");
        expect((await registry.statementPublication(id)).exists).to.equal(false);
        expect(await registry.head(tenant, index, original.scope)).to.deep.equal(head);
      }
    }
    expect(await registry.queryFilter(registry.filters.StatementPublished())).to.have.length(events.length);
    const id = await registry.statementId(tenant, base);
    await registry.connect(publisher).publishStatement(tenant, base);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
  });

  it("rejects unknown statements, relabeled tenants and proof expiry beyond approval without mirroring", async function () {
    const { registry, tenant, publisher, consumer, statement, id, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    await approve();
    const missing = ethers.id("synthetic-missing-statement");
    await expect(registry.inspect(tenant, missing, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    await expect(registry.connect(consumer).mirror(tenant, missing, receiptId, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "UnauthorizedConsumer");
    // Match publisher and epoch so rejection must enforce statement tenant binding.
    const foreign = ethers.id("synthetic-foreign-tenant");
    await registry.setPublisher(foreign, publisher.address);
    expect(await registry.publisherEpochs(foreign)).to.equal(await registry.publisherEpochs(tenant));
    await expect(registry.inspect(foreign, id, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    await expect(registry.connect(consumer).mirror(foreign, id, receiptId, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    const extended = [...signals];
    extended[5] = String(BigInt(statement.validUntil.toString()) + 1n);
    await expect(registry.inspect(tenant, id, a, b, c, extended))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, extended))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    for (const scope of [tenant, foreign]) {
      expect(await registry.mirroredReceipts(scope, signals[3])).to.equal(ethers.ZeroHash);
    }
    expect(await registry.queryFilter(registry.filters.AuthorizationMirrored())).to.have.length(0);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(receiptId);
    expect(await registry.mirroredReceipts(foreign, signals[3])).to.equal(ethers.ZeroHash);
    expect(await registry.queryFilter(registry.filters.AuthorizationMirrored())).to.have.length(1);
  });

  it("rejects source heads issued after evaluation while retaining the original valid statement", async function () {
    const { registry, tenant, publisher, statement, id, pins, bundle, a, b, c, signals } = await loadFixture(fixture);
    const issuedAt = await time.latest();
    expect(issuedAt).to.be.greaterThan(Number(statement.evaluatedAt));
    const events = await registry.queryFilter(registry.filters.StatementPublished());
    for (let kind = 0; kind < 6; kind++) {
      const scope = ethers.id(`synthetic-later-source-${kind}`);
      await registry.connect(publisher).publishHead(
        tenant, kind, scope, pins[kind].digest, bundle.heads[kind].value,
        0, issuedAt, statement.validUntil, true,
      );
      const candidate = { ...statement, pins: statement.pins.map((pin, i) => i === kind ? { ...pin, scope } : pin) };
      const candidateId = await registry.statementId(tenant, candidate);
      await expect(registry.connect(publisher).publishStatement(tenant, candidate))
        .to.be.revertedWithCustomError(registry, "InvalidState");
      expect((await registry.statementPublication(candidateId)).exists).to.equal(false);
    }
    expect(await registry.queryFilter(registry.filters.StatementPublished())).to.have.length(events.length);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
  });

  it("expires a pinned head at its own deadline even while the statement and proof remain live", async function () {
    const { registry, tenant, publisher, consumer, statement, pins, bundle, a, b, c, signals, receiptId } = await loadFixture(fixture);
    const scope = ethers.id("synthetic-short-lived-head");
    const deadline = (await time.latest()) + 10;
    expect(BigInt(statement.validUntil.toString())).to.be.greaterThan(BigInt(deadline));
    await registry.connect(publisher).publishHead(
      tenant, 0, scope, pins[0].digest, bundle.heads[0].value,
      0, statement.evaluatedAt, deadline, true,
    );
    const candidate = { ...statement, pins: statement.pins.map((pin, i) => i === 0 ? { ...pin, scope } : pin) };
    const id = await registry.statementId(tenant, candidate);
    await registry.connect(publisher).publishStatement(tenant, candidate);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await time.increaseTo(deadline);
    await expect(registry.inspect(tenant, id, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    expect((await registry.statementPublication(id)).exists).to.equal(true);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
    expect(await registry.queryFilter(registry.filters.AuthorizationMirrored())).to.have.length(0);
  });

  it("inspects read-only, then mirrors only the approved receipt with its designated caller", async function () {
    const { registry, tenant, consumer, outsider, id, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    await approve();
    expect(await registry.consumptionOwner()).to.equal("postgresql");
    await expect(registry.connect(consumer).mirror(tenant, id, ethers.id("wrong-receipt"), a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "AuthorizationUnavailable");
    await expect(registry.connect(outsider).mirror(tenant, id, receiptId, a, b, c, signals)).to.be.revertedWithCustomError(registry, "UnauthorizedConsumer");
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals))
      .to.emit(registry, "AuthorizationMirrored").withArgs(tenant, id, receiptId, signals[3]);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(receiptId);
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals)).to.be.revertedWithCustomError(registry, "AlreadyMirrored");
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
  });

  it("accepts participant and receipt evidence produced after proof evaluation", async function () {
    const { registry, tenant, publisher, consumer, statement, pins, a, b, c, signals, receiptId } = await loadFixture(fixture);
    const issuedAt = await time.latest();
    expect(issuedAt).to.be.greaterThan(Number(statement.evaluatedAt));
    await registry.connect(publisher).publishHead(tenant, 6, pins[6].scope, pins[6].digest,
      0, 1, issuedAt, statement.validUntil, true);
    const updated = { ...statement, pins: pins.map((pin, i) => i === 6 ? { ...pin, revision: 2 } : pin) };
    const id = await registry.statementId(tenant, updated);
    await registry.connect(publisher).publishStatement(tenant, updated);
    await registry.connect(publisher).publishHead(tenant, 7, pins[7].scope, receiptId,
      1, 0, issuedAt, statement.validUntil, true);
    await registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(receiptId);
  });

  async function batchFixture() {
    const result = await loadFixture(fixture);
    const { pins, statement, bundle } = result;
    const updates = pins.map((pin, i) => ({
      scope: pin.scope, digest: pin.digest, value: bundle.heads[i].value,
      expectedRevision: i === 7 ? 0 : 1, validFrom: statement.evaluatedAt,
      validUntil: statement.validUntil, enabled: true, replace: i === 7,
    }));
    // A new designated caller produces a distinct immutable statement, reusing seven heads.
    return { ...result, updates, batchStatement: { ...statement, consumer: result.outsider.address } };
  }

  it("atomically publishes a batch, reuses unchanged heads and exposes recovery identity", async function () {
    const { registry, tenant, publisher, outsider, pins, updates, batchStatement, receiptId, a, b, c, signals } = await batchFixture();
    const id = await registry.statementId(tenant, batchStatement);
    expect(await registry.statementPublication(id)).to.deep.equal([false, 0n]);
    await registry.connect(publisher).publishBatch(tenant, 1, updates, batchStatement);
    expect(await registry.statementPublication(id)).to.deep.equal([true, 1n]);
    for (let i = 0; i < 8; i++) expect((await registry.head(tenant, i, pins[i].scope)).revision).to.equal(1);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await expect(registry.connect(publisher).publishBatch(tenant, 1, updates, batchStatement))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    await registry.connect(outsider).mirror(tenant, id, receiptId, a, b, c, signals);
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(receiptId);
  });

  it("rolls back an earlier replacement when later reused heads or pins disagree", async function () {
    const { registry, tenant, publisher, pins, updates, batchStatement, a, b, c, signals } = await batchFixture();
    const replacements = updates.map((update, i) => i === 0 ? { ...update, replace: true } : { ...update });
    const statement = { ...batchStatement, pins: batchStatement.pins.map((pin, i) => i === 0 ? { ...pin, revision: 2 } : { ...pin }) };
    const before = await Promise.all(pins.map((pin, i) => registry.head(tenant, i, pin.scope)));
    const headEvents = await registry.queryFilter(registry.filters.HeadPublished());
    const statementEvents = await registry.queryFilter(registry.filters.StatementPublished());
    for (const fault of ["pin-scope", "pin-digest", "digest", "value", "from", "until", "enabled"]) {
      const altered = replacements.map(update => ({ ...update }));
      const candidate = { ...statement, pins: statement.pins.map(pin => ({ ...pin })) };
      if (fault === "pin-scope") candidate.pins[6].scope = ethers.id("mismatched-scope");
      else if (fault === "pin-digest") candidate.pins[6].digest = ethers.id("mismatched-digest");
      else if (fault === "digest") {
        // Align the claimed pin, isolating the comparison with the retained head.
        altered[6].digest = ethers.id("unretained-digest");
        candidate.pins[6].digest = altered[6].digest;
      } else if (fault === "value") altered[6].value = 1;
      else if (fault === "from") altered[6].validFrom = BigInt(altered[6].validFrom.toString()) + 1n;
      else if (fault === "until") altered[6].validUntil = BigInt(altered[6].validUntil.toString()) - 1n;
      else altered[6].enabled = false;
      const id = await registry.statementId(tenant, candidate);
      await expect(registry.connect(publisher).publishBatch(tenant, 1, altered, candidate))
        .to.be.revertedWithCustomError(registry, "InvalidState");
      expect((await registry.statementPublication(id)).exists).to.equal(false);
      for (let i = 0; i < 8; i++) expect(await registry.head(tenant, i, pins[i].scope)).to.deep.equal(before[i]);
      expect(await registry.queryFilter(registry.filters.HeadPublished())).to.have.length(headEvents.length);
      expect(await registry.queryFilter(registry.filters.StatementPublished())).to.have.length(statementEvents.length);
      expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
    }
    const id = await registry.statementId(tenant, statement);
    await registry.connect(publisher).publishBatch(tenant, 1, replacements, statement);
    expect((await registry.head(tenant, 0, pins[0].scope)).revision).to.equal(2);
    expect((await registry.head(tenant, 7, pins[7].scope)).revision).to.equal(1);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
  });

  it("rolls back every head if the final statement or a later checkpoint rejects", async function () {
    const { registry, tenant, publisher, pins, updates, batchStatement } = await batchFixture();
    const replaced = updates.map((u) => ({ ...u, replace: true }));
    const next = { ...batchStatement, pins: pins.map((p, i) => ({ ...p, revision: i === 7 ? 1 : 2 })) };
    await expect(registry.connect(publisher).publishBatch(tenant, 1, replaced, { ...next, projectionCommitment: 0 }))
      .to.be.revertedWithCustomError(registry, "InvalidStatement");
    await expect(registry.connect(publisher).publishBatch(tenant, 1,
      replaced.map((u, i) => i === 7 ? { ...u, expectedRevision: 1 } : u), next))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    for (let i = 0; i < 8; i++) expect((await registry.head(tenant, i, pins[i].scope)).revision).to.equal(i === 7 ? 0 : 1);
    expect(await registry.statementPublication(await registry.statementId(tenant, next))).to.deep.equal([false, 0n]);
  });

  it("rejects stale publisher epochs, callers and mismatched reused checkpoint values", async function () {
    const { registry, tenant, publisher, outsider, updates, batchStatement } = await batchFixture();
    await expect(registry.connect(outsider).publishBatch(tenant, 1, updates, batchStatement))
      .to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.connect(publisher).publishBatch(tenant, 1,
      updates.map((u, i) => i === 0 ? { ...u, value: BigInt(u.value) + 1n } : u), batchStatement))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    await registry.setPublisher(tenant, publisher.address);
    await expect(registry.connect(publisher).publishBatch(tenant, 1, updates, batchStatement))
      .to.be.revertedWithCustomError(registry, "InvalidState");
    await expect(registry.connect(publisher).publishBatch(tenant, 2, updates, batchStatement))
      .to.be.revertedWithCustomError(registry, "InvalidState");
  });

  it("keeps a non-ALLOW authorization separate from a valid current proof", async function () {
    const { registry, tenant, consumer, id, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    await approve(false);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "AuthorizationUnavailable");
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
  });

  it("rejects untrusted publication, foreign scope, changed context and invalid proof without recording a mirror", async function () {
    const { registry, tenant, publisher, consumer, outsider, statement, id, pins, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    await expect(registry.connect(outsider).publishStatement(tenant, statement)).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.connect(publisher).publishStatement(tenant, statement)).to.be.revertedWithCustomError(registry, "StatementExists");
    await expect(registry.connect(outsider).publishHead(tenant, 0, pins[0].scope, pins[0].digest, 1, 1,
      statement.evaluatedAt, statement.validUntil, true)).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.inspect(ethers.id("foreign"), id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    for (const index of [0, 1, 2, 4, 5, 6, 7]) {
      const changed = [...signals]; changed[index] = index === 5 ? String(await time.latest()) : String(BigInt(signals[index]) + 1n);
      await expect(registry.inspect(tenant, id, a, b, c, changed)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    }
    const zeroNullifier = [...signals]; zeroNullifier[3] = "0";
    await expect(registry.inspect(tenant, id, a, b, c, zeroNullifier)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    await approve();
    const q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const changedC: G1 = [c[0], String(q - BigInt(c[1]))];
    expect(await registry.inspect(tenant, id, a, b, changedC, signals)).to.equal(false);
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, changedC, signals)).to.be.revertedWithCustomError(registry, "InvalidProof");
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
  });

  for (let kind = 0; kind < 7; kind++) {
    it(`invalidates an existing statement after checkpoint ${kind} changes, even if its digest is restored`, async function () {
      const { registry, tenant, publisher, statement, id, pins, bundle, a, b, c, signals } = await loadFixture(fixture);
      await registry.connect(publisher).publishHead(tenant, kind, pins[kind].scope, ethers.id("replacement"),
        bundle.heads[kind].value, 1, statement.evaluatedAt, statement.validUntil, true);
      await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
      await registry.connect(publisher).publishHead(tenant, kind, pins[kind].scope, pins[kind].digest,
        bundle.heads[kind].value, 2, statement.evaluatedAt, statement.validUntil, true);
      await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
      expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
    });
  }

  it("rejects expired statements", async function () {
    const { registry, tenant, outsider, id, a, b, c, signals } = await loadFixture(fixture);
    await time.increaseTo(BigInt(signals[5]));
    await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidStatement");
  });

  it("invalidates a live statement when its publisher is replaced or disabled", async function () {
    const { registry, tenant, publisher, outsider, statement, pins, id, a, b, c, signals } = await loadFixture(fixture);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await registry.setPublisher(tenant, outsider.address);
    await expect(registry.connect(publisher).publishHead(tenant, 3, pins[3].scope, pins[3].digest,
      0, 1, statement.evaluatedAt, statement.validUntil, true)).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    await registry.setPublisher(tenant, ethers.ZeroAddress);
    await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidStatement");
  });

  it("rejects disabled credential and revoked ALLOW checkpoints", async function () {
    const { registry, tenant, publisher, consumer, statement, pins, id, a, b, c, signals, approve, receiptId } = await loadFixture(fixture);
    await approve();
    await registry.connect(publisher).publishHead(tenant, 7, pins[7].scope, pins[7].digest,
      1, 1, statement.evaluatedAt, statement.validUntil, false);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await expect(registry.connect(consumer).mirror(tenant, id, receiptId, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    await registry.connect(publisher).publishHead(tenant, 3, pins[3].scope, pins[3].digest,
      0, 1, statement.evaluatedAt, statement.validUntil, false);
    await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    expect(await registry.mirroredReceipts(tenant, signals[3])).to.equal(ethers.ZeroHash);
  });
});
