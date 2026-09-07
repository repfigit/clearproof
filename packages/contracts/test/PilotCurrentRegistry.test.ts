import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture, time } from "@nomicfoundation/hardhat-network-helpers";
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
    const approve = (allow = true) => registry.connect(publisher).publishHead(tenant, 7, pins[7].scope,
      pins[7].digest, allow ? 1 : 0, 0, evaluatedAt, bundle.valid_until, true);
    return { registry, pairing, tenant, publisher, consumer, outsider, statement, id, pins, bundle, a, b, c, signals, approve };
  }

  it("inspects without approval or consumption, then consumes only with ALLOW and the designated caller", async function () {
    const { registry, tenant, consumer, outsider, id, a, b, c, signals, approve } = await loadFixture(fixture);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    expect(await registry.consumed(tenant, signals[3])).to.equal(false);
    await expect(registry.connect(consumer).consume(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    await approve();
    await expect(registry.connect(outsider).consume(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "UnauthorizedConsumer");
    await expect(registry.connect(consumer).consume(tenant, id, a, b, c, signals))
      .to.emit(registry, "AuthorizationConsumed").withArgs(tenant, id, signals[3]);
    expect(await registry.consumed(tenant, signals[3])).to.equal(true);
    await expect(registry.connect(consumer).consume(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "AlreadyConsumed");
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
  });

  it("keeps a non-ALLOW authorization separate from a valid current proof", async function () {
    const { registry, tenant, consumer, id, a, b, c, signals, approve } = await loadFixture(fixture);
    await approve(false);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await expect(registry.connect(consumer).consume(tenant, id, a, b, c, signals))
      .to.be.revertedWithCustomError(registry, "AuthorizationUnavailable");
    expect(await registry.consumed(tenant, signals[3])).to.equal(false);
  });

  it("rejects untrusted publication, foreign scope, changed context and invalid proof without consuming", async function () {
    const { registry, tenant, publisher, consumer, outsider, statement, id, pins, a, b, c, signals, approve } = await loadFixture(fixture);
    await expect(registry.connect(outsider).publishStatement(tenant, statement)).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.connect(publisher).publishStatement(tenant, statement)).to.be.revertedWithCustomError(registry, "StatementExists");
    await expect(registry.connect(outsider).publishHead(tenant, 0, pins[0].scope, pins[0].digest, 1, 1,
      statement.evaluatedAt, statement.validUntil, true)).to.be.revertedWithCustomError(registry, "UnauthorizedPublisher");
    await expect(registry.inspect(ethers.id("foreign"), id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    for (const index of [0, 1, 2, 4, 5, 6, 7]) {
      const changed = [...signals]; changed[index] = index === 5 ? String(await time.latest()) : String(BigInt(signals[index]) + 1n);
      await expect(registry.inspect(tenant, id, a, b, c, changed)).to.be.revertedWithCustomError(registry, "InvalidStatement");
    }
    await approve();
    const q = 21888242871839275222246405745257275088696311157297823662689037894645226208583n;
    const changedC: G1 = [c[0], String(q - BigInt(c[1]))];
    expect(await registry.inspect(tenant, id, a, b, changedC, signals)).to.equal(false);
    await expect(registry.connect(consumer).consume(tenant, id, a, b, changedC, signals)).to.be.revertedWithCustomError(registry, "InvalidProof");
    expect(await registry.consumed(tenant, signals[3])).to.equal(false);
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
      expect(await registry.consumed(tenant, signals[3])).to.equal(false);
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
    const { registry, tenant, publisher, consumer, statement, pins, id, a, b, c, signals, approve } = await loadFixture(fixture);
    await approve();
    await registry.connect(publisher).publishHead(tenant, 7, pins[7].scope, pins[7].digest,
      1, 1, statement.evaluatedAt, statement.validUntil, false);
    expect(await registry.inspect(tenant, id, a, b, c, signals)).to.equal(true);
    await expect(registry.connect(consumer).consume(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    await registry.connect(publisher).publishHead(tenant, 3, pins[3].scope, pins[3].digest,
      0, 1, statement.evaluatedAt, statement.validUntil, false);
    await expect(registry.inspect(tenant, id, a, b, c, signals)).to.be.revertedWithCustomError(registry, "InvalidState");
    expect(await registry.consumed(tenant, signals[3])).to.equal(false);
  });
});
