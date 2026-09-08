import { expect } from "chai";
import { ethers } from "hardhat";
import { loadFixture } from "@nomicfoundation/hardhat-network-helpers";

describe("Pairing library on actual EVM precompiles", function () {
  async function fixture() {
    const harness = await (await ethers.getContractFactory("PairingHarness")).deploy();
    const [first, second] = await harness.generators();
    // Copy ethers results into mutable ABI inputs.
    const p = { X: first.X, Y: first.Y };
    const q = { X: [...second.X] as [bigint, bigint], Y: [...second.Y] as [bigint, bigint] };
    return { harness, p, q };
  }

  it("satisfies generator, negation, addition, multiplication and pairing identities", async function () {
    const { harness, p, q } = await loadFixture(fixture);
    expect(p).to.deep.equal({ X: 1n, Y: 2n });
    const negative = await harness.negate(p);
    const n = { X: negative.X, Y: negative.Y };
    expect(await harness.negate({ X: 0, Y: 0 })).to.deep.equal([0n, 0n]);
    expect(await harness.negate(n)).to.deep.equal([p.X, p.Y]);
    expect(await harness.add(p, n)).to.deep.equal([0n, 0n]);
    expect(await harness.multiply(p, 0)).to.deep.equal([0n, 0n]);
    expect(await harness.multiply(p, 1)).to.deep.equal([p.X, p.Y]);
    expect(await harness.multiply(p, 2)).to.deep.equal(await harness.add(p, p));
    expect(await harness.pairing([], [])).to.equal(true);
    expect(await harness.pairing([p], [q])).to.equal(false);
    expect(await harness.pairing([p, n], [q, q])).to.equal(true);
  });

  it("rejects mismatched inventories and off-curve operands with exact errors", async function () {
    const { harness, p, q } = await loadFixture(fixture);
    await expect(harness.pairing([p], [])).to.be.revertedWith("Pairing: mismatched input lengths");
    await expect(harness.pairing([], [q])).to.be.revertedWith("Pairing: mismatched input lengths");
    for (const operands of [[{ X: 1, Y: 1 }, p], [p, { X: 1, Y: 1 }]] as const) {
      await expect(harness.add(...operands)).to.be.revertedWith("Pairing: ecadd failed");
    }
    await expect(harness.multiply({ X: 1, Y: 1 }, 1)).to.be.revertedWith("Pairing: ecmul failed");
    await expect(harness.pairing([{ X: 1, Y: 1 }], [q])).to.be.revertedWith("Pairing: ecpairing failed");
    expect(await harness.multiply(p, 1)).to.deep.equal([p.X, p.Y]);
  });
});
