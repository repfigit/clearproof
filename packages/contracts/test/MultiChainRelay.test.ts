import { expect } from "chai";
import { ethers } from "hardhat";
import { ChildProcess, execFile, spawn } from "node:child_process";
import * as fs from "node:fs";
import * as net from "node:net";
import * as os from "node:os";
import * as path from "node:path";
import { promisify } from "node:util";

const execute = promisify(execFile);
const pause = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));
async function unusedPort(): Promise<number> {
  const server = net.createServer();
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const port = (server.address() as net.AddressInfo).port;
  await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
  return port;
}
async function stop(node: ChildProcess) {
  if (node.exitCode !== null || node.signalCode !== null) return;
  const exited = new Promise<void>(resolve => node.once("exit", () => resolve()));
  process.kill(-node.pid!, "SIGTERM");
  await Promise.race([exited, pause(5000)]);
  if (node.exitCode === null && node.signalCode === null) {
    process.kill(-node.pid!, "SIGKILL");
    await exited;
  }
}

describe("Multi-chain sanctions relay entrypoint", function () {
  it("synchronizes two owned chains, detects failed targets and closes its clients", async function () {
    this.timeout(120000);
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), "clearproof-multichain-relay-"));
    const nodes: ChildProcess[] = [];
    const providers: InstanceType<typeof ethers.JsonRpcProvider>[] = [];
    try {
      const scripts = path.join(directory, "packages/contracts/scripts");
      const deployments = path.join(directory, "packages/contracts/deployments");
      fs.mkdirSync(scripts, { recursive: true });
      fs.mkdirSync(deployments);
      fs.mkdirSync(path.join(directory, "artifacts"));
      fs.writeFileSync(path.join(directory, "package.json"), '{"private":true}');
      fs.symlinkSync(path.resolve(__dirname, "../../../node_modules"), path.join(directory, "node_modules"), "dir");
      // The contracts workspace uses ethers v6; another workspace also installs v5.
      fs.symlinkSync(path.resolve(__dirname, "../node_modules"), path.join(directory, "packages/contracts/node_modules"), "dir");
      for (const name of ["relay-sanctions-root.ts", "networks.ts"]) {
        fs.copyFileSync(path.resolve(__dirname, "../scripts", name), path.join(scripts, name));
      }
      fs.writeFileSync(path.join(directory, "artifacts/sanctions_tree.json"), JSON.stringify({ root: "123", leaf_count: 100 }));
      const identity = ethers.Wallet.createRandom();
      const env: NodeJS.ProcessEnv = { ...process.env, DEPLOYER_PRIVATE_KEY: identity.privateKey,
        SKIP_CONFIRM: "1", RELAY_NETWORKS: "ethereum,base", TS_NODE_PROJECT: path.resolve(__dirname, "../tsconfig.json") };
      const oracles: any[] = [];
      for (const [name, chainId, rpcVariable] of [["ethereum", 1, "ETHEREUM_RPC_URL"], ["base", 8453, "BASE_RPC_URL"]] as const) {
        const config = path.join(directory, `${name}.config.cjs`);
        fs.writeFileSync(config, `module.exports = { networks: { hardhat: { chainId: ${chainId}, hardfork: "prague" } } };`);
        const port = await unusedPort();
        const node = spawn(process.execPath, [require.resolve("hardhat/internal/cli/cli"), "node", "--config", config,
          "--hostname", "127.0.0.1", "--port", String(port)], {
          cwd: directory, detached: true, stdio: "ignore",
        });
        nodes.push(node);
        const url = `http://127.0.0.1:${port}`;
        const provider = new ethers.JsonRpcProvider(url, chainId, { staticNetwork: true, cacheTimeout: 0 });
        providers.push(provider);
        const deadline = Date.now() + 20000;
        while (true) {
          if (node.exitCode !== null) throw new Error(`Owned ${name} node exited: ${node.exitCode}`);
          try {
            expect(await provider.send("eth_chainId", [])).to.equal(ethers.toQuantity(chainId));
            break;
          } catch (error) {
            if (Date.now() >= deadline) throw error;
            await pause(100);
          }
        }
        env[rpcVariable] = url;
        await provider.send("hardhat_setBalance", [identity.address, ethers.toQuantity(10n ** 20n)]);
        const signer = new ethers.NonceManager(identity.connect(provider));
        const oracle = await (await ethers.getContractFactory("SanctionsOracle", signer)).deploy(
          identity.address, ethers.id(`synthetic-${name}`), 100);
        await oracle.waitForDeployment();
        const relay = await (await ethers.getContractFactory("SanctionsRootRelay", signer)).deploy(identity.address, await oracle.getAddress());
        await relay.waitForDeployment();
        await (await oracle.grantRole(ethers.id("ORACLE_ROLE"), await relay.getAddress())).wait();
        await provider.send("evm_increaseTime", [3601]);
        await provider.send("evm_mine", []);
        fs.writeFileSync(path.join(deployments, `${name}.json`), JSON.stringify({ chainId: String(chainId),
          contracts: { SanctionsOracle: await oracle.getAddress(), SanctionsRootRelay: await relay.getAddress() } }));
        oracles.push(oracle);
      }
      const args = ["-r", require.resolve("ts-node/register"), path.join(scripts, "relay-sanctions-root.ts")];
      const options = { cwd: path.resolve(__dirname, ".."), env, timeout: 30000 };
      const result = await execute(process.execPath, args, options);
      expect(result.stdout).to.contain("2 succeeded, 0 failed");
      for (const oracle of oracles) {
        expect(await oracle.currentRoot()).to.equal(ethers.zeroPadValue(ethers.toBeHex(123n), 32));
        expect(await oracle.leafCount()).to.equal(100n);
      }
      // An idle second invocation must exit rather than retaining provider timers.
      const repeated = await execute(process.execPath, args, options);
      expect(repeated.stdout).to.contain("All networks are up to date");
      for (const extra of [{ RELAY_NETWORKS: "ethereum,unknown" },
        { RELAY_NETWORKS: "ethereum", ETHEREUM_RPC_URL: env.BASE_RPC_URL }]) {
        let failed: any;
        try { await execute(process.execPath, args, { ...options, env: { ...env, ...extra } }); }
        catch (error) { failed = error; }
        expect(failed?.code).to.equal(1);
        expect(failed.stdout).not.to.contain("All networks are up to date");
        expect(failed.stdout).to.contain("0 succeeded, 1 failed");
      }
    } finally {
      for (const provider of providers) provider.destroy();
      for (const node of nodes) await stop(node);
      fs.rmSync(directory, { recursive: true, force: true });
    }
    expect(nodes.every(node => node.exitCode !== null || node.signalCode !== null)).to.equal(true);
  });
});
