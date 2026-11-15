import * as path from "path";
import * as snarkjs from "snarkjs";
import type { Groth16Proof } from "./protocol";

/**
 * Local Groth16 proving with snarkjs against the downloaded gatekeeper
 * artifacts. The circuit is small (a few hundred constraints); measured
 * locally at well under a second per proof once the WASM is warm, which
 * leaves ample room inside the platform's 60-second response deadline.
 *
 * This module knows nothing about HTTP or the platform — it only turns
 * witness inputs into a proof and can check a proof against the
 * verification key, which is what the demo and the test harness use.
 */
export class GatekeeperProver {
  private wasmPath: string;
  private zkeyPath: string;

  constructor(circuitsDir: string) {
    this.wasmPath = path.join(circuitsDir, "gatekeeper.wasm");
    this.zkeyPath = path.join(circuitsDir, "gatekeeper_final.zkey");
  }

  async generate(
    witness: Record<string, string>,
  ): Promise<{ proof: Groth16Proof; publicSignals: string[] }> {
    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      witness,
      this.wasmPath,
      this.zkeyPath,
    );
    return { proof: proof as Groth16Proof, publicSignals };
  }

  async check(
    verificationKey: unknown,
    publicSignals: string[],
    proof: Groth16Proof,
  ): Promise<boolean> {
    return snarkjs.groth16.verify(verificationKey, publicSignals, proof);
  }

  /**
   * Shut down the proving worker pool so a short-lived process (tests,
   * demo CLI) can exit cleanly. snarkjs/ffjavascript spins up a pool of
   * worker threads the first time a proof is generated and never tears it
   * down on its own — without this call the process hangs forever after
   * the first fullProve, even though every proof already succeeded.
   *
   * The BN128 curve instance is cached on `globalThis.curve_bn128` by
   * ffjavascript and exposes `terminate()`, which stops the workers. A
   * later proof rebuilds the curve (and its workers) on demand, so
   * calling this mid-life is safe; it is simply unnecessary for the
   * long-running server, which is supposed to stay up.
   *
   * Never throws: shutdown must not mask a real result.
   */
  async shutdown(): Promise<void> {
    try {
      const curve = (globalThis as { curve_bn128?: { terminate?: () => Promise<void> } })
        .curve_bn128;
      if (curve && typeof curve.terminate === "function") {
        await curve.terminate();
      }
    } catch {
      /* proving workers are best-effort to stop; the process still exits */
    }
  }
}
