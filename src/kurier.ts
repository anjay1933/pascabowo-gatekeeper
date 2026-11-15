import type { Groth16Proof } from "./protocol";

/**
 * Kurier (zkVerify) proof submission — mainnet, REST.
 *
 *   POST {KURIER_API_URL}/submit-proof/{KURIER_API_KEY}
 *   { proofType: "groth16", vkRegistered: true,
 *     proofOptions: { library: "snarkjs", curve: "bn128" },
 *     proofData: { proof, publicSignals, vk: <vk_hash> } }
 *   -> { jobId, optimisticVerify }
 *   GET {KURIER_API_URL}/job-status/{KURIER_API_KEY}/{jobId}
 *   lifecycle: Queued -> Valid -> Submitted -> IncludedInBlock -> Finalized
 *   (or Failed). A txHash exists from Submitted onward, so polling returns
 *   as soon as one is known instead of blocking the task answer on
 *   finalization; the Kurier job keeps finalizing server-side regardless.
 *
 * The gatekeeper vk_hash is already registered on mainnet, so
 * vkRegistered: true and no register-vk call is needed.
 *
 * This module never throws: any failure yields null, and the caller still
 * answers the task with the locally generated proof + public signals.
 */

export interface KurierResult {
  jobId: string;
  status: string;
  txHash?: string;
  finalized: boolean;
}

export interface KurierSettings {
  apiKey: string | null;
  apiUrl: string;
  vkHash: string;
  pollIntervalMs: number;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function submitProofToKurier(
  settings: KurierSettings,
  proof: Groth16Proof,
  publicSignals: string[],
  budgetMs: number,
): Promise<KurierResult | null> {
  if (!settings.apiKey) return null;
  const key = settings.apiKey;
  const deadline = Date.now() + Math.max(0, budgetMs);
  try {
    const submitRes = await fetch(`${settings.apiUrl}/submit-proof/${key}`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        proofType: "groth16",
        vkRegistered: true,
        proofOptions: { library: "snarkjs", curve: "bn128" },
        proofData: { proof, publicSignals, vk: settings.vkHash },
      }),
    });
    if (!submitRes.ok) {
      console.error(`[kurier] submit-proof HTTP ${submitRes.status}`);
      return null;
    }
    const job = (await submitRes.json()) as {
      jobId?: string;
      optimisticVerify?: string;
    };
    if (!job.jobId) {
      console.error("[kurier] submit-proof response missing jobId");
      return null;
    }

    let status = "Submitted";
    let lastTxHash: string | undefined;
    while (Date.now() < deadline) {
      await sleep(
        Math.min(settings.pollIntervalMs, Math.max(0, deadline - Date.now())),
      );
      const statusRes = await fetch(
        `${settings.apiUrl}/job-status/${key}/${job.jobId}`,
      );
      if (!statusRes.ok) {
        console.error(`[kurier] job-status HTTP ${statusRes.status}`);
        continue;
      }
      const state = (await statusRes.json()) as {
        status?: string;
        txHash?: string;
        transactionInfo?: { txHash?: string };
      };
      status = state.status ?? status;
      const txHash = state.txHash ?? state.transactionInfo?.txHash;
      if (txHash) lastTxHash = txHash;
      if (status === "Failed") {
        return { jobId: job.jobId, status, txHash, finalized: false };
      }
      if (txHash) {
        return {
          jobId: job.jobId,
          status,
          txHash,
          finalized: status === "Finalized",
        };
      }
    }
    return { jobId: job.jobId, status, txHash: lastTxHash, finalized: false };
  } catch (err) {
    console.error("[kurier] submission error:", (err as Error).message);
    return null;
  }
}
