import { apiGet } from "@/lib/api/client";

export type ModelSummary = {
  model: {
    name: string;
    trained_at: string;
    training_rows: number;
    test_metrics: {
      precision: number;
      recall: number;
      f1: number;
      accuracy: number;
      false_positive_rate: number;
      test_rows: number;
      test_attack_share: number;
    };
  };
  threshold: number;
};

export function getModelSummary(signal?: AbortSignal): Promise<ModelSummary> {
  return apiGet<ModelSummary>("/api/v1/network/model", signal);
}
