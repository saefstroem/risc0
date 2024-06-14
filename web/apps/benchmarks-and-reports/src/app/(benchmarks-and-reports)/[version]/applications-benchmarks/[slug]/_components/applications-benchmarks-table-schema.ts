import * as v from "valibot";

const applicationsBenchmarksTableSchema = {
  main: v.object({
    name: v.string(),
    size: v.string(),
    speed: v.string(),
    total_duration: v.string(),
    total_cycles: v.string(),
    user_cycles: v.string(),
    proof_bytes: v.string(),
  }),
  "release-0.21": v.object({
    job_name: v.string(),
    job_size: v.string(),
    exec_duration: v.string(),
    proof_duration: v.string(),
    total_duration: v.string(),
    verify_duration: v.string(),
    insn_cycles: v.string(),
    prove_cycles: v.string(),
    proof_bytes: v.string(),
  }),
  "release-1.0": v.object({
    name: v.string(),
    size: v.string(),
    speed: v.string(),
    total_duration: v.string(),
    total_cycles: v.string(),
    user_cycles: v.string(),
    proof_bytes: v.string(),
  }),
};

export type ApplicationsBenchmarksTableSchema<T extends keyof typeof applicationsBenchmarksTableSchema> = v.InferOutput<
  (typeof applicationsBenchmarksTableSchema)[T]
>;
