import { type InferOutput as vInferOutput, object as vObject, string as vString } from "valibot";

const applicationsBenchmarksTableSchema = {
  main: vObject({
    name: vString(),
    size: vString(),
    speed: vString(),
    total_duration: vString(),
    total_cycles: vString(),
    user_cycles: vString(),
    proof_bytes: vString(),
  }),
  "release-0.21": vObject({
    job_name: vString(),
    job_size: vString(),
    exec_duration: vString(),
    proof_duration: vString(),
    total_duration: vString(),
    verify_duration: vString(),
    insn_cycles: vString(),
    prove_cycles: vString(),
    proof_bytes: vString(),
  }),
  "release-1.0": vObject({
    name: vString(),
    size: vString(),
    speed: vString(),
    total_duration: vString(),
    total_cycles: vString(),
    user_cycles: vString(),
    proof_bytes: vString(),
  }),
};

export type ApplicationsBenchmarksTableSchema<T extends keyof typeof applicationsBenchmarksTableSchema> = vInferOutput<
  (typeof applicationsBenchmarksTableSchema)[T]
>;
