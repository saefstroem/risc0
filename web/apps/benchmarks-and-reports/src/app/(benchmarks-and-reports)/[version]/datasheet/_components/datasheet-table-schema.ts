import { type InferOutput as vInferOutput, number as vNumber, object as vObject, string as vString } from "valibot";

const datasheetTableSchema = vObject({
  cycles: vNumber(),
  duration: vNumber(),
  hashfn: vString(),
  name: vString(),
  ram: vNumber(),
  seal: vNumber(),
  throughput: vNumber(),
  total_cycles: vNumber(),
  user_cycles: vNumber(),
});

export type DatasheetTableSchema = vInferOutput<typeof datasheetTableSchema>;
