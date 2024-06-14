import * as v from "valibot";

const datasheetTableSchema = v.object({
  cycles: v.number(),
  duration: v.number(),
  hashfn: v.string(),
  name: v.string(),
  ram: v.number(),
  seal: v.number(),
  throughput: v.number(),
  total_cycles: v.number(),
  user_cycles: v.number(),
});

export type DatasheetTableSchema = v.InferOutput<typeof datasheetTableSchema>;
