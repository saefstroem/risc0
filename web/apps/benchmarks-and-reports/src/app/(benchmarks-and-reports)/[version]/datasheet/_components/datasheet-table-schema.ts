import { number as vNumber, object as vObject, type Output as vOutput, string as vString } from "@valibot/valibot";

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

export type DatasheetTableSchema = vOutput<typeof datasheetTableSchema>;
