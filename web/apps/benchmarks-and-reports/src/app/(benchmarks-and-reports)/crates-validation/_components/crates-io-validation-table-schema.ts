import * as v from "valibot";

const cratesIoValidationTableSchema = v.object({
  name: v.string(),
  version: v.string(),
  status: v.picklist(["Success", "BuildFail", "RunFail", "Skipped"]),
  custom_profile: v.string(),
  build_errors: v.optional(v.string()),
});

export type CratesIoValidationTableSchema = v.InferOutput<typeof cratesIoValidationTableSchema>;
