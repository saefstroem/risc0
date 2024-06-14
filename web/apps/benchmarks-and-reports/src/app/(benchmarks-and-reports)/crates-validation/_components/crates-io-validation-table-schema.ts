import {
  type InferOutput as vInferOutput,
  object as vObject,
  optional as vOptional,
  picklist as vPicklist,
  string as vString,
} from "valibot";

const cratesIoValidationTableSchema = vObject({
  name: vString(),
  version: vString(),
  status: vPicklist(["Success", "BuildFail", "RunFail", "Skipped"]),
  custom_profile: vString(),
  build_errors: vOptional(vString()),
});

export type CratesIoValidationTableSchema = vInferOutput<typeof cratesIoValidationTableSchema>;
