import {
  object as vObject,
  optional as vOptional,
  type Output as vOutput,
  picklist as vPicklist,
  string as vString,
} from "@valibot/valibot";

const cratesIoValidationTableSchema = vObject({
  name: vString(),
  version: vString(),
  status: vPicklist(["Success", "BuildFail", "RunFail", "Skipped"]),
  custom_profile: vString(),
  build_errors: vOptional(vString()),
});

export type CratesIoValidationTableSchema = vOutput<typeof cratesIoValidationTableSchema>;
