import { isAbsolute } from "node:path";
import { executableFormatHintSchema } from "../domain/dosCom.js";
import { localPathStringSchema } from "../domain/localPath.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
  rawBinarySelectionError,
} from "../domain/rawBinary.js";
import { z } from "zod";
import { analysisProviderSelectorSchema } from "./providerSelection.js";

/** Caller-supplied analysis snapshot path; must name its destination absolutely. */
const snapshotPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "snapshot_path must be an absolute local filesystem path (for example /tmp/rea/analysis.json or C:\\rea\\analysis.json)",
  })
  .describe(
    "Absolute local filesystem path for the analysis snapshot; relative paths are rejected.",
  );

/** Caller-supplied analysis target path; must name the target absolutely. */
const binaryTargetPathSchema = localPathStringSchema
  .refine(isAbsolute, {
    message:
      "path must be an absolute local filesystem path (for example /tmp/fixture.bin or C:\\analysis\\fixture.bin)",
  })
  .describe(
    "Absolute local filesystem path for the analysis target; relative paths are rejected.",
  );

/** Input contract for opening a target with an optional staged snapshot. */
export const openBinaryInputSchema = z
  .strictObject({
    path: binaryTargetPathSchema,
    format: executableFormatHintSchema
      .optional()
      .describe(
        "Explicit headerless interpretation: dos-com or raw-binary. Omission preserves header-based detection.",
      ),
    architecture: binaryArchitectureSchema
      .optional()
      .describe(
        "Caller-supplied CPU family. Required with format=raw-binary; rejected otherwise.",
      ),
    entry_point: rawBinaryEntryPointSchema
      .optional()
      .describe(
        "Caller-supplied code entry address (0xhex). File offset 0 maps here unless base_address is supplied. Required with format=raw-binary; rejected otherwise.",
      ),
    base_address: rawBinaryEntryPointSchema
      .optional()
      .describe("Raw file offset 0 load address; defaults to entry_point."),
    bit_width: z
      .union([z.literal(32), z.literal(64)])
      .optional()
      .describe("Required for raw riscv; omitted for other architectures."),
    provider_id: analysisProviderSelectorSchema.optional(),
    snapshot_path: snapshotPathSchema.optional(),
  })
  .superRefine((value, context) => {
    const pairing = rawBinarySelectionError({
      ...(value.base_address === undefined
        ? {}
        : { baseAddress: value.base_address }),
      ...(value.bit_width === undefined ? {} : { bitWidth: value.bit_width }),
      ...(value.format === undefined ? {} : { format: value.format }),
      ...(value.architecture === undefined
        ? {}
        : { architecture: value.architecture }),
      ...(value.entry_point === undefined
        ? {}
        : { entryPoint: value.entry_point }),
    });
    if (pairing === undefined) return;
    context.addIssue({
      code: "custom",
      path:
        value.format === "raw-binary"
          ? value.architecture === undefined
            ? ["architecture"]
            : value.entry_point === undefined
              ? ["entry_point"]
              : ["bit_width"]
          : value.base_address !== undefined
            ? ["base_address"]
            : value.bit_width !== undefined
              ? ["bit_width"]
              : value.architecture !== undefined
                ? ["architecture"]
                : ["entry_point"],
      message: pairing,
    });
  });

/** Input contract for closing a target after an optional atomic snapshot. */
export const closeBinaryInputSchema = z.strictObject({
  snapshot_path: snapshotPathSchema.optional(),
  overwrite: z.boolean().default(false),
});
