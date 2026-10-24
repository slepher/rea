import {
  executableFormatHintSchema,
  type ExecutableFormatHint,
} from "../domain/dosCom.js";
import type { BinaryArchitecture } from "../domain/binaryTargetTypes.js";
import {
  binaryArchitectureSchema,
  rawBinaryEntryPointSchema,
} from "../domain/rawBinary.js";
import { analysisProviderSelectorSchema } from "../contracts/providerSelection.js";
import type { AnalysisProviderSelector } from "../contracts/providerSelection.js";
import { z } from "zod";
import type { Logger } from "pino";

export const providerSelectionOption = analysisProviderSelectorSchema
  .optional()
  .describe(
    "Bind deep analysis to a provider ID or use deterministic auto selection",
  );

/** Explicit interpretation for headerless native executable formats. */
export const formatSelectionOption = executableFormatHintSchema
  .optional()
  .describe(
    "Explicit headerless interpretation (dos-com or raw-binary); omission preserves header-based detection",
  );

export const architectureSelectionOption = binaryArchitectureSchema
  .optional()
  .describe(
    "Caller-supplied CPU family; required with --target-format raw-binary",
  );

export const entryPointSelectionOption = rawBinaryEntryPointSchema
  .optional()
  .describe(
    "Caller-supplied code entry address (0xhex); required with --target-format raw-binary",
  );

/** Shared CLI flags that bind a native target interpretation. */
export const nativeOpenOptionFields = {
  "target-format": formatSelectionOption,
  architecture: architectureSelectionOption,
  "entry-point": entryPointSelectionOption,
  "base-address": rawBinaryEntryPointSchema
    .optional()
    .describe("Raw file offset 0 load address; defaults to entry-point"),
  "bit-width": z.coerce
    .number()
    .pipe(z.union([z.literal(32), z.literal(64)]))
    .optional()
    .describe("Required for raw riscv: 32 or 64"),
  provider: providerSelectionOption,
};

/** Native CLI flags consumed when opening a target for one-shot analysis. */
export interface NativeOpenCliFlags {
  readonly snapshot?: string | undefined;
  readonly provider?: AnalysisProviderSelector | undefined;
  readonly "target-format"?: ExecutableFormatHint | undefined;
  readonly architecture?: BinaryArchitecture | undefined;
  readonly "entry-point"?: string | undefined;
  readonly "base-address"?: string | undefined;
  readonly "bit-width"?: 32 | 64 | undefined;
}

export const directAnalysisOptions = (
  logger: Logger,
  snapshotPath: string | undefined,
  providerId: AnalysisProviderSelector | undefined,
  formatHint?: ExecutableFormatHint,
  architecture?: BinaryArchitecture,
  entryPoint?: string,
  baseAddress?: string,
  bitWidth?: 32 | 64,
) => ({
  logger,
  snapshotPath,
  ...(baseAddress === undefined ? {} : { baseAddress }),
  ...(bitWidth === undefined ? {} : { bitWidth }),
  ...(formatHint === undefined ? {} : { formatHint }),
  ...(architecture === undefined ? {} : { architecture }),
  ...(entryPoint === undefined ? {} : { entryPoint }),
  ...(providerId === undefined ? {} : { providerId }),
});

/** Map native CLI flags onto the shared one-shot analysis options. */
export const directAnalysisOptionsFromCli = (
  logger: Logger,
  options: NativeOpenCliFlags,
) =>
  directAnalysisOptions(
    logger,
    options.snapshot,
    options.provider,
    options["target-format"],
    options.architecture,
    options["entry-point"],
    options["base-address"],
    options["bit-width"],
  );
