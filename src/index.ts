#!/usr/bin/env node

import { execFile } from "node:child_process";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";
import { Adversary, Severity, log, type RuleContext } from "@adversarylabs/sdk";

const execute = promisify(execFile);

const TODO_LANDMINE =
  /\b(TODO|FIXME|XXX|HACK)\b(?![^\n]{0,80}\b(https?:\/\/|#[0-9]+|[A-Z]+-\d+)\b)/i;

// Dual naming left after a partial rename (common maintainer nit).
const UNFINISHED_RENAME_PAIRS: Array<{ a: RegExp; b: RegExp; label: string }> = [
  { a: /\bold[A-Z_]/, b: /\bnew[A-Z_]/, label: "old*/new* dual naming" },
  { a: /\b\w+Legacy\b/, b: /\b\w+V2\b/, label: "Legacy*/V2* dual naming" },
  { a: /\b\w+_old\b/i, b: /\b\w+_new\b/i, label: "_old/_new dual naming" },
];

const RECORDER_NAME = /(?:record|logger|trace|issue|audit|persist)/i;
const SECRET_MASKER_NAME = /(?:mask|redact|saniti[sz]e|scrub)/i;

interface MaskingGuarantee {
  recorder: string;
  sanitizer: string;
  path: string;
  line: number;
  start: number;
  end: number;
}

interface ScopedSource {
  path: string;
  content: string;
  previousContent?: string;
  changedLines: Set<number>;
  status: "added" | "modified" | "repository";
}

interface ErrorDomainMismatch {
  errorName: string;
  errorDomain: string;
  operationDomain: string;
  evidence: Array<{ line: number; message: string }>;
}

interface DomainSignal {
  kind: "operation" | "diagnostic" | "scope";
  line: number;
  message: string;
  tokens: Set<string>;
}

interface ErrorConstruction {
  name: string;
  tokens: Set<string>;
}

const OPERATION_NAME =
  /\b(?:[A-Za-z_]\w*(?:::[A-Za-z_]\w*|\.[A-Za-z_]\w*)*[_A-Z]?)?(?:create|open|read|write|load|save|delete|remove|parse|decode|encode|connect|send|receive|fetch|store|update|mount|setup|configure|validate|publish|render|compile|copy|move|rename|lock|unlock)[A-Za-z0-9_]*(?:!\s*)?\(/i;
const DIAGNOSTIC_CALL =
  /\b(?:tracing::)?(?:log|logger|trace|debug|info|warn|warning|error|fatal|printf|println|eprintln)(?:!|\.[A-Za-z_]\w*)?\s*\(/i;
const COMPATIBILITY_MARKER =
  /\b(?:alias|backward(?:s)?[-_ ]compat|compatibility|deprecated|legacy|normalize[ds]?|translate[ds]?|interoperab|wire[-_ ]format)\b/i;

const DOMAIN_STOP_WORDS = new Set([
  "all", "and", "any", "app", "application", "argument", "async", "attempt", "bad",
  "call", "cause", "close", "closed", "code", "config", "configuration", "construct",
  "create", "created", "creating", "data", "delete", "deleted", "deleting", "directory",
  "dir", "do", "done", "error", "exception", "failed", "failure", "fatal", "file", "from",
  "event", "generic", "get", "got", "group", "handle", "handler", "id", "input", "internal", "invalid", "io",
  "load", "loaded", "loading", "map", "message", "missing", "new", "not", "open", "opened",
  "object", "opening", "operation", "output", "path", "persist", "persistence", "read", "reading", "record", "remove", "removed", "request", "resource", "response", "result",
  "return", "save", "saved", "service", "set", "shared", "state", "status", "subdirectory", "task", "the",
  "this", "to", "unable", "unavailable", "unexpected", "unknown", "update", "updated", "value", "variant", "with",
  "write", "writing",
]);

export function createApp(): Adversary {
  const app = new Adversary({
    name: "review/nits",
    version: "0.0.12",
    // Nits are intentionally Severity.Info; surface them rather than drop as noise.
    review: {
      maximumFindings: 8,
      minimumConfidence: "medium",
      includeInformational: true,
    },
  });

  app.rule("nits.todo_landmine", async (ctx) => {
    const sources = await loadScopedSources(ctx);
    let emitted = 0;
    for (const source of sources) {
      if (emitted >= 3) break;
      if (shouldSkipPath(source.path)) continue;
      const content = source.content || "";
      const lines = content.split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (!isEligibleLine(source, i + 1)) continue;
        if (!isCommentish(line, source.path) && !TODO_LANDMINE.test(line)) continue;
        if (!TODO_LANDMINE.test(line)) continue;
        // Require TODO-like token on a comment or end-of-line note.
        if (!isCommentish(line, source.path) && !/\b(TODO|FIXME|XXX|HACK)\b/.test(line)) {
          continue;
        }
        log.info(`TODO landmine in ${source.path}:${i + 1}`);
        ctx.finding({
          ruleId: "nits.todo_landmine",
          category: "style",
          severity: Severity.Info,
          confidence: "medium",
          title: "TODO landmine without ownership",
          summary:
            "A TODO/FIXME/HACK was introduced without a ticket or URL. That tends to rot.",
          evidence: [
            {
              file: rel(ctx, source.path),
              line: i + 1,
              message: line.trim().slice(0, 160),
            },
          ],
          recommendation:
            "Attach an issue/URL, or fix the underlying problem before landing. Do not leave anonymous landmines.",
        });
        emitted++;
        break;
      }
    }
  });

  app.rule("nits.unfinished_rename", async (ctx) => {
    const sources = await loadScopedSources(ctx);
    for (const source of sources) {
      if (shouldSkipPath(source.path)) continue;
      const content = source.content || "";
      for (const pair of UNFINISHED_RENAME_PAIRS) {
        if (pair.a.test(content) && pair.b.test(content)) {
          const line = firstEligibleMatchLine(source, pair.a) ?? firstEligibleMatchLine(source, pair.b);
          if (line === undefined) continue;
          log.info(`Unfinished rename pattern in ${source.path}`);
          ctx.finding({
            ruleId: "nits.unfinished_rename",
            category: "style",
            severity: Severity.Info,
            confidence: "medium",
            title: "Possible unfinished rename",
            summary: `Both sides of a rename still appear (${pair.label}). Finish the rename or drop the dead name.`,
            evidence: [
              {
                file: rel(ctx, source.path),
                line,
                message: pair.label,
              },
            ],
            recommendation:
              "Complete the rename in one change, or remove the obsolete symbol so only one name remains.",
          });
          return;
        }
      }
    }
  });

  app.rule("nits.stale_comment_marker", async (ctx) => {
    const sources = await loadScopedSources(ctx);
    const stale =
      /\b(this (is|was) (no longer|not) used|obsolete|remove this later|temporary hack)\b/i;
    let emitted = 0;
    for (const source of sources) {
      if (emitted >= 2) break;
      if (shouldSkipPath(source.path)) continue;
      const lines = (source.content || "").split("\n");
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        if (!isEligibleLine(source, i + 1)) continue;
        if (!isCommentish(line, source.path)) continue;
        if (!stale.test(line)) continue;
        ctx.finding({
          ruleId: "nits.stale_comment_marker",
          category: "style",
          severity: Severity.Info,
          confidence: "low",
          title: "Comment admits temporary/obsolete state",
          summary:
            "Comment language suggests temporary or obsolete code left in place. Clean it up or remove the comment and the code.",
          evidence: [
            {
              file: rel(ctx, source.path),
              line: i + 1,
              message: line.trim().slice(0, 160),
            },
          ],
          recommendation: "Either finish the cleanup or drop the dead path and comment.",
        });
        emitted++;
        break;
      }
    }
  });

  app.rule("nits.redundant_secret_masking", async (ctx) => {
    const sources = await loadScopedSources(ctx);
    const guarantees = sources.flatMap((source) =>
      findMaskingGuarantees(source.path, source.content || ""),
    );
    let emitted = 0;

    for (const source of sources) {
      if (emitted >= 3) break;
      if (shouldSkipPath(source.path)) continue;
      const lines = (source.content || "").split("\n");
      let offset = 0;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i] ?? "";
        const guarantee = guarantees.find(
          (candidate) =>
            candidate.path === source.path &&
            !(
              offset >= candidate.start &&
              offset < candidate.end
            ) && containsNestedMaskingCall(line, candidate),
        );
        if (guarantee === undefined) {
          offset += line.length + 1;
          continue;
        }
        if (
          !isEligibleLine(source, i + 1) &&
          !isEligibleLine(source, guarantee.line)
        ) {
          offset += line.length + 1;
          continue;
        }

        ctx.finding({
          ruleId: "nits.redundant_secret_masking",
          category: "style",
          severity: Severity.Info,
          confidence: "medium",
          title: "Redundant secret masking before recorder",
          summary: `${guarantee.recorder} already applies ${guarantee.sanitizer} before emitting this value, so masking it at the call site is redundant.`,
          evidence: [
            {
              file: rel(ctx, source.path),
              line: i + 1,
              message: line.trim().slice(0, 160),
            },
            {
              file: rel(ctx, guarantee.path),
              line: guarantee.line,
              message: `${guarantee.recorder} applies ${guarantee.sanitizer} to its input`,
            },
          ],
          recommendation: `Pass the original value to ${guarantee.recorder} and let its ${guarantee.sanitizer} guarantee own the redaction.`,
        });
        emitted++;
        break;
      }
    }
  });

  app.rule("nits.dockerfile_run_indentation", async (ctx) => {
    const sources = await loadScopedSources(ctx, {
      cacheKey: "dockerfiles",
      include: isDockerfilePath,
      limit: 100,
    });
    let emitted = 0;

    for (const source of sources) {
      if (emitted >= 3) break;
      for (const outlier of findDockerfileRunIndentationOutliers(source.content || "")) {
        if (!isEligibleLine(source, outlier.line)) continue;
        ctx.finding({
          ruleId: "nits.dockerfile_run_indentation",
          category: "style",
          severity: Severity.Info,
          confidence: "medium",
          title: "Inconsistent Dockerfile RUN indentation",
          summary: `This line uses ${outlier.actual} leading spaces while the adjacent continuation lines use ${outlier.expected}.`,
          evidence: [
            {
              file: rel(ctx, source.path),
              line: outlier.line,
              message: outlier.text.trim().slice(0, 160),
            },
          ],
          recommendation: `Align this continuation line to ${outlier.expected} leading spaces for consistency with the surrounding RUN block.`,
        });
        emitted++;
        break;
      }
    }
  });

  app.rule("nits.error_domain_mismatch", async (ctx) => {
    const sources = await loadScopedSources(ctx, {
      cacheKey: "error-domain-mismatch",
      include: isReviewableImplementationPath,
      limit: 150,
    });
    let emitted = 0;

    for (const source of sources) {
      if (emitted >= 3) break;
      if (source.status === "repository" || shouldSkipErrorDomainPath(source.path)) continue;

      for (const mismatch of findErrorDomainMismatches(source)) {
        ctx.finding({
          ruleId: "nits.error_domain_mismatch",
          category: "style",
          severity: Severity.Info,
          confidence: "medium",
          title: "Error name contradicts the operation domain",
          summary: `The changed ${mismatch.errorName} error names the ${mismatch.errorDomain} domain, while the surrounding operation and diagnostic consistently describe ${mismatch.operationDomain}.`,
          evidence: mismatch.evidence.map((evidence) => ({
            file: rel(ctx, source.path),
            line: evidence.line,
            message: evidence.message,
          })),
          recommendation: `Use an error variant for ${mismatch.operationDomain}, or a deliberately generic error name shared by both domains.`,
        });
        emitted++;
        break;
      }
    }
  });

  app.rule("nits.diagnostic_operation_mismatch", async (ctx) => {
    const sources = await loadScopedSources(ctx, {
      cacheKey: "diagnostic-operation-mismatch",
      include: isReviewableImplementationPath,
      limit: 150,
    });
    let emitted = 0;
    for (const source of sources) {
      if (emitted >= 3) break;
      const operation = operationFromPath(source.path);
      if (operation === undefined || shouldSkipErrorDomainPath(source.path)) continue;
      const lines = source.content.split(/\r?\n/);
      for (let index = 0; index < lines.length; index += 1) {
        const line = lines[index] ?? "";
        if (!isEligibleLine(source, index + 1) || !DIAGNOSTIC_CALL.test(line)) continue;
        const mismatch = conflictingDiagnosticOperation(line, operation);
        if (mismatch === undefined) continue;
        ctx.finding({
          ruleId: "nits.diagnostic_operation_mismatch",
          category: "style",
          severity: Severity.Info,
          confidence: "medium",
          title: "Diagnostic names the wrong operation",
          summary: `This ${operation} handler's changed diagnostic says ${mismatch}, which sends operators toward a different workflow.`,
          evidence: [{
            file: rel(ctx, source.path),
            line: index + 1,
            message: line.trim().slice(0, 160),
          }],
          recommendation: `Describe the ${operation} operation or the immediate verification step in this diagnostic.`,
        });
        emitted += 1;
        break;
      }
    }
  });

  return app;
}

const PATH_OPERATIONS = ["create", "enable", "disable", "delete", "remove", "update", "login", "logout"] as const;

function operationFromPath(path: string): string | undefined {
  const segments = path.toLowerCase().replace(/\.[^.\/]+$/, "").split(/[\/_-]+/);
  return PATH_OPERATIONS.find((operation) => segments.includes(operation));
}

function conflictingDiagnosticOperation(line: string, operation: string): string | undefined {
  const lower = line.toLowerCase();
  const actionPhrase = lower.match(
    /(?:cannot|can't|unable\s+to|failed\s+to|failure\s+(?:to|while|during)|error\s+(?:while|during))\s+(?:proceed\s+with\s+)?([^.;,)]+)/,
  )?.[1];
  if (actionPhrase === undefined) return undefined;
  const primary = PATH_OPERATIONS.find((candidate) =>
    new RegExp(`\\b${candidate}(?:ing|d|s)?\\b`).test(actionPhrase));
  return primary !== undefined && primary !== operation ? primary : undefined;
}

interface ScopedLoadOptions {
  cacheKey?: string;
  include?: (path: string) => boolean;
  limit?: number;
}

async function loadScopedSources(
  ctx: RuleContext,
  options: ScopedLoadOptions = {},
): Promise<ScopedSource[]> {
  const key = `nits.changed-line-sources:${options.cacheKey ?? "all"}`;
  const cached = ctx.cache.get(key);
  if (cached !== undefined) return cached as ScopedSource[];

  const loaded = await ctx.loadInScopeSources({
    include: options.include,
    limit: options.limit ?? 150,
  });
  const wholeTarget = ctx.change === null || ctx.change.scanMode === "all";
  const sources: ScopedSource[] = [];
  for (const source of loaded) {
    if (wholeTarget || source.status === "repository") {
      sources.push({
        path: source.path,
        content: source.content,
        previousContent: undefined,
        changedLines: new Set<number>(),
        status: "repository",
      });
      continue;
    }

    const change = await changedSource(ctx, source.path);
    sources.push({
      path: source.path,
      content: source.content,
      previousContent: change.previousContent,
      changedLines: change.changedLines,
      status: change.status,
    });
  }
  ctx.cache.set(key, sources);
  return sources;
}

function isEligibleLine(source: ScopedSource, line: number): boolean {
  return (
    source.status === "repository" ||
    source.status === "added" ||
    source.changedLines.has(line)
  );
}

function firstEligibleMatchLine(source: ScopedSource, expression: RegExp): number | undefined {
  const flags = expression.flags.includes("g") ? expression.flags : `${expression.flags}g`;
  const pattern = new RegExp(expression.source, flags);
  for (const match of source.content.matchAll(pattern)) {
    if (match.index === undefined) continue;
    const line = source.content.slice(0, match.index).split(/\r?\n/).length;
    if (isEligibleLine(source, line)) return line;
  }
  return undefined;
}

async function changedSource(
  ctx: RuleContext,
  path: string,
): Promise<Pick<ScopedSource, "changedLines" | "status" | "previousContent">> {
  const base = ctx.change?.baseRef;
  if (base === undefined || !(await existsAtRevision(ctx.repoPath, base, path))) {
    return { changedLines: new Set<number>(), status: "added", previousContent: undefined };
  }

  const args = ["diff", "--unified=0", base];
  const head = ctx.change?.headRef;
  if (head !== undefined && !ctx.change?.worktree) args.push(head);
  args.push("--", path);
  const patch = await gitOutput(ctx.repoPath, args);
  const previousContent = await gitOutput(ctx.repoPath, ["show", `${base}:${path}`]);
  return { changedLines: changedLineNumbers(patch), status: "modified", previousContent };
}

async function existsAtRevision(repoPath: string, revision: string, path: string): Promise<boolean> {
  try {
    await execute("git", ["-C", repoPath, "cat-file", "-e", `${revision}:${path}`], {
      maxBuffer: 1024 * 1024,
    });
    return true;
  } catch {
    return false;
  }
}

async function gitOutput(repoPath: string, args: string[]): Promise<string> {
  const result = await execute("git", ["-C", repoPath, ...args], {
    encoding: "utf8",
    maxBuffer: 8 * 1024 * 1024,
  });
  return result.stdout;
}

function changedLineNumbers(patch: string): Set<number> {
  const lines = new Set<number>();
  for (const match of patch.matchAll(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/gm)) {
    const start = Number(match[1]);
    const count = match[2] === undefined ? 1 : Number(match[2]);
    for (let line = start; line < start + count; line += 1) lines.add(line);
  }
  return lines;
}

function findErrorDomainMismatches(source: ScopedSource): ErrorDomainMismatch[] {
  const lines = source.content.split(/\r?\n/);
  const mismatches: ErrorDomainMismatch[] = [];

  for (let index = 0; index < lines.length; index++) {
    const lineNumber = index + 1;
    if (!source.changedLines.has(lineNumber) && source.status !== "added") continue;
    const line = lines[index] ?? "";
    const construction = errorConstructionAt(line);
    if (construction === undefined) continue;

    const scope = enclosingFunctionScope(lines, index);
    if (scope === undefined) continue;
    if (
      source.status === "modified" &&
      source.previousContent !== undefined &&
      previousScopeContainsConstruction(source.previousContent, scope.name, line)
    ) {
      continue;
    }
    const localStart = Math.max(scope.start, index - 7);
    const localEnd = Math.min(scope.end, index + 3);
    const localText = lines.slice(localStart, localEnd + 1).join("\n");
    if (COMPATIBILITY_MARKER.test(localText)) continue;

    const operation = nearestOperationSignal(lines, scope, index);
    const diagnostic = nearestDiagnosticSignal(lines, scope, index);
    const scopeSignal = domainSignal("scope", scope.start, scope.name, scope.name);
    if (
      diagnostic === undefined ||
      operation === undefined ||
      !hasErrorMappingRelationship(lines, scope.start, operation.line - 1, index)
    ) {
      continue;
    }

    const supporting = [operation, scopeSignal].filter(
      (signal): signal is DomainSignal => signal !== undefined,
    );
    const operationDomain = [...diagnostic.tokens]
      .filter((token) => supporting.some((signal) => signal.tokens.has(token)))
      .sort((left, right) => right.length - left.length || left.localeCompare(right))[0];
    if (operationDomain === undefined) continue;
    if (operation.tokens.size > 0 && !operation.tokens.has(operationDomain)) continue;

    const contextTokens = new Set(
      [diagnostic, ...supporting].flatMap((signal) => [...signal.tokens]),
    );
    const errorDomain = [...construction.tokens]
      .filter((token) => token !== operationDomain && !contextTokens.has(token))
      .sort((left, right) => right.length - left.length || left.localeCompare(right))[0];
    if (errorDomain === undefined) continue;

    const operationEvidence = supporting.find((signal) => signal.tokens.has(operationDomain));
    if (operationEvidence === undefined) continue;
    mismatches.push({
      errorName: construction.name,
      errorDomain,
      operationDomain,
      evidence: uniqueEvidence([
        { line: lineNumber, message: line.trim().slice(0, 180) },
        { line: operationEvidence.line, message: operationEvidence.message.slice(0, 180) },
        { line: diagnostic.line, message: diagnostic.message.slice(0, 180) },
      ]),
    });
  }

  return mismatches;
}

function errorConstructionAt(line: string): ErrorConstruction | undefined {
  const code = codeWithoutTrailingComment(line);
  if (code.trim() === "") return undefined;
  const syntax = maskStringLiterals(code);

  const qualified = syntax.match(
    /\b([A-Z][A-Za-z0-9_]*(?:Error|Exception))(?:::|\.)([A-Z][A-Za-z0-9_]*)\s*\(/,
  );
  if (qualified?.[2] !== undefined) {
    const name = `${qualified[1]}::${qualified[2]}`;
    return { name, tokens: domainTokens(qualified[2]) };
  }

  const constructed = syntax.match(/\b(?:new|raise)\s+([A-Z][A-Za-z0-9_]*(?:Error|Exception))\s*\(/);
  if (constructed?.[1] !== undefined) {
    const message = stringLiterals(code).join(" ");
    const tokens = domainTokens(message === "" ? constructed[1] : message);
    return { name: constructed[1], tokens };
  }

  const functional = syntax.match(
    /\b((?:fmt\.)?Errorf|errors?\.New|anyhow|bail|eyre)\s*!?\s*\(/,
  );
  if (functional?.[1] !== undefined) {
    const message = stringLiterals(code).join(" ");
    if (message === "") return undefined;
    return { name: functional[1], tokens: domainTokens(message) };
  }

  return undefined;
}

function maskStringLiterals(code: string): string {
  let result = "";
  let quote: string | undefined;
  let escaped = false;
  for (const character of code) {
    if (quote !== undefined) {
      result += " ";
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      result += " ";
    } else {
      result += character;
    }
  }
  return result;
}

function previousScopeContainsConstruction(
  previousContent: string,
  scopeName: string,
  currentLine: string,
): boolean {
  const semanticLine = codeWithoutTrailingComment(currentLine).trim();
  if (semanticLine === "") return true;
  const previousLines = previousContent.split(/\r?\n/);
  for (let index = 0; index < previousLines.length; index++) {
    const signature = functionNameAt(previousLines[index] ?? "");
    if (signature?.name !== scopeName) continue;
    const scope = enclosingFunctionScope(previousLines, index);
    if (scope === undefined || scope.start !== index) continue;
    if (
      previousLines
        .slice(scope.start, scope.end + 1)
        .some((line) => codeWithoutTrailingComment(line).trim() === semanticLine)
    ) {
      return true;
    }
  }
  return false;
}

function nearestOperationSignal(
  lines: string[],
  scope: { start: number; end: number; name: string },
  candidate: number,
): DomainSignal | undefined {
  for (let index = candidate - 1; index >= Math.max(scope.start, candidate - 6); index--) {
    const line = codeWithoutTrailingComment(lines[index] ?? "");
    if (DIAGNOSTIC_CALL.test(line) || errorConstructionAt(line) !== undefined) continue;
    if (!OPERATION_NAME.test(line)) continue;
    const identifiers = line.replace(/(["'`])(?:\\.|(?!\1).)*\1/g, " ");
    const signal = domainSignal("operation", index, line.trim(), identifiers);
    return signal;
  }
  return undefined;
}

function hasErrorMappingRelationship(
  lines: string[],
  scopeStart: number,
  operation: number,
  candidate: number,
): boolean {
  if (operation >= candidate) return false;
  const relationship = lines
    .slice(Math.max(scopeStart, operation), candidate + 1)
    .map(codeWithoutTrailingComment)
    .join("\n");
  return (
    /\b(?:map_err|inspect_err|or_else|catch|except|rescue|recover)\b/.test(relationship) ||
    /\b(?:if|unless)\b[^\n{:]*(?:err|error|exception|cause)\b[^\n]*[{:]?/i.test(
      relationship,
    )
  );
}

function nearestDiagnosticSignal(
  lines: string[],
  scope: { start: number; end: number; name: string },
  candidate: number,
): DomainSignal | undefined {
  const candidates: DomainSignal[] = [];
  for (
    let index = Math.max(scope.start, candidate - 3);
    index <= Math.min(scope.end, candidate + 2);
    index++
  ) {
    if (index === candidate) continue;
    const line = codeWithoutTrailingComment(lines[index] ?? "");
    if (!DIAGNOSTIC_CALL.test(line)) continue;
    const message = stringLiterals(line).join(" ");
    if (message === "") continue;
    const signal = domainSignal("diagnostic", index, line.trim(), message);
    if (signal.tokens.size > 0) candidates.push(signal);
  }
  return candidates.sort(
    (left, right) => Math.abs(left.line - candidate) - Math.abs(right.line - candidate),
  )[0];
}

function domainSignal(
  kind: DomainSignal["kind"],
  zeroBasedLine: number,
  message: string,
  tokenSource: string,
): DomainSignal {
  return { kind, line: zeroBasedLine + 1, message, tokens: domainTokens(tokenSource) };
}

function domainTokens(value: string): Set<string> {
  const words = value
    .replace(/([a-z0-9])([A-Z])/g, "$1 $2")
    .replace(/([A-Z]+)([A-Z][a-z])/g, "$1 $2")
    .toLowerCase()
    .match(/[a-z][a-z0-9]*/g) ?? [];
  return new Set(
    words
      .map((word) => singularDomainWord(word))
      .filter((word) => word.length >= 4 && !DOMAIN_STOP_WORDS.has(word)),
  );
}

function singularDomainWord(word: string): string {
  if (word.length > 5 && word.endsWith("ies")) return `${word.slice(0, -3)}y`;
  if (word.length > 5 && word.endsWith("s") && !word.endsWith("ss")) return word.slice(0, -1);
  return word;
}

function stringLiterals(code: string): string[] {
  const values: string[] = [];
  for (const match of code.matchAll(/(["'`])((?:\\.|(?!\1).)*)\1/g)) {
    if (match[2] !== undefined) values.push(match[2].replace(/\\[nrt]/g, " "));
  }
  return values;
}

function codeWithoutTrailingComment(line: string): string {
  let quote: string | undefined;
  let escaped = false;
  for (let index = 0; index < line.length - 1; index++) {
    const character = line[index];
    if (quote !== undefined) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === quote) quote = undefined;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") {
      quote = character;
      continue;
    }
    if (character === "/" && line[index + 1] === "/") return line.slice(0, index);
    if (character === "#" && (index === 0 || /\s/.test(line[index - 1] ?? ""))) {
      return line.slice(0, index);
    }
  }
  return line;
}

function enclosingFunctionScope(
  lines: string[],
  candidate: number,
): { start: number; end: number; name: string } | undefined {
  for (let start = candidate; start >= Math.max(0, candidate - 80); start--) {
    const signature = functionNameAt(lines[start] ?? "");
    if (signature === undefined) continue;
    if (signature.python) {
      const indentation = (lines[start] ?? "").match(/^\s*/)?.[0].length ?? 0;
      let end = lines.length - 1;
      for (let index = start + 1; index < lines.length; index++) {
        const line = lines[index] ?? "";
        if (line.trim() === "") continue;
        const current = line.match(/^\s*/)?.[0].length ?? 0;
        if (current <= indentation) {
          end = index - 1;
          break;
        }
      }
      if (candidate <= end) return { start, end, name: signature.name };
      continue;
    }

    const end = bracedScopeEnd(lines, start);
    if (end !== undefined && candidate <= end) return { start, end, name: signature.name };
  }
  return undefined;
}

function functionNameAt(line: string): { name: string; python: boolean } | undefined {
  const code = codeWithoutTrailingComment(line);
  const rust = code.match(/\bfn\s+([A-Za-z_]\w*)\s*(?:<[^>]*>)?\s*\(/);
  if (rust?.[1] !== undefined) return { name: rust[1], python: false };
  const go = code.match(/\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)\s*\(/);
  if (go?.[1] !== undefined) return { name: go[1], python: false };
  const named = code.match(/\bfunction\s+([A-Za-z_$][\w$]*)\s*\(/);
  if (named?.[1] !== undefined) return { name: named[1], python: false };
  const python = code.match(/^\s*(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(/);
  if (python?.[1] !== undefined) return { name: python[1], python: true };
  const method = code.match(
    /^\s*(?:pub(?:\([^)]*\))?\s+|private\s+|protected\s+|public\s+|static\s+|async\s+)*(?:[A-Za-z_$][\w$<>:[\],.?&* ]+\s+)?([A-Za-z_$][\w$]*)\s*\([^;]*\)\s*(?:[^;{]*)\{/,
  );
  if (method?.[1] !== undefined && !/^(?:if|for|while|switch|catch|match)$/.test(method[1])) {
    return { name: method[1], python: false };
  }
  return undefined;
}

function bracedScopeEnd(lines: string[], start: number): number | undefined {
  let depth = 0;
  let opened = false;
  for (let index = start; index < lines.length; index++) {
    const code = codeWithoutTrailingComment(lines[index] ?? "").replace(
      /(["'`])(?:\\.|(?!\1).)*\1/g,
      "",
    );
    for (const character of code) {
      if (character === "{") {
        depth++;
        opened = true;
      } else if (character === "}" && opened) {
        depth--;
        if (depth === 0) return index;
      }
    }
    if (!opened && index > start + 5) return undefined;
  }
  return undefined;
}

function uniqueEvidence(
  evidence: Array<{ line: number; message: string }>,
): Array<{ line: number; message: string }> {
  const seen = new Set<number>();
  return evidence.filter((item) => {
    if (seen.has(item.line)) return false;
    seen.add(item.line);
    return true;
  });
}

function isReviewableImplementationPath(path: string): boolean {
  const normalized = path.replace(/\\/g, "/").toLowerCase();
  return /\.(?:c|cc|cpp|cs|go|java|js|jsx|kt|kts|m|mm|php|py|rb|rs|swift|ts|tsx)$/.test(
    normalized,
  );
}

function shouldSkipErrorDomainPath(path: string): boolean {
  const normalized = `/${path.replace(/\\/g, "/").toLowerCase()}`;
  return (
    shouldSkipPath(path) ||
    /\/(?:fixtures?|testdata|tests?|__tests__|spec|specs|vendor|vendors|generated|gen|mocks?|snapshots?)\//.test(
      normalized,
    ) ||
    /(?:^|\/)(?:generated|mock)[^/]*\.[^/]+$/.test(normalized) ||
    /(?:_test\.go|\.(?:test|spec)\.[cm]?[jt]sx?)$/.test(normalized)
  );
}

function rel(ctx: { relpath?: (p: string) => string }, path: string): string {
  return ctx.relpath ? ctx.relpath(path) : path;
}

function shouldSkipPath(path: string): boolean {
  const p = path.replace(/\\/g, "/");
  return (
    p.includes("/.git/") ||
    p.includes("node_modules/") ||
    p.includes("/dist/") ||
    p.endsWith(".gitkeep") ||
    p.endsWith("package-lock.json")
  );
}

interface IndentationOutlier {
  line: number;
  actual: number;
  expected: number;
  text: string;
}

function isDockerfilePath(path: string): boolean {
  const name = path.replace(/\\/g, "/").split("/").at(-1)?.toLowerCase() ?? "";
  return name === "dockerfile" || name.startsWith("dockerfile.") || name.endsWith(".dockerfile");
}

function findDockerfileRunIndentationOutliers(content: string): IndentationOutlier[] {
  const lines = content.split("\n");
  const outliers: IndentationOutlier[] = [];

  for (let runLine = 0; runLine < lines.length; runLine++) {
    const first = lines[runLine] ?? "";
    if (!/^\s*RUN\b/i.test(first) || !hasLineContinuation(first)) continue;

    let end = runLine;
    while (end + 1 < lines.length && hasLineContinuation(lines[end] ?? "")) end++;
    if (end - runLine < 3) {
      runLine = end;
      continue;
    }

    const block = lines.slice(runLine, end + 1);
    if (isStructurallyIndentedRunBlock(block)) {
      runLine = end;
      continue;
    }

    for (let current = runLine + 2; current < end; current++) {
      const previous = lines[current - 1] ?? "";
      const line = lines[current] ?? "";
      const next = lines[current + 1] ?? "";
      if (
        previous.trim() === "" ||
        line.trim() === "" ||
        next.trim() === "" ||
        /^\s*#/.test(line) ||
        /^[ \t]*\t/.test(previous) ||
        /^[ \t]*\t/.test(line) ||
        /^[ \t]*\t/.test(next)
      ) {
        continue;
      }

      const expected = leadingSpaces(previous);
      const actual = leadingSpaces(line);
      if (
        expected === 0 ||
        leadingSpaces(next) !== expected ||
        Math.abs(actual - expected) !== 1
      ) {
        continue;
      }

      outliers.push({ line: current + 1, actual, expected, text: line });
    }
    runLine = end;
  }

  return outliers;
}

function hasLineContinuation(line: string): boolean {
  return /\\\s*$/.test(line);
}

function leadingSpaces(line: string): number {
  return line.match(/^ */)?.[0].length ?? 0;
}

function isStructurallyIndentedRunBlock(lines: string[]): boolean {
  if (lines.some((line) => line.includes("<<"))) return true;

  return lines.some((line) => {
    const shell = line.trim().replace(/^(?:&&|\|\|)\s*/, "");
    return /^(?:if|then|elif|else|fi|for|while|until|case|esac|select|do|done)\b/.test(shell) ||
      /^[({]/.test(shell);
  });
}

function isCommentish(line: string, path: string): boolean {
  const t = line.trim();
  if (t.startsWith("//") || t.startsWith("#") || t.startsWith("*") || t.startsWith("/*")) {
    return true;
  }
  if (path.endsWith(".md")) return true;
  return /\/\/.*\b(TODO|FIXME|XXX|HACK)\b/i.test(line);
}

function findMaskingGuarantees(path: string, content: string): MaskingGuarantee[] {
  const guarantees: MaskingGuarantee[] = [];
  const signature = /(?:^|\n)[^\n{};]*?\b([A-Za-z_]\w*)\s*\(([^()\n]*)\)\s*(?:[^\n{]*)\{/g;
  const controlWords = new Set(["catch", "for", "if", "switch", "while"]);

  for (const match of content.matchAll(signature)) {
    const recorder = match[1];
    const parameters = match[2];
    if (
      recorder === undefined ||
      parameters === undefined ||
      controlWords.has(recorder) ||
      !RECORDER_NAME.test(recorder)
    ) {
      continue;
    }

    const open = (match.index ?? 0) + match[0].lastIndexOf("{");
    const end = matchingBrace(content, open);
    if (end === undefined) continue;
    const body = content.slice(open + 1, end);
    const parameterNames = extractParameterNames(parameters, path);
    const call = /\b(?:[A-Za-z_]\w*\.)*([A-Za-z_]\w*)\s*\(([^()\n]*)\)/g;

    for (const sanitizerCall of body.matchAll(call)) {
      const sanitizer = sanitizerCall[1];
      const args = sanitizerCall[2];
      const sanitizerOffset = sanitizerCall.index ?? 0;
      const sanitizerLine = body.slice(0, sanitizerOffset).split("\n").length;
      const line = body.split("\n")[sanitizerLine - 1] ?? "";
      if (
        sanitizer === undefined ||
        args === undefined ||
        !SECRET_MASKER_NAME.test(sanitizer) ||
        !parameterNames.some((parameter) =>
          new RegExp(`\\b${escapeRegex(parameter)}\\b`).test(args),
        ) ||
        !isTopLevelNestedCall(body, sanitizerOffset, line, sanitizer)
      ) {
        continue;
      }
      const sourceLine = content.slice(0, open + 1).split("\n").length + sanitizerLine - 1;
      guarantees.push({ recorder, sanitizer, path, line: sourceLine, start: open, end });
    }
  }

  return guarantees;
}

function isTopLevelNestedCall(
  body: string,
  sanitizerOffset: number,
  line: string,
  sanitizer: string,
): boolean {
  const prefix = body.slice(0, sanitizerOffset);
  const depth = [...prefix].reduce(
    (value, character) => value + (character === "{" ? 1 : character === "}" ? -1 : 0),
    0,
  );
  if (depth !== 0) return false;

  const beforeSanitizer = line.slice(0, line.search(new RegExp(`\\b${escapeRegex(sanitizer)}\\b`)));
  return /\b[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*\s*\([^;]*$/.test(beforeSanitizer);
}

function extractParameterNames(parameters: string, path: string): string[] {
  return parameters
    .split(",")
    .map((parameter) => parameter.trim().split("=")[0]?.trim() ?? "")
    .map((parameter) => {
      const beforeType = parameter.split(":")[0]?.trim() ?? "";
      const identifiers = beforeType.match(/[A-Za-z_]\w*/g) ?? [];
      if (path.endsWith(".go")) return identifiers[0];
      return identifiers.at(-1);
    })
    .filter((parameter): parameter is string => parameter !== undefined);
}

function matchingBrace(content: string, open: number): number | undefined {
  let depth = 0;
  for (let i = open; i < content.length; i++) {
    if (content[i] === "{") depth++;
    if (content[i] === "}") depth--;
    if (depth === 0) return i + 1;
  }
  return undefined;
}

function containsNestedMaskingCall(line: string, guarantee: MaskingGuarantee): boolean {
  const recorder = escapeRegex(guarantee.recorder);
  const sanitizer = escapeRegex(guarantee.sanitizer);
  return new RegExp(`\\b${recorder}\\s*\\([^;\\n]*\\b${sanitizer}\\s*\\(`).test(line);
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

const app = createApp();
export default app;

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await app.runFromEnvironment();
}
