import { Ajv2020, type ValidateFunction } from 'ajv/dist/2020.js';
import file from '../types/file.json' with { type: 'json' };
import profile from '../types/profile.json' with { type: 'json' };
import scape from '../types/scape.json' with { type: 'json' };

/** The JSON Schemas of the core record types, by type name. */
export const coreTypeSchemas: Record<string, object> = { profile, file, scape };

const ajv = new Ajv2020({ allErrors: false, strict: true });
const validators = new Map<string, ValidateFunction>(
  Object.entries(coreTypeSchemas).map(([type, schema]) => [type, ajv.compile(schema)]),
);

export function isCoreType(type: string): boolean {
  return validators.has(type);
}

/** `null` when the body is valid (or the type is not a known core type), otherwise the first problem. */
export function bodyProblem(type: string, body: unknown): string | null {
  const validate = validators.get(type);
  if (validate === undefined || validate(body)) return null;
  const error = validate.errors?.[0];
  return error ? `${error.instancePath || '/'} ${error.message ?? 'is invalid'}` : 'is invalid';
}
