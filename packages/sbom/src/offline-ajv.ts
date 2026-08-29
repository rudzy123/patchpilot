import ajvModule from 'ajv';
import addFormatsModule from 'ajv-formats';
import type { Options } from 'ajv';
import type { FormatsPlugin } from 'ajv-formats';

import { isSyntacticIdnEmail, isSyntacticIriReference } from './formats.js';

type AjvConstructor = new (options?: Options) => import('ajv').default;
export type OfflineAjv = InstanceType<AjvConstructor>;

const AJV_FORMATS_REQUIRED_BY_VENDORED_SCHEMAS = ['date-time', 'uri'] as const;

function asConstructor(mod: unknown): AjvConstructor {
  if (typeof mod === 'function') {
    return mod as AjvConstructor;
  }
  if (
    typeof mod === 'object' &&
    mod !== null &&
    'default' in mod &&
    typeof mod.default === 'function'
  ) {
    return mod.default as AjvConstructor;
  }
  throw new Error('Ajv constructor was not found.');
}

function asFormatsPlugin(mod: unknown): FormatsPlugin {
  if (typeof mod === 'function') {
    return mod as FormatsPlugin;
  }
  if (
    typeof mod === 'object' &&
    mod !== null &&
    'default' in mod &&
    typeof mod.default === 'function'
  ) {
    return mod.default as FormatsPlugin;
  }
  throw new Error('ajv-formats plugin was not found.');
}

const Ajv = asConstructor(ajvModule);
const addFormats = asFormatsPlugin(addFormatsModule);

export function createOfflineAjv(): OfflineAjv {
  const ajv = new Ajv({
    strict: true,
    // Official CycloneDX JSON schemas omit `type: object` beside `required` and
    // place required properties behind $ref/oneOf. Ajv's extra schema-authoring
    // checks reject that shape; instance validation stays strict.
    strictRequired: false,
    strictTypes: false,
    $data: false,
    coerceTypes: false,
    useDefaults: false,
    removeAdditional: false,
    allErrors: false,
    validateFormats: true,
  });

  if (typeof ajv.opts.loadSchema === 'function') {
    throw new Error('Ajv loadSchema must not be configured; missing $ref values fail closed.');
  }

  addFormats(ajv, {
    formats: [...AJV_FORMATS_REQUIRED_BY_VENDORED_SCHEMAS],
    keywords: false,
  });
  ajv.addKeyword({ keyword: 'meta:enum', schemaType: 'object' });
  ajv.addFormat('iri-reference', {
    type: 'string',
    validate: isSyntacticIriReference,
  });
  ajv.addFormat('idn-email', {
    type: 'string',
    validate: isSyntacticIdnEmail,
  });

  return ajv;
}
