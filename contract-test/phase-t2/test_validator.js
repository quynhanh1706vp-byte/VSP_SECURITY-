// Meta-tests for vsp_schema_validator.js
// Run: node test_validator.js

'use strict';

// Try both layouts: same folder OR parent folder (when run from phase-t2/)
const fs = require('fs');
const path = require('path');
let validatorPath = './vsp_schema_validator';
if (!fs.existsSync(path.join(__dirname, 'vsp_schema_validator.js'))) {
  validatorPath = '../vsp_schema_validator';
}
const { validate } = require(validatorPath);

let passed = 0, failed = 0;
function assert(label, cond, detail='') {
  if (cond) { passed++; console.log('  ✓ ' + label); }
  else      { failed++; console.log('  ✗ ' + label + (detail ? ' — ' + detail : '')); }
}
function assertValid(label, value, schema, root={}) {
  const errs = validate(value, schema, root);
  assert(label, errs.length === 0, errs.join('; '));
}
function assertInvalid(label, value, schema, expectedSubstr, root={}) {
  const errs = validate(value, schema, root);
  if (errs.length === 0) {
    failed++;
    console.log('  ✗ ' + label + ' — expected error containing "' + expectedSubstr + '" but got no errors');
    return;
  }
  const found = errs.some(e => e.includes(expectedSubstr));
  if (found) { passed++; console.log('  ✓ ' + label); }
  else {
    failed++;
    console.log('  ✗ ' + label + ' — errors did not contain "' + expectedSubstr + '". Got: ' + errs.join(' | '));
  }
}

// ─── Type ───────────────────────────────────────────────────────────────────
console.log('\n── type ──');
assertValid('string accepts string', 'hello', { type: 'string' });
assertInvalid('string rejects number', 42, { type: 'string' }, 'expected string');
assertValid('integer accepts 5', 5, { type: 'integer' });
assertInvalid('integer rejects 5.5', 5.5, { type: 'integer' }, 'expected integer');
assertValid('number accepts 5.5', 5.5, { type: 'number' });
assertValid('boolean accepts true', true, { type: 'boolean' });
assertValid('array accepts []', [], { type: 'array' });
assertInvalid('array rejects {}', {}, { type: 'array' }, 'expected array');
assertValid('object accepts {}', {}, { type: 'object' });

// ─── Null / nullable ────────────────────────────────────────────────────────
console.log('\n── nullable ──');
assertValid('nullable:true accepts null', null, { type: 'string', nullable: true });
assertInvalid('null rejected without nullable', null, { type: 'string' }, 'null but type');

// ─── Enum ───────────────────────────────────────────────────────────────────
console.log('\n── enum ──');
assertValid('enum accepts member', 'PASS', { type: 'string', enum: ['PASS','FAIL'] });
assertInvalid('enum rejects non-member', 'URGENT', { type: 'string', enum: ['CRITICAL','HIGH'] }, 'not in enum');

// ─── Required ───────────────────────────────────────────────────────────────
console.log('\n── required ──');
assertValid('required all present', { id:1, name:'x' }, { type:'object', required:['id','name'] });
assertInvalid('required missing field',
  { id: 1 },
  { type: 'object', required: ['id', 'name'] },
  "missing required property 'name'");

// ─── Properties ─────────────────────────────────────────────────────────────
console.log('\n── properties ──');
assertValid('property type matches',
  { age: 30 },
  { type: 'object', properties: { age: { type: 'integer' } } });
assertInvalid('property type mismatch',
  { age: 'thirty' },
  { type: 'object', properties: { age: { type: 'integer' } } },
  'age: expected integer');

// ─── Nested objects ─────────────────────────────────────────────────────────
console.log('\n── nested ──');
assertValid('nested ok', { user: { id: 'u1' } }, {
  type: 'object',
  properties: { user: { type: 'object', required: ['id'], properties: { id: { type: 'string' } } } }
});
assertInvalid('nested required missing',
  { user: {} },
  { type: 'object', properties: { user: { type: 'object', required: ['id'] } } },
  '$.user: missing required');

// ─── Arrays ─────────────────────────────────────────────────────────────────
console.log('\n── arrays ──');
assertValid('array of strings', ['a','b'], { type: 'array', items: { type: 'string' } });
assertInvalid('array element type mismatch',
  ['a', 2],
  { type: 'array', items: { type: 'string' } },
  '$[1]: expected string');
assertValid('array of objects', [{ id: 1 }], {
  type: 'array', items: { type: 'object', required: ['id'], properties: { id: { type: 'integer' } } }
});

// ─── String constraints ─────────────────────────────────────────────────────
console.log('\n── string constraints ──');
assertValid('minLength ok', 'hello', { type: 'string', minLength: 3 });
assertInvalid('minLength fail', 'hi', { type: 'string', minLength: 3 }, 'minLength');
assertValid('pattern ok', '123456', { type: 'string', pattern: '^[0-9]{6}$' });
assertInvalid('pattern fail', '12abc', { type: 'string', pattern: '^[0-9]{6}$' }, 'pattern');

// ─── Number constraints ─────────────────────────────────────────────────────
console.log('\n── number constraints ──');
assertValid('minimum ok', 50, { type: 'integer', minimum: 0, maximum: 100 });
assertInvalid('minimum fail', -1, { type: 'integer', minimum: 0 }, 'minimum');
assertInvalid('maximum fail', 101, { type: 'integer', maximum: 100 }, 'maximum');

// ─── Format ─────────────────────────────────────────────────────────────────
console.log('\n── format ──');
assertValid('email ok', 'a@b.com', { type: 'string', format: 'email' });
assertInvalid('email fail', 'not-an-email', { type: 'string', format: 'email' }, 'email');
assertValid('uuid ok', 'a1b2c3d4-5678-9abc-def0-123456789012', { type: 'string', format: 'uuid' });
assertInvalid('uuid fail', 'not-uuid', { type: 'string', format: 'uuid' }, 'uuid');
assertValid('date-time ok', '2026-04-28T10:30:00Z', { type: 'string', format: 'date-time' });
assertInvalid('date-time fail', 'yesterday', { type: 'string', format: 'date-time' }, 'date-time');

// ─── $ref ───────────────────────────────────────────────────────────────────
console.log('\n── $ref ──');
const root = {
  components: {
    schemas: {
      Run: {
        type: 'object',
        required: ['id', 'status'],
        properties: {
          id:     { type: 'string' },
          status: { type: 'string', enum: ['QUEUED','RUNNING','DONE'] }
        }
      }
    }
  }
};
assertValid('ref resolution',
  { id: 'r1', status: 'DONE' },
  { $ref: '#/components/schemas/Run' },
  root);
assertInvalid('ref + enum violation',
  { id: 'r1', status: 'WHATEVER' },
  { $ref: '#/components/schemas/Run' },
  'not in enum',
  root);

// ─── oneOf / allOf / anyOf ──────────────────────────────────────────────────
console.log('\n── oneOf / allOf / anyOf ──');
assertValid('oneOf string OR number — string',
  'hi',
  { oneOf: [{ type: 'string' }, { type: 'number' }] });
assertValid('oneOf string OR number — number',
  42,
  { oneOf: [{ type: 'string' }, { type: 'number' }] });
assertInvalid('oneOf neither',
  true,
  { oneOf: [{ type: 'string' }, { type: 'number' }] },
  'matches none');

// allOf composition
assertValid('allOf composes required',
  { a: 1, b: 'x' },
  { allOf: [
    { type: 'object', required: ['a'], properties: { a: { type: 'integer' } } },
    { type: 'object', required: ['b'], properties: { b: { type: 'string' } } }
  ]});
assertInvalid('allOf: missing from second',
  { a: 1 },
  { allOf: [
    { type: 'object', required: ['a'] },
    { type: 'object', required: ['b'] }
  ]},
  "missing required property 'b'");

// ─── additionalProperties ───────────────────────────────────────────────────
console.log('\n── additionalProperties ──');
assertInvalid('additionalProperties:false rejects extra',
  { id: 1, secret: 'leak' },
  { type: 'object', additionalProperties: false, properties: { id: { type: 'integer' } } },
  "unexpected property 'secret'");
assertValid('additionalProperties: schema validates extras',
  { known: 1, extra1: 'a', extra2: 'b' },
  {
    type: 'object',
    properties: { known: { type: 'integer' } },
    additionalProperties: { type: 'string' }
  });
assertInvalid('additionalProperties: schema rejects bad extras',
  { known: 1, extra: 99 },
  {
    type: 'object',
    properties: { known: { type: 'integer' } },
    additionalProperties: { type: 'string' }
  },
  'extra: expected string');

// ─── Real-world: VSP Run schema ─────────────────────────────────────────────
console.log('\n── real VSP Run schema ──');
const vspRoot = {
  components: { schemas: {
    Run: {
      type: 'object',
      required: ['id', 'mode', 'status'],
      properties: {
        id:     { type: 'string', format: 'uuid' },
        mode:   { type: 'string', enum: ['SAST','DAST','SCA','SECRETS','IAC','FULL','FULL_SOC'] },
        status: { type: 'string', enum: ['QUEUED','RUNNING','DONE','FAILED','CANCELLED'] },
        gate:   { type: 'string', enum: ['PASS','WARN','FAIL'] },
        score:  { type: 'number' },
      }
    }
  }}
};
assertValid('valid Run',
  {
    id: 'a1b2c3d4-5678-9abc-def0-123456789012',
    mode: 'SAST',
    status: 'DONE',
    gate: 'PASS',
    score: 95.5
  },
  { $ref: '#/components/schemas/Run' },
  vspRoot);
assertInvalid('Run: invalid mode enum',
  { id: 'a1b2c3d4-5678-9abc-def0-123456789012', mode: 'WHATEVER', status: 'DONE' },
  { $ref: '#/components/schemas/Run' },
  'not in enum',
  vspRoot);
assertInvalid('Run: invalid uuid format',
  { id: 'not-a-uuid', mode: 'SAST', status: 'DONE' },
  { $ref: '#/components/schemas/Run' },
  'uuid',
  vspRoot);

console.log(`\n=== ${passed} passed, ${failed} failed ===`);
process.exit(failed > 0 ? 1 : 0);
