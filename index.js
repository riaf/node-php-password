'use strict';

const bcrypt = require('bcrypt');

const PASSWORD_BCRYPT = 1;
const PASSWORD_DEFAULT = PASSWORD_BCRYPT;

const BCRYPT_IDENTIFIERS = new Set(['$2a$', '$2b$', '$2x$', '$2y$']);

exports.get_info = get_info;
exports.hash = hash;
exports.needs_rehash = needs_rehash;
exports.verify = verify;
exports.password_get_info = get_info;
exports.password_hash = hash;
exports.password_needs_rehash = needs_rehash;
exports.password_verify = verify;
exports.password_algos = password_algos;
exports.PASSWORD_DEFAULT = PASSWORD_DEFAULT;
exports.PASSWORD_BCRYPT = PASSWORD_BCRYPT;

function normalizeOptions(options) {
  return {
    cost: 10,
    ...options,
  };
}

function get_info(hash) {
  const info = {
    algo: 0,
    algoName: 'unknown',
    options: {},
  };

  if (typeof hash !== 'string') {
    return info;
  }

  const prefix = hash.slice(0, 4);
  if (BCRYPT_IDENTIFIERS.has(prefix) && hash.length === 60) {
    info.algo = PASSWORD_BCRYPT;
    info.algoName = 'bcrypt';
    info.options.cost = Number.parseInt(hash.slice(4, 6), 10);
  }

  return info;
}

function resolveAlgo(algo) {
  if (algo === undefined || algo === null) {
    return PASSWORD_DEFAULT;
  }

  if (algo === PASSWORD_BCRYPT || algo === '2y' || algo === 'bcrypt') {
    return PASSWORD_BCRYPT;
  }

  return algo;
}

function hash(password, algo, options) {
  const resolvedAlgo = resolveAlgo(algo);
  const normalizedOptions = normalizeOptions(options);

  switch (resolvedAlgo) {
    case PASSWORD_BCRYPT: {
      if (!Number.isInteger(normalizedOptions.cost) || normalizedOptions.cost < 4 || normalizedOptions.cost > 31) {
        throw new Error(`Invalid bcrypt cost parameter specified: ${normalizedOptions.cost}`);
      }

      return bcrypt.hashSync(password, normalizedOptions.cost);
    }

    default:
      throw new Error(`Unknown password hashing algorithm: ${resolvedAlgo}`);
  }
}

function needs_rehash(passwordHash, algo, options) {
  const resolvedAlgo = resolveAlgo(algo);
  const info = get_info(passwordHash);
  const normalizedOptions = normalizeOptions(options);

  if (info.algo !== resolvedAlgo) {
    return true;
  }

  switch (resolvedAlgo) {
    case PASSWORD_BCRYPT:
      return info.options.cost !== normalizedOptions.cost;
    default:
      return true;
  }
}

function verify(password, passwordHash) {
  const info = get_info(passwordHash);
  if (info.algo !== PASSWORD_BCRYPT) {
    return false;
  }

  // bcrypt on Node.js accepts $2a$/$2b$, but PHP can emit $2y$.
  const comparableHash = passwordHash.startsWith('$2y$')
    ? `$2b$${passwordHash.slice(4)}`
    : passwordHash;

  return bcrypt.compareSync(password, comparableHash);
}

function password_algos() {
  return ['2y'];
}
