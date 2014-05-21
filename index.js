var bcrypt = require('bcrypt')
  , _ = require('lodash')
  , PASSWORD_BCRYPT = 1
  , PASSWORD_DEFAULT = PASSWORD_BCRYPT;

exports.get_info = get_info;
exports.hash = hash;
exports.needs_rehash = needs_rehash;
exports.verify = verify;
exports.PASSWORD_DEFAULT = PASSWORD_DEFAULT;
exports.PASSWORD_BCRYPT = PASSWORD_BCRYPT;

/**
 * Returns information about the given hash
 *
 * @param {string} hash - A hash created by hash (password_hash).
 * @return {object} - Returns an object with three elements (algo, algoName, options).
 */
function get_info(hash) {
  var info = {
    algo: 0,
    algoName: 'unknown',
    options: {}
  };

  if (_.contains(['$2a$', '$2x$', '$2y$'], hash.substring(0, 4)) && hash.length === 60) {
    info.algo = PASSWORD_BCRYPT;
    info.algoName = 'bcrypt';
    info.options.cost = parseInt(hash.substring(4, 2), 10);
  }

  return info;
}

/**
 * Creates a password hash
 *
 * @param {string} password - The user's password.
 * @param {integer} algo - A password algorithm constant denoting the algorithm to use when hashing the password.
 * @param {object} options - An associative array containing options.
 * @return {string}
 */
function hash(password, algo, options) {
  var salt
    , hashedPassword
    , algo = algo || PASSWORD_DEFAULT
    , options = _.assign({ cost: 10, salt: null }, options);

  switch (algo) {
    case PASSWORD_BCRYPT:
      if (options.cost < 4 || options.cost > 31) {
        throw new Error("Invalid bcrypt cost parameter specified: " + options.cost);
      }

      salt = options.salt || bcrypt.genSaltSync(options.cost);
      hashedPassword = bcrypt.hashSync(password, salt);

      break;

    default:
      throw new Error("Unknown password hashing algorithm: " + algo);
  }

  return hashedPassword;
}

/**
 * Checks if the given hash matches the given options
 *
 * @param {string} hash - A hash created by hash (password_hash).
 * @param {integer} algo - A password algorithm constant denoting the algorithm to use when hashing the password.
 * @param {object} options - An associative array containing options.
 */
function needs_rehash(hash, algo, options) {
  var info = get_info(hash)
    , options = _.assign({ cost: 10, salt: null }, options);

  if (info.algo !== algo) {
    return true;
  }

  switch (algo) {
    case PASSWORD_BCRYPT:
      if (info.options.cost !== options.cost) {
        return true;
      }
      break;
  }

  return false;
}

/**
 * Verifies that a password matches a hash
 *
 * @param {string} password - The user's password.
 * @param {string} hash - A hash created by hash (password_hash).
 */
function verify(password, hash) {
  var info = get_info(hash);

  if (info.algo === PASSWORD_BCRYPT) {
    hash = '$2a$' + hash.substring(4);
  }

  return bcrypt.compareSync(password, hash);
}
