node-php-password
=================

Compatibility helpers for PHP `password_*` functions on modern Node.js.

## Requirements

- Node.js 20+

## Installation

```sh
npm install php-password
```

## Usage

```javascript
const phpPassword = require('php-password');

const password = 'passw0rd';
const hashedPassword = phpPassword.password_hash(password, phpPassword.PASSWORD_DEFAULT, { cost: 10 });

if (phpPassword.password_verify(password, hashedPassword)) {
  console.log('Success');
}

const info = phpPassword.password_get_info(hashedPassword);
console.log(info);
```

## Supported API

- `hash` / `password_hash`
- `verify` / `password_verify`
- `get_info` / `password_get_info`
- `needs_rehash` / `password_needs_rehash`
- `password_algos`
- `PASSWORD_DEFAULT`
- `PASSWORD_BCRYPT`

## Development

```sh
npm test
npm run lint
```
