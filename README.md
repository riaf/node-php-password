node-php-password
=================

Compatibility with the password_* functions on PHP


Installation
------------

```sh
$ npm install php-password
```


Usage
-----

```javascript
var phpPassword = require('php-password');

// Example password
var password = 'passw0rd';

// Create hashed password
var hashedPassword = phpPassword.hash(password);

// Verify the password
if (phpPassword.verify(password, hashedPassword)) {
  console.log('Success');
} else {
  console.log('Failed');
}
```
