// module.exports = {
//   verify: require('./verify'),
//   sign: require('./sign'),
//   JsonWebTokenError: require('./lib/JsonWebTokenError'),
//   NotBeforeError: require('./lib/NotBeforeError'),
//   TokenExpiredError: require('./lib/TokenExpiredError'),
// };
//
// Object.defineProperty(module.exports, 'decode', {
//   enumerable: false,
//   value: require('./decode'),
// });

import { decode } from "./decode";
import JsonWebTokenError from "./lib/JsonWebTokenError";
import { NotBeforeError } from "./lib/NotBeforeError";
import { TokenExpiredError } from "./lib/TokenExpiredError";
import { sign } from "./sign";
import { verify } from "./verify";

export { sign, verify, decode, JsonWebTokenError, NotBeforeError, TokenExpiredError };
