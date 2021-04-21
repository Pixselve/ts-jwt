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

export * from "./decode"
export * from "./types"
export * from "./verify"
export * from "./sign"
export * from "./lib/JsonWebTokenError"
export * from "./lib/NotBeforeError"
export * from "./lib/TokenExpiredError"
