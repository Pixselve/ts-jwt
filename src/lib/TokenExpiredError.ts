// var JsonWebTokenError = require('./JsonWebTokenError');
//
// var TokenExpiredError = function (message, expiredAt) {
//   JsonWebTokenError.call(this, message);
//   this.name = 'TokenExpiredError';
//   this.expiredAt = expiredAt;
// };
//
// TokenExpiredError.prototype = Object.create(JsonWebTokenError.prototype);
//
// TokenExpiredError.prototype.constructor = TokenExpiredError;
//
// module.exports = TokenExpiredError;


import JsonWebTokenError from "./JsonWebTokenError";

export class TokenExpiredError extends JsonWebTokenError {
  constructor(message: string, public expiredAt: Date) {
    super(message);
  }
}
