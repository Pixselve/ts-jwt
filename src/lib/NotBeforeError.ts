// var JsonWebTokenError = require('./JsonWebTokenError');
//
// var NotBeforeError = function (message, date) {
//   JsonWebTokenError.call(this, message);
//   this.name = 'NotBeforeError';
//   this.date = date;
// };
//
// NotBeforeError.prototype = Object.create(JsonWebTokenError.prototype);
//
// NotBeforeError.prototype.constructor = NotBeforeError;
//
// module.exports = NotBeforeError;

import JsonWebTokenError from "./JsonWebTokenError";

export class NotBeforeError extends JsonWebTokenError {
  constructor(message: string, public date: Date) {
    super(message);
    this.name = "NotBeforeError"
  }
}
