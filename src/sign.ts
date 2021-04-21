import { Algorithm, Secret } from "./types";
import timespan from "./lib/timespan";
import jws from "jws";
import PS_SUPPORTED from "./lib/psSupported";

import includes from "lodash.includes";
import isBoolean from "lodash.isboolean";
import isInteger from "lodash.isinteger";
import isNumber from "lodash.isnumber";
import isPlainObject from "lodash.isplainobject";
import isString from "lodash.isstring";
import once from "lodash.once";

const SUPPORTED_ALGS = [
  "RS256",
  "RS384",
  "RS512",
  "ES256",
  "ES384",
  "ES512",
  "HS256",
  "HS384",
  "HS512",
  "none",
];
if (PS_SUPPORTED) {
  SUPPORTED_ALGS.splice(3, 0, "PS256", "PS384", "PS512");
}

const sign_options_schema = {
  expiresIn: {
    isValid: function (value: unknown) {
      return isInteger(value) || (isString(value) && value);
    },
    message:
      '"expiresIn" should be a number of seconds or string representing a timespan',
  },
  notBefore: {
    isValid: function (value: unknown) {
      return isInteger(value) || (isString(value) && value);
    },
    message:
      '"notBefore" should be a number of seconds or string representing a timespan',
  },
  audience: {
    isValid: function (value: unknown) {
      return isString(value) || Array.isArray(value);
    },
    message: '"audience" must be a string or array',
  },
  algorithm: {
    isValid: includes.bind(null, SUPPORTED_ALGS),
    message: '"algorithm" must be a valid string enum value',
  },
  header: { isValid: isPlainObject, message: '"header" must be an object' },
  encoding: { isValid: isString, message: '"encoding" must be a string' },
  issuer: { isValid: isString, message: '"issuer" must be a string' },
  subject: { isValid: isString, message: '"subject" must be a string' },
  jwtid: { isValid: isString, message: '"jwtid" must be a string' },
  noTimestamp: {
    isValid: isBoolean,
    message: '"noTimestamp" must be a boolean',
  },
  keyid: { isValid: isString, message: '"keyid" must be a string' },
  mutatePayload: {
    isValid: isBoolean,
    message: '"mutatePayload" must be a boolean',
  },
};

const registered_claims_schema = {
  iat: { isValid: isNumber, message: '"iat" should be a number of seconds' },
  exp: { isValid: isNumber, message: '"exp" should be a number of seconds' },
  nbf: { isValid: isNumber, message: '"nbf" should be a number of seconds' },
};

function validate(schema: any, allowUnknown: boolean, object: Record<string, any>, parameterName: any) {
  if (!isPlainObject(object)) {
    throw new Error('Expected "' + parameterName + '" to be a plain object.');
  }
  Object.keys(object).forEach(function (key) {
    const validator = schema[key];
    if (!validator) {
      if (!allowUnknown) {
        throw new Error(
          '"' + key + '" is not allowed in "' + parameterName + '"'
        );
      }
      return;
    }
    if (!validator.isValid(object[key])) {
      throw new Error(validator.message);
    }
  });
}

function validateOptions(options: object) {
  return validate(sign_options_schema, false, options, "options");
}

function validatePayload(payload: object) {
  return validate(registered_claims_schema, true, payload, "payload");
}

const options_to_payload = {
  audience: "aud",
  issuer: "iss",
  subject: "sub",
  jwtid: "jti",
};

const options_for_objects = [
  "expiresIn",
  "notBefore",
  "noTimestamp",
  "audience",
  "issuer",
  "subject",
  "jwtid",
];

export interface SignOptions {
  /**
   * Signature algorithm. Could be one of these values :
   * - HS256:    HMAC using SHA-256 hash algorithm (default)
   * - HS384:    HMAC using SHA-384 hash algorithm
   * - HS512:    HMAC using SHA-512 hash algorithm
   * - RS256:    RSASSA using SHA-256 hash algorithm
   * - RS384:    RSASSA using SHA-384 hash algorithm
   * - RS512:    RSASSA using SHA-512 hash algorithm
   * - ES256:    ECDSA using P-256 curve and SHA-256 hash algorithm
   * - ES384:    ECDSA using P-384 curve and SHA-384 hash algorithm
   * - ES512:    ECDSA using P-521 curve and SHA-512 hash algorithm
   * - none:     No digital signature or MAC value included
   */
  algorithm?: Algorithm;
  keyid?: string;
  /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, "2 days", "10h", "7d" */
  expiresIn?: string | number;
  /** expressed in seconds or a string describing a time span [zeit/ms](https://github.com/zeit/ms.js).  Eg: 60, "2 days", "10h", "7d" */
  notBefore?: string | number;
  audience?: string | string[];
  subject?: string;
  issuer?: string;
  jwtid?: string;
  mutatePayload?: boolean;
  noTimestamp?: boolean;
  header?: object;
  encoding?: string;
}

export type SignCallback = (
  err: Error | null,
  encoded?: string
) => void;

export default function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, callback: SignCallback): void;

export default function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, options?: SignOptions): string;
export default function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, options: SignOptions, callback: SignCallback): void;
export default function sign(payload: string | Buffer | object, secretOrPrivateKey: Secret, options: SignOptions | SignCallback = {} as SignOptions, callback?: SignCallback): void | string {
  if (typeof options === "function") {
    callback = options;
    options = {} as SignOptions;
  }


  const isObjectPayload = typeof payload === "object" && !Buffer.isBuffer(payload);

  const header = Object.assign(
    {
      alg: options.algorithm || "HS256",
      typ: isObjectPayload ? "JWT" : undefined,
      kid: options.keyid,
    },
    options.header
  );

  function failure(err: Error | null) {
    if (callback) {
      return callback(err);
    }
    throw err;
  }

  if (!secretOrPrivateKey && options.algorithm !== "none") {
    return failure(new Error("secretOrPrivateKey must have a value"));
  }

  if (typeof payload === "undefined") {
    return failure(new Error("payload is required"));
  } else if (isObjectPayload) {
    payload = payload as Object;
    try {
      validatePayload(payload);
    } catch (error) {
      return failure(error);
    }
    if (!options.mutatePayload) {
      payload = Object.assign({}, payload);
    }
  } else {
    const invalid_options = options_for_objects.filter(function (opt) {
      // @ts-ignore
      return typeof options[opt] !== "undefined";
    });

    if (invalid_options.length > 0) {
      return failure(
        new Error(
          "invalid " +
          invalid_options.join(",") +
          " option for " +
          typeof payload +
          " payload"
        )
      );
    }
  }


  if (
    // @ts-ignore
    typeof payload.exp !== "undefined" &&
    typeof options.expiresIn !== "undefined"
  ) {
    return failure(
      new Error(
        'Bad "options.expiresIn" option the payload already has an "exp" property.'
      )
    );
  }

  if (
    // @ts-ignore
    typeof payload.nbf !== "undefined" &&
    typeof options.notBefore !== "undefined"
  ) {
    return failure(
      new Error(
        'Bad "options.notBefore" option the payload already has an "nbf" property.'
      )
    );
  }

  try {
    validateOptions(options);
  } catch (error) {
    return failure(error);
  }
  // @ts-ignore
  const timestamp = payload.iat || Math.floor(Date.now() / 1000);

  if (options.noTimestamp) {
    // @ts-ignore
    delete payload.iat;
  } else if (isObjectPayload) {
    // @ts-ignore
    payload.iat = timestamp;
  }

  if (typeof options.notBefore !== "undefined") {
    try {
// @ts-ignore
      payload.nbf = timespan(options.notBefore, timestamp);
    } catch (err) {
      return failure(err);
    }
    // @ts-ignore
    if (typeof payload.nbf === "undefined") {
      return failure(
        new Error(
          '"notBefore" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        )
      );
    }
  }

  if (typeof options.expiresIn !== "undefined" && typeof payload === "object") {
    try {
      // @ts-ignore
      payload.exp = timespan(options.expiresIn, timestamp);
    } catch (err) {
      return failure(err);
    }
    // @ts-ignore
    if (typeof payload.exp === "undefined") {
      return failure(
        new Error(
          '"expiresIn" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
        )
      );
    }
  }

  Object.keys(options_to_payload).forEach(function (key) {
    // @ts-ignore
    const claim = options_to_payload[key];
    // @ts-ignore
    if (typeof options[key] !== "undefined") {
      // @ts-ignore
      if (typeof payload[claim] !== "undefined") {
        return failure(
          new Error(
            'Bad "options.' +
            key +
            '" option. The payload already has an "' +
            claim +
            '" property.'
          )
        );
      }
      // @ts-ignore
      payload[claim] = options[key];
    }
  });

  const encoding = options.encoding || "utf8";

  if (typeof callback === "function") {
    callback = callback && once(callback);

    jws
      .createSign({
        header: header,
        privateKey: secretOrPrivateKey,
        payload: payload,
        encoding: encoding,
      })
      .once("error", callback)
      .once("done", function (signature: string | undefined) {
        if (callback) {
          callback(null, signature);
        }
      });
  } else {
    return jws.sign({
      header: header,
      payload: payload,
      secret: secretOrPrivateKey,
      encoding: encoding,
    });
  }
}
