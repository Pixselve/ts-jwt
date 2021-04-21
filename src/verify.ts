import JsonWebTokenError from "./lib/JsonWebTokenError";
import { NotBeforeError } from "./lib/NotBeforeError";
import { TokenExpiredError } from "./lib/TokenExpiredError";
import decode from "./decode";
import { Secret } from "./types";
import {Algorithm} from "./types";

const timespan = require('./lib/timespan');
const PS_SUPPORTED = require('./lib/psSupported');
const jws = require('jws');

const PUB_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512'];
const RSA_KEY_ALGS: Algorithm[] = ['RS256', 'RS384', 'RS512'];
const HS_ALGS: Algorithm[] = ['HS256', 'HS384', 'HS512'];

if (PS_SUPPORTED) {
  PUB_KEY_ALGS.splice(3, 0, 'PS256', 'PS384', 'PS512');
  RSA_KEY_ALGS.splice(3, 0, 'PS256', 'PS384', 'PS512');
}
export type VerifyErrors =
  | JsonWebTokenError
  | NotBeforeError
  | TokenExpiredError;


export type VerifyCallback = (
  err: VerifyErrors | null,
  decoded: object | undefined,
) => void;



export interface VerifyOptions {
  algorithms?: Algorithm[];
  audience?: string | RegExp | Array<string | RegExp>;
  clockTimestamp?: number;
  clockTolerance?: number;
  /** return an object with the decoded `{ payload, header, signature }` instead of only the usual content of the payload. */
  complete?: boolean;
  issuer?: string | string[];
  ignoreExpiration?: boolean;
  ignoreNotBefore?: boolean;
  jwtid?: string;
  /**
   * If you want to check `nonce` claim, provide a string value here.
   * It is used on Open ID for the ID Tokens. ([Open ID implementation notes](https://openid.net/specs/openid-connect-core-1_0.html#NonceNotes))
   */
  nonce?: string;
  subject?: string;
  /**
   * @deprecated
   * Max age of token
   */
  maxAge?: string;
}

export type SigningKeyCallback = (
  err: any,
  signingKey?: Secret,
) => void;

export interface JwtHeader {
  alg: string;
  typ?: string;
  kid?: string;
  jku?: string;
  x5u?: string;
  x5t?: string;
}

export type GetPublicKeyOrSecret = (
  header: JwtHeader,
  callback: SigningKeyCallback
) => void;

export function verify(token: string, secretOrPublicKey: Secret | GetPublicKeyOrSecret, options?: VerifyOptions): object | string;
export function verify(token: string, secretOrPublicKey: Secret | GetPublicKeyOrSecret, callback?: VerifyCallback): void;
export default function verify(token: string, secretOrPublicKey: Secret | GetPublicKeyOrSecret, options: VerifyOptions | VerifyCallback = {}, callback?: VerifyCallback): any {
  if ((typeof options === 'function') && !callback) {
    callback = options;
    options = {};
  }

  //clone this object since we are going to mutate it.
  options = Object.assign({}, options) as VerifyOptions;

  let done: (err: JsonWebTokenError | null, data?: any) => void;

  if (callback) {
    done = callback;
  } else {
    done = function (err, data?) {
      if (err) throw err;
      return data;
    };
  }

  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    return done(new JsonWebTokenError('clockTimestamp must be a number'));
  }

  if (options.nonce !== undefined && (typeof options.nonce !== 'string' || options.nonce.trim() === '')) {
    return done(new JsonWebTokenError('nonce must be a non-empty string'));
  }

  const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000);

  if (!token) {
    return done(new JsonWebTokenError('jwt must be provided'));
  }

  if (typeof token !== 'string') {
    return done(new JsonWebTokenError('jwt must be a string'));
  }

  const parts = token.split('.');

  if (parts.length !== 3) {
    return done(new JsonWebTokenError('jwt malformed'));
  }

  let decodedToken: Record<string, any> | null;

  try {
    decodedToken = decode(token, { complete: true });
  } catch (err) {
    return done(err);
  }

  if (!decodedToken) {
    return done(new JsonWebTokenError('invalid token'));
  }

  const header = decodedToken.header;
  let getSecret;

  if (typeof secretOrPublicKey === 'function') {
    if (!callback) {
      return done(new JsonWebTokenError('verify must be called asynchronous if secret or public key is provided as a callback'));
    }

    getSecret = secretOrPublicKey;
  } else {
    getSecret = function (header: any, secretCallback: (err: null, getSecret: Secret) => any) {
      return secretCallback(null, secretOrPublicKey);
    };
  }

  return getSecret(header, function (err, secretOrPublicKey) {
    options = options as VerifyOptions
    if (err) {
      return done(new JsonWebTokenError('error in secret or public key callback: ' + err.message));
    }

    const hasSignature = parts[2].trim() !== '';

    if (!hasSignature && secretOrPublicKey) {
      return done(new JsonWebTokenError('jwt signature is required'));
    }

    if (hasSignature && !secretOrPublicKey) {
      return done(new JsonWebTokenError('secret or public key must be provided'));
    }

    if (!hasSignature && !options.algorithms) {
      options.algorithms = ['none'];
    }

    if (!options.algorithms) {
      options.algorithms = secretOrPublicKey?.toString().includes('BEGIN CERTIFICATE') ||
      secretOrPublicKey?.toString().includes('BEGIN PUBLIC KEY') ? PUB_KEY_ALGS :
        secretOrPublicKey?.toString().includes('BEGIN RSA PUBLIC KEY') ? RSA_KEY_ALGS : HS_ALGS;

    }

    if (!~options.algorithms.indexOf(decodedToken?.header.alg)) {
      return done(new JsonWebTokenError('invalid algorithm'));
    }

    let valid;

    try {
      valid = jws.verify(token, decodedToken?.header.alg, secretOrPublicKey);
    } catch (e) {
      return done(e);
    }

    if (!valid) {
      return done(new JsonWebTokenError('invalid signature'));
    }

    const payload = decodedToken?.payload;

    if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
      if (typeof payload.nbf !== 'number') {
        return done(new JsonWebTokenError('invalid nbf value'));
      }
      if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
        return done(new NotBeforeError('jwt not active', new Date(payload.nbf * 1000)));
      }
    }

    if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
      if (typeof payload.exp !== 'number') {
        return done(new JsonWebTokenError('invalid exp value'));
      }
      if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)));
      }
    }

    if (options.audience) {
      const audiences = Array.isArray(options.audience) ? options.audience : [options.audience];
      const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud];

      const match = target.some(function (targetAudience: string) {
        return audiences.some(function (audience) {
          return audience instanceof RegExp ? audience.test(targetAudience) : audience === targetAudience;
        });
      });

      if (!match) {
        return done(new JsonWebTokenError('jwt audience invalid. expected: ' + audiences.join(' or ')));
      }
    }

    if (options.issuer) {
      const invalid_issuer =
        (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
        (Array.isArray(options.issuer) && options.issuer.indexOf(payload.iss) === -1);

      if (invalid_issuer) {
        return done(new JsonWebTokenError('jwt issuer invalid. expected: ' + options.issuer));
      }
    }

    if (options.subject) {
      if (payload.sub !== options.subject) {
        return done(new JsonWebTokenError('jwt subject invalid. expected: ' + options.subject));
      }
    }

    if (options.jwtid) {
      if (payload.jti !== options.jwtid) {
        return done(new JsonWebTokenError('jwt jwtid invalid. expected: ' + options.jwtid));
      }
    }

    if (options.nonce) {
      if (payload.nonce !== options.nonce) {
        return done(new JsonWebTokenError('jwt nonce invalid. expected: ' + options.nonce));
      }
    }

    if (options.maxAge) {
      if (typeof payload.iat !== 'number') {
        return done(new JsonWebTokenError('iat required when maxAge is specified'));
      }

      const maxAgeTimestamp = timespan(options.maxAge, payload.iat);
      if (typeof maxAgeTimestamp === 'undefined') {
        return done(new JsonWebTokenError('"maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'));
      }
      if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
        return done(new TokenExpiredError('maxAge exceeded', new Date(maxAgeTimestamp * 1000)));
      }
    }

    if (options.complete === true) {
      const signature = decodedToken?.signature;

      return done(null, {
        header: header,
        payload: payload,
        signature: signature
      });
    }

    return done(null, payload);
  });
}
