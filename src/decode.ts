import * as jws from "jws";

export interface DecodeOptions {
  complete?: boolean;
  json?: boolean;
}
export function decode(token: string, options: DecodeOptions & { json: true } | DecodeOptions & { complete: true }): null | Record<string, any>;
export function decode(token: string, options?: DecodeOptions): null | Record<string, any> | string {
  // @ts-ignore - Bad types, jws.decode accept a second argument. Check https://github.com/auth0/node-jws/blob/8857ee77623104e5cf9955932165ddf9cea1b72c/lib/verify-stream.js#L57
  const decoded = jws.decode(token, options);
  if (!decoded) {
    return null;
  }
  let payload = decoded.payload;

  //try parse the payload
  if (typeof payload === 'string') {
    try {
      const obj = JSON.parse(payload);
      if (obj !== null && typeof obj === 'object') {
        payload = obj;
      }
    } catch (e) {
    }
  }

  //return header if `complete` option is enabled.  header includes claims
  //such as `kid` and `alg` used to select the key within a JWKS needed to
  //verify the signature
  if (options?.complete === true) {
    return {
      header: decoded.header,
      payload: payload,
      signature: decoded.signature
    };
  }
  return payload;
};
