export type Secret =
  | string
  | Buffer
  | { key: string | Buffer; passphrase: string };
export type Algorithm =
  "HS256" | "HS384" | "HS512" |
  "RS256" | "RS384" | "RS512" |
  "ES256" | "ES384" | "ES512" |
  "PS256" | "PS384" | "PS512" |
  "none";
