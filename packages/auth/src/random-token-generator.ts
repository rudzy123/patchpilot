export const SESSION_TOKEN_BYTES = 32;

export type RandomTokenGenerator = {
  generate(byteLength: number): string;
};
