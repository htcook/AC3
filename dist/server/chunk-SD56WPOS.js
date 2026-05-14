import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/fips-ssh.ts
function getFIPSSSHSummary() {
  return {
    kex: [...FIPS_KEX],
    ciphers: [...FIPS_CIPHERS],
    macs: [...FIPS_MACS],
    hostKeys: [...FIPS_HOST_KEY]
  };
}
var FIPS_KEX, FIPS_CIPHERS, FIPS_MACS, FIPS_HOST_KEY, FIPS_SSH_ALGORITHMS;
var init_fips_ssh = __esm({
  "server/lib/fips-ssh.ts"() {
    "use strict";
    FIPS_KEX = [
      "curve25519-sha256",
      "curve25519-sha256@libssh.org",
      "ecdh-sha2-nistp521",
      "ecdh-sha2-nistp384",
      "ecdh-sha2-nistp256",
      "diffie-hellman-group18-sha512",
      "diffie-hellman-group16-sha512",
      "diffie-hellman-group14-sha256"
    ];
    FIPS_CIPHERS = [
      "aes256-gcm@openssh.com",
      "aes128-gcm@openssh.com",
      "aes256-ctr",
      "aes192-ctr",
      "aes128-ctr"
    ];
    FIPS_MACS = [
      "hmac-sha2-512-etm@openssh.com",
      "hmac-sha2-256-etm@openssh.com",
      "hmac-sha2-512",
      "hmac-sha2-256"
    ];
    FIPS_HOST_KEY = [
      "ssh-ed25519",
      "ecdsa-sha2-nistp521",
      "ecdsa-sha2-nistp384",
      "ecdsa-sha2-nistp256",
      "rsa-sha2-512",
      "rsa-sha2-256"
    ];
    FIPS_SSH_ALGORITHMS = {
      kex: FIPS_KEX,
      cipher: FIPS_CIPHERS,
      serverHostKey: FIPS_HOST_KEY,
      hmac: FIPS_MACS
    };
  }
});

export {
  FIPS_SSH_ALGORITHMS,
  getFIPSSSHSummary,
  init_fips_ssh
};
