import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/server-instance.ts
import os from "os";
import crypto from "crypto";
var SERVER_INSTANCE_ID, SERVER_START_TIME;
var init_server_instance = __esm({
  "server/lib/server-instance.ts"() {
    SERVER_INSTANCE_ID = [
      os.hostname().replace(/[^a-zA-Z0-9-]/g, "").slice(0, 20),
      process.pid,
      Math.floor(Date.now() / 1e3),
      crypto.randomBytes(2).toString("hex")
    ].join("-");
    SERVER_START_TIME = Date.now();
    console.log(`[ServerInstance] ID: ${SERVER_INSTANCE_ID}`);
  }
});

export {
  SERVER_INSTANCE_ID,
  SERVER_START_TIME,
  init_server_instance
};
