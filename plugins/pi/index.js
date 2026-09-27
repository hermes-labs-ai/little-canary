import { createInputHandler } from "./screen.js";

export default function littleCanary(pi) {
  pi.on("input", createInputHandler());
}
