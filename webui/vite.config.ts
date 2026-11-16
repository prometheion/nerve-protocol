// The web UIs of the center and the node: two pages and the login, built
// into dist/ and embedded by the Rust programs (nerve-transport's build.rs),
// so `cargo build` needs no Node. Every script and style is a file of its
// own with a hash in its name: the servers' CSP allows no inline script or
// style (docs/dev/web-uis.md).
/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// `NERVE_DEV_UI=http://127.0.0.1:7480 npm run dev` serves the sources with
// the API of a running center or node behind them (docs/dev/web-uis.md).
// Its posts carry that server's origin, as its own page's do.
const target = process.env.NERVE_DEV_UI;
const proxy = target
  ? Object.fromEntries(
      ["/api", "/login", "/logout", "/assets"].map((p) => [
        p,
        {
          target,
          changeOrigin: true,
          secure: false,
          configure: (server: { on: (e: string, f: (req: { setHeader: (k: string, v: string) => void }) => void) => void }) =>
            server.on("proxyReq", (req) => req.setHeader("origin", target)),
        },
      ]),
    )
  : undefined;

export default defineConfig({
  plugins: [react()],
  base: "/",
  // The tests read the app's theme and icons, which the web UIs follow.
  server: { fs: { allow: [".", "../crates/nerve/ui"] }, proxy },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // An image or a font small enough to inline would become a data: URL in
    // the CSS; every asset stays a file.
    assetsInlineLimit: 0,
    // The polyfill is a script Vite would inline into the page.
    modulePreload: { polyfill: false },
    reportCompressedSize: false,
    rollupOptions: {
      input: { center: "center.html", node: "node.html", login: "login.html" },
    },
  },
  test: {
    environment: "happy-dom",
    include: ["src/**/*.test.{ts,tsx}"],
    restoreMocks: true,
    // The token test reads the stylesheets as they are.
    css: true,
  },
});
