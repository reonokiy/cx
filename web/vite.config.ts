import { fileURLToPath, URL } from "node:url"
import react from "@vitejs/plugin-react"
import tailwind from "@tailwindcss/vite"
import { defineConfig } from "vite"

export default defineConfig({
  base: "/ui/",
  plugins: [react(), tailwind()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  server: {
    host: "127.0.0.1",
    proxy: { "/v1": process.env.CX_API_ORIGIN ?? "http://127.0.0.1:8080" },
  },
})
