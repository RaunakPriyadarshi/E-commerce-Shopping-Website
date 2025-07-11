import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  define: {
    "process.env": process.env, // keep if you're using .env variables
  },
  server: {
    proxy: {
      "/api": {
        target: "http://localhost:5000", // Replace with your backend URL/port
        changeOrigin: true,
        secure: false,
      },
    },
  },
});
