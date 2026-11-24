import { z } from "zod"

// Configure Zod v4 in jitless mode before any schema modules are evaluated
// so it never probes `Function("")` under cx-server's strict CSP (`default-src 'self'`).
z.config({ jitless: true })
