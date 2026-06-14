const express = require("express");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

const LANDING = path.join(__dirname, "public", "landing.html");
const DASHBOARD = path.join(__dirname, "public", "index.html");

// Landing page is the default route.
app.get("/", (_req, res) => res.sendFile(LANDING));

// The tool itself (Runner / Repeater / History / Checklist / Settings) lives at /dashboard.
app.get("/dashboard", (_req, res) => res.sendFile(DASHBOARD));

// Static assets for the dashboard (app.js, styles.css). index:false so it doesn't hijack "/".
app.use(express.static(path.join(__dirname, "public"), { index: false }));

app.listen(PORT, () =>
  console.log(`\n  GraphRaider — landing http://localhost:${PORT}  ·  dashboard http://localhost:${PORT}/dashboard\n`)
);
