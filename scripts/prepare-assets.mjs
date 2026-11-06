import { copyFile, mkdir } from "node:fs/promises";

const output = new URL("../dist/", import.meta.url);
await mkdir(output, { recursive: true });
// Explicitly allow only public files; never publish repository/config files.
for (const name of ["index.html", "app.js", "styles.css", "_headers"]) {
  await copyFile(new URL(`../${name}`, import.meta.url), new URL(name, output));
}
