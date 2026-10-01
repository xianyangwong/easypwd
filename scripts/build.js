import { cp, mkdir, readdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const destination = `${root}dist/easypwd`;
await mkdir(`${root}dist`, { recursive: true });
await rm(destination, { recursive: true, force: true });
await cp(`${root}extension`, destination, { recursive: true });
await cp(`${root}LICENSE`, `${destination}/LICENSE`);
console.log(`EasyPwd extension built in dist/easypwd (${(await readdir(destination)).length} files).`);
