import { execFile } from 'child_process';
import { promisify } from 'util';
import path from 'path';
import { existsSync } from 'fs';

export const execFileAsync = promisify(execFile);

export function findInPath(binName) {
    const pathEnv = process.env.PATH || '';
    const parts = pathEnv.split(path.delimiter).filter(Boolean);
    const exts = process.platform === 'win32' ? (process.env.PATHEXT || '.EXE;.CMD;.BAT;.COM').split(';') : [''];
    for (const dir of parts) {
        for (const ext of exts) {
            const candidate = path.join(dir, binName + ext);
            try {
                if (existsSync(candidate)) return candidate;
            } catch { }
        }
    }
    return null;
}

export async function sleep(ms) {
    await new Promise((resolve) => setTimeout(resolve, ms));
}
