import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import {ChildProcess, spawn, spawnSync} from 'node:child_process';
import http from 'node:http';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {defineConfig, Plugin} from 'vite';

const ROOT_DIR = path.dirname(fileURLToPath(import.meta.url));
const DEV_API_PORT = (process.env.KASHF_API_PORT || '8001').trim() || '8001';

function checkBackendHealth(port: string): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(
      `http://127.0.0.1:${port}/api/health`,
      {timeout: 500},
      (res) => {
        let body = '';
        res.setEncoding('utf8');
        res.on('data', (chunk) => {
          body += chunk;
        });
        res.on('end', () => {
          resolve(res.statusCode === 200 && body.includes('"ok"'));
        });
      },
    );
    req.on('error', () => resolve(false));
    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });
  });
}

function findPython3Executable(): string | null {
  const candidates = process.platform === 'win32' ? ['python', 'python3'] : ['python3', 'python'];
  for (const cmd of candidates) {
    const res = spawnSync(cmd, ['-c', 'import sys; raise SystemExit(0 if sys.version_info[0] >= 3 else 1)'], {
      stdio: 'ignore',
    });
    if (res.status === 0) {
      return cmd;
    }
  }
  return null;
}

function kashfPythonBackendPlugin(apiPort: string): Plugin {
  return {
    name: 'kashf-python-backend',
    apply: 'serve',
    configureServer(server) {
      let child: ChildProcess | null = null;

      const cleanup = () => {
        if (child && !child.killed) {
          child.kill('SIGTERM');
          child = null;
        }
      };

      const readyPromise = (async () => {
        if (await checkBackendHealth(apiPort)) {
          return;
        }
        const pythonBin = findPython3Executable();
        if (!pythonBin) {
          console.error('[kashf] Python 3 runtime not found; /api requests will fail.');
          return;
        }

        const entryScript = path.resolve(ROOT_DIR, 'backend', 'main.py');
        child = spawn(pythonBin, [entryScript], {
          cwd: ROOT_DIR,
          env: {
            ...process.env,
            HOST: '127.0.0.1',
            PORT: apiPort,
          },
          stdio: 'inherit',
        });

        child.on('exit', () => {
          child = null;
        });

        for (let attempt = 0; attempt < 40; attempt += 1) {
          if (await checkBackendHealth(apiPort)) {
            return;
          }
          await new Promise((r) => setTimeout(r, 150));
        }
      })();

      server.httpServer?.once('close', cleanup);
      process.once('exit', cleanup);

      server.middlewares.use('/api', (_req, _res, next) => {
        void readyPromise.then(() => next(), next);
      });
    },
  };
}

export default defineConfig(() => {
  return {
    plugins: [react(), tailwindcss(), kashfPythonBackendPlugin(DEV_API_PORT)],
    resolve: {
      alias: {
        '@': ROOT_DIR,
      },
    },
    server: {
      proxy: {
        '/api': {
          target: `http://127.0.0.1:${DEV_API_PORT}`,
          changeOrigin: true,
        },
      },
      // HMR is disabled in AI Studio via DISABLE_HMR env var.
      // Do not modify—file watching is disabled to prevent flickering during agent edits.
      hmr: process.env.DISABLE_HMR !== 'true',
      // Disable file watching when DISABLE_HMR is true to save CPU during agent edits.
      watch: process.env.DISABLE_HMR === 'true' ? null : {},
    },
  };
});
