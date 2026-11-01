import dotenv from 'dotenv';
import fs from 'node:fs';
import path from 'node:path';
import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { pluginApiRouter } from './routes/plugin-api.routes';
import { remoteFeatureRouter } from './routes/remote-feature.routes';
import { adminApiRouter } from './routes/admin-api.routes';
import { ed25519Service } from './crypto/ed25519.service';
import { dbService } from './database/db.service';

dotenv.config();
dotenv.config({ path: path.resolve(__dirname, '..', '..', '.env.local') });
dotenv.config({ path: path.resolve(__dirname, '..', '.env.local') });

export function createApp() {
  const app = express();

  app.use(
    helmet({
      contentSecurityPolicy: false // Allow embedded dashboard scripts/styles
    })
  );
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  // Cloud Database (Supabase PostgreSQL) State Sync Middleware for Vercel Serverless
  app.use('/api', async (_req, res, next) => {
    await dbService.ensureLoaded();
    const originalJson = res.json.bind(res);
    res.json = ((body: unknown) => {
      dbService.flush().finally(() => {
        originalJson(body);
      });
      return res;
    }) as typeof res.json;
    next();
  });

  // Health & Cryptographic Identity endpoint
  app.get('/api/v1/health', (_req, res) => {
    res.json({
      status: 'OK',
      service: 'WordPress License Protection Central Server',
      version: '1.0.0',
      storageMode: dbService.isCloudDatabaseEnabled() ? 'SUPABASE_POSTGRESQL' : 'LOCAL_JSON',
      ed25519KeyId: ed25519Service.getKeyId(),
      ed25519PublicKeyBase64: ed25519Service.getPublicKeyBase64(),
      timestamp: new Date().toISOString()
    });
  });

  // 1. WordPress Plugin Licensing Endpoints (Module 2, 3, 4, 5, 6)
  app.use('/api/v1/plugin', pluginApiRouter);

  // 2. Server-Side Commercial Core Features Engine (Module 7)
  app.use('/api/v1/remote-features', remoteFeatureRouter);

  // 3. Central License Management & RBAC Admin API (Module 1 & 6)
  app.use('/api/v1/admin', adminApiRouter);

  // 4. Serve Modern Central License Admin Dashboard SPA
  const publicCandidates = [
    path.resolve(__dirname, '..', 'public'),
    path.join(process.cwd(), 'license-server', 'public'),
    path.join(process.cwd(), 'public')
  ];
  const publicDir = publicCandidates.find((d) => fs.existsSync(d)) || publicCandidates[0];
  app.use(express.static(publicDir));
  app.get('/', (_req, res) => {
    res.sendFile(path.join(publicDir, 'index.html'));
  });
  app.get('/app.js', (_req, res) => {
    res.sendFile(path.join(publicDir, 'app.js'));
  });

  return app;
}

if (require.main === module) {
  const port = Number(process.env.PORT || 4000);
  const app = createApp();
  app.listen(port, () => {
    console.log('==============================================================');
    console.log(`🛡️  CENTRAL LICENSE SERVER RUNNING ON: http://localhost:${port}`);
    console.log(`📊 ADMIN DASHBOARD UI:                http://localhost:${port}`);
    console.log(`🔑 ED25519 PUBLIC KEY (For WP Plugin): ${ed25519Service.getPublicKeyBase64()}`);
    console.log('==============================================================');
  });
}

