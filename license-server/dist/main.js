"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.createApp = createApp;
const dotenv_1 = __importDefault(require("dotenv"));
const node_fs_1 = __importDefault(require("node:fs"));
const node_path_1 = __importDefault(require("node:path"));
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const helmet_1 = __importDefault(require("helmet"));
const plugin_api_routes_1 = require("./routes/plugin-api.routes");
const remote_feature_routes_1 = require("./routes/remote-feature.routes");
const admin_api_routes_1 = require("./routes/admin-api.routes");
const ed25519_service_1 = require("./crypto/ed25519.service");
const db_service_1 = require("./database/db.service");
dotenv_1.default.config();
function createApp() {
    const app = (0, express_1.default)();
    app.use((0, helmet_1.default)({
        contentSecurityPolicy: false // Allow embedded dashboard scripts/styles
    }));
    app.use((0, cors_1.default)());
    app.use(express_1.default.json({ limit: '1mb' }));
    // Cloud Database (Supabase PostgreSQL) State Sync Middleware for Vercel Serverless
    app.use('/api', async (_req, res, next) => {
        await db_service_1.dbService.ensureLoaded();
        const originalJson = res.json.bind(res);
        res.json = ((body) => {
            db_service_1.dbService.flush().finally(() => {
                originalJson(body);
            });
            return res;
        });
        next();
    });
    // Health & Cryptographic Identity endpoint
    app.get('/api/v1/health', (_req, res) => {
        res.json({
            status: 'OK',
            service: 'WordPress License Protection Central Server',
            version: '1.0.0',
            storageMode: db_service_1.dbService.isCloudDatabaseEnabled() ? 'SUPABASE_POSTGRESQL' : 'LOCAL_JSON',
            ed25519KeyId: ed25519_service_1.ed25519Service.getKeyId(),
            ed25519PublicKeyBase64: ed25519_service_1.ed25519Service.getPublicKeyBase64(),
            timestamp: new Date().toISOString()
        });
    });
    // 1. WordPress Plugin Licensing Endpoints (Module 2, 3, 4, 5, 6)
    app.use('/api/v1/plugin', plugin_api_routes_1.pluginApiRouter);
    // 2. Server-Side Commercial Core Features Engine (Module 7)
    app.use('/api/v1/remote-features', remote_feature_routes_1.remoteFeatureRouter);
    // 3. Central License Management & RBAC Admin API (Module 1 & 6)
    app.use('/api/v1/admin', admin_api_routes_1.adminApiRouter);
    // 4. Serve Modern Central License Admin Dashboard SPA
    const publicCandidates = [
        node_path_1.default.resolve(__dirname, '..', 'public'),
        node_path_1.default.join(process.cwd(), 'license-server', 'public'),
        node_path_1.default.join(process.cwd(), 'public')
    ];
    const publicDir = publicCandidates.find((d) => node_fs_1.default.existsSync(d)) || publicCandidates[0];
    app.use(express_1.default.static(publicDir));
    app.get('/', (_req, res) => {
        res.sendFile(node_path_1.default.join(publicDir, 'index.html'));
    });
    app.get('/app.js', (_req, res) => {
        res.sendFile(node_path_1.default.join(publicDir, 'app.js'));
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
        console.log(`🔑 ED25519 PUBLIC KEY (For WP Plugin): ${ed25519_service_1.ed25519Service.getPublicKeyBase64()}`);
        console.log('==============================================================');
    });
}
