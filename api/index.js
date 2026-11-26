import { app, initDb } from '../server.js';

let databaseReady;

export default async function handler(req, res) {
  if (!databaseReady) {
    databaseReady = initDb().catch((error) => {
      databaseReady = undefined;
      throw error;
    });
  }
  try {
    await databaseReady;
  } catch (error) {
    console.error('Database initialization failed:', error.message);
    return res.status(503).json({ success: false, message: 'The database is temporarily unavailable.' });
  }

  const requestUrl = req.url || '/api';
  const pathname = new URL(requestUrl, 'http://localhost').pathname;
  if (pathname !== '/api' && !pathname.startsWith('/api/')) {
    req.url = `/api${requestUrl.startsWith('/') ? requestUrl : `/${requestUrl}`}`;
  }
  return app(req, res);
}
