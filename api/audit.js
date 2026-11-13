export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const rawUrl = req.query.url;
  if (!rawUrl || typeof rawUrl !== 'string') {
    return res.status(400).json({ error: 'Missing ?url= parameter' });
  }

  let targetUrl = rawUrl.trim();
  if (!/^https?:\/\//i.test(targetUrl)) {
    targetUrl = 'https://' + targetUrl;
  }

  let parsed;
  try {
    parsed = new URL(targetUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) {
      return res.status(400).json({ error: 'Only http/https URLs are supported' });
    }
  } catch {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  const start = Date.now();
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 8000);
    const response = await fetch(parsed.toString(), {
      method: 'GET',
      redirect: 'follow',
      signal: controller.signal,
      headers: { 'User-Agent': 'AuditPulse-Bot/1.0 (+https://github.com/TrioA/auditpulse)' }
    });
    clearTimeout(timeout);
    const ttfbMs = Date.now() - start;
    const html = await response.text();
    const headers = {};
    response.headers.forEach((v, k) => { headers[k.toLowerCase()] = v; });

    const securityChecks = [
      { key: 'strict-transport-security', label: 'HSTS (Strict-Transport-Security)', present: Boolean(headers['strict-transport-security']), weight: 20 },
      { key: 'content-security-policy', label: 'Content-Security-Policy (CSP)', present: Boolean(headers['content-security-policy']), weight: 20 },
      { key: 'x-frame-options', label: 'X-Frame-Options', present: Boolean(headers['x-frame-options']), weight: 15 },
      { key: 'x-content-type-options', label: 'X-Content-Type-Options', present: Boolean(headers['x-content-type-options']), weight: 15 },
      { key: 'referrer-policy', label: 'Referrer-Policy', present: Boolean(headers['referrer-policy']), weight: 15 },
      { key: 'permissions-policy', label: 'Permissions-Policy', present: Boolean(headers['permissions-policy']), weight: 15 }
    ];
    const securityScore = securityChecks.reduce((acc, c) => acc + (c.present ? c.weight : 0), 0);

    const hasTitle = /<title[^>]*>([^<]+)<\/title>/i.test(html);
    const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
    const hasMetaDesc = /<meta[^>]+name=["']description["'][^>]*>/i.test(html);
    const hasViewport = /<meta[^>]+name=["']viewport["'][^>]*>/i.test(html);
    const hasOgTitle = /<meta[^>]+property=["']og:title["'][^>]*>/i.test(html);
    const hasCanonical = /<link[^>]+rel=["']canonical["'][^>]*>/i.test(html);

    const seoChecks = [
      { label: 'Title Tag', present: hasTitle, weight: 25 },
      { label: 'Meta Description', present: hasMetaDesc, weight: 25 },
      { label: 'Mobile Viewport', present: hasViewport, weight: 20 },
      { label: 'OpenGraph Title', present: hasOgTitle, weight: 15 },
      { label: 'Canonical Link', present: hasCanonical, weight: 15 }
    ];
    const seoScore = seoChecks.reduce((acc, c) => acc + (c.present ? c.weight : 0), 0);

    const scriptCount = (html.match(/<script\b/gi) || []).length;
    const htmlSizeKb = Math.round((Buffer.byteLength(html, 'utf8') / 1024) * 10) / 10;
    const perfScore = Math.max(20, Math.min(100, 100 - (ttfbMs > 800 ? 25 : ttfbMs > 400 ? 10 : 0) - (scriptCount > 15 ? 20 : 0)));

    const overallScore = Math.round((securityScore * 0.4) + (seoScore * 0.35) + (perfScore * 0.25));

    return res.status(200).json({
      url: response.url,
      status: response.status,
      ttfbMs,
      htmlSizeKb,
      scriptCount,
      title: titleMatch ? titleMatch[1].trim() : null,
      scores: { overall: overallScore, security: securityScore, seo: seoScore, performance: perfScore },
      securityChecks,
      seoChecks,
      auditedAt: new Date().toISOString()
    });
  } catch (err) {
    return res.status(502).json({ error: err.message || 'Failed to fetch target URL' });
  }
}
