'use strict';

const { MailtrapClient } = require('mailtrap');
const { config } = require('../config');

function otpHtmlTemplate(siteUrl, code) {
  return `
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Your OTP Code</title>
    <style>
      body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial, sans-serif; background: #f8fafc; color: #0f172a; padding: 24px; }
      .card { max-width: 520px; margin: 0 auto; background: white; border-radius: 12px; border: 1px solid #e2e8f0; padding: 24px; }
      .logo { text-align: center; margin-bottom: 12px; }
      .code { font-size: 28px; letter-spacing: 4px; font-weight: 700; background: #f1f5f9; padding: 12px 16px; border-radius: 8px; display: inline-block; }
      .muted { color: #64748b; font-size: 14px; }
      a { color: #0ea5e9; text-decoration: none; }
    </style>
  </head>
  <body>
    <div class="card">
      <div class="logo">
        <h2>ROMA Auth Proxy</h2>
      </div>
      <p>Use the code below to complete your login. This code expires in 10 minutes.</p>
      <p style="text-align:center;">
        <span class="code">${code}</span>
      </p>
      <p class="muted">If you did not request this, you can ignore this email.</p>
      <p class="muted">crROMA API — <a href="${siteUrl}">${siteUrl}</a></p>
    </div>
  </body>
  </html>
  `;
}

function isPlaceholderToken(token) {
  if (!token) return true;
  const t = String(token).trim();
  return t.length === 0 || t.toLowerCase().includes('your_mailtrap_token') || t === '<YOUR-TOKEN-HERE>';
}

/**
 * Send an OTP code using the official Mailtrap SDK.
 * Falls back to debug mode (logs OTP) when MAILTRAP_TOKEN is not configured.
 * Returns: { ok: boolean, info: any, debug: boolean, code?: string }
 */
async function sendOtpEmail(toEmail, code) {
  const token = config.mailtrap && config.mailtrap.token;
  const senderEmail = (config.mailtrap && config.mailtrap.senderEmail) || 'no-reply@localhost';
  const senderName = (config.mailtrap && config.mailtrap.senderName) || 'ROMA Auth Proxy';

  try {
    if (!isPlaceholderToken(token)) {
      const client = new MailtrapClient({ token });
      const sender = { email: senderEmail, name: senderName };
      const info = await client.send({
        from: sender,
        to: [{ email: toEmail }],
        subject: 'Your ROMA Proxy OTP Code',
        text: `Your OTP code is: ${code}\nThis code expires in 10 minutes.\n${config.siteBaseUrl}`,
        html: otpHtmlTemplate(config.siteBaseUrl, code),
        category: 'otp'
      });
      return { ok: true, info, debug: false };
    }
    throw new Error('MAILTRAP_TOKEN not configured');
  } catch (err) {
    const status = (err && err.response && err.response.status) || (err && err.status) || null;
    const msg = err && (err.message || String(err));
    try { console.warn(`[Mailtrap] sendOtp failed status=${status}: ${msg}. Falling back to debug OTP.`); } catch (_) {}
    try { console.warn(`[DEBUG] OTP for ${toEmail}: ${code}`); } catch (_) {}
    return { ok: true, info: { error: msg, status }, debug: true, code };
  }
}

module.exports = {
  sendOtpEmail
};