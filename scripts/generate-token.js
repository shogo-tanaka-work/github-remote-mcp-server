#!/usr/bin/env node

/**
 * OAuth Client ID / Client Secret Generator for GitHub MCP Server
 *
 * 使用方法:
 *   node scripts/generate-token.js
 *
 * 生成されたIDとSecretを wrangler secret put で登録してください
 */

import crypto from 'crypto';

// ============================================
// 生成
// ============================================

/**
 * base64url エンコード（URL安全、パディングなし）
 */
function toBase64url(buf) {
  return buf.toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

// Client ID: 16バイト (128bit) のランダム値をプレフィックス付きで生成
const clientIdRaw = crypto.randomBytes(16);
const CLIENT_ID = `ghm_${toBase64url(clientIdRaw)}`;

// Client Secret: 48バイト (384bit) の高エントロピーランダム値
const clientSecretRaw = crypto.randomBytes(48);
const CLIENT_SECRET = toBase64url(clientSecretRaw);

// ============================================
// 出力
// ============================================

console.log('\n' + '='.repeat(70));
console.log('🔑 OAuth Client ID / Secret Generated Successfully');
console.log('='.repeat(70));

console.log('\n📋 生成された値（以下をコピーしてください）:');
console.log('-'.repeat(70));
console.log(`OAUTH_CLIENT_ID     = ${CLIENT_ID}`);
console.log(`OAUTH_CLIENT_SECRET = ${CLIENT_SECRET}`);
console.log('-'.repeat(70));

console.log('\n🔒 セキュリティ強度:');
console.log('  • Client ID:     128bit ランダム（プレフィックス ghm_ 付き）');
console.log('  • Client Secret: 384bit ランダム（base64url エンコード）');

console.log('\n🚀 Wrangler への登録コマンド:');
console.log('-'.repeat(70));
console.log(`echo "${CLIENT_ID}" | wrangler secret put OAUTH_CLIENT_ID`);
console.log(`echo "${CLIENT_SECRET}" | wrangler secret put OAUTH_CLIENT_SECRET`);
console.log('-'.repeat(70));

console.log('\n📝 Claude カスタムコネクタ設定:');
console.log('-'.repeat(70));
console.log('  リモートMCPサーバーURL : https://<Worker名>.<サブドメイン>.workers.dev/mcp');
console.log(`  OAuth Client ID       : ${CLIENT_ID}`);
console.log(`  OAuth Client Secret   : ${CLIENT_SECRET}`);
console.log('-'.repeat(70));

console.log('\n⚠️  注意事項:');
console.log('  • このスクリプトを実行するたびに新しい値が生成されます');
console.log('  • 再生成した場合は wrangler secret put で上書き登録してください');
console.log('  • Secret は安全に保管し、第三者と共有しないでください');

console.log('\n' + '='.repeat(70) + '\n');
