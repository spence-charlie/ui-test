import React, { useState, useEffect } from 'react';
import { 
  Eye, EyeOff, Copy, Check, AlertCircle, Lock, Unlock, Code, Zap, Shield, Key, RefreshCw, Download, Calendar, Clock 
} from 'lucide-react';

const JWTPage = () => {
  const [jwtToken, setJwtToken] = useState('');
  const [decodedHeader, setDecodedHeader] = useState('');
  const [decodedPayload, setDecodedPayload] = useState('');
  const [signature, setSignature] = useState('');
  const [headerInput, setHeaderInput] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payloadInput, setPayloadInput] = useState('{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022,\n  "exp": 1735689600\n}');
  const [secretKey, setSecretKey] = useState('your-256-bit-secret');
  const [showSecret, setShowSecret] = useState(false);
  const [activeTab, setActiveTab] = useState('decode');
  const [copyStates, setCopyStates] = useState({});
  const [decodeError, setDecodeError] = useState(null);
  const [encodeError, setEncodeError] = useState(null);
  const [isValidJWT, setIsValidJWT] = useState(false);
  const [tokenExpiry, setTokenExpiry] = useState(null);
  const [isTokenExpired, setIsTokenExpired] = useState(false);
  const [signatureValid, setSignatureValid] = useState(null);

  // Sample JWT
  const sampleJWT =
    'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MzU2ODk2MDB9.kP_DQyZdBcVfOGaB8Q3lE7-PRLJXrOxcOw7D5tlA7Ok';

  // Base64 URL encode/decode with UTF-8
  const base64UrlEncode = (str) => {
    const utf8 = new TextEncoder().encode(str);
    let binary = '';
    utf8.forEach((b) => (binary += String.fromCharCode(b)));
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };

  const base64UrlDecode = (str) => {
    let padding = str.length % 4;
    if (padding) str += '='.repeat(4 - padding);
    const binStr = atob(str.replace(/-/g, '+').replace(/_/g, '/'));
    const bytes = Uint8Array.from(binStr, (c) => c.charCodeAt(0));
    return new TextDecoder().decode(bytes);
  };

  // HMAC SHA256
  const hmacSHA256 = async (message, secret) => {
    const encoder = new TextEncoder();
    const key = await crypto.subtle.importKey(
      'raw',
      encoder.encode(secret),
      { name: 'HMAC', hash: 'SHA-256' },
      false,
      ['sign']
    );
    const signature = await crypto.subtle.sign('HMAC', key, encoder.encode(message));
    return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
  };

  // Verify signature
  const verifySignature = async (token, secret) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return false;

      const message = `${parts[0]}.${parts[1]}`;
      const expectedSignature = await hmacSHA256(message, secret);
      return parts[2] === expectedSignature;
    } catch {
      return false;
    }
  };

  // Generate random secret
  const generateRandomSecret = () => {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    const secret = Array.from(array, (b) => b.toString(16).padStart(2, '0')).join('');
    setSecretKey(secret);
  };

  // Update payload timestamps
  const updateTimestamps = () => {
    try {
      const payload = JSON.parse(payloadInput);
      const now = Math.floor(Date.now() / 1000);
      payload.iat = now;
      payload.exp = now + 3600;
      setPayloadInput(JSON.stringify(payload, null, 2));
    } catch {
      // ignore
    }
  };

  // Format timestamp
  const formatTimestamp = (ts) => {
    if (!ts) return 'N/A';
    try {
      return new Date(ts * 1000).toLocaleString();
    } catch {
      return 'Invalid';
    }
  };

  // Expiry check
  const checkTokenExpiry = (payloadObj) => {
    if (payloadObj?.exp) {
      const now = Math.floor(Date.now() / 1000);
      setTokenExpiry(payloadObj.exp);
      setIsTokenExpired(now > payloadObj.exp);
    } else {
      setTokenExpiry(null);
      setIsTokenExpired(false);
    }
  };

  // Decode JWT
  const decodeJWT = async (token) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        setDecodeError('Invalid JWT format. Should have 3 parts separated by dots.');
        setIsValidJWT(false);
        setSignatureValid(null);
        return;
      }

      const header = JSON.parse(base64UrlDecode(parts[0]));
      if (header.alg !== 'HS256') {
        setDecodeError(`Unsupported algorithm: ${header.alg}. Only HS256 is supported.`);
        setIsValidJWT(false);
        return;
      }

      const payload = JSON.parse(base64UrlDecode(parts[1]));
      const sig = parts[2];

      setDecodedHeader(JSON.stringify(header, null, 2));
      setDecodedPayload(JSON.stringify(payload, null, 2));
      setSignature(sig);
      setIsValidJWT(true);
      setDecodeError(null);

      checkTokenExpiry(payload);

      if (secretKey && secretKey !== 'your-256-bit-secret') {
        const valid = await verifySignature(token, secretKey);
        setSignatureValid(valid);
      } else {
        setSignatureValid(null);
      }
    } catch {
      setDecodeError('Invalid JWT token. Please check the format.');
      setIsValidJWT(false);
      setSignatureValid(null);
    }
  };

  // Encode JWT
  const encodeJWT = async () => {
    try {
      const header = JSON.parse(headerInput);
      const payload = JSON.parse(payloadInput);
      if (header.alg !== 'HS256') {
        setEncodeError('Only HS256 algorithm is supported for encoding.');
        return;
      }

      const h = base64UrlEncode(JSON.stringify(header));
      const p = base64UrlEncode(JSON.stringify(payload));
      const msg = `${h}.${p}`;
      const sig = await hmacSHA256(msg, secretKey);
      const token = `${msg}.${sig}`;

      setJwtToken(token);
      setEncodeError(null);
      await decodeJWT(token);
    } catch {
      setEncodeError('Invalid JSON format in header or payload.');
    }
  };

  // Export
  const exportToken = () => {
    const data = {
      token: jwtToken,
      header: decodedHeader,
      payload: decodedPayload,
      signature,
      created: new Date().toISOString(),
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'jwt-token.json';
    a.click();
    URL.revokeObjectURL(url);
  };

  // Copy
  const copyToClipboard = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStates((prev) => ({ ...prev, [key]: true }));
      setTimeout(() => {
        setCopyStates((prev) => ({ ...prev, [key]: false }));
      }, 2000);
    } catch (err) {
      console.error('Copy failed: ', err);
    }
  };

  // Effects
  useEffect(() => {
    if (jwtToken && activeTab === 'decode') {
      decodeJWT(jwtToken);
    }
  }, [jwtToken, activeTab]);

  useEffect(() => {
    setJwtToken(sampleJWT);
  }, []);

  const TabButton = ({ tab, label, icon: Icon }) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`flex items-center gap-3 px-8 py-4 rounded-xl font-semibold transition-all duration-300 shadow-lg ${
        activeTab === tab
          ? 'bg-gradient-to-r from-indigo-500 to-purple-600 text-white scale-105'
          : 'bg-white text-gray-600 hover:bg-gray-50 border-2 border-gray-200'
      }`}
    >
      <Icon size={20} />
      {label}
    </button>
  );

  const CopyButton = ({ text, copyKey, className = '' }) => (
    <button
      onClick={() => copyToClipboard(text, copyKey)}
      className={`p-2 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-600 hover:text-gray-800 transition-all duration-200 ${className}`}
      title="Copy"
    >
      {copyStates[copyKey] ? <Check size={16} className="text-green-600" /> : <Copy size={16} />}
    </button>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-white to-blue-50 p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-12">
          <div className="flex justify-center mb-6">
            <div className="p-4 bg-gradient-to-r from-indigo-500 to-purple-600 rounded-2xl shadow-lg">
              <Shield className="text-white" size={48} />
            </div>
          </div>
          <h1 className="text-5xl font-bold bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-6">
            JWT Encoder / Decoder
          </h1>
        </div>

        {/* Tabs */}
        <div className="flex justify-center gap-6 mb-12">
          <TabButton tab="decode" label="Decode JWT" icon={Unlock} />
          <TabButton tab="encode" label="Encode JWT" icon={Lock} />
        </div>

        {/* Layout */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          {/* Input Panel */}
          <div className="space-y-6">
            <div className="bg-white rounded-2xl p-8 shadow-xl border border-gray-200">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold flex items-center gap-3 text-gray-800">
                  <Code className="text-indigo-600" size={24} />
                  {activeTab === 'decode' ? 'JWT Token Input' : 'JWT Components'}
                </h2>
                {activeTab === 'decode' && (
                  <button
                    onClick={() => setJwtToken(sampleJWT)}
                    className="px-6 py-2 bg-gradient-to-r from-blue-500 to-indigo-600 text-white rounded-xl"
                  >
                    Load Sample
                  </button>
                )}
              </div>

              {activeTab === 'decode' ? (
                <>
                  <textarea
                    value={jwtToken}
                    onChange={(e) => setJwtToken(e.target.value)}
                    className="w-full h-32 p-4 bg-gray-50 border-2 border-gray-200 rounded-xl font-mono text-sm"
                  />
                  {decodeError && (
                    <div className="flex items-center gap-2 text-red-600 text-sm mt-3">
                      <AlertCircle size={16} />
                      {decodeError}
                    </div>
                  )}
                  <div className="mt-4">
                    <label className="block text-sm font-semibold mb-2 flex items-center gap-2">
                      <Key size={16} />
                      Secret Key:
                    </label>
                    <div className="relative">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={secretKey}
                        onChange={(e) => setSecretKey(e.target.value)}
                        className="w-full p-3 pr-20 border-2 rounded-xl"
                      />
                      <button
                        onClick={() => setShowSecret(!showSecret)}
                        className="absolute right-3 top-3 p-2"
                      >
                        {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <textarea
                    value={headerInput}
                    onChange={(e) => setHeaderInput(e.target.value)}
                    className="w-full h-24 p-4 bg-red-50 border-2 border-red-200 rounded-xl font-mono text-sm"
                  />
                  <textarea
                    value={payloadInput}
                    onChange={(e) => setPayloadInput(e.target.value)}
                    className="w-full h-32 p-4 bg-purple-50 border-2 border-purple-200 rounded-xl font-mono text-sm"
                  />
                  <div className="mt-4">
                    <label className="block text-sm font-semibold mb-2 flex items-center gap-2">
                      <Key size={16} />
                      Secret Key:
                    </label>
                    <div className="relative">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={secretKey}
                        onChange={(e) => setSecretKey(e.target.value)}
                        className="w-full p-3 pr-20 border-2 rounded-xl"
                      />
                      <button
                        onClick={() => setShowSecret(!showSecret)}
                        className="absolute right-3 top-3 p-2"
                      >
                        {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                      </button>
                    </div>
                  </div>
                  <button
                    onClick={encodeJWT}
                    className="w-full py-3 bg-gradient-to-r from-green-500 to-emerald-600 text-white rounded-xl"
                  >
                    <Zap size={18} /> Generate JWT
                  </button>
                  {encodeError && (
                    <div className="flex items-center gap-2 text-red-600 text-sm mt-3">
                      <AlertCircle size={16} />
                      {encodeError}
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {/* Output Panel */}
          <div className="space-y-6">
            {activeTab === 'decode' ? (
              <>
                <div className="p-4 bg-red-50 rounded-xl">
                  <h3 className="text-red-700 font-bold mb-2">Header</h3>
                  <pre className="bg-white p-3 rounded-xl text-sm font-mono">{decodedHeader}</pre>
                </div>
                <div className="p-4 bg-purple-50 rounded-xl">
                  <h3 className="text-purple-700 font-bold mb-2">Payload</h3>
                  <pre className="bg-white p-3 rounded-xl text-sm font-mono">{decodedPayload}</pre>
                  {tokenExpiry && (
                    <div className="mt-2 text-sm">
                      <Clock size={14} className="inline mr-1" />
                      {isTokenExpired
                        ? `Expired on ${formatTimestamp(tokenExpiry)}`
                        : `Expires on ${formatTimestamp(tokenExpiry)}`}
                    </div>
                  )}
                </div>
                <div className="p-4 bg-cyan-50 rounded-xl">
                  <h3 className="text-cyan-700 font-bold mb-2">Signature</h3>
                  <pre className="bg-white p-3 rounded-xl text-sm font-mono break-all">{signature}</pre>
                  {signatureValid !== null && (
                    <div
                      className={`mt-2 text-sm font-semibold ${
                        signatureValid ? 'text-green-700' : 'text-red-700'
                      }`}
                    >
                      {signatureValid ? 'Signature verified ✅' : 'Signature invalid ❌'}
                    </div>
                  )}
                </div>
              </>
            ) : (
              <div className="p-4 bg-green-50 rounded-xl">
                <h3 className="text-green-700 font-bold mb-2">Generated JWT</h3>
                <pre className="bg-white p-3 rounded-xl text-sm font-mono break-all">{jwtToken}</pre>
              </div>
            )}
            {jwtToken && (
              <button
                onClick={exportToken}
                className="w-full py-2 bg-gray-700 text-white rounded-xl"
              >
                <Download size={16} className="inline mr-2" />
                Export Token
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default JWTPage;
