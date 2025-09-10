import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Copy, Check, AlertCircle, Lock, Unlock, Code, Zap } from 'lucide-react';

const JWTPage = () => {
  const [jwtToken, setJwtToken] = useState('');
  const [decodedHeader, setDecodedHeader] = useState('');
  const [decodedPayload, setDecodedPayload] = useState('');
  const [signature, setSignature] = useState('');
  const [headerInput, setHeaderInput] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payloadInput, setPayloadInput] = useState('{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022\n}');
  const [secretKey, setSecretKey] = useState('your-256-bit-secret');
  const [showSecret, setShowSecret] = useState(false);
  const [activeTab, setActiveTab] = useState('decode');
  const [copyStates, setCopyStates] = useState({});
  const [errors, setErrors] = useState({});
  const [isValidJWT, setIsValidJWT] = useState(false);

  // Sample JWT for demo
  const sampleJWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

  // Base64 URL encode/decode functions
  const base64UrlEncode = (str) => {
    return btoa(str)
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  };

  const base64UrlDecode = (str) => {
    let padding = str.length % 4;
    if (padding) {
      str += '='.repeat(4 - padding);
    }
    return atob(str.replace(/-/g, '+').replace(/_/g, '/'));
  };

  // HMAC SHA256 implementation (simplified for demo)
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

  // Decode JWT
  const decodeJWT = (token) => {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) {
        setErrors({ decode: 'Invalid JWT format. JWT should have 3 parts separated by dots.' });
        setIsValidJWT(false);
        return;
      }

      const header = JSON.parse(base64UrlDecode(parts[0]));
      const payload = JSON.parse(base64UrlDecode(parts[1]));
      const sig = parts[2];

      setDecodedHeader(JSON.stringify(header, null, 2));
      setDecodedPayload(JSON.stringify(payload, null, 2));
      setSignature(sig);
      setIsValidJWT(true);
      setErrors({});
    } catch (error) {
      setErrors({ decode: 'Invalid JWT token. Please check the format.' });
      setIsValidJWT(false);
    }
  };

  // Encode JWT
  const encodeJWT = async () => {
    try {
      const header = JSON.parse(headerInput);
      const payload = JSON.parse(payloadInput);

      const headerEncoded = base64UrlEncode(JSON.stringify(header));
      const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
      const message = `${headerEncoded}.${payloadEncoded}`;
      
      const sig = await hmacSHA256(message, secretKey);
      const token = `${message}.${sig}`;
      
      setJwtToken(token);
      setErrors({});
    } catch (error) {
      setErrors({ encode: 'Invalid JSON format in header or payload.' });
    }
  };

  // Copy to clipboard
  const copyToClipboard = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStates({ ...copyStates, [key]: true });
      setTimeout(() => setCopyStates({ ...copyStates, [key]: false }), 2000);
    } catch (err) {
      console.error('Failed to copy: ', err);
    }
  };

  // Auto-decode when JWT token changes
  useEffect(() => {
    if (jwtToken && activeTab === 'decode') {
      decodeJWT(jwtToken);
    }
  }, [jwtToken, activeTab]);

  // Load sample JWT on mount
  useEffect(() => {
    setJwtToken(sampleJWT);
  }, []);

  const TabButton = ({ tab, label, icon: Icon }) => (
    <button
      onClick={() => setActiveTab(tab)}
      className={`flex items-center gap-2 px-6 py-3 rounded-lg font-semibold transition-all duration-200 ${
        activeTab === tab
          ? 'bg-gradient-to-r from-blue-500 to-purple-600 text-white shadow-lg'
          : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
      }`}
    >
      <Icon size={18} />
      {label}
    </button>
  );

  const CopyButton = ({ text, copyKey, className = '' }) => (
    <button
      onClick={() => copyToClipboard(text, copyKey)}
      className={`p-2 rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors ${className}`}
      title="Copy to clipboard"
    >
      {copyStates[copyKey] ? <Check size={16} className="text-green-400" /> : <Copy size={16} />}
    </button>
  );

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-6">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-5xl font-bold bg-gradient-to-r from-blue-400 to-purple-500 bg-clip-text text-transparent mb-4">
            JWT Encoder/Decoder
          </h1>
          <p className="text-gray-400 text-lg">
            Encode and decode JSON Web Tokens with a modern, secure interface
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex justify-center gap-4 mb-8">
          <TabButton tab="decode" label="Decode JWT" icon={Unlock} />
          <TabButton tab="encode" label="Encode JWT" icon={Lock} />
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          {/* Left Panel - Input */}
          <div className="space-y-6">
            <div className="bg-gray-800 rounded-xl p-6 shadow-2xl border border-gray-700">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold flex items-center gap-2">
                  <Code size={20} />
                  {activeTab === 'decode' ? 'JWT Token Input' : 'JWT Components'}
                </h2>
                {activeTab === 'decode' && (
                  <button
                    onClick={() => setJwtToken(sampleJWT)}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded-lg text-sm font-medium transition-colors"
                  >
                    Load Sample
                  </button>
                )}
              </div>

              {activeTab === 'decode' ? (
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Paste your JWT token here:
                    </label>
                    <div className="relative">
                      <textarea
                        value={jwtToken}
                        onChange={(e) => setJwtToken(e.target.value)}
                        className="w-full h-32 p-4 bg-gray-900 border border-gray-600 rounded-lg resize-none font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                      />
                      <CopyButton
                        text={jwtToken}
                        copyKey="jwt-input"
                        className="absolute top-2 right-2"
                      />
                    </div>
                    {errors.decode && (
                      <div className="flex items-center gap-2 text-red-400 text-sm mt-2">
                        <AlertCircle size={16} />
                        {errors.decode}
                      </div>
                    )}
                  </div>
                  
                  {isValidJWT && (
                    <div className="flex items-center gap-2 text-green-400 text-sm">
                      <Check size={16} />
                      Valid JWT format detected
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Header */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Header:
                    </label>
                    <div className="relative">
                      <textarea
                        value={headerInput}
                        onChange={(e) => setHeaderInput(e.target.value)}
                        className="w-full h-24 p-4 bg-gray-900 border border-gray-600 rounded-lg resize-none font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                      <CopyButton
                        text={headerInput}
                        copyKey="header-input"
                        className="absolute top-2 right-2"
                      />
                    </div>
                  </div>

                  {/* Payload */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Payload:
                    </label>
                    <div className="relative">
                      <textarea
                        value={payloadInput}
                        onChange={(e) => setPayloadInput(e.target.value)}
                        className="w-full h-32 p-4 bg-gray-900 border border-gray-600 rounded-lg resize-none font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                      <CopyButton
                        text={payloadInput}
                        copyKey="payload-input"
                        className="absolute top-2 right-2"
                      />
                    </div>
                  </div>

                  {/* Secret Key */}
                  <div>
                    <label className="block text-sm font-medium text-gray-300 mb-2">
                      Secret Key:
                    </label>
                    <div className="relative">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={secretKey}
                        onChange={(e) => setSecretKey(e.target.value)}
                        className="w-full p-4 pr-20 bg-gray-900 border border-gray-600 rounded-lg font-mono text-sm focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                      />
                      <div className="absolute right-2 top-2 flex gap-2">
                        <button
                          onClick={() => setShowSecret(!showSecret)}
                          className="p-2 rounded-lg bg-gray-700 hover:bg-gray-600 transition-colors"
                          title={showSecret ? 'Hide secret' : 'Show secret'}
                        >
                          {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={encodeJWT}
                    className="w-full py-4 bg-gradient-to-r from-green-500 to-blue-600 hover:from-green-600 hover:to-blue-700 rounded-lg font-semibold transition-all duration-200 flex items-center justify-center gap-2 shadow-lg"
                  >
                    <Zap size={20} />
                    Generate JWT Token
                  </button>

                  {errors.encode && (
                    <div className="flex items-center gap-2 text-red-400 text-sm">
                      <AlertCircle size={16} />
                      {errors.encode}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Right Panel - Output */}
          <div className="space-y-6">
            {activeTab === 'decode' ? (
              <>
                {/* Header Section */}
                <div className="bg-gradient-to-r from-red-900/20 to-pink-900/20 rounded-xl p-6 shadow-2xl border border-red-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-red-300">Header</h3>
                    <CopyButton text={decodedHeader} copyKey="header" />
                  </div>
                  <pre className="bg-gray-900 p-4 rounded-lg overflow-auto text-sm font-mono max-h-40">
                    <code className="text-red-300">{decodedHeader || 'No valid JWT token provided'}</code>
                  </pre>
                </div>

                {/* Payload Section */}
                <div className="bg-gradient-to-r from-purple-900/20 to-blue-900/20 rounded-xl p-6 shadow-2xl border border-purple-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-purple-300">Payload</h3>
                    <CopyButton text={decodedPayload} copyKey="payload" />
                  </div>
                  <pre className="bg-gray-900 p-4 rounded-lg overflow-auto text-sm font-mono max-h-40">
                    <code className="text-purple-300">{decodedPayload || 'No valid JWT token provided'}</code>
                  </pre>
                </div>

                {/* Signature Section */}
                <div className="bg-gradient-to-r from-cyan-900/20 to-teal-900/20 rounded-xl p-6 shadow-2xl border border-cyan-500/30">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-semibold text-cyan-300">Signature</h3>
                    <CopyButton text={signature} copyKey="signature" />
                  </div>
                  <pre className="bg-gray-900 p-4 rounded-lg overflow-auto text-sm font-mono">
                    <code className="text-cyan-300 break-all">{signature || 'No valid JWT token provided'}</code>
                  </pre>
                  <p className="text-gray-400 text-sm mt-2">
                    Verify signature with your secret key to ensure token integrity.
                  </p>
                </div>
              </>
            ) : (
              /* Generated JWT Output */
              <div className="bg-gradient-to-r from-green-900/20 to-blue-900/20 rounded-xl p-6 shadow-2xl border border-green-500/30">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-semibold text-green-300 flex items-center gap-2">
                    <Zap size={20} />
                    Generated JWT Token
                  </h3>
                  <CopyButton text={jwtToken} copyKey="generated-jwt" />
                </div>
                <div className="bg-gray-900 p-4 rounded-lg">
                  <code className="text-green-300 break-all font-mono text-sm">
                    {jwtToken || 'Click "Generate JWT Token" to create a new token'}
                  </code>
                </div>
                {jwtToken && (
                  <div className="mt-4 p-3 bg-green-900/30 rounded-lg">
                    <p className="text-green-300 text-sm flex items-center gap-2">
                      <Check size={16} />
                      JWT token generated successfully! You can now use this token for authentication.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Info Panel */}
            <div className="bg-gray-800/50 rounded-xl p-6 shadow-xl border border-gray-600">
              <h3 className="text-lg font-semibold mb-4 text-blue-300">About JWT</h3>
              <div className="space-y-3 text-sm text-gray-400">
                <p>
                  <strong className="text-gray-300">JSON Web Token (JWT)</strong> is a compact, URL-safe means of representing claims between two parties.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <div className="p-3 bg-red-900/20 rounded-lg border border-red-500/30">
                    <strong className="text-red-300">Header</strong>
                    <p className="text-xs mt-1">Contains metadata about the token</p>
                  </div>
                  <div className="p-3 bg-purple-900/20 rounded-lg border border-purple-500/30">
                    <strong className="text-purple-300">Payload</strong>
                    <p className="text-xs mt-1">Contains the claims and data</p>
                  </div>
                  <div className="p-3 bg-cyan-900/20 rounded-lg border border-cyan-500/30">
                    <strong className="text-cyan-300">Signature</strong>
                    <p className="text-xs mt-1">Ensures token integrity</p>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default JWTPage;