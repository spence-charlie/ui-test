import React, { useState, useEffect } from 'react';
import { Eye, EyeOff, Copy, Check, AlertCircle, Lock, Unlock, Code, Zap, Shield, Key } from 'lucide-react';

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
      className={`flex items-center gap-3 px-8 py-4 rounded-xl font-semibold transition-all duration-300 shadow-lg ${
        activeTab === tab
          ? 'bg-gradient-to-r from-indigo-500 to-purple-600 text-white shadow-xl transform scale-105'
          : 'bg-white text-gray-600 hover:bg-gray-50 border-2 border-gray-200 hover:border-gray-300'
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
      title="Copy to clipboard"
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
          <h1 className="text-6xl font-bold bg-gradient-to-r from-indigo-600 via-purple-600 to-pink-600 bg-clip-text text-transparent mb-6">
            JWT Encoder/Decoder
          </h1>
          <p className="text-gray-600 text-xl max-w-2xl mx-auto leading-relaxed">
            Securely encode and decode JSON Web Tokens with our modern, intuitive interface
          </p>
        </div>

        {/* Tab Navigation */}
        <div className="flex justify-center gap-6 mb-12">
          <TabButton tab="decode" label="Decode JWT" icon={Unlock} />
          <TabButton tab="encode" label="Encode JWT" icon={Lock} />
        </div>

        {/* Main Content */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-8">
          {/* Left Panel - Input */}
          <div className="space-y-6">
            <div className="bg-white rounded-2xl p-8 shadow-xl border border-gray-200 backdrop-blur-sm">
              <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-bold flex items-center gap-3 text-gray-800">
                  <Code className="text-indigo-600" size={24} />
                  {activeTab === 'decode' ? 'JWT Token Input' : 'JWT Components'}
                </h2>
                {activeTab === 'decode' && (
                  <button
                    onClick={() => setJwtToken(sampleJWT)}
                    className="px-6 py-3 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white rounded-xl font-medium transition-all duration-200 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
                  >
                    Load Sample
                  </button>
                )}
              </div>

              {activeTab === 'decode' ? (
                <div className="space-y-6">
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                      Paste your JWT token here:
                    </label>
                    <div className="relative">
                      <textarea
                        value={jwtToken}
                        onChange={(e) => setJwtToken(e.target.value)}
                        className="w-full h-36 p-4 bg-gray-50 border-2 border-gray-200 rounded-xl resize-none font-mono text-sm focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 transition-all duration-200"
                        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
                      />
                      <CopyButton
                        text={jwtToken}
                        copyKey="jwt-input"
                        className="absolute top-3 right-3"
                      />
                    </div>
                    {errors.decode && (
                      <div className="flex items-center gap-3 text-red-600 text-sm mt-3 p-3 bg-red-50 rounded-lg border border-red-200">
                        <AlertCircle size={16} />
                        {errors.decode}
                      </div>
                    )}
                  </div>
                  
                  {isValidJWT && (
                    <div className="flex items-center gap-3 text-green-700 text-sm p-3 bg-green-50 rounded-lg border border-green-200">
                      <Check size={16} />
                      Valid JWT format detected
                    </div>
                  )}
                </div>
              ) : (
                <div className="space-y-6">
                  {/* Header */}
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                      Header:
                    </label>
                    <div className="relative">
                      <textarea
                        value={headerInput}
                        onChange={(e) => setHeaderInput(e.target.value)}
                        className="w-full h-28 p-4 bg-red-50 border-2 border-red-200 rounded-xl resize-none font-mono text-sm focus:ring-2 focus:ring-red-400 focus:border-red-400 transition-all duration-200"
                      />
                      <CopyButton
                        text={headerInput}
                        copyKey="header-input"
                        className="absolute top-3 right-3"
                      />
                    </div>
                  </div>

                  {/* Payload */}
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3">
                      Payload:
                    </label>
                    <div className="relative">
                      <textarea
                        value={payloadInput}
                        onChange={(e) => setPayloadInput(e.target.value)}
                        className="w-full h-36 p-4 bg-purple-50 border-2 border-purple-200 rounded-xl resize-none font-mono text-sm focus:ring-2 focus:ring-purple-400 focus:border-purple-400 transition-all duration-200"
                      />
                      <CopyButton
                        text={payloadInput}
                        copyKey="payload-input"
                        className="absolute top-3 right-3"
                      />
                    </div>
                  </div>

                  {/* Secret Key */}
                  <div>
                    <label className="block text-sm font-semibold text-gray-700 mb-3 flex items-center gap-2">
                      <Key size={16} className="text-cyan-600" />
                      Secret Key:
                    </label>
                    <div className="relative">
                      <input
                        type={showSecret ? 'text' : 'password'}
                        value={secretKey}
                        onChange={(e) => setSecretKey(e.target.value)}
                        className="w-full p-4 pr-20 bg-cyan-50 border-2 border-cyan-200 rounded-xl font-mono text-sm focus:ring-2 focus:ring-cyan-400 focus:border-cyan-400 transition-all duration-200"
                      />
                      <div className="absolute right-3 top-3 flex gap-2">
                        <button
                          onClick={() => setShowSecret(!showSecret)}
                          className="p-2 rounded-lg bg-gray-100 hover:bg-gray-200 text-gray-600 transition-colors"
                          title={showSecret ? 'Hide secret' : 'Show secret'}
                        >
                          {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                        </button>
                      </div>
                    </div>
                  </div>

                  <button
                    onClick={encodeJWT}
                    className="w-full py-4 bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-600 hover:to-emerald-700 text-white rounded-xl font-semibold transition-all duration-200 flex items-center justify-center gap-3 shadow-lg hover:shadow-xl transform hover:-translate-y-0.5"
                  >
                    <Zap size={20} />
                    Generate JWT Token
                  </button>

                  {errors.encode && (
                    <div className="flex items-center gap-3 text-red-600 text-sm p-3 bg-red-50 rounded-lg border border-red-200">
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
                <div className="bg-gradient-to-br from-red-50 to-pink-50 rounded-2xl p-6 shadow-lg border-2 border-red-200">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-red-700 flex items-center gap-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      Header
                    </h3>
                    <CopyButton text={decodedHeader} copyKey="header" />
                  </div>
                  <pre className="bg-white p-4 rounded-xl overflow-auto text-sm font-mono max-h-40 border border-red-200">
                    <code className="text-red-600">{decodedHeader || 'No valid JWT token provided'}</code>
                  </pre>
                </div>

                {/* Payload Section */}
                <div className="bg-gradient-to-br from-purple-50 to-indigo-50 rounded-2xl p-6 shadow-lg border-2 border-purple-200">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-purple-700 flex items-center gap-2">
                      <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                      Payload
                    </h3>
                    <CopyButton text={decodedPayload} copyKey="payload" />
                  </div>
                  <pre className="bg-white p-4 rounded-xl overflow-auto text-sm font-mono max-h-40 border border-purple-200">
                    <code className="text-purple-600">{decodedPayload || 'No valid JWT token provided'}</code>
                  </pre>
                </div>

                {/* Signature Section */}
                <div className="bg-gradient-to-br from-cyan-50 to-blue-50 rounded-2xl p-6 shadow-lg border-2 border-cyan-200">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-bold text-cyan-700 flex items-center gap-2">
                      <div className="w-3 h-3 bg-cyan-500 rounded-full"></div>
                      Signature
                    </h3>
                    <CopyButton text={signature} copyKey="signature" />
                  </div>
                  <pre className="bg-white p-4 rounded-xl overflow-auto text-sm font-mono border border-cyan-200">
                    <code className="text-cyan-600 break-all">{signature || 'No valid JWT token provided'}</code>
                  </pre>
                  <div className="mt-4 p-3 bg-cyan-100 rounded-lg">
                    <p className="text-cyan-700 text-sm flex items-center gap-2">
                      <Shield size={16} />
                      Verify signature with your secret key to ensure token integrity.
                    </p>
                  </div>
                </div>
              </>
            ) : (
              /* Generated JWT Output */
              <div className="bg-gradient-to-br from-green-50 to-emerald-50 rounded-2xl p-6 shadow-lg border-2 border-green-200">
                <div className="flex items-center justify-between mb-4">
                  <h3 className="text-lg font-bold text-green-700 flex items-center gap-2">
                    <Zap className="text-green-600" size={20} />
                    Generated JWT Token
                  </h3>
                  <CopyButton text={jwtToken} copyKey="generated-jwt" />
                </div>
                <div className="bg-white p-4 rounded-xl border border-green-200">
                  <code className="text-green-600 break-all font-mono text-sm">
                    {jwtToken || 'Click "Generate JWT Token" to create a new token'}
                  </code>
                </div>
                {jwtToken && (
                  <div className="mt-4 p-4 bg-green-100 rounded-xl">
                    <p className="text-green-700 flex items-center gap-2 font-medium">
                      <Check size={18} />
                      JWT token generated successfully! Ready for authentication.
                    </p>
                  </div>
                )}
              </div>
            )}

            {/* Info Panel */}
            <div className="bg-gradient-to-br from-slate-50 to-gray-100 rounded-2xl p-6 shadow-lg border-2 border-gray-200">
              <h3 className="text-xl font-bold mb-4 text-gray-800 flex items-center gap-2">
                <Shield className="text-indigo-600" size={24} />
                About JWT
              </h3>
              <div className="space-y-4 text-sm text-gray-600">
                <p className="leading-relaxed">
                  <strong className="text-gray-800">JSON Web Token (JWT)</strong> is a compact, URL-safe means of representing claims between two parties in a secure manner.
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                  <div className="p-4 bg-red-50 rounded-xl border border-red-200">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-3 h-3 bg-red-500 rounded-full"></div>
                      <strong className="text-red-700">Header</strong>
                    </div>
                    <p className="text-xs text-red-600">Contains metadata about the token type and algorithm</p>
                  </div>
                  <div className="p-4 bg-purple-50 rounded-xl border border-purple-200">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-3 h-3 bg-purple-500 rounded-full"></div>
                      <strong className="text-purple-700">Payload</strong>
                    </div>
                    <p className="text-xs text-purple-600">Contains the claims and user data</p>
                  </div>
                  <div className="p-4 bg-cyan-50 rounded-xl border border-cyan-200">
                    <div className="flex items-center gap-2 mb-2">
                      <div className="w-3 h-3 bg-cyan-500 rounded-full"></div>
                      <strong className="text-cyan-700">Signature</strong>
                    </div>
                    <p className="text-xs text-cyan-600">Verifies token integrity and authenticity</p>
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