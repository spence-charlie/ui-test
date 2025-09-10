import React, { useState, useEffect } from "react";
import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/ui/tabs";
import { Card, CardHeader, CardContent, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Eye,
  EyeOff,
  Copy,
  Check,
  Shield,
  Key,
  Download,
  Zap,
} from "lucide-react";

// ===== Utilities =====
const base64UrlEncode = (str) => {
  const utf8 = new TextEncoder().encode(str);
  let binary = "";
  utf8.forEach((b) => (binary += String.fromCharCode(b)));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
};

const base64UrlDecode = (str) => {
  let padding = str.length % 4;
  if (padding) str += "=".repeat(4 - padding);
  const binStr = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  const bytes = Uint8Array.from(binStr, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
};

const hmacSHA256 = async (message, secret) => {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return base64UrlEncode(String.fromCharCode(...new Uint8Array(signature)));
};

// ===== Component =====
const JWTTool = () => {
  const [jwtToken, setJwtToken] = useState("");
  const [header, setHeader] = useState('{\n  "alg": "HS256",\n  "typ": "JWT"\n}');
  const [payload, setPayload] = useState('{\n  "sub": "1234567890",\n  "name": "John Doe",\n  "iat": 1516239022,\n  "exp": 1735689600\n}');
  const [secret, setSecret] = useState("your-256-bit-secret");
  const [showSecret, setShowSecret] = useState(false);
  const [copyStates, setCopyStates] = useState({});
  const [decodeData, setDecodeData] = useState(null);
  const [expiryInfo, setExpiryInfo] = useState(null);
  const [sigValid, setSigValid] = useState(null);

  // Sample JWT
  const sample =
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE3MzU2ODk2MDB9.kP_DQyZdBcVfOGaB8Q3lE7-PRLJXrOxcOw7D5tlA7Ok";

  // Decode JWT
  const decodeJWT = async (token) => {
    try {
      const parts = token.split(".");
      if (parts.length !== 3) return;

      const h = JSON.parse(base64UrlDecode(parts[0]));
      const p = JSON.parse(base64UrlDecode(parts[1]));
      const s = parts[2];

      setDecodeData({ header: h, payload: p, signature: s });

      if (p.exp) {
        const now = Math.floor(Date.now() / 1000);
        setExpiryInfo({
          exp: p.exp,
          expired: now > p.exp,
        });
      }

      if (secret && secret !== "your-256-bit-secret") {
        const valid = await verifySignature(token, secret);
        setSigValid(valid);
      }
    } catch {
      setDecodeData(null);
      setExpiryInfo(null);
      setSigValid(null);
    }
  };

  const verifySignature = async (token, sec) => {
    try {
      const [h, p, s] = token.split(".");
      const expected = await hmacSHA256(`${h}.${p}`, sec);
      return s === expected;
    } catch {
      return false;
    }
  };

  // Encode JWT
  const encodeJWT = async () => {
    try {
      const h = JSON.parse(header);
      const p = JSON.parse(payload);
      const hEnc = base64UrlEncode(JSON.stringify(h));
      const pEnc = base64UrlEncode(JSON.stringify(p));
      const msg = `${hEnc}.${pEnc}`;
      const sig = await hmacSHA256(msg, secret);
      const token = `${msg}.${sig}`;
      setJwtToken(token);
      decodeJWT(token);
    } catch {
      alert("Invalid JSON in header or payload");
    }
  };

  // Copy helper
  const copyToClipboard = async (text, key) => {
    try {
      await navigator.clipboard.writeText(text);
      setCopyStates((prev) => ({ ...prev, [key]: true }));
      setTimeout(
        () => setCopyStates((prev) => ({ ...prev, [key]: false })),
        1500
      );
    } catch {}
  };

  useEffect(() => {
    if (jwtToken) decodeJWT(jwtToken);
  }, [jwtToken, secret]);

  useEffect(() => {
    setJwtToken(sample);
  }, []);

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="flex justify-center mb-8">
        <Shield size={40} className="text-indigo-600" />
      </div>
      <h1 className="text-4xl font-bold text-center mb-8">
        JWT Encoder / Decoder
      </h1>

      <Tabs defaultValue="decode" className="w-full">
        <TabsList className="grid w-full grid-cols-2">
          <TabsTrigger value="decode">Decode</TabsTrigger>
          <TabsTrigger value="encode">Encode</TabsTrigger>
        </TabsList>

        {/* Decode */}
        <TabsContent value="decode">
          <Card className="mt-6">
            <CardHeader>
              <CardTitle>JWT Token</CardTitle>
            </CardHeader>
            <CardContent>
              <Textarea
                value={jwtToken}
                onChange={(e) => setJwtToken(e.target.value)}
                placeholder="Paste JWT here"
                className="mb-4 font-mono text-sm"
              />
              <Button onClick={() => setJwtToken(sample)} size="sm">
                Load Sample
              </Button>
            </CardContent>
          </Card>

          {decodeData && (
            <div className="grid md:grid-cols-3 gap-4 mt-6">
              <Card>
                <CardHeader className="flex flex-row justify-between items-center">
                  <CardTitle>Header</CardTitle>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() =>
                      copyToClipboard(JSON.stringify(decodeData.header, null, 2), "header")
                    }
                  >
                    {copyStates.header ? <Check size={16} /> : <Copy size={16} />}
                  </Button>
                </CardHeader>
                <CardContent>
                  <pre className="text-sm bg-red-50 p-2 rounded font-mono">
                    {JSON.stringify(decodeData.header, null, 2)}
                  </pre>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row justify-between items-center">
                  <CardTitle>Payload</CardTitle>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() =>
                      copyToClipboard(JSON.stringify(decodeData.payload, null, 2), "payload")
                    }
                  >
                    {copyStates.payload ? <Check size={16} /> : <Copy size={16} />}
                  </Button>
                </CardHeader>
                <CardContent>
                  <pre className="text-sm bg-purple-50 p-2 rounded font-mono">
                    {JSON.stringify(decodeData.payload, null, 2)}
                  </pre>
                  {expiryInfo && (
                    <Badge
                      className={`mt-2 ${
                        expiryInfo.expired ? "bg-red-500" : "bg-green-500"
                      }`}
                    >
                      {expiryInfo.expired
                        ? "Expired"
                        : `Valid until ${new Date(expiryInfo.exp * 1000).toLocaleString()}`}
                    </Badge>
                  )}
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="flex flex-row justify-between items-center">
                  <CardTitle>Signature</CardTitle>
                  <Button
                    size="icon"
                    variant="ghost"
                    onClick={() => copyToClipboard(decodeData.signature, "sig")}
                  >
                    {copyStates.sig ? <Check size={16} /> : <Copy size={16} />}
                  </Button>
                </CardHeader>
                <CardContent>
                  <pre className="text-xs bg-blue-50 p-2 rounded font-mono break-all">
                    {decodeData.signature}
                  </pre>
                  {sigValid !== null && (
                    <Badge className={sigValid ? "bg-green-500" : "bg-red-500"} mt-2>
                      {sigValid ? "Signature Verified" : "Invalid Signature"}
                    </Badge>
                  )}
                </CardContent>
              </Card>
            </div>
          )}
        </TabsContent>

        {/* Encode */}
        <TabsContent value="encode">
          <div className="grid md:grid-cols-2 gap-6 mt-6">
            <Card>
              <CardHeader>
                <CardTitle>Header</CardTitle>
              </CardHeader>
              <CardContent>
                <Textarea
                  value={header}
                  onChange={(e) => setHeader(e.target.value)}
                  className="font-mono text-sm"
                />
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Payload</CardTitle>
              </CardHeader>
              <CardContent>
                <Textarea
                  value={payload}
                  onChange={(e) => setPayload(e.target.value)}
                  className="font-mono text-sm"
                />
              </CardContent>
            </Card>
          </div>

          <Card className="mt-6">
            <CardHeader>
              <CardTitle>Secret Key</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex gap-2">
                <Input
                  type={showSecret ? "text" : "password"}
                  value={secret}
                  onChange={(e) => setSecret(e.target.value)}
                  className="font-mono"
                />
                <Button
                  variant="outline"
                  onClick={() => setShowSecret(!showSecret)}
                >
                  {showSecret ? <EyeOff size={16} /> : <Eye size={16} />}
                </Button>
              </div>
            </CardContent>
          </Card>

          <div className="mt-6 flex gap-4">
            <Button onClick={encodeJWT} className="flex items-center gap-2">
              <Zap size={16} /> Generate JWT
            </Button>
            <Button
              variant="secondary"
              onClick={() => copyToClipboard(jwtToken, "token")}
            >
              {copyStates.token ? <Check size={16} /> : <Copy size={16} />}
              Copy Token
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                const blob = new Blob([jwtToken], { type: "text/plain" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = "jwt.txt";
                a.click();
                URL.revokeObjectURL(url);
              }}
            >
              <Download size={16} /> Export
            </Button>
          </div>

          {jwtToken && (
            <Card className="mt-6">
              <CardHeader>
                <CardTitle>Generated JWT</CardTitle>
              </CardHeader>
              <CardContent>
                <pre className="text-xs bg-green-50 p-2 rounded font-mono break-all">
                  {jwtToken}
                </pre>
              </CardContent>
            </Card>
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default JWTTool;
