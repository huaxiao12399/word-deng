import crypto from 'crypto';
import clientPromise from './db';

// 验证会话令牌
function verifySessionToken(token) {
  return token && token.length === 64; // 简单的长度检查
}

// 验证密码哈希
function verifyPasswordHash(passwordHash, storedHash) {
  return passwordHash === storedHash;
}

export default async function handler(req, res) {
  // 检查认证状态
  const sessionToken = req.cookies?.authenticated;
  const deviceId = req.cookies?.deviceId;
  const passwordHash = req.cookies?.passwordHash;

  if (!sessionToken || !deviceId || !passwordHash || !verifySessionToken(sessionToken)) {
    return res.status(401).json({ error: '未授权访问' });
  }

  // 从数据库获取当前登录的设备信息
  const client = await clientPromise;
  const db = client.db('word-pin');
  const device = await db.collection('devices').findOne({ passwordHash });
  
  if (!device || device.deviceId !== deviceId) {
    return res.status(401).json({ 
      error: '当前设备未登录',
      message: '系统仅允许同时登录一台设备。如需在此设备上使用，请重新输入密码登录。'
    });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const API_URL = "https://generativelanguage.googleapis.com/v1beta";
    const API_KEY = process.env.GEMINI_API_KEY;

    if (!API_KEY) {
      throw new Error('API key is not configured');
    }

    const payload = req.body;
    if (!payload.contents || !payload.contents[0]?.parts?.[0]?.text) {
      return res.status(400).json({ error: 'Invalid request format' });
    }

    const response = await fetch(`${API_URL}/models/gemini-2.0-flash:generateContent?key=${API_KEY}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      console.error('Gemini API Error:', {
        status: response.status,
        data: errorData,
        timestamp: new Date().toISOString()
      });
      throw new Error(`HTTP error! status: ${response.status}`);
    }

    const data = await response.json();
    
    if (data.candidates && data.candidates.length > 0) {
      const result = data.candidates[0].content.parts[0].text;
      res.json({ result });
    } else {
      throw new Error('No valid response from API');
    }
  } catch (error) {
    console.error('API Error:', {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      error: 'Failed to fetch word information',
      details: error.message 
    });
  }
}