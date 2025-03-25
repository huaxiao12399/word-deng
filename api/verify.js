import crypto from 'crypto';
import clientPromise from './db';

// 简单的密码哈希函数
function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

// 生成安全的会话令牌
function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// 生成设备标识
function generateDeviceId(req) {
  const userAgent = req.headers['user-agent'] || '';
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  return crypto.createHash('sha256').update(`${userAgent}${ip}`).digest('hex');
}

// 验证会话令牌
function verifySessionToken(token) {
  return token && token.length === 64; // 简单的长度检查
}

export default async function handler(req, res) {
  // 处理 GET 请求（检查登录状态）
  if (req.method === 'GET') {
    try {
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

      return res.status(200).json({ success: true });
    } catch (error) {
      console.error('Auth Check Error:', {
        message: error.message,
        stack: error.stack,
        timestamp: new Date().toISOString(),
        type: error.constructor.name
      });
      return res.status(500).json({ 
        error: '验证失败，请稍后重试',
        details: process.env.NODE_ENV === 'development' ? error.message : undefined
      });
    }
  }

  // 处理 POST 请求（登录）
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    console.log('开始处理登录请求');
    const { password } = req.body;
    
    // 输入验证
    if (!password || typeof password !== 'string') {
      return res.status(400).json({ error: '请输入有效的密码' });
    }

    // 获取密码列表并哈希处理
    const passwords = process.env.ACCESS_PASSWORDS?.split(',').map(p => p.trim()) || [];
    if (passwords.length === 0) {
      console.error('ACCESS_PASSWORDS 环境变量未设置');
      return res.status(500).json({ error: '服务器配置错误' });
    }

    console.log('尝试连接数据库');
    // 测试数据库连接
    const client = await clientPromise;
    const db = client.db('word-pin');
    console.log('数据库连接成功');

    const hashedPasswords = passwords.map(p => hashPassword(p));
    const hashedInput = hashPassword(password);

    // 检查输入的密码是否在允许的密码列表中
    if (hashedPasswords.includes(hashedInput)) {
      const sessionToken = generateSessionToken();
      const deviceId = generateDeviceId(req);
      
      console.log('密码验证成功，更新设备信息');
      // 将当前设备信息存储到数据库
      await db.collection('devices').updateOne(
        { passwordHash: hashedInput },
        { 
          $set: { 
            deviceId,
            lastLogin: new Date(),
            passwordHash: hashedInput
          } 
        },
        { upsert: true }
      );
      console.log('设备信息更新成功');
      
      const cookieOptions = [
        'Path=/',
        'HttpOnly',
        'SameSite=Strict',
        'Max-Age=86400', // 24小时过期
        'Secure' // 仅在HTTPS下传输
      ];

      // 设置安全的 cookie
      res.setHeader('Set-Cookie', [
        `authenticated=${sessionToken}; ${cookieOptions.join('; ')}`,
        `deviceId=${deviceId}; ${cookieOptions.join('; ')}`,
        `passwordHash=${hashedInput}; ${cookieOptions.join('; ')}`,
        `lastLogin=${Date.now()}; ${cookieOptions.join('; ')}`
      ]);

      // 记录成功的登录
      console.log(`登录成功：${new Date().toISOString()} from device ${deviceId}`);
      return res.status(200).json({ success: true });
    }

    // 记录失败的登录尝试
    console.warn(`登录失败：${new Date().toISOString()}`);
    return res.status(401).json({ error: '密码错误' });
  } catch (error) {
    // 记录详细错误信息
    console.error('登录错误:', {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString(),
      type: error.constructor.name,
      mongodbUri: process.env.MONGODB_URI ? '已设置' : '未设置'
    });
    return res.status(500).json({ 
      error: '验证失败，请稍后重试',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
} 
