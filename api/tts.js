import crypto from 'crypto';

// 验证会话令牌
function verifySessionToken(token) {
  // 这里可以添加更复杂的会话验证逻辑
  return token && token.length === 64; // 简单的长度检查
}

export default async function handler(req, res) {
  // 检查认证状态
  const sessionToken = req.cookies?.authenticated;
  if (!sessionToken || !verifySessionToken(sessionToken)) {
    return res.status(401).json({ error: '未授权访问' });
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const { text } = req.body;
    if (!text) {
      return res.status(400).json({ error: 'Text is required' });
    }

    const subscription_key = process.env.AZURE_SPEECH_KEY;
    const region = process.env.AZURE_SPEECH_REGION || 'eastasia';
    const endpoint = `https://${region}.tts.speech.microsoft.com/cognitiveservices/v1`;

    if (!subscription_key) {
      throw new Error('Azure Speech API key is not configured');
    }

    // 转义特殊字符
    const escapedText = text.replace(/[&<>"']/g, char => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;'
    })[char]);

    const ssml = `
<speak version="1.0" xmlns="http://www.w3.org/2001/10/synthesis" xml:lang="en-US">
    <voice name="en-GB-SoniaNeural">
        <prosody rate="0%" pitch="0%">
            ${escapedText}
        </prosody>
    </voice>
</speak>`;

    const response = await fetch(endpoint, {
      method: 'POST',
      headers: {
        'Ocp-Apim-Subscription-Key': subscription_key,
        'Content-Type': 'application/ssml+xml',
        'X-Microsoft-OutputFormat': 'audio-24khz-160kbitrate-mono-mp3'
      },
      body: ssml
    });

    if (!response.ok) {
      console.error('Azure Speech API Error:', {
        status: response.status,
        timestamp: new Date().toISOString()
      });
      throw new Error(`Azure Speech API error: ${response.status}`);
    }

    const audioBuffer = await response.arrayBuffer();
    res.setHeader('Content-Type', 'audio/mpeg');
    res.send(Buffer.from(audioBuffer));
  } catch (error) {
    console.error('TTS Error:', {
      message: error.message,
      stack: error.stack,
      timestamp: new Date().toISOString()
    });
    res.status(500).json({ 
      error: 'Failed to generate speech',
      details: error.message 
    });
  }
} 