import { MongoClient } from 'mongodb';

if (!process.env.MONGODB_URI) {
  throw new Error('请在环境变量中设置 MONGODB_URI');
}

const uri = process.env.MONGODB_URI;
const options = {
  connectTimeoutMS: 10000, // 连接超时时间
  socketTimeoutMS: 45000,  // Socket 超时时间
  maxPoolSize: 10,         // 最大连接池大小
};

let client;
let clientPromise;

if (process.env.NODE_ENV === 'development') {
  // 在开发环境中使用全局变量来保持连接池
  if (!global._mongoClientPromise) {
    client = new MongoClient(uri, options);
    global._mongoClientPromise = client.connect()
      .catch(err => {
        console.error('MongoDB 连接错误:', {
          message: err.message,
          stack: err.stack,
          timestamp: new Date().toISOString()
        });
        throw err;
      });
  }
  clientPromise = global._mongoClientPromise;
} else {
  // 在生产环境中创建新的连接
  client = new MongoClient(uri, options);
  clientPromise = client.connect()
    .catch(err => {
      console.error('MongoDB 连接错误:', {
        message: err.message,
        stack: err.stack,
        timestamp: new Date().toISOString()
      });
      throw err;
    });
}

// 测试连接
clientPromise
  .then(client => {
    console.log('MongoDB 连接成功');
    return client.db('word-pin').command({ ping: 1 });
  })
  .then(() => {
    console.log('MongoDB 数据库可用');
  })
  .catch(err => {
    console.error('MongoDB 连接测试失败:', {
      message: err.message,
      stack: err.stack,
      timestamp: new Date().toISOString()
    });
  });

export default clientPromise; 