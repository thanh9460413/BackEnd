require('dotenv').config();
const express = require('express');
const cron= require('node-cron');
const http = require('http');
const { Server } = require('socket.io');
const sql = require('mssql');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const { log } = require('console');
const ngrok = require('ngrok');
const { initializeApp } = require('firebase/app');
const { getDatabase, ref, set } = require('firebase/database');
const app = express();
const server = http.createServer(app);

// ✅ Cấu hình socket.io
const io = new Server(server, {
  cors: {
    origin: '*', // 👈 sửa nếu bạn muốn giới hạn nguồn
    methods: ['GET', 'POST']
  }
});

app.use(express.json());
app.use(cors());
app.use('/uploads', express.static(path.join(__dirname, 'public/uploads'))); // Trả ảnh avatar

// ✅ Cấu hình DB
const dbConfig = {
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  server: process.env.DB_SERVER,
  database: process.env.DB_DATABASE,
  options: { encrypt: false }
};

// ✅ Kết nối SQL
sql.connect(dbConfig)
  .then(() => console.log("✅ Connected to SQL Server"))
  .catch(err => console.error("❌ Database connection failed:", err));

// ✅ Middleware xác thực JWT
const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) return res.status(401).json({ error: 'Token is missing' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Token is invalid or expired' });
    req.user = user;
    next();
  });
};

// ✅ Cấu hình upload file (avatar)
const upload = multer({ storage: multer.memoryStorage() });

// ✅ Socket.io connection
io.on('connection', (socket) => {
  console.log('📡 Socket connected:', socket.id);

  socket.on('disconnect', () => {
    console.log('❌ Socket disconnected:', socket.id);
  });
});

// 📌 API: Super Admin Login
app.post('/superadmin/login', async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await sql.query`SELECT * FROM Users WHERE username = ${username} AND role = 'super_admin'`;

    if (result.recordset.length > 0) {
      const user = result.recordset[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const token = jwt.sign(
          { userId: user.id, username: user.username, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        return res.json({ token });
      } else {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      return res.status(401).json({ message: 'User not found' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 📌 API: Regular User/Admin Login
app.post('/login', async (req, res) => {
  const { username, password, server_name } = req.body;

  try {
    // Validate server_name
    if (!server_name) {
      return res.status(400).json({ message: 'Server name is required for regular users and admins' });
    }

    // Fetch server_id based on server_name
    const serverResult = await sql.query`SELECT id FROM Servers WHERE name = ${server_name}`;

    if (serverResult.recordset.length === 0) {
      return res.status(404).json({ message: 'Server not found' });
    }

    const server_id = serverResult.recordset[0].id;

    // Validate user with username and server_id
    const userResult = await sql.query`SELECT * FROM Users WHERE username = ${username} AND server_id = ${server_id}`;

    if (userResult.recordset.length > 0) {
      const user = userResult.recordset[0];
      const match = await bcrypt.compare(password, user.password);

      if (match) {
        const token = jwt.sign(
          { userId: user.id, username: user.username, role: user.role, server_id: user.server_id },
          process.env.JWT_SECRET,
          { expiresIn: '24h' }
        );
        return res.json({ token });
      } else {
        return res.status(401).json({ message: 'Invalid credentials' });
      }
    } else {
      return res.status(401).json({ message: 'User not found or invalid server ID' });
    }
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});


// 📌 API: Create User (with avatar)
app.post('/users/create', upload.single('avatar'), async (req, res) => {
  const { username, password, server_id, role } = req.body;

  try {
    let avatarUrl = null;

    if (req.file) {
      const avatarPath = `/uploads/${Date.now()}_${req.file.originalname}`;
      fs.writeFileSync(`./public${avatarPath}`, req.file.buffer);
      avatarUrl = `${req.protocol}://${req.get('host')}${avatarPath}`;
    }

    const hashedPassword = await bcrypt.hash(password, 12);

    await sql.query`INSERT INTO Users (username, password, avatar_url, server_id, role)
                        VALUES (${username}, ${hashedPassword}, ${avatarUrl}, ${server_id}, ${role})`;

    res.status(201).json({ message: 'User created successfully', avatarUrl });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Failed to create user' });
  }
});

// 📌 API: Create Group (with avatar)
app.post('/groups/create', authenticateToken, upload.single('avatar'), async (req, res) => {
  try {
    const { name, server_id, admin_id, members, avatar_url } = req.body;

    if (!name || !server_id || !admin_id || !members) {
      return res.status(400).json({ message: 'Missing required fields' });
    }

    let avatarUrl = avatar_url || null;

    if (req.file) {
      const avatarPath = `/uploads/${Date.now()}_${req.file.originalname}`;
      fs.writeFileSync(`./public${avatarPath}`, req.file.buffer);
      avatarUrl = `${req.protocol}://${req.get('host')}${avatarPath}`;
    }

    // Tạo nhóm
    const groupResult = await sql.query`
      INSERT INTO Groups (name, avatar_url, server_id, admin_id)
      VALUES (${name}, ${avatarUrl}, ${server_id}, ${admin_id});
      SELECT SCOPE_IDENTITY() AS groupId;
    `;

    const groupId = groupResult.recordset[0].groupId;

    // Parse danh sách member
    const memberArray = JSON.parse(members);

    for (const userId of memberArray) {
      await sql.query`
        INSERT INTO GroupMembers (group_id, user_id)
        VALUES (${groupId}, ${userId});
      `;
    }

    // ✅ Tạo phòng chat cho nhóm này
    const chatRoomResult = await sql.query`
      INSERT INTO ChatRooms (type, group_id, user1_id, user2_id, server_id)
      VALUES ('group', ${groupId}, NULL, NULL, ${server_id});
      SELECT SCOPE_IDENTITY() AS chatRoomId;
    `;

    const chatRoomId = chatRoomResult.recordset[0].chatRoomId;

    res.status(201).json({
      success: true,
      message: 'Group and ChatRoom created successfully',
      groupId,
      chatRoomId,
      avatarUrl,
    });
  } catch (error) {
    console.error('Error creating group & chatroom:', error);
    res.status(500).json({ success: false, message: 'Failed to create group & chatroom' });
  }
});



// 📌 API: Send Message (with image)
app.post('/messages', authenticateToken, upload.single('media'), async (req, res) => {
    const { chat_id, content } = req.body;
    const sender_id = req.user.userId;
    const server_id = req.user.server_id;

    let mediaUrl = null;

    if (req.file) {
        try {
            // Tạo thư mục uploads nếu chưa tồn tại
            const uploadsDir = path.join(__dirname, 'public/uploads');
            if (!fs.existsSync(uploadsDir)) {
                fs.mkdirSync(uploadsDir, { recursive: true });
            }

            // Lưu ảnh vào thư mục uploads với tên file bao gồm server_id
            const fileName = `server_${server_id}_${Date.now()}_${req.file.originalname}`;
            const filePath = path.join(uploadsDir, fileName);
            fs.writeFileSync(filePath, req.file.buffer);
            
            // Tạo URL đầy đủ cho ảnh
            const baseUrl = `${req.protocol}://${req.get('host')}`;
            mediaUrl = `${baseUrl}/uploads/${fileName}`;

            // Lưu tin nhắn vào SQL Server
            await sql.query`
                INSERT INTO Messages (chat_id, sender_id, server_id, content, image_url)
                VALUES (${chat_id}, ${sender_id}, ${server_id}, ${content}, ${mediaUrl})
            `;

            const newMessage = {
                chat_id,
                sender_id,
                server_id,
                content,
                image_url: mediaUrl,
                created_at: new Date().toISOString(),
            };

            res.status(201).json(newMessage);
        } catch (error) {
            console.error("Error saving image:", error);
            return res.status(500).json({ error: "Không thể lưu ảnh" });
        }
    } else {
        // Nếu không có file, vẫn lưu tin nhắn mà không có hình ảnh
        await sql.query`
            INSERT INTO Messages (chat_id, sender_id, server_id, content, image_url)
            VALUES (${chat_id}, ${sender_id}, ${server_id}, ${content}, NULL)
        `;

        const newMessage = {
            chat_id,
            sender_id,
            server_id,
            content,
            image_url: null,
            created_at: new Date().toISOString(),
        };

        res.status(201).json(newMessage);
    }
});



// 📌 API: Fetch Messages (per chat)
app.get('/messages/:chat_id', authenticateToken, async (req, res) => {
  try {
    const result = await sql.query`
    SELECT 
      m.*, 
      u.name AS sender_name,
      u.avatar_url AS sender_avatar,
      cr.type AS chatroom_type,
      cr.group_id,
      cr.user1_id,
      cr.user2_id,
      g.name AS group_name,
      g.avatar_url AS group_avatar
    FROM Messages m
    INNER JOIN ChatRooms cr ON m.chat_id = cr.id
    INNER JOIN Users u ON m.sender_id = u.id
    LEFT JOIN Groups g ON cr.group_id = g.id
    WHERE m.chat_id = ${req.params.chat_id}
      AND cr.server_id = ${req.user.server_id}
    ORDER BY m.created_at ASC
  `;



    res.json(result.recordset);
  } catch (error) {
    console.error('Error fetching messages:', error);
    res.status(500).json({ error: 'Failed to fetch messages' });
  }
});
app.post('/messages/read/:chatId', authenticateToken, async (req, res) => {
  const { chatId } = req.params;

  try {
    const result = await sql.query`
        UPDATE Messages
        SET reader = 1
        WHERE chat_id = ${chatId}
          AND chat_id IN (SELECT id FROM ChatRooms WHERE server_id = ${req.user.server_id})`;

    if (result.rowsAffected[0] === 0) {
      return res.status(404).json({ message: 'No messages found or accessible for this chat' });
    }

    res.json({ message: 'Messages marked as read successfully' });
  } catch (error) {
    console.error('Error marking messages as read:', error);
    res.status(500).json({ error: 'Failed to update messages' });
  }
});
// 📌 API: Get messages for a specific user
app.get('/user/messages', authenticateToken, async (req, res) => {
  const userId = req.user.userId;
  const serverId = req.user.server_id;

  try {
    if (!userId || !serverId) {
      return res.status(403).json({ error: 'Invalid token' });
    }

    // 1. ChatRoom 1-1 (cá nhân)
    const oneToOneChatRooms = await sql.query`
      SELECT cr.id AS chat_id,
             cr.type,
             u1.id AS user1_id, u1.name AS user1_name, u1.avatar_url AS user1_avatar,
             u2.id AS user2_id, u2.name AS user2_name, u2.avatar_url AS user2_avatar,
             (
               SELECT TOP 1 m.content
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message,
             (
               SELECT TOP 1 m.created_at 
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message_time,
            (
               SELECT TOP 1 m.reader
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message_reader 
      FROM ChatRooms cr
      LEFT JOIN Users u1 ON cr.user1_id = u1.id
      LEFT JOIN Users u2 ON cr.user2_id = u2.id
      WHERE cr.type = '1-1'
        AND cr.server_id = ${serverId}
        AND (cr.user1_id = ${userId} OR cr.user2_id = ${userId})
    `;

    // 2. Group ChatRooms (nhóm)
    const groupChatRooms = await sql.query`
      SELECT cr.id AS chat_id,
             cr.type,
             g.id AS group_id, g.name AS group_name, g.avatar_url AS group_avatar,
             (
               SELECT TOP 1 m.content 
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message,
             (
               SELECT TOP 1 m.created_at 
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message_time,
                          (
               SELECT TOP 1 m.reader
               FROM Messages m 
               WHERE m.chat_id = cr.id 
               ORDER BY m.created_at DESC
             ) AS last_message_reader 
      FROM ChatRooms cr
      INNER JOIN Groups g ON cr.group_id = g.id
      INNER JOIN GroupMembers gm ON g.id = gm.group_id
      WHERE cr.type = 'group'
        AND cr.server_id = ${serverId}
        AND gm.user_id = ${userId}
    `;

    // Gộp lại cả 2 loại chatroom
    const allChatRooms = [
      ...oneToOneChatRooms.recordset.map(room => ({
        type: '1-1',
        ...room,
      })),
      ...groupChatRooms.recordset.map(room => ({
        type: 'group',
        ...room,
      })),
    ].sort((a, b) => new Date(b.last_message_time || 0) - new Date(a.last_message_time || 0));

    res.json({ chatrooms: allChatRooms });
  } catch (error) {
    console.error('Error fetching user chatrooms and messages:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/user/:userId/:server_id', authenticateToken, async (req, res) => {
  const userId = req.params.userId;
  const server_id = req.params.server_id;

  try {
    if (!userId || !server_id) {
      return res.status(400).json({ error: 'User ID and Server ID are required' });
    }

    // Truy vấn thông tin người dùng từ cơ sở dữ liệu
    const result = await sql.query`
      SELECT id, username, name, avatar_url, role, created_at
      FROM Users
      WHERE id = ${userId} AND server_id = ${server_id}
    `;

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found or does not belong to this server' });
    }

    res.json(result.recordset[0]);
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});
app.get('/users/:server_id', authenticateToken, async (req, res) => {
  const server_id = req.params.server_id;

  try {
    if ( !server_id) {
      return res.status(400).json({ error: 'User ID and Server ID are required' });
    }

    // Truy vấn thông tin người dùng từ cơ sở dữ liệu
    const result = await sql.query`
      SELECT id, username, name, avatar_url, role, created_at
      FROM Users
      WHERE server_id = ${server_id}
    `;

    if (result.recordset.length === 0) {
      return res.status(404).json({ error: 'User not found or does not belong to this server' });
    }

    res.json(result.recordset);
  } catch (error) {
    console.error('Error fetching user info:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/chat/create', authenticateToken, async (req, res) => {
  const { user1_id, user2_id, type } = req.body;
  const serverId = req.user.server_id;

  if (!user1_id || !user2_id || !type || !serverId) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    // Kiểm tra xem đã có phòng chat 1-1 giữa 2 user này chưa
    const existingRoom = await sql.query`
      SELECT * FROM ChatRooms
      WHERE type = '1-1'
        AND server_id = ${serverId}
        AND ((user1_id = ${user1_id} AND user2_id = ${user2_id})
          OR (user1_id = ${user2_id} AND user2_id = ${user1_id}))
    `;

    if (existingRoom.recordset.length > 0) {
      return res.status(200).json({ message: 'Chat room already exists', chatroom: existingRoom.recordset[0] });
    }

    // Tạo phòng chat mới
    const result = await sql.query`
      INSERT INTO ChatRooms (user1_id, user2_id, type, server_id)
      OUTPUT INSERTED.*
      VALUES (${user1_id}, ${user2_id}, ${type}, ${serverId})
    `;

    res.status(201).json({ message: 'Chat room created', chatroom: result.recordset[0] });
  } catch (error) {
    console.error('Error creating 1-1 chat room:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// 📌 API: Register New User
app.post('/user/register', authenticateToken, upload.none(), async (req, res) => {
  try {
    const { username, password, name, server_id, role, avatar_url } = req.body;

    // Validate required fields
    if (!username || !password || !name || !server_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Vui lòng điền đầy đủ thông tin' 
      });
    }

    // Check if username already exists
    const existingUser = await sql.query`
      SELECT * FROM Users 
      WHERE username = ${username} AND server_id = ${server_id}
    `;

    if (existingUser.recordset.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tên đăng nhập đã tồn tại' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Insert new user
    const result = await sql.query`
      INSERT INTO Users (username, password, name, server_id, role, avatar_url)
      VALUES (${username}, ${hashedPassword}, ${name}, ${server_id}, ${role || 'user'}, ${avatar_url})
    `;

    if (result.rowsAffected[0] > 0) {
      res.json({ 
        success: true, 
        message: 'Đã thêm người dùng mới' 
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Không thể thêm người dùng' 
      });
    }
  } catch (error) {
    console.error('Error registering user:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Có lỗi xảy ra khi thêm người dùng' 
    });
  }
});

// 📌 API: Create New Admin
app.post('/users/create-admin', authenticateToken, async (req, res) => {
  try {
    const { username, password, name, role, avatar_url, server_id } = req.body;

    // Validate required fields
    if (!username?.trim() || !password?.trim() || !name?.trim() || !server_id) {
      return res.status(400).json({ 
        success: false, 
        message: 'Vui lòng nhập đầy đủ thông tin và chọn server' 
      });
    }

    // Check if username already exists in the server
    const existingUser = await sql.query`
      SELECT * FROM Users 
      WHERE username = ${username} AND server_id = ${server_id}
    `;

    if (existingUser.recordset.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tên đăng nhập đã tồn tại trong server này' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create new admin user
    const result = await sql.query`
      INSERT INTO Users (username, password, name, role, avatar_url, server_id, created_at)
      VALUES (${username}, ${hashedPassword}, ${name}, ${role}, ${avatar_url}, ${server_id}, GETDATE())
    `;

    if (result.rowsAffected[0] > 0) {
      res.json({ 
        success: true, 
        message: 'Admin đã được tạo thành công' 
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Không thể tạo admin' 
      });
    }
  } catch (error) {
    console.error('Error creating admin:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Không thể tạo admin' 
    });
  }
});

// 📌 API: Get Servers List
app.get('/servers', authenticateToken, async (req, res) => {
  try {
    const result = await sql.query`
      SELECT id, name, created_at,time_delete
      FROM Servers
      ORDER BY created_at DESC
    `;

    res.json(result.recordset);
  } catch (error) {
    console.error('Error fetching servers:', error);
    res.status(500).json({ error: 'Failed to fetch servers' });
  }
});

// 📌 API: Create New Server
app.post('/servers/create', authenticateToken, async (req, res) => {
  try {
    const { name, time_delete } = req.body;

    // Validate required fields
    if (!name || !name.trim()) {
      return res.status(400).json({ 
        success: false, 
        message: 'Vui lòng nhập tên server' 
      });
    }

    // Validate time format (HH:mm)
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
    if (!timeRegex.test(time_delete)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Định dạng thời gian không hợp lệ. Sử dụng HH:mm' 
      });
    }

    // Check if server name already exists
    const existingServer = await sql.query`
      SELECT * FROM Servers 
      WHERE name = ${name}
    `;

    if (existingServer.recordset.length > 0) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tên server đã tồn tại' 
      });
    }

    // Get current date
    const today = new Date();
    const year = today.getFullYear();
    const month = String(today.getMonth() + 1).padStart(2, '0');
    const day = String(today.getDate()).padStart(2, '0');

    // Combine current date with selected time
    const fullDateTime = `${year}-${month}-${day} ${time_delete}`;

    // Create new server
    const result = await sql.query`
      INSERT INTO Servers (name, time_delete, created_at)
      VALUES (${name}, ${fullDateTime}, GETDATE())
    `;

    if (result.rowsAffected[0] > 0) {
      res.json({ 
        success: true, 
        message: 'Server đã được tạo thành công' 
      });
    } else {
      res.status(500).json({ 
        success: false, 
        message: 'Không thể tạo server' 
      });
    }
  } catch (error) {
    console.error('Error creating server:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Không thể tạo server' 
    });
  }
});

// 📌 API: Get Server Admins
app.get('/server/:serverName/admin', authenticateToken, async (req, res) => {
  try {
    const { serverName } = req.params;

    // Get server admins
    const result = await sql.query`
      SELECT u.id, u.username, u.name, u.avatar_url, u.created_at
      FROM Users u
      INNER JOIN Servers s ON u.server_id = s.id
      WHERE s.name = ${serverName} AND u.role = 'admin'
      ORDER BY u.created_at DESC
    `;

    res.json({
      success: true,
      admins: result.recordset
    });
  } catch (error) {
    console.error('Error fetching server admins:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to fetch server admins' 
    });
  }
});

// Cron job để xóa tin nhắn theo thời gian của từng server
cron.schedule('* * * * *', async () => { // Chạy mỗi phút để kiểm tra
  try {
    const pool = await sql.connect(dbConfig);
    
    // Lấy danh sách server và thời gian xóa của chúng
    const serverResult = await pool.request().query('SELECT id, name, time_delete FROM Servers');
    const servers = serverResult.recordset;

    const currentTime = new Date();
    const currentHour = currentTime.getHours();
    const currentMinute = currentTime.getMinutes();
    const currentTimeString = `${currentHour.toString().padStart(2, '0')}:${currentMinute.toString().padStart(2, '0')}`;

    for (const server of servers) {
      if (!server.time_delete) {
        continue;
      }

      // Lấy thời gian từ database
      const serverTime = new Date(server.time_delete);
      const serverHour = serverTime.getUTCHours();
      const serverMinute = serverTime.getUTCMinutes();
      const serverTimeString = `${serverHour.toString().padStart(2, '0')}:${serverMinute.toString().padStart(2, '0')}`;

      // So sánh chính xác giờ và phút
      if (serverHour === currentHour && serverMinute === currentMinute) {
        // Lấy danh sách ảnh cần xóa
        const imagesResult = await pool.request()
          .input('serverId', sql.Int, server.id)
          .query('SELECT image_url FROM Messages WHERE server_id = @serverId AND image_url IS NOT NULL');

        // Xóa các file ảnh
        for (const image of imagesResult.recordset) {
          if (image.image_url) {
            // Lấy tên file từ URL đầy đủ
            const fileName = image.image_url.split('/').pop();
            // Kiểm tra xem file có thuộc server này không
            if (fileName.startsWith(`server_${server.id}_`)) {
              const imagePath = path.join(__dirname, 'public/uploads', fileName);
              try {
                fs.unlinkSync(imagePath);
              } catch (error) {
                console.error(`Error deleting image ${imagePath}:`, error);
              }
            }
          }
        }

        // Xóa tin nhắn của server cụ thể
        const deleteResult = await pool.request()
          .input('serverId', sql.Int, server.id)
          .query('DELETE FROM Messages WHERE server_id = @serverId');
      }
    }
  } catch (error) {
    console.error("❌ Lỗi khi xóa tin nhắn:", error);
  }
});

const firebaseConfig = {
  apiKey: "AIzaSyBX2sYalQKoq7O2yeMzHJYdtnSF3BCuSTc",
  authDomain: "chatapp-107c2.firebaseapp.com",
  projectId: "chatapp-107c2",
  storageBucket: "chatapp-107c2.firebasestorage.app",
  messagingSenderId: "378233725708",
  appId: "1:378233725708:web:e6ef368da171c8d2755f29",
  measurementId: "G-795TKNDSTB",
  databaseURL: "https://chatapp-107c2-default-rtdb.firebaseio.com"
};

// Initialize Firebase
const firebaseApp = initializeApp(firebaseConfig);
const database = getDatabase(firebaseApp);

// 📌 API: Get Group Members
app.get('/chat/:chatId/members', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const serverId = req.user.server_id;

    // First verify the chat room exists and is a group chat
    const chatRoomResult = await sql.query`
      SELECT cr.*, g.id as group_id
      FROM ChatRooms cr
      INNER JOIN Groups g ON cr.group_id = g.id
      WHERE cr.id = ${chatId} 
      AND cr.type = 'group'
      AND cr.server_id = ${serverId}
    `;

    if (chatRoomResult.recordset.length === 0) {
      return res.status(404).json({ error: 'Group chat not found' });
    }

    const groupId = parseInt(chatRoomResult.recordset[0].group_id);
    if (isNaN(groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }

    // Get all members of the group using request
    const request = new sql.Request();
    request.input('groupId', sql.Int, groupId);
    request.input('serverId', sql.Int, parseInt(serverId));
    
    const membersResult = await request.query(`
      SELECT 
        u.id,
        u.username,
        u.name,
        u.avatar_url,
        u.role
      FROM GroupMembers gm
      INNER JOIN Users u ON gm.user_id = u.id
      WHERE gm.group_id = @groupId
      AND u.server_id = @serverId
      ORDER BY u.name ASC
    `);

    res.json(membersResult.recordset);
  } catch (error) {
    console.error('Error fetching group members:', error);
    res.status(500).json({ error: 'Failed to fetch group members' });
  }
});

// 📌 API: Remove User from Group
app.post('/chat/:chatId/remove-user', authenticateToken, async (req, res) => {
  try {
    const { chatId } = req.params;
    const { user_id } = req.body;
    const serverId = req.user.server_id;

    // Verify the chat room exists and is a group chat
    const chatRoomResult = await sql.query`
      SELECT cr.*, g.id as group_id, g.admin_id
      FROM ChatRooms cr
      INNER JOIN Groups g ON cr.group_id = g.id
      WHERE cr.id = ${chatId} 
      AND cr.type = 'group'
      AND cr.server_id = ${serverId}
    `;

    if (chatRoomResult.recordset.length === 0) {
      return res.status(404).json({ error: 'Group chat not found' });
    }

    const groupId = parseInt(chatRoomResult.recordset[0].group_id);
    if (isNaN(groupId)) {
      return res.status(400).json({ error: 'Invalid group ID' });
    }

    const adminId = parseInt(chatRoomResult.recordset[0].admin_id);
    if (isNaN(adminId)) {
      return res.status(400).json({ error: 'Invalid admin ID' });
    }

    // Check if the requesting user is the admin
    if (req.user.userId !== adminId) {
      return res.status(403).json({ error: 'Only group admin can remove members' });
    }

    // Check if the user to be removed is not the admin
    const userIdToRemove = parseInt(user_id);
    if (isNaN(userIdToRemove)) {
      return res.status(400).json({ error: 'Invalid user ID' });
    }

    if (userIdToRemove === adminId) {
      return res.status(400).json({ error: 'Cannot remove group admin' });
    }

    // Remove the user from the group using prepared statement
    const pool = await sql.connect(dbConfig);
    const request = pool.request();
    request.input('groupId', sql.Int, groupId);
    request.input('userId', sql.Int, userIdToRemove);
    
    const removeResult = await request.query(
      'DELETE FROM GroupMembers WHERE group_id = @groupId AND user_id = @userId'
    );

    if (removeResult.rowsAffected[0] === 0) {
      return res.status(404).json({ error: 'User is not a member of this group' });
    }

    res.json({ 
      success: true, 
      message: 'User removed from group successfully' 
    });
  } catch (error) {
    console.error('Error removing user from group:', error);
    res.status(500).json({ error: 'Failed to remove user from group' });
  }
});

// 📌 API: Add New Members to Group
app.post('/groups/add-members', authenticateToken, async (req, res) => {
  try {
    const { chat_id, members } = req.body;
    const serverId = req.user.server_id;

    if (!chat_id || !members) {
      return res.status(400).json({ 
        success: false, 
        message: 'Missing required fields' 
      });
    }

    // Convert chat_id to integer23w
    const chatId = parseInt(chat_id);
    if (isNaN(chatId)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid chat ID' 
      });
    }

    // Verify the chat room exists and is a group chat
    const chatRoomResult = await sql.query`
      SELECT cr.*, g.id as group_id, g.admin_id
      FROM ChatRooms cr
      INNER JOIN Groups g ON cr.group_id = g.id
      WHERE cr.id = ${chatId} 
      AND cr.type = 'group'
      AND cr.server_id = ${serverId}
    `;

    if (chatRoomResult.recordset.length === 0) {
      return res.status(404).json({ 
        success: false, 
        message: 'Group chat not found or you do not have permission' 
      });
    }

    const groupId = parseInt(chatRoomResult.recordset[0].group_id);
    if (isNaN(groupId)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid group ID' 
      });
    }

    // Parse danh sách member mới và chuyển đổi sang số
    let memberArray;
    try {
      memberArray = JSON.parse(members).map(id => parseInt(id));
      if (memberArray.some(isNaN)) {
        throw new Error('Invalid member IDs');
      }
    } catch (error) {
      return res.status(400).json({ 
        success: false, 
        message: 'Invalid members format' 
      });
    }

    // Thêm từng thành viên mới vào nhóm
    for (const userId of memberArray) {
      // Kiểm tra xem user đã là thành viên của nhóm chưa
      const existingMember = await sql.query`
        SELECT * FROM GroupMembers 
        WHERE group_id = ${groupId} AND user_id = ${userId}
      `;

      if (existingMember.recordset.length === 0) {
        await sql.query`
          INSERT INTO GroupMembers (group_id, user_id)
          VALUES (${groupId}, ${userId})
        `;
      }
    }

    res.status(200).json({
      success: true,
      message: 'New members added to group successfully'
    });
  } catch (error) {
    console.error('Error adding members to group:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Failed to add members to group' 
    });
  }
});

// 📌 API: Update Server
app.put('/servers/:id', authenticateToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, time_delete } = req.body;

    
    // Validate required fields
    if (!name || !time_delete) {
      return res.status(400).json({ 
        success: false, 
        message: 'Tên server và thời gian xóa tin nhắn là bắt buộc' 
      });
    }

    // Validate time format (HH:mm)
    const timeRegex = /^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$/;
    if (!timeRegex.test(time_delete)) {
      return res.status(400).json({ 
        success: false, 
        message: 'Định dạng thời gian không hợp lệ. Sử dụng HH:mm' 
      });
    }

    // Format time to match database format (HH:mm:00.0000000)
    const formattedTime = `${time_delete}:00.0000000`;

    // Update server
    const result = await sql.query`
      UPDATE Servers 
      SET name = ${name}, time_delete = ${formattedTime}
      WHERE id = ${id}
    `;

    if (result.rowsAffected[0] > 0) {
      // Get updated server
      const updatedServer = await sql.query`
        SELECT * FROM Servers WHERE id = ${id}
      `;

      res.json({ 
        success: true, 
        message: 'Cập nhật server thành công',
        server: updatedServer.recordset[0]
      });
    } else {
      res.status(404).json({ 
        success: false, 
        message: 'Không tìm thấy server' 
      });
    }
  } catch (error) {
    console.error('Error updating server:', error);
    res.status(500).json({ 
      success: false, 
      message: 'Không thể cập nhật server' 
    });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  //console.log(`✅ Server running at http://localhost:${PORT}`);
  
  // ❌ Bỏ hoặc comment phần này nếu không muốn dùng ngrok
  
  // ngrok.connect(PORT).then(url => {
  //   const ngrokRef = ref(database, 'ngrok');
  //   set(ngrokRef, { url }).then(() => {
  //     console.log('✅ Ngrok URL saved to Firebase:', url);
  //   }).catch(error => {
  //     console.error('❌ Error saving ngrok URL:', error);
  //   });
  // }).catch(error => {
  //   console.error('❌ Error connecting to ngrok:', error);
  // });
  
});
