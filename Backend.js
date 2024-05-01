const express = require('express')
const bodyParser = require('body-parser')
const cors = require('cors')
const {open} = require('sqlite')
const sqlite3 = require('sqlite3')
const path = require('path')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const swaggerUI = require('swagger-ui-express')
const YAML = require('yamljs')
const swaggerJSDocs = YAML.load('./api.yaml')

const databasePath = path.join(__dirname, 'user.db')

const app = express()
app.use(cors())
app.use(bodyParser.json())
app.use(express.json())

app.use('/api-docs', swaggerUI.serve, swaggerUI.setup(swaggerJSDocs))

let database = null
const initializeDbAndServer = async () => {
  try {
    database = await open({
      filename: databasePath,
      driver: sqlite3.Database,
    })
    app.listen(3002, () =>
      console.log('Server Running at http://localhost:3002/'),
    )
  } catch (error) {
    console.log(`DB Error: ${error.message}`)
    process.exit(1)
  }
}
initializeDbAndServer()

app.post('/register', async (request, response) => {
  try {
    const {username, email, password} = request.body

    // Checking if user already exists
    const selectUserQuery = 'SELECT * FROM Users WHERE Name = ?'
    const dbUser = await database.get(selectUserQuery, [username])

    if (dbUser) {
      response.status(400).send('User already exists')
    } else {
      // Hashing password
      const hashedPassword = await bcrypt.hash(password, 10)

      // Inserting new user
      const createUserQuery = `
        INSERT INTO userDetails (Name, Email, password)
        VALUES (?, ?, ?)`

      const dbResponse = await database.run(createUserQuery, [
        username,
        hashedPassword,
      ])
      const newUserId = dbResponse.lastID

      response.send(`Created new user with User ID ${newUserId}`)
    }
  } catch (error) {
    console.error('Error during registration:', error)
    response.status(500).send('Internal Server Error')
  }
})

app.post('/login', async (request, response) => {
  try {
    const {username, password} = request.body
    const selectUserQuery = 'SELECT * FROM Users WHERE Name = ?'
    const dbUser = await database.get(selectUserQuery, [username])
    if (!dbUser) {
      response.status(400).send('Invalid User')
    } else {
      const isPasswordMatched = await bcrypt.compare(password, dbUser.password)
      if (isPasswordMatched) {
        const payload = {Name: username}
        const jwtToken = jwt.sign(payload, 'MY_SECRET_TOKEN')
        response.send({jwtToken})
      } else {
        response.status(400).send('Invalid Password')
      }
    }
  } catch (error) {
    console.error('Error during login:', error)
    response.status(500).send('Internal Server Error')
  }
})

//Middleware function to authenticate the user. by validating the jwt token.
const authenticateToken = async (request, response, next) => {
  try {
    let jwtToken
    const authHeader = request.headers['authorization']
    if (authHeader !== undefined) {
      jwtToken = authHeader.split(' ')[1]
      console.log(jwtToken)
    }
    if (jwtToken === undefined) {
      response.status(401)
      response.send('Invalid JWT Token, it has been destroyed or undefined')
    } else {
      jwt.verify(jwtToken, 'MY_SECRET_TOKEN', async (error, payload) => {
        if (error) {
          response.status(401)
          response.send('Invalid JWT Token')
        } else {
          request.username = payload.Name
          next()
        }
      })
    }
  } catch (error) {
    console.error('Error in authentication:', error)
    response.status(500).send('Internal Server Error')
  }
}


app.put('/changePassword', authenticateToken, async (request, response) => {
  try {
    const {newPassword} = request.body
    if (!newPassword) {
      return response.status(400).send('New password is required')
    }

    const newHashedPassword = await bcrypt.hash(newPassword, 10)
    const putQuery = 'UPDATE Users SET password = ? WHERE Name = ?'
    await database.run(putQuery, [newHashedPassword, request.username])

    response.send('Password Updated')
  } catch (error) {
    console.error('Error updating password:', error)
    response.status(500).send('Error updating password')
  }
})

app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Simulated user authentication logic - replace with your actual logic
  if (username === 'admin' && password === 'adminpassword') {
      const token = jwt.sign({ username: username }, SECRET_KEY);
      res.json({ token: token });
  } else {
      res.status(401).json({ error: 'Unauthorized: Invalid credentials' });
  }
});

// GET all tasks
app.get('/tasks', authenticateToken, async (req, res) => {
  try {
      const rows = await db.all('SELECT * FROM Tasks');
      res.json(rows);
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

// GET a specific task by ID
app.get('/tasks/:id', authenticateToken, async (req, res) => {
  const taskId = req.params.id;
  try {
      const row = await db.get('SELECT * FROM Tasks WHERE id = ?', [taskId]);
      if (!row) {
          res.status(404).json({ error: 'Task not found' });
      } else {
          res.json(row);
      }
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

// POST create a new task
app.post('/tasks', authenticateToken, async (req, res) => {
  const { title, description, status, assignee_id } = req.body;
  const createdAt = new Date().toISOString();
  try {
      const result = await db.run('INSERT INTO Tasks (title, description, status, assignee_id, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)', [title, description, status, assignee_id, createdAt, createdAt]);
      res.json({ id: result.lastID });
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

// PUT update a task by ID
app.put('/tasks/:id', authenticateToken, async (req, res) => {
  const taskId = req.params.id;
  const { title, description, status, assignee_id } = req.body;
  const updatedAt = new Date().toISOString();
  try {
      const result = await db.run('UPDATE Tasks SET title = ?, description = ?, status = ?, assignee_id = ?, updated_at = ? WHERE id = ?', [title, description, status, assignee_id, updatedAt, taskId]);
      if (result.changes === 0) {
          res.status(404).json({ error: 'Task not found' });
      } else {
          res.json({ message: 'Task updated successfully' });
      }
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

// DELETE a task by ID
app.delete('/tasks/:id', authenticateToken, async (req, res) => {
  const taskId = req.params.id;
  try {
      const result = await db.run('DELETE FROM Tasks WHERE id = ?', [taskId]);
      if (result.changes === 0) {
          res.status(404).json({ error: 'Task not found' });
      } else {
          res.json({ message: 'Task deleted successfully' });
      }
  } catch (err) {
      res.status(500).json({ error: err.message });
  }
});

