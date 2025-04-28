import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken'; // <-- Import JWT library

// Configuración para ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuración de variables de entorno
dotenv.config();

// --- JWT Configuration ---
// Ensure JWT_SECRET is set in your .env file
if (!process.env.JWT_SECRET) {
  console.error("FATAL ERROR: JWT_SECRET is not defined in environment variables.");
  process.exit(1); // Exit if secret is not set
}
const jwtSecret = process.env.JWT_SECRET;
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '24h'; // Token expiration time (e.g., 1 hour)

const app = express();
const port = process.env.PORT || 3001;

// Middleware
app.use(cors());
app.use(express.json());

// Configuración de la conexión a la base de datos
const dbConfig = {
  host: process.env.HOST_DB || 'localhost',
  port: process.env.PORT_DB || 3306,
  user: process.env.USER || 'root',
  password: process.env.PASSWORD || 'root',
  database: process.env.DATABASE || 'test',
  connectionLimit: process.env.CONNECTION_LIMIT || 10,
  dateStrings: true // <-- Important: Keep dates as strings from DB
};

// Crear pool de conexiones MySQL
const pool = mysql.createPool(dbConfig);

// --- JWT Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  // Format: "Bearer TOKEN"
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) {
    console.log('Auth attempt failed: No token provided.');
    return res.status(401).json({ message: 'Acceso denegado: No se proporcionó token' }); // if there isn't any token
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error('JWT Verification Error:', err.message);
      // Differentiate between expired and invalid tokens
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expirado' });
      }
      return res.status(403).json({ message: 'Token inválido' }); // Forbidden
    }
    // Add user payload (from token) to request object
    req.user = user;
    console.log(`User authenticated: ${user.email} (ID: ${user.id})`);
    next(); // pass the execution off to whatever request the client intended
  });
};

// --- (Optional) Authorization Middleware for Superusers ---
const authorizeSuperuser = (req, res, next) => {
    // This middleware assumes 'authenticateToken' has already run
    if (!req.user || !req.user.is_superuser) {
        console.warn(`Authorization failed: User ${req.user?.email} (ID: ${req.user?.id}) is not a superuser.`);
        return res.status(403).json({ message: 'Acceso denegado: Se requiere rol de superusuario' });
    }
    console.log(`Superuser authorized: ${req.user.email}`);
    next();
};


// --- PUBLIC ROUTES ---

// Ruta para verificar que el servidor está funcionando
app.get('/api/test', (req, res) => {
  res.json({ message: 'Servidor funcionando correctamente' });
});

// Ruta para autenticar usuarios (Login) - Generates JWT
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).json({ message: 'Email y contraseña son requeridos' });
    }

    const connection = await pool.getConnection();
    const [users] = await connection.query(`
      SELECT id, name, last_name, email, password, agency, is_superuser
      FROM users
      WHERE email = ?
    `, [email]);
    connection.release();

    if (users.length === 0) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }
    const user = users[0];

    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');
    if (user.password !== hashedPassword) {
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    // --- Generate JWT ---
    const userPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      last_name: user.last_name,
      agency: user.agency,
      is_superuser: !!user.is_superuser // Ensure boolean
    };

    const token = jwt.sign(userPayload, jwtSecret, { expiresIn: jwtExpiresIn });
    console.log(`Login successful, JWT generated for: ${user.email}`);

    res.json({
      success: true,
      token: token,
      user: { // Send back basic user info (optional, can be derived from token on client)
        id: user.id,
        name: user.name,
        last_name: user.last_name,
        email: user.email,
        agency: user.agency,
        is_superuser: !!user.is_superuser
      }
    });
  } catch (error) {
    console.error('Error de autenticación:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});


// --- PROTECTED ROUTES ---
// Apply JWT authentication middleware to all routes defined below this line
app.use('/api', authenticateToken);

// Ruta para obtener todos los empleados (Protected)
app.get('/api/employees', async (req, res) => {
  // Access granted because authenticateToken middleware passed
  console.log(`User ${req.user.email} requesting all employees.`);
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(`
      SELECT
        e.id,
        e.name,
        e.last_name,
        e.agency,
        DATE_FORMAT(e.date_of_birth, '%Y-%m-%d') as date_of_birth, -- Use ISO format for consistency
        DATE_FORMAT(e.high_date, '%Y-%m-%d') as high_date,         -- Use ISO format for consistency
        e.status,
        DATE_FORMAT(e.low_date, '%Y-%m-%d') as low_date,           -- Use ISO format for consistency
        e.photo,
        e.id_user,
        u.email as user_email,
        e.last_modified,
        e.modified_by,
        mod_user.email as modified_by_email -- Get modifier email
      FROM employees e
      JOIN users u ON e.id_user = u.id
      LEFT JOIN users mod_user ON e.modified_by = mod_user.id -- Join to get modifier email
    `);
    connection.release();

    // Ensure dates are null if they are originally null in DB
    const formattedEmployees = rows.map(employee => ({
      ...employee,
      date_of_birth: employee.date_of_birth || null,
      high_date: employee.high_date || null,
      low_date: employee.low_date || null,
      last_modified: employee.last_modified ? new Date(employee.last_modified).toISOString() : null,
      modified_by: employee.modified_by || null,
      modified_by_email: employee.modified_by_email || null
    }));

    res.json(formattedEmployees);
  } catch (error) {
    console.error('Error al obtener empleados:', error);
    res.status(500).json({ message: 'Error al obtener datos de empleados', error: error.message });
  }
});

// Ruta para obtener un empleado por ID (Protected)
app.get('/api/employees/:id', async (req, res) => {
  console.log(`User ${req.user.email} requesting employee ID: ${req.params.id}`);
  try {
    const { id } = req.params;
    const connection = await pool.getConnection();
    const [rows] = await connection.query(`
       SELECT
        e.id,
        e.name,
        e.last_name,
        e.agency,
        DATE_FORMAT(e.date_of_birth, '%Y-%m-%d') as date_of_birth,
        DATE_FORMAT(e.high_date, '%Y-%m-%d') as high_date,
        e.status,
        DATE_FORMAT(e.low_date, '%Y-%m-%d') as low_date,
        e.photo,
        e.id_user,
        u.email as user_email,
        e.last_modified,
        e.modified_by,
        mod_user.email as modified_by_email
      FROM employees e
      JOIN users u ON e.id_user = u.id
      LEFT JOIN users mod_user ON e.modified_by = mod_user.id
      WHERE e.id = ?
    `, [id]);
    connection.release();

    if (rows.length === 0) {
      return res.status(404).json({ message: 'Empleado no encontrado' });
    }

    const employee = rows[0];
    res.json({
      ...employee,
      date_of_birth: employee.date_of_birth || null,
      high_date: employee.high_date || null,
      low_date: employee.low_date || null,
      last_modified: employee.last_modified ? new Date(employee.last_modified).toISOString() : null,
      modified_by: employee.modified_by || null,
      modified_by_email: employee.modified_by_email || null
    });
  } catch (error) {
    console.error('Error al obtener empleado:', error);
    res.status(500).json({ message: 'Error al obtener datos del empleado', error: error.message });
  }
});

// Ruta para crear un nuevo empleado (Protected)
app.post('/api/employees', async (req, res) => {
    // req.user contains authenticated user info
    console.log(`User ${req.user.email} attempting to create employee.`);
    try {
        const { name, last_name, agency, date_of_birth, high_date, status, photo, id_user } = req.body;
        const creatingUserId = req.user.id; // Get the ID of the user making the request

        // Basic validation
        if (!name || !last_name || !agency || !date_of_birth || !high_date || !status || !id_user) {
            return res.status(400).json({ message: 'Todos los campos requeridos (excepto fecha de baja y foto) deben ser proporcionados' });
        }

        // Validate date formats (expecting YYYY-MM-DD from frontend)
        const dateFormatRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateFormatRegex.test(date_of_birth) || !dateFormatRegex.test(high_date)) {
             return res.status(400).json({ message: 'Formato de fecha inválido. Use YYYY-MM-DD.' });
        }

        const connection = await pool.getConnection();

        // Verify the assigned id_user exists
        const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id_user]);
        if (existingUsers.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'El usuario asignado (id_user) no existe' });
        }

        // Insert the new employee
        // Note: We don't set low_date, last_modified, or modified_by on creation
        const [result] = await connection.query(`
            INSERT INTO employees (name, last_name, agency, date_of_birth, high_date, status, photo, id_user)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [name, last_name, agency, date_of_birth, high_date, status, photo || null, id_user]); // Use null for photo if not provided

        connection.release();
        console.log(`Employee created successfully with ID: ${result.insertId} by user ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: 'Empleado creado exitosamente',
            employeeId: result.insertId
        });
    } catch (error) {
        console.error('Error al crear empleado:', error);
        // Check for specific DB errors like duplicate entry if needed
        res.status(500).json({ message: 'Error en el servidor al crear empleado', error: error.message });
    }
});

// Ruta para actualizar un empleado existente (Protected)
app.put('/api/employees/:id', async (req, res) => {
    // req.user contains authenticated user info
    const modifyingUserId = req.user.id; // ID of the user performing the update
    const { id } = req.params;
    console.log(`User ${req.user.email} attempting to update employee ID: ${id}`);

    try {
        const { name, last_name, agency, date_of_birth, high_date, status, low_date, photo, id_user } = req.body;

        // Basic validation
        if (!name || !last_name || !agency || !date_of_birth || !high_date || !status || !id_user) {
            return res.status(400).json({ message: 'Todos los campos requeridos (excepto fecha de baja y foto) deben ser proporcionados' });
        }

        // Validate date formats (expecting YYYY-MM-DD)
        const dateFormatRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateFormatRegex.test(date_of_birth) || !dateFormatRegex.test(high_date) || (low_date && !dateFormatRegex.test(low_date))) {
             return res.status(400).json({ message: 'Formato de fecha inválido. Use YYYY-MM-DD.' });
        }


        const connection = await pool.getConnection();

        // Check if employee exists
        const [existingEmployees] = await connection.query('SELECT id FROM employees WHERE id = ?', [id]);
        if (existingEmployees.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }

        // Check if assigned user (id_user) exists
        const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id_user]);
        if (existingUsers.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'El usuario asignado (id_user) no existe' });
        }

        // Get current timestamp for last_modified
        const lastModified = new Date().toISOString().slice(0, 19).replace('T', ' '); // Format 'YYYY-MM-DD HH:MM:SS'

        // Update the employee record
        // Use NULL for low_date if it's empty or null, otherwise use the provided value
        const [result] = await connection.query(`
            UPDATE employees
            SET name = ?, last_name = ?, agency = ?,
                date_of_birth = ?, high_date = ?, status = ?,
                low_date = ?, photo = ?, id_user = ?,
                last_modified = ?, modified_by = ?
            WHERE id = ?
        `, [
            name, last_name, agency,
            date_of_birth, high_date, status,
            (low_date && low_date.trim() !== '') ? low_date : null, // Handle null/empty low_date
            photo || null, // Handle null photo
            id_user,
            lastModified, // Set last modified timestamp
            modifyingUserId, // Set modified_by to the logged-in user's ID
            id
        ]);

        connection.release();

        if (result.affectedRows === 0) {
             // Should not happen if the existence check passed, but good practice
             return res.status(404).json({ message: 'Empleado no encontrado durante la actualización' });
        }
        console.log(`Employee ID: ${id} updated successfully by user ${req.user.email}`);

        res.json({
            success: true,
            message: 'Empleado actualizado exitosamente'
        });
    } catch (error) {
        console.error(`Error al actualizar empleado ID ${id}:`, error);
        res.status(500).json({ message: 'Error en el servidor al actualizar empleado', error: error.message });
    }
});

// Ruta para eliminar un empleado (Protected)
app.delete('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
    console.log(`User ${req.user.email} attempting to delete employee ID: ${id}`);
    try {
        const connection = await pool.getConnection();

        // Check if employee exists before deleting
        const [existingEmployees] = await connection.query('SELECT id FROM employees WHERE id = ?', [id]);
        if (existingEmployees.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }

        // Delete the employee
        const [result] = await connection.query('DELETE FROM employees WHERE id = ?', [id]);
        connection.release();

        if (result.affectedRows === 0) {
             // Should not happen if the existence check passed
             return res.status(404).json({ message: 'Empleado no encontrado durante la eliminación' });
        }

        console.log(`Employee ID: ${id} deleted successfully by user ${req.user.email}`);
        res.json({
            success: true,
            message: 'Empleado eliminado exitosamente'
        });
    } catch (error) {
        console.error(`Error al eliminar empleado ID ${id}:`, error);
        res.status(500).json({ message: 'Error en el servidor al eliminar empleado', error: error.message });
    }
});


// --- USER MANAGEMENT ROUTES (Protected & Superuser Only) ---
// Apply Superuser authorization only to these user management routes
app.use('/api/users', authorizeSuperuser);

// Ruta para crear un nuevo usuario/administrador (Protected + Superuser Only)
app.post('/api/users', async (req, res) => {
  console.log(`Superuser ${req.user.email} attempting to create a new user.`);
  try {
    const { name, last_name, email, password, agency, is_superuser } = req.body;

    if (!name || !last_name || !email || !password || !agency) {
      return res.status(400).json({ message: 'Nombre, apellido, email, contraseña y agencia son requeridos' });
    }

    const connection = await pool.getConnection();

    const [existingUsers] = await connection.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      connection.release();
      return res.status(409).json({ message: 'Ya existe un usuario con este correo electrónico' });
    }

    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

    const [result] = await connection.query(`
      INSERT INTO users (name, last_name, email, password, agency, is_superuser)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [name, last_name, email, hashedPassword, agency, is_superuser ? 1 : 0]); // Ensure 1 or 0

    connection.release();
    console.log(`User created successfully with ID: ${result.insertId} by superuser ${req.user.email}`);

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      userId: result.insertId
    });
  } catch (error) {
    console.error('Error al crear usuario:', error);
    res.status(500).json({ message: 'Error en el servidor', error: error.message });
  }
});

// Ruta para obtener todos los usuarios (Protected + Superuser Only)
app.get('/api/users', async (req, res) => {
  console.log(`Superuser ${req.user.email} requesting all users.`);
  try {
    const connection = await pool.getConnection();
    const [users] = await connection.query(`
      SELECT id, name, last_name, email, agency, is_superuser
      FROM users
      ORDER BY id ASC
    `);
    connection.release();

    // Convert is_superuser to boolean for consistency
    const formattedUsers = users.map(user => ({
        ...user,
        is_superuser: !!user.is_superuser
    }));

    res.json(formattedUsers);
  } catch (error) {
    console.error('Error al obtener usuarios:', error);
    res.status(500).json({ message: 'Error al obtener datos de usuarios', error: error.message });
  }
});

// Ruta para obtener un usuario por ID (Protected + Superuser Only)
app.get('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`Superuser ${req.user.email} requesting user ID: ${id}`);
  try {
    // Allow superuser to get any user, or a user to get their own profile?
    // Current implementation: Only superuser can get any user by ID via this route.
    // If you want users to get their own profile, you might need a separate route
    // like /api/users/me or adjust logic here.

    const connection = await pool.getConnection();
    const [users] = await connection.query(`
      SELECT id, name, last_name, email, agency, is_superuser
      FROM users
      WHERE id = ?
    `, [id]);
    connection.release();

    if (users.length === 0) {
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    res.json({
        ...users[0],
        is_superuser: !!users[0].is_superuser // Ensure boolean
    });
  } catch (error) {
    console.error(`Error al obtener usuario ID ${id}:`, error);
    res.status(500).json({ message: 'Error al obtener datos del usuario', error: error.message });
  }
});

// Ruta para actualizar un usuario existente (Protected + Superuser Only)
app.put('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`Superuser ${req.user.email} attempting to update user ID: ${id}`);
  try {
    const { name, last_name, email, password, agency, is_superuser } = req.body;

    // Basic validation (ensure required fields are present, maybe more checks)
     if (!name || !last_name || !email || !agency) {
      return res.status(400).json({ message: 'Nombre, apellido, email y agencia son requeridos' });
    }

    const connection = await pool.getConnection();

    // Check if user exists
    const [existingUsers] = await connection.query('SELECT id, email FROM users WHERE id = ?', [id]);
    if (existingUsers.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Check if the new email is already taken by *another* user
    if (email !== existingUsers[0].email) {
        const [emailCheck] = await connection.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, id]);
        if (emailCheck.length > 0) {
            connection.release();
            return res.status(409).json({ message: 'El nuevo correo electrónico ya está en uso por otro usuario' });
        }
    }


    let query;
    let params;
    let hashedPassword = null;

    if (password && password.trim() !== '') {
      hashedPassword = crypto.createHash('md5').update(password).digest('hex');
      query = `
        UPDATE users
        SET name = ?, last_name = ?, email = ?, password = ?, agency = ?, is_superuser = ?
        WHERE id = ?
      `;
      params = [name, last_name, email, hashedPassword, agency, is_superuser ? 1 : 0, id];
    } else {
      // Don't update password if it's not provided or empty
      query = `
        UPDATE users
        SET name = ?, last_name = ?, email = ?, agency = ?, is_superuser = ?
        WHERE id = ?
      `;
      params = [name, last_name, email, agency, is_superuser ? 1 : 0, id];
    }

    const [result] = await connection.query(query, params);
    connection.release();

     if (result.affectedRows === 0) {
         // Should not happen based on existence check
         return res.status(404).json({ message: 'Usuario no encontrado durante la actualización' });
    }
    console.log(`User ID: ${id} updated successfully by superuser ${req.user.email}`);

    res.json({
      success: true,
      message: 'Usuario actualizado exitosamente'
    });
  } catch (error) {
    console.error(`Error al actualizar usuario ID ${id}:`, error);
    // Handle potential duplicate email error from DB if the check above fails somehow
    if (error.code === 'ER_DUP_ENTRY') {
         return res.status(409).json({ message: 'Error: El correo electrónico ya está en uso.' });
    }
    res.status(500).json({ message: 'Error en el servidor al actualizar usuario', error: error.message });
  }
});

// Ruta para eliminar un usuario (Protected + Superuser Only)
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  console.log(`Superuser ${req.user.email} attempting to delete user ID: ${id}`);

  // Prevent superuser from deleting themselves? (Optional safeguard)
  if (parseInt(id, 10) === req.user.id) {
      console.warn(`Superuser ${req.user.email} attempted to delete their own account.`);
      return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta de superusuario.' });
  }

  try {
    const connection = await pool.getConnection();

    // Check if user exists
    const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id]);
    if (existingUsers.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Check if any employees are assigned to this user (as id_user OR modified_by)
    const [assignedEmployees] = await connection.query(
        'SELECT id FROM employees WHERE id_user = ? LIMIT 1',
        [id]
    );
     const [modifiedEmployees] = await connection.query(
        'SELECT id FROM employees WHERE modified_by = ? LIMIT 1',
        [id]
    );

    if (assignedEmployees.length > 0 || modifiedEmployees.length > 0) {
      connection.release();
      console.warn(`Attempt failed to delete user ID ${id}: User has associated employees.`);
      return res.status(400).json({
        message: 'No se puede eliminar este usuario porque tiene empleados asignados o ha modificado registros de empleados. Reasigne o actualice esos empleados primero.'
      });
    }

    // Delete the user
    const [result] = await connection.query('DELETE FROM users WHERE id = ?', [id]);
    connection.release();

    if (result.affectedRows === 0) {
        // Should not happen based on existence check
        return res.status(404).json({ message: 'Usuario no encontrado durante la eliminación' });
    }

    console.log(`User ID: ${id} deleted successfully by superuser ${req.user.email}`);
    res.json({
      success: true,
      message: 'Usuario eliminado exitosamente'
    });
  } catch (error) {
    console.error(`Error al eliminar usuario ID ${id}:`, error);
    // Handle potential foreign key constraint errors if the checks fail
    res.status(500).json({ message: 'Error en el servidor al eliminar usuario', error: error.message });
  }
});


// --- Server Start ---
app.listen(port, "0.0.0.0", () => {
  console.log(`Servidor RH Admin ejecutándose en: http://0.0.0.0:${port}`);
  console.log(`JWT Tokens will expire in: ${jwtExpiresIn}`);
});