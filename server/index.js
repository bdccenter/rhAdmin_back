import express from 'express';
import mysql from 'mysql2/promise';
import cors from 'cors'; // Asegúrate que está importado
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import path from 'path';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';

// Configuración para ESM
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuración de variables de entorno
dotenv.config();

// --- JWT Configuration ---
if (!process.env.JWT_SECRET) {
  console.error("FATAL ERROR: JWT_SECRET is not defined in environment variables.");
  process.exit(1);
}
const jwtSecret = process.env.JWT_SECRET;
const jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';

const app = express();
const port = process.env.PORT || 3001;

// --- Configuración de CORS ---
// Define los orígenes permitidos explícitamente. ¡Más seguro para producción!
const allowedOrigins = [
    'https://rhadminfront-production.up.railway.app', // Tu frontend en Railway
    // Puedes añadir orígenes de desarrollo si es necesario, ej:
    // 'http://localhost:3000',
    // 'http://localhost:5173', // Si usas Vite por defecto
];

const corsOptions = {
  origin: function (origin, callback) {
    // Permite solicitudes sin origen (como Postman, curl en algunos casos) o si el origen está en la lista blanca
    if (!origin || allowedOrigins.indexOf(origin) !== -1) {
      callback(null, true);
    } else {
      console.warn(`CORS blocked for origin: ${origin}`); // Loguea orígenes bloqueados
      callback(new Error(`Origin ${origin} not allowed by CORS`)); // Error más descriptivo
    }
  },
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'], // Métodos HTTP permitidos
  allowedHeaders: ['Content-Type', 'Authorization'], // Cabeceras permitidas (¡IMPORTANTE!)
  credentials: true, // Necesario si manejas cookies o auth más complejo, no daña tenerlo para Bearer tokens
  optionsSuccessStatus: 200 // Para compatibilidad con navegadores más antiguos o específicos
};


// --- Middleware ---

// !! Usa la configuración CORS detallada !!
app.use(cors(corsOptions));

// Habilita el manejo de solicitudes OPTIONS explícitamente ANTES de otras rutas
// Esto asegura que las solicitudes preflight de CORS sean manejadas correctamente
app.options('*', cors(corsOptions)); // Habilita pre-flight para todas las rutas

// Middleware para parsear JSON
app.use(express.json());


// Configuración de la conexión a la base de datos
const dbConfig = {
  host: process.env.HOST_DB || 'localhost',
  port: parseInt(process.env.PORT_DB || '3306', 10), // Asegurar que el puerto es número
  user: process.env.USER || 'root',
  password: process.env.PASSWORD || 'root',
  database: process.env.DATABASE || 'test',
  connectionLimit: parseInt(process.env.CONNECTION_LIMIT || '10', 10), // Asegurar que es número
  dateStrings: true // Importante: Mantiene las fechas como strings desde la DB
};

// Crear pool de conexiones MySQL
let pool;
try {
    pool = mysql.createPool(dbConfig);
    console.log("MySQL Pool created successfully.");
    // Intenta obtener una conexión para verificar
    pool.getConnection()
        .then(connection => {
            console.log("Database connection successful!");
            connection.release();
        })
        .catch(err => {
            console.error("FATAL ERROR: Database connection failed on initial check:", err.message);
            console.error("DB Config used:", { ...dbConfig, password: '***' }); // No loguear password
            process.exit(1);
        });
} catch (error) {
    console.error("FATAL ERROR: Failed to create MySQL Pool:", error.message);
    console.error("DB Config used:", { ...dbConfig, password: '***' });
    process.exit(1);
}


// --- JWT Authentication Middleware ---
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Formato: "Bearer TOKEN"

  if (token == null) {
    console.log('Auth attempt failed: No token provided.');
    // Asegúrate que la ruta OPTIONS no requiera token
    if (req.method === 'OPTIONS') {
        return next(); // Permite la solicitud preflight sin token
    }
    return res.status(401).json({ message: 'Acceso denegado: No se proporcionó token' });
  }

  jwt.verify(token, jwtSecret, (err, user) => {
    if (err) {
      console.error('JWT Verification Error:', err.message);
      if (err.name === 'TokenExpiredError') {
        return res.status(401).json({ message: 'Token expirado' });
      }
      return res.status(403).json({ message: 'Token inválido' });
    }
    req.user = user; // Añade payload del usuario al objeto request
    console.log(`User authenticated: ${user.email} (ID: ${user.id}) for path: ${req.path}`);
    next();
  });
};

// --- (Optional) Authorization Middleware for Superusers ---
const authorizeSuperuser = (req, res, next) => {
    // Asume que authenticateToken ya se ejecutó
    if (!req.user || !req.user.is_superuser) {
        console.warn(`Authorization failed: User ${req.user?.email} (ID: ${req.user?.id}) is not a superuser for path ${req.path}.`);
        return res.status(403).json({ message: 'Acceso denegado: Se requiere rol de superusuario' });
    }
    console.log(`Superuser authorized: ${req.user.email} for path: ${req.path}`);
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
    console.log(`Attempting login for email: ${email}`);
    const [users] = await connection.query(`
      SELECT id, name, last_name, email, password, agency, is_superuser
      FROM users
      WHERE email = ?
    `, [email]);
    connection.release();

    if (users.length === 0) {
      console.log(`Login failed: User not found for email: ${email}`);
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }
    const user = users[0];

    // !! ADVERTENCIA DE SEGURIDAD: MD5 NO ES SEGURO PARA CONTRASEÑAS !!
    // !! Considera migrar a bcrypt o Argon2 !!
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

    if (user.password !== hashedPassword) {
      console.log(`Login failed: Incorrect password for email: ${email}`);
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    // --- Generate JWT ---
    const userPayload = {
      id: user.id,
      email: user.email,
      name: user.name,
      last_name: user.last_name,
      agency: user.agency,
      is_superuser: !!user.is_superuser // Asegura que sea booleano
    };

    const token = jwt.sign(userPayload, jwtSecret, { expiresIn: jwtExpiresIn });
    console.log(`Login successful, JWT generated for: ${user.email}`);

    res.json({
      success: true,
      token: token,
      user: { // Devuelve info básica del usuario (puede derivarse del token en el cliente)
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
    res.status(500).json({ message: 'Error en el servidor durante el login', error: error.message });
  }
});


// --- PROTECTED ROUTES ---
// Aplica el middleware JWT a todas las rutas definidas debajo de esta línea
app.use('/api', authenticateToken);

// Ruta para obtener todos los empleados (Protegido)
app.get('/api/employees', async (req, res) => {
  console.log(`User ${req.user.email} requesting all employees.`);
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(`
      SELECT
        e.id, e.name, e.last_name, e.agency,
        e.date_of_birth, e.high_date, e.status, e.low_date, -- Mantener formato de DB
        e.photo, e.id_user,
        u.email as user_email,
        e.last_modified, e.modified_by,
        mod_user.email as modified_by_email
      FROM employees e
      JOIN users u ON e.id_user = u.id
      LEFT JOIN users mod_user ON e.modified_by = mod_user.id -- Join para obtener email del modificador
      ORDER BY e.id ASC
    `);
    connection.release();

    // Formatear fechas para salida ISO si es necesario, o dejarlas como string de DB
    const formattedEmployees = rows.map(employee => ({
      ...employee,
      date_of_birth: employee.date_of_birth, // Ya es 'YYYY-MM-DD' por dateStrings:true
      high_date: employee.high_date,         // Ya es 'YYYY-MM-DD'
      low_date: employee.low_date || null,   // Asegurar null si no existe
      last_modified: employee.last_modified ? new Date(employee.last_modified).toISOString() : null, // Convertir a ISO String UTC
      modified_by: employee.modified_by || null,
      modified_by_email: employee.modified_by_email || null
    }));

    res.json(formattedEmployees);
  } catch (error) {
    console.error('Error al obtener empleados:', error);
    res.status(500).json({ message: 'Error al obtener datos de empleados', error: error.message });
  }
});

// Ruta para obtener un empleado por ID (Protegido)
app.get('/api/employees/:id', async (req, res) => {
  const { id } = req.params;
   if (isNaN(parseInt(id))) { // Validación básica del ID
      return res.status(400).json({ message: 'ID de empleado inválido' });
  }
  console.log(`User ${req.user.email} requesting employee ID: ${id}`);
  try {
    const connection = await pool.getConnection();
    const [rows] = await connection.query(`
       SELECT
        e.id, e.name, e.last_name, e.agency,
        e.date_of_birth, e.high_date, e.status, e.low_date,
        e.photo, e.id_user,
        u.email as user_email,
        e.last_modified, e.modified_by,
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
      date_of_birth: employee.date_of_birth,
      high_date: employee.high_date,
      low_date: employee.low_date || null,
      last_modified: employee.last_modified ? new Date(employee.last_modified).toISOString() : null,
      modified_by: employee.modified_by || null,
      modified_by_email: employee.modified_by_email || null
    });
  } catch (error) {
    console.error(`Error al obtener empleado ID ${id}:`, error);
    res.status(500).json({ message: 'Error al obtener datos del empleado', error: error.message });
  }
});

// Ruta para crear un nuevo empleado (Protegido)
app.post('/api/employees', async (req, res) => {
    console.log(`User ${req.user.email} attempting to create employee.`);
    try {
        const { name, last_name, agency, date_of_birth, high_date, status, photo, id_user } = req.body;
        const creatingUserId = req.user.id;

        // Validación básica
        if (!name || !last_name || !agency || !date_of_birth || !high_date || !status || !id_user) {
            return res.status(400).json({ message: 'Nombre, apellido, agencia, fecha de nacimiento, fecha de alta, estado y ID de usuario son requeridos.' });
        }

        // Validación simple de formato de fecha (YYYY-MM-DD)
        const dateFormatRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateFormatRegex.test(date_of_birth) || !dateFormatRegex.test(high_date)) {
             return res.status(400).json({ message: 'Formato de fecha inválido. Use YYYY-MM-DD.' });
        }
         if (isNaN(parseInt(id_user))) {
            return res.status(400).json({ message: 'ID de usuario inválido.' });
        }


        const connection = await pool.getConnection();

        // Verificar que el id_user asignado existe
        const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id_user]);
        if (existingUsers.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'El usuario asignado (id_user) no existe' });
        }

        // Insertar el nuevo empleado
        // No se establece low_date, last_modified, ni modified_by en la creación
        const [result] = await connection.query(`
            INSERT INTO employees (name, last_name, agency, date_of_birth, high_date, status, photo, id_user)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [name, last_name, agency, date_of_birth, high_date, status, photo || null, id_user]); // Usar null para foto si no se provee

        connection.release();
        console.log(`Employee created successfully with ID: ${result.insertId} by user ${req.user.email}`);

        res.status(201).json({
            success: true,
            message: 'Empleado creado exitosamente',
            employeeId: result.insertId
        });
    } catch (error) {
        console.error('Error al crear empleado:', error);
        // Podrías chequear error.code para errores específicos como ER_DUP_ENTRY si tienes constraints
        res.status(500).json({ message: 'Error en el servidor al crear empleado', error: error.message });
    }
});

// Ruta para actualizar un empleado existente (Protegido)
app.put('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
    const modifyingUserId = req.user.id; // ID del usuario que realiza la actualización
    if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID de empleado inválido' });
    }
    console.log(`User ${req.user.email} attempting to update employee ID: ${id}`);

    try {
        const { name, last_name, agency, date_of_birth, high_date, status, low_date, photo, id_user } = req.body;

        // Validación básica
        if (!name || !last_name || !agency || !date_of_birth || !high_date || !status || !id_user) {
            return res.status(400).json({ message: 'Nombre, apellido, agencia, fecha nacimiento, fecha alta, estado y ID de usuario son requeridos' });
        }
         if (isNaN(parseInt(id_user))) {
            return res.status(400).json({ message: 'ID de usuario inválido.' });
        }

        // Validación formato fechas
        const dateFormatRegex = /^\d{4}-\d{2}-\d{2}$/;
        if (!dateFormatRegex.test(date_of_birth) || !dateFormatRegex.test(high_date) || (low_date && low_date.trim() !== '' && !dateFormatRegex.test(low_date))) {
             return res.status(400).json({ message: 'Formato de fecha inválido. Use YYYY-MM-DD.' });
        }

        const connection = await pool.getConnection();

        // Verificar si el empleado existe
        const [existingEmployees] = await connection.query('SELECT id FROM employees WHERE id = ?', [id]);
        if (existingEmployees.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }

        // Verificar si el usuario asignado (id_user) existe
        const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id_user]);
        if (existingUsers.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'El usuario asignado (id_user) no existe' });
        }

        // Obtener timestamp actual para last_modified
        const lastModified = new Date().toISOString().slice(0, 19).replace('T', ' '); // Formato 'YYYY-MM-DD HH:MM:SS' UTC

        // Actualizar registro del empleado
        const finalLowDate = (low_date && low_date.trim() !== '') ? low_date.trim() : null; // Usar NULL si está vacío o es null

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
            finalLowDate, // Fecha de baja (puede ser NULL)
            photo || null, // Foto (puede ser NULL)
            id_user,
            lastModified, // Timestamp de última modificación
            modifyingUserId, // ID del usuario que modifica
            id
        ]);

        connection.release();

        if (result.affectedRows === 0) {
             return res.status(404).json({ message: 'Empleado no encontrado durante la actualización (inesperado)' });
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

// Ruta para eliminar un empleado (Protegido)
app.delete('/api/employees/:id', async (req, res) => {
    const { id } = req.params;
     if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID de empleado inválido' });
    }
    console.log(`User ${req.user.email} attempting to delete employee ID: ${id}`);
    try {
        const connection = await pool.getConnection();

        // Verificar si existe antes de eliminar
        const [existingEmployees] = await connection.query('SELECT id FROM employees WHERE id = ?', [id]);
        if (existingEmployees.length === 0) {
            connection.release();
            return res.status(404).json({ message: 'Empleado no encontrado' });
        }

        // Eliminar el empleado
        const [result] = await connection.query('DELETE FROM employees WHERE id = ?', [id]);
        connection.release();

        if (result.affectedRows === 0) {
             return res.status(404).json({ message: 'Empleado no encontrado durante la eliminación (inesperado)' });
        }

        console.log(`Employee ID: ${id} deleted successfully by user ${req.user.email}`);
        res.json({
            success: true,
            message: 'Empleado eliminado exitosamente'
        });
    } catch (error) {
        console.error(`Error al eliminar empleado ID ${id}:`, error);
        // Captura errores de Foreign Key si intentas eliminar algo referenciado (aunque las verificaciones previas deberían ayudar)
        if (error.code === 'ER_ROW_IS_REFERENCED_2') { // Código MySQL para FK constraint fail
             return res.status(400).json({ message: 'No se puede eliminar el empleado, puede estar referenciado en otra tabla.' });
        }
        res.status(500).json({ message: 'Error en el servidor al eliminar empleado', error: error.message });
    }
});


// --- USER MANAGEMENT ROUTES (Protegido & Solo Superusuario) ---
// Aplica el middleware de autorización de Superusuario a estas rutas
// Se ejecutará DESPUÉS de authenticateToken porque se define más tarde para este path específico
app.use('/api/users', authorizeSuperuser);

// Ruta para crear un nuevo usuario/administrador (Protegido + Superusuario)
app.post('/api/users', async (req, res) => {
  console.log(`Superuser ${req.user.email} attempting to create a new user.`);
  try {
    const { name, last_name, email, password, agency, is_superuser } = req.body;

    if (!name || !last_name || !email || !password || !agency) {
      return res.status(400).json({ message: 'Nombre, apellido, email, contraseña y agencia son requeridos' });
    }
     // Validación básica de email
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ message: 'Formato de correo electrónico inválido' });
    }

    const connection = await pool.getConnection();

    // Verificar si el email ya existe
    const [existingUsers] = await connection.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      connection.release();
      return res.status(409).json({ message: 'Ya existe un usuario con este correo electrónico' }); // 409 Conflict
    }

    // !! ADVERTENCIA DE SEGURIDAD: MD5 NO ES SEGURO !!
    const hashedPassword = crypto.createHash('md5').update(password).digest('hex');

    // Insertar nuevo usuario
    const [result] = await connection.query(`
      INSERT INTO users (name, last_name, email, password, agency, is_superuser)
      VALUES (?, ?, ?, ?, ?, ?)
    `, [name, last_name, email, hashedPassword, agency, is_superuser ? 1 : 0]); // Asegura 1 o 0

    connection.release();
    console.log(`User created successfully with ID: ${result.insertId} by superuser ${req.user.email}`);

    res.status(201).json({
      success: true,
      message: 'Usuario creado exitosamente',
      userId: result.insertId
    });
  } catch (error) {
    console.error('Error al crear usuario:', error);
     if (error.code === 'ER_DUP_ENTRY') {
        return res.status(409).json({ message: 'Error: El correo electrónico ya está en uso (DB constraint).' });
    }
    res.status(500).json({ message: 'Error en el servidor al crear usuario', error: error.message });
  }
});

// Ruta para obtener todos los usuarios (Protegido + Superusuario)
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

    // Convertir is_superuser a booleano para consistencia
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

// Ruta para obtener un usuario por ID (Protegido + Superusuario)
app.get('/api/users/:id', async (req, res) => {
  const { id } = req.params;
   if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID de usuario inválido' });
    }
  console.log(`Superuser ${req.user.email} requesting user ID: ${id}`);
  try {
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
        is_superuser: !!users[0].is_superuser // Asegura booleano
    });
  } catch (error) {
    console.error(`Error al obtener usuario ID ${id}:`, error);
    res.status(500).json({ message: 'Error al obtener datos del usuario', error: error.message });
  }
});

// Ruta para actualizar un usuario existente (Protegido + Superusuario)
app.put('/api/users/:id', async (req, res) => {
  const { id } = req.params;
   if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID de usuario inválido' });
    }
  console.log(`Superuser ${req.user.email} attempting to update user ID: ${id}`);
  try {
    const { name, last_name, email, password, agency, is_superuser } = req.body;

    // Validación básica
     if (!name || !last_name || !email || !agency) {
      return res.status(400).json({ message: 'Nombre, apellido, email y agencia son requeridos' });
    }
    if (!/\S+@\S+\.\S+/.test(email)) {
        return res.status(400).json({ message: 'Formato de correo electrónico inválido' });
    }

    const connection = await pool.getConnection();

    // Verificar si el usuario existe
    const [currentUser] = await connection.query('SELECT id, email FROM users WHERE id = ?', [id]);
    if (currentUser.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Verificar si el nuevo email ya está en uso por OTRO usuario
    if (email !== currentUser[0].email) {
        const [emailCheck] = await connection.query('SELECT id FROM users WHERE email = ? AND id != ?', [email, id]);
        if (emailCheck.length > 0) {
            connection.release();
            return res.status(409).json({ message: 'El nuevo correo electrónico ya está en uso por otro usuario' });
        }
    }

    let query;
    let params;
    let hashedPassword = null;

    // Solo hashear y actualizar contraseña si se proporciona una no vacía
    if (password && password.trim() !== '') {
      // !! ADVERTENCIA DE SEGURIDAD: MD5 !!
      hashedPassword = crypto.createHash('md5').update(password.trim()).digest('hex');
      query = `
        UPDATE users
        SET name = ?, last_name = ?, email = ?, password = ?, agency = ?, is_superuser = ?
        WHERE id = ?
      `;
      params = [name, last_name, email, hashedPassword, agency, is_superuser ? 1 : 0, id];
    } else {
      // No actualizar la contraseña
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
         // Podría pasar si el ID existe pero los datos son idénticos a los ya existentes? (Aun así, no es un error real)
         // O si hubo un problema inesperado. Por seguridad, devolvemos 404 si no se afectó nada.
         console.warn(`User update for ID ${id} resulted in 0 affected rows.`);
         // Devolvemos éxito de todos modos si los datos eran iguales, pero podrías querer cambiar esto.
         // return res.status(404).json({ message: 'Usuario no encontrado o datos no cambiaron' });
    }
    console.log(`User ID: ${id} updated successfully by superuser ${req.user.email}`);

    res.json({
      success: true,
      message: 'Usuario actualizado exitosamente'
    });
  } catch (error) {
    console.error(`Error al actualizar usuario ID ${id}:`, error);
    if (error.code === 'ER_DUP_ENTRY') {
         return res.status(409).json({ message: 'Error: El correo electrónico ya está en uso (DB constraint).' });
    }
    res.status(500).json({ message: 'Error en el servidor al actualizar usuario', error: error.message });
  }
});

// Ruta para eliminar un usuario (Protegido + Superusuario)
app.delete('/api/users/:id', async (req, res) => {
  const { id } = req.params;
  const requestingUserId = req.user.id; // ID del superusuario que hace la solicitud
   if (isNaN(parseInt(id))) {
        return res.status(400).json({ message: 'ID de usuario inválido' });
    }

  console.log(`Superuser ${req.user.email} attempting to delete user ID: ${id}`);

  // Salvaguarda: Impedir que un superusuario se elimine a sí mismo
  if (parseInt(id, 10) === requestingUserId) {
      console.warn(`Superuser ${req.user.email} attempted to delete their own account (ID: ${id}).`);
      return res.status(400).json({ message: 'No puedes eliminar tu propia cuenta de superusuario.' });
  }

  try {
    const connection = await pool.getConnection();

    // Verificar si el usuario a eliminar existe
    const [existingUsers] = await connection.query('SELECT id FROM users WHERE id = ?', [id]);
    if (existingUsers.length === 0) {
      connection.release();
      return res.status(404).json({ message: 'Usuario no encontrado' });
    }

    // Verificar si hay empleados asignados a este usuario (como id_user O modified_by)
    // Usamos EXISTS para eficiencia, no necesitamos los IDs de los empleados
    const [assignedCheck] = await connection.query(
        'SELECT EXISTS(SELECT 1 FROM employees WHERE id_user = ? LIMIT 1) as has_assigned',
        [id]
    );
     const [modifiedCheck] = await connection.query(
        'SELECT EXISTS(SELECT 1 FROM employees WHERE modified_by = ? LIMIT 1) as has_modified',
        [id]
    );

    if (assignedCheck[0].has_assigned || modifiedCheck[0].has_modified) {
      connection.release();
      const reason = assignedCheck[0].has_assigned ? 'asignados' : 'modificados por';
      console.warn(`Attempt failed to delete user ID ${id}: User has employees ${reason} them.`);
      return res.status(400).json({
        message: `No se puede eliminar este usuario porque tiene empleados ${reason} él. Reasigne o actualice esos empleados primero.`
      });
    }

    // Eliminar el usuario
    const [result] = await connection.query('DELETE FROM users WHERE id = ?', [id]);
    connection.release();

    if (result.affectedRows === 0) {
        // No debería ocurrir si la verificación de existencia pasó
        return res.status(404).json({ message: 'Usuario no encontrado durante la eliminación (inesperado)' });
    }

    console.log(`User ID: ${id} deleted successfully by superuser ${req.user.email}`);
    res.json({
      success: true,
      message: 'Usuario eliminado exitosamente'
    });
  } catch (error) {
    console.error(`Error al eliminar usuario ID ${id}:`, error);
    // Manejar errores de FK por si acaso las verificaciones fallan o hay otras dependencias
    if (error.code === 'ER_ROW_IS_REFERENCED_2') {
         return res.status(400).json({ message: 'No se puede eliminar el usuario, está referenciado en otra parte de la base de datos.' });
    }
    res.status(500).json({ message: 'Error en el servidor al eliminar usuario', error: error.message });
  }
});


// --- Error Handling Middleware (Genérico al final) ---
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err);
  // Si el error es de CORS (lanzado por nuestra función origin)
  if (err.message.includes('Not allowed by CORS')) {
    return res.status(403).json({ message: err.message });
  }
  // Otros errores inesperados
  res.status(500).json({ message: 'Error interno del servidor inesperado', error: err.message });
});


// --- Server Start ---
app.listen(port, "0.0.0.0", () => {
  console.log(`Servidor RH Admin ejecutándose en: http://0.0.0.0:${port}`);
  console.log(`JWT Tokens will expire in: ${jwtExpiresIn}`);
  console.log(`Allowed CORS origins: ${allowedOrigins.join(', ')}`);
  console.log("----------------------------------------------------");
});

// Manejo de cierre grácil (opcional pero bueno para producción)
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server and DB pool');
  // Cierra el servidor HTTP (deja de aceptar nuevas conexiones)
  // Necesitarías guardar la referencia del servidor: const server = app.listen(...)
  // server.close(() => { ... });

  // Cierra el pool de la base de datos
  if (pool) {
    pool.end(err => {
      if (err) {
        console.error('Error closing DB pool:', err);
      } else {
        console.log('DB pool closed.');
      }
      process.exit(err ? 1 : 0);
    });
  } else {
      process.exit(0);
  }
});