// Loads PostgreSQL client library and extracts Pool class
const {Pool} = require("pg"); // Pool class is used to manage database connections for efficient querying

// Create pool for querying database
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: {
        rejectUnauthorized: false
    }
    /* host: "localhost", // Database server
    user: "postgres", // Database username
    password: process.env.DB_PASSWORD, // User password
    database: "vaultsec_db", // Database name
    port: 5432 // Port number
    */
});

// Query test to check database connection working
pool.query('SELECT NOW()', (err, res) => {
    // If connection fails, log error
    if (err)
    {
        console.error('Database connection failed:', err);
    }
    else
    {
        console.log('Database connected successfully at:', res.rows[0].now);
    }
});

module.exports = pool;