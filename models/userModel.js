const pool = require("../database/db");

class User
{
    static async createUser(email, verifierHash, kdfSalt)
    {
        try
        {
            /* Insert user to database */
            const result = await pool.query(
                `INSERT INTO users (email, hashed_login_verifier, kdf_salt) VALUES($1, $2, $3) RETURNING *`,
                [email, verifierHash, kdfSalt]
            );
            return result.rows[0];
        }
        catch (error)
        {
            // PostgreSQL unique violation code (something added twice)
            if (error.code === "23505")
            {
                throw new Error("Email already in use");
            }
            throw error; // Re-throw other errors
        }
    };

    static async findByEmail(email)
    {
        try
        {
            // Returns verifier and salt - needed for login and key derivation
            const result = await pool.query(
                `SELECT id, email, hashed_login_verifier, kdf_salt, totp_enabled FROM users WHERE email = $1`, 
                [email]
            );
            return result.rows[0] || null;
        }
        catch (error)
        {
            // console.error("findByEmail raw error:", error);
            throw new Error("Database error during email lookup");
        }
    };

    static async findById(id)
    {
        try
        {
            // Excludes sensitive columns - used only to identify an authenticated user
            const result = await pool.query(
                `SELECT id, email, created_at, totp_enabled, hashed_login_verifier FROM users WHERE id = $1`,
                [id]
            );
            return result.rows[0] || null;
        }
        catch (error)
        {
            throw new Error("Database error during user lookup");
        }
    };

    static async changePassword(id, verifierHash)
    {
        try
        {
            const result = await pool.query(
                `UPDATE users
                SET hashed_login_verifier = $2
                WHERE id = $1 RETURNING *`, [id, verifierHash]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Failed to change password");
        }
    }

    static async deleteAccount(id)
    {
        try
        {
            const result = await pool.query(
                `DELETE FROM users WHERE id = $1 RETURNING *`, [id]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Failed to delete account");
        }
    }
}

module.exports = User;