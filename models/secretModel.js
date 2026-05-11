const pool = require("../database/db");

class Secret
{
    /* Insert new secret into database */
    static async addSecret(userId, name, encryptedBlob, iv)
    {
        try
        {
            const result = await pool.query(
                `INSERT INTO secrets (user_id, name, encrypted_blob, iv)
                VALUES ($1, $2, $3, $4) RETURNING *`, [userId, name, encryptedBlob, iv]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error while creating secret.");
        }
    }

    /* Find all secrets belonging to a user */
    static async findAllByUserId(userId)
    {
        try
        {
            const result = await pool.query(
                `SELECT secret_id, name, encrypted_blob, iv FROM secrets WHERE user_id = $1`, [userId]
            );
            return result.rows;
        }
        catch (error)
        {
            throw new Error("Database error while fetching secrets");
        }
    }

    /* Find specific user secret */
    static async findById(secretId, userId)
    {
        try
        {
            const result = await pool.query(
                `SELECT secret_id, name, encrypted_blob, iv
                FROM secrets
                WHERE secret_id = $1 AND user_id = $2`, [secretId, userId]
            );
            return result.rows[0] || null;
        }
        catch (error)
        {
            throw new Error("Database error while fetching secret");
        }
    }

    /* Update a user secret */
    static async updateSecret(secretId, userId, name, encryptedBlob, iv)
    {
        try
        {
            const result = await pool.query(
                `UPDATE secrets
                SET name = $1, encrypted_blob = $2, iv = $3, updated_at = CURRENT_TIMESTAMP
                WHERE secret_id = $4 AND user_id = $5
                RETURNING *`, [name, encryptedBlob, iv, secretId, userId]
            )
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error updating secret");
        }
    }

    /* Delete a user secret */
    static async deleteSecret(secretId, userId)
    {
        try
        {
            const result = await pool.query(
                `DELETE FROM secrets WHERE user_id = $1 AND secret_id = $2`, [userId, secretId]
            );
            return result.rowCount > 0;
        }
        catch (error)
        {
            throw new Error("Database error deleting secret");
        }
    }
}

module.exports = Secret;