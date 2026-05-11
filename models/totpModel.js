const pool = require('../database/db');

class TOTP
{
    static async updateTotpSecret(userId, ciphertext, iv, authTag)
    {
        try
        {
            const secret = `${ciphertext}:${iv}:${authTag}`;

            const result = await pool.query(
                `UPDATE users
                SET totp_secret = $1
                WHERE id = $2 RETURNING *`, [secret, userId]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error updating TOTP");
        }
    }

    static async enableTotp(userId, timestamp)
    {
        try
        {
            const result = await pool.query(
                `UPDATE users
                SET totp_enabled = true, totp_verified_at = $2
                WHERE id = $1 RETURNING *`, [userId, timestamp]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error enabling TOTP");
        }
    }

    static async disableTotp(userId)
    {
        try
        {
            const result = await pool.query(
                `UPDATE users
                SET totp_enabled = false, totp_secret = NULL, totp_verified_at = NULL
                WHERE id = $1 RETURNING *`, [userId]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error disabling TOTP");
        }
    }

    static async findTotpSecret(userId)
    {
        try
        {
            const result = await pool.query(
                `SELECT totp_secret FROM users WHERE id = $1`, [userId]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error finding TOTP");
        }
    }

    static async updateTotpVerification(userId, prevCode)
    {
        try
        {
            const result = await pool.query(
                `UPDATE users SET totp_last_used_code = $1 
                WHERE id = $2 RETURNING *`, [prevCode, userId]
            );
            return result.rows[0];
        }
        catch (error)
        {
            throw new Error("Database error updating/verifiying TOTP");
        }
    }
}

module.exports = {TOTP};