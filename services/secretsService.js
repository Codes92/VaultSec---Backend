/**
 * Secrets service receives data from the route and calls appropriate Secret model function
 * Throws meaningful error when nothing is found (i.e. secret doesn't exist)
 * Returns result back to route
 * 
 * The reason for this layer rather than going from route to model directly is architectural consistency
 * - everything goes through a service layer.
 * Future updates such as logging and encryption validation also have a clean place to be put in
 */

const Secret = require("../models/secretModel");

async function addNewUserSecret(userId, name, encryptedBlob, iv)
{
    try
    {
        const newSecret = await Secret.addSecret(userId, name, encryptedBlob, iv);
        return {secretId: newSecret.secret_id, 
                name: newSecret.name,
                encryptedBlob: newSecret.encrypted_blob,
                iv: newSecret.iv,
                createdAt: newSecret.created_at
            };
    }
    catch (error)
    {
        throw new Error("Secret unable to be created.") // For user
    }
}

async function getAllUserSecrets(userId)
{
    try
    {
        // Model function already returns an array of secrets.
        // This function just needs to map over that array.
        const secrets = await Secret.findAllByUserId(userId);
        return secrets.map(secret => ({
            secretId: secret.secret_id,
            name: secret.name,
            encryptedBlob: secret.encrypted_blob,
            iv: secret.iv,
            createdAt: secret.created_at
        }));
    }
    catch (error)
    {
        throw new Error("Unable to retrieve secrets");
    }
}

async function getUserSecret(secretId, userId)
{
    let secret;

    try
    {
        secret = await Secret.findById(secretId, userId);
    }
    catch (error)
    {
        throw new Error("Unable to retrieve secret");
    }
    
    if (!secret)
    {
        throw new Error("Secret not found");
    }

    return {secretId: secret.secret_id, 
            name: secret.name,
            encryptedBlob: secret.encrypted_blob,
            iv: secret.iv,
            createdAt: secret.created_at};
}

async function updateUserSecret(secretId, userId, name, encryptedBlob, iv)
{
    let updatedSecret;

    try
    {
        updatedSecret = await Secret.updateSecret(secretId, userId, name, encryptedBlob, iv)
    }
    catch (error)
    {
        throw new Error("Unable to update secret");
    }

    if (!updatedSecret)
    {
        throw new Error("Secret not updated");
    }

    return {secretId: updatedSecret.secret_id,
            name: updatedSecret.name,
            encryptedBlob: updatedSecret.encrypted_blob,
            iv: updatedSecret.iv};  
}

async function deleteUserSecret(secretId, userId)
{
    try
    {
        const deletedSecret = await Secret.deleteSecret(secretId, userId);
        return deletedSecret;
    }
    catch (error)
    {
        throw new Error("Unable to delete secret");
    }
}

module.exports = {addNewUserSecret,
                  getAllUserSecrets,
                  getUserSecret,
                  updateUserSecret,
                  deleteUserSecret}