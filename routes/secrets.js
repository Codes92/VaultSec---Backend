/** Routes for secrets */
const express = require("express");
const {isLoggedIn} = require("../middleware/validateAuth");
const router = express.Router();

const { getAllUserSecrets, getUserSecret, addNewUserSecret, updateUserSecret, deleteUserSecret } = require("../services/secretsService");

// Route to get all secrets for a user
router.get('/', isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        const userId = req.user.userId;

        const secrets = await getAllUserSecrets(userId);
        if (secrets.length === 0)
        {
            return res.json({secrets: [], message: "You have no secrets in your vault!"});
        }
        return res.json({secrets});
    }
    catch(error)
    {
        res.status(500).json({error: error.message});
    }
});

// Route to get specific secret via id check
router.get('/:id', isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        const userId = req.user.userId;
        const secretId = req.params.id;
        const secret = await getUserSecret(secretId, userId);
        
        res.json({secret});
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

// Route to add new secret to user vault
router.post('/', isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        const userId = req.user.userId;
        const {name, encryptedBlob, iv} = req.body;
        const newSecret = await addNewUserSecret(userId, name, encryptedBlob, iv);

        // Res status for adding new resource = 201;
        res.status(201).json({newSecret, message: "Secret added to your vault"});
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

// Route to update a user secret
router.put('/:id', isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        const userId = req.user.userId;
        const secretId = req.params.id;
        const {name, encryptedBlob, iv} = req.body;
        
        const updatedSecret = await updateUserSecret(secretId, userId, name, encryptedBlob, iv);

        // 200 for updating an existing resource
        res.status(200).json({updatedSecret, message: "Secret successfully updated"})
    }
    catch (error)
    {
        res.status(500).json({error: error.message});
    }
});

router.delete('/:id', isLoggedIn, async(req, res) => {
    try
    {
        // const userId = 1 <-- Testing
        const userId = req.user.userId;
        const secretId = req.params.id;
        
        const deletedSecret = await deleteUserSecret(secretId, userId);
        
        return res.json({deletedSecret});
    }
    catch (error)
    {
         res.status(500).json({error: error.message});
    }
});

module.exports = router;