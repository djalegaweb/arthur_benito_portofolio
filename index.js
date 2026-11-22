const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const multer = require('multer');

const app = express();
const PORT = 3000;
const DB_PATH = path.join(__dirname, 'data', 'db.json');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));


function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return { salt, hash };
}


function verifyPassword(password, salt, originalHash) {
    const hash = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');
    return hash === originalHash;
}

// Initialisation de la base de données JSON si elle n'existe pas
function initDB() {
    if (!fs.existsSync(DB_PATH)) {
       
        const { salt, hash } = hashPassword('Arthur2026xxx:#');
        const initialData = {
            admin: {
                username: 'arthur',
                salt: salt,
                passwordHash: hash
            },
            profile: {
                name: 'Arthur Bénito',
                bio: 'Photographe professionnel spécialisé dans le portrait, la mode et la photographie événementielle. Capturer l’instant avec émotion et précision.',
                email: 'contact@arthurbenito.com',
                phone: '+225 00 00 00 00 00'
            },
            photos: []
        };
        fs.writeFileSync(DB_PATH, JSON.stringify(initialData, null, 2));
    }
}
initDB();

// Lecture / Écriture JSON
const readDB = () => JSON.parse(fs.readFileSync(DB_PATH, 'utf-8'));
const writeDB = (data) => fs.writeFileSync(DB_PATH, JSON.stringify(data, null, 2));

// Configuration Multer pour l'upload d'images
const storage = multer.diskStorage({
    destination: (req, file, cb) => cb(null, 'public/uploads/'),
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, uniqueSuffix + path.extname(file.originalname));
    }
});
const upload = multer({ storage });

// Stockage simple des tokens de session en mémoire
const activeTokens = new Set();

// Middleware d'authentification
function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    if (token && activeTokens.has(token)) {
        next();
    } else {
        res.status(401).json({ error: 'Non autorisé. Veuillez vous connecter.' });
    }
}

// --- ROUTES API ---

// 1. Connexion Admin
app.post('/api/login', (req, res) => {
    const { username, password } = req.body;
    const db = readDB();

    if (username === db.admin.username && verifyPassword(password, db.admin.salt, db.admin.passwordHash)) {
        const token = crypto.randomBytes(32).toString('hex');
        activeTokens.add(token);
        res.json({ token });
    } else {
        res.status(401).json({ error: 'Identifiants incorrects' });
    }
});

// 2. Récupérer toutes les données publiques (Profil + Photos)
app.get('/api/portfolio', (req, res) => {
    const db = readDB();
    res.json({
        profile: db.profile,
        photos: db.photos
    });
});

// 3. Mettre à jour le profil (Bio, contact)
app.put('/api/profile', requireAuth, (req, res) => {
    const db = readDB();
    db.profile = { ...db.profile, ...req.body };
    writeDB(db);
    res.json({ message: 'Profil mis à jour', profile: db.profile });
});

// 4. Ajouter une photo
app.post('/api/photos', requireAuth, upload.single('image'), (req, res) => {
    if (!req.file) return res.status(400).json({ error: 'Aucune image fournie' });

    const db = readDB();
    const newPhoto = {
        id: Date.now().toString(),
        title: req.body.title || 'Sans titre',
        category: req.body.category || 'Général',
        description: req.body.description || '',
        imageUrl: `/uploads/${req.file.filename}`,
        createdAt: new Date().toISOString()
    };

    db.photos.unshift(newPhoto); // Ajoute au début
    writeDB(db);
    res.json(newPhoto);
});

// 5. Modifier une photo (Titre, catégorie, description, ou nouvelle image)
app.put('/api/photos/:id', requireAuth, upload.single('image'), (req, res) => {
    const db = readDB();
    const index = db.photos.findIndex(p => p.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Photo introuvable' });

    const oldPhoto = db.photos[index];
    let imageUrl = oldPhoto.imageUrl;

    // Si une nouvelle image est envoyée, supprimer l'ancienne du disque
    if (req.file) {
        const oldPath = path.join(__dirname, 'public', oldPhoto.imageUrl);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
        imageUrl = `/uploads/${req.file.filename}`;
    }

    db.photos[index] = {
        ...oldPhoto,
        title: req.body.title ?? oldPhoto.title,
        category: req.body.category ?? oldPhoto.category,
        description: req.body.description ?? oldPhoto.description,
        imageUrl
    };

    writeDB(db);
    res.json(db.photos[index]);
});

// 6. Supprimer une photo
app.delete('/api/photos/:id', requireAuth, (req, res) => {
    const db = readDB();
    const index = db.photos.findIndex(p => p.id === req.params.id);

    if (index === -1) return res.status(404).json({ error: 'Photo introuvable' });

    // Supprimer le fichier physique
    const filePath = path.join(__dirname, 'public', db.photos[index].imageUrl);
    if (fs.existsSync(filePath)) fs.unlinkSync(filePath);

    db.photos.splice(index, 1);
    writeDB(db);
    res.json({ message: 'Photo supprimée' });
});

app.listen(PORT, () => {
    console.log(`Serveur démarré sur http://localhost:${PORT}`);
    console.log(`Admin disponible sur http://localhost:${PORT}/admin.html`);
});
