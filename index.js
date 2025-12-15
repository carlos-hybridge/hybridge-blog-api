const express = require('express');
require('dotenv').config({silent: true});
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const {Strategy: JwtStrategy, ExtractJwt} = require('passport-jwt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({extended: true}));
const port = process.env.PORT || 3000;
const db = require('./models');

passport.use('local',
    new LocalStrategy(
        {usernameField: 'email', passwordField: 'password', session: false},
        async (email, password, done) => {
            try {
                const user = await db.User.findOne({where: {email}});
                if (!user) {
                    return done(null, false, {message: 'Usuario no existe'});
                }
                const ok = await bcrypt.compare(password, user.password);
                if (!ok) {
                    return done(null, false, {message: 'Contraseña incorrecta'});
                }
                return done(null, user); // autenticado
            } catch (err) {
                return done(err);
            }
        }
    )
);

app.get('/', (req, res) => {
    res.json({message: 'Bienvenido a la API de Hybridge Blog Posts'});
});

/** Registro */
app.post('/api/signup', async (req, res) => {
    try {
        const {name, email, password} = req.body;
        const hash = await bcrypt.hash(password, 10);
        const user = await db.User.create({name, email, password: hash});
        res.status(201).json({id: user.id, email: user.email});
    } catch (e) {
        res.status(400).json({error: e.message});
    }
});

passport.use('jwt',
    new JwtStrategy(
        {
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: process.env.JWT_SECRET,
            session: false
        },
        async (payload, done) => {
            try {
                const user = await db.User.findByPk(payload.id);
                if (!user) return done(null, false);
                return done(null, user);
            } catch (err) {
                return done(err, false);
            }
        }
    )
);

/** Login → genera token */
app.post('/api/login',
    passport.authenticate('local', {session: false}),
    (req, res) => {
        const payload = {id: req.user.id};
        const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn: '1h'});
        res.json({token, token_type: 'Bearer'});
    }
);

app.get('/api/profile',
    passport.authenticate('jwt', {session: false}),
    (req, res) => {
        // `req.user` viene de la estrategia JWT
        res.json({id: req.user.id, email: req.user.email, msg: 'Acceso concedido 👋'});
    }
);

// Posts endpoints
app.get('/api/posts', async (req, res) => {
    const posts = await db.Post.findAll();
    res.json(posts)
});

/** Login → genera token */
app.post('/api/login',
    passport.authenticate('local', {session: false}),
    (req, res) => {
        const payload = {id: req.user.id};
        const token = jwt.sign(payload, process.env.JWT_SECRET, {expiresIn: '1h'});
        res.json({token, token_type: 'Bearer'});
    }
);

app.post('/api/posts',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {title, content, authorId} = req.body;

        if (!title || !content || !authorId) {
            return res.status(400).json({error: 'Todos los campos son requeridos'});
        }

        const newPost = {
            title,
            content,
            authorId,
            date: new Date()
        };

        const savedPost = await db.Post.create(newPost);
        res.status(201).json(savedPost);
    });

app.get('/api/posts/:id', async (req, res) => {
    const {id} = req.params;
    const post = await db.Post.findByPk(id);

    if (!post) {
        return res.status(404).json({error: 'Post no encontrado'});
    }

    res.json(post);
});

app.patch('/api/posts/:id',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {id} = req.params;
        const {title, content, authorId} = req.body;
        const post = await db.Post.findByPk(id);

        if (!post) {
            return res.status(404).json({error: 'Post no encontrado'});
        }
        if (title) post.title = title;
        if (content) post.content = content;
        if (authorId) post.authorId = authorId;

        await post.save();
        res.json(post);
    });

app.delete('/api/posts/:id',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {id} = req.params;
        const post = await db.Post.findByPk(id);

        if (!post) {
            return res.status(404).json({error: 'Post no encontrado'});
        }
        await post.destroy();
        res.json({message: 'Post eliminado correctamente'});
    });

// Authors endpoint
app.get('/api/authors', async (req, res) => {
    const authors = await db.Author.findAll();
    res.json(authors);
});

app.post('/api/authors',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {name} = req.body;
        const author = await db.Author.create({name});
        res.status(201).json(author);
    });

app.get('/api/authors/:id', async (req, res) => {
    const {id} = req.params;
    const author = await db.Author.findByPk(id);

    if (!author) {
        return res.status(404).json({error: 'Autor no encontrado'});
    }

    res.json(author);
});

app.patch('/api/authors/:id',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {id} = req.params;
        const {name} = req.body;
        const author = await db.Author.findByPk(id);

        if (!author) {
            return res.status(404).json({error: 'Autor no concentrate'});
        }

        author.name = name;
        await author.save();
        res.json(author);
    });

app.delete('/api/authors/:id',
    passport.authenticate('jwt', {session: false}),
    async (req, res) => {
        const {id} = req.params;
        const author = await db.Author.findByPk(id);

        if (!author) {
            return res.status(404).json({error: 'Autor no encontrado'});
        }

        await author.destroy();
        res.json({message: 'Autor eliminado correctamente'});
    });

app.listen(port, () => {
    console.log(`Listening on http://localhost:${port}`);
});

