require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()
//Config JSON response
app.use(express.json())

//Models
const User = require('./models/User')

//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//Open Route - public route
app.get('/', (req, res) =>{
    res.status(200).json({ msg: "Bem vindo a nossa API!" })
})

//Register User
app.post('/auth/register', async(req, res) =>{

    const { name, email, password, confirmpassword } = req.body

    //Validations
    if(!name){
        return res.status(422).json({ msg: "O nome é obrigatório!" })
    }
    if(!email){
        return res.status(422).json({ msg: "O email é obrigatório!" })
    }
    if(!password){
        return res.status(422).json({ msg: "A senha é obrigatório!" })
    }
    if(password != confirmpassword){
        return res.status(422).json({ msg: "As senhas devem ser iguais!" })
    }

    //Check if user exists
    const userExists = await User.findOne({ email: email })

    if(userExists){
        return res.status(422).json({ msg: "Este e-mail já está registrado!" })
    }

    //create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()

        res.status(201).json({ msg: "Usuário criado com sucesso!" })
    } catch(error) {
        console.log(error)
        res.status(500).json({ msg: "Erro no servidor!" })
    }

})

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.swyfb.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(()=>{
    app.listen(4000)
    console.log("Conectou ao banco!")
}).catch((err)=> console.log(err))
