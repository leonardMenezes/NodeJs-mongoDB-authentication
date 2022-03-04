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
const { json } = require('express/lib/response')

//Credencials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS

//Open Route - public route
app.get('/', (req, res) =>{
    res.status(200).json({ msg: "Bem vindo a nossa API!" })
})

async function ValidationRegister(req, res, next){
    const { name, email, password, confirmpassword } = req.body

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

    next()
}

//Register User
app.post('/auth/register', ValidationRegister, async(req, res) =>{

    const { name, email, password, confirmpassword } = req.body

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

//Login User
app.post("/auth/login", async(req, res) => {
    const { email, password } = req.body

    //validations
    if(!email){
        return res.status(422).json({ msg: "O email é obrigatório!" })
    }
    if(!password){
        return res.status(422).json({ msg: "A senha é obrigatório!" })
    }

    //Check if user exists
    const user = await User.findOne({ email: email })

    if(!user){
        return res.status(404).json({ msg: "Usuário não encontrado!" })
    }

    //check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({ msg: "Senha inválida!" })
    }

    try {
        const secret = process.env.SECRET
        const id = user.id

        const token = jwt.sign(
            {
            id: user.id
        }, 
        secret,
        )

        res.status(200).json({ msg: 'Autenticação realizada com sucesso', token, id })

    } catch (error) {
        console.log(error)
        res.status(500).json({ msg: "Erro no servidor!" })
    }
})

//Private Route
app.get("/user/:id", checkToken, async(req, res)=>{
    const id = req.params.id

    //verifica se o id é um ObjectId válido
    if( !mongoose.Types.ObjectId.isValid(id) ){
        return res.status(404).json({ msg: 'Usuário não encontrado!' })
    }
    
    //check if user exists
    const user = await User.findById(id, '-password') // o parametro '-password' exclui o campo password do retorno
    
    res.status(200).json({ user })
    
})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({ msg: "Acesso negado!" })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
        
    } catch (error) {
        res.status(400).json({ msg: "Token inválido!" })
    }

}

mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@cluster0.swyfb.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(()=>{
    app.listen(4000)
    console.log("Conectou ao banco!")
}).catch((err)=> console.log(err))
