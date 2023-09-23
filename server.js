const express = require('express');
const mongoose = require('mongoose');
const app = express();

require('dotenv').config();

app.use(express.json());
app.use('/api/auth', require('./routes/authRoutes'));

//connect DB and start server
const PORT = process.env.PORT || 5000;
mongoose
    .connect(process.env.MONGO_URL)
    .then(()=>{
        app.listen(PORT, ()=>{
            console.log(`Server is running at port ${PORT}`);
        })
}).catch((err)=>console.log(err));