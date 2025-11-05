<div align="center">

# 🔐 Auth Service  
### A secure, modular authentication microservice built with **Node.js**, **Express**, and **Redis**

[![Node.js](https://img.shields.io/badge/Node.js-43853D?style=for-the-badge&logo=node.js&logoColor=white)](https://nodejs.org/)
[![Express](https://img.shields.io/badge/Express.js-404D59?style=for-the-badge)](https://expressjs.com/)
[![Redis](https://img.shields.io/badge/Redis-DC382D?style=for-the-badge&logo=redis&logoColor=white)](https://redis.io/)
[![Deploy with Vercel](https://img.shields.io/badge/Vercel-000000?style=for-the-badge&logo=vercel&logoColor=white)](https://vercel.com)

<br>

💡 **Official Repository:**  
👉 [ZIPP — GitHub Repository](https://github.com/PIYUSH-GIRI23/zipp)

</div>

---

## 🚀 Features

- 🔑 **JWT Authentication** — Secure token-based authentication and middleware.  
- 🔁 **Redis Integration** — Session caching and OTP management with Redis.  
- 🧠 **Utility Functions** — Password hashing, OTP generation, data validation, etc.  
- ☁️ **Cloudinary Support** — Image and file management for user profiles.  
- 🔐 **Passkey & OTP Login** — Advanced authentication flows.  
- 🧩 **Microservice Ready** — Built for modular integration with other services.  
- ⚙️ **Environment Config** — Centralized `.env` and `.env.config` for configuration.  
- ☁️ **Vercel Deployment** — Simple and scalable hosting.  

---

## 🧱 Project Structure

<pre>
auth/
├── db/                          # Database connection and models (if any)
│
├── middleware/                  # Authentication middlewares
│   └── jwt.js                   # JWT verification and handling
│
├── node_modules/                # Installed dependencies
│
├── redis/                       # Redis setup and session handling
│   └── redis_init.js
│
├── routes/                      # Route controllers
│   └── manageAuth.js
│
├── utils/                       # Utility modules
│   ├── cloudinary/              # Cloudinary integration
│   ├── dataVerification.js      # Input validation and sanitization
│   ├── googleAuth.js            # Google OAuth integration
│   ├── jwtUtils.js              # JWT sign/verify utilities
│   ├── otp.js                   # OTP generation and management
│   ├── passkey.js               # Passkey authentication logic
│   ├── passwordHashing.js       # Secure password hashing (bcrypt/argon2)
│   ├── usernameGenerator.js     # Smart username generation utility
│   └── verifyOtp.js             # OTP verification handler
│
├── .env                         # Environment variables
├── .env.config                  # Environment configuration template
├── .gitignore                   # Git ignored files
├── package.json                 # Project dependencies & metadata
├── package-lock.json            # Locked dependency versions
├── Readme.md                    # Project documentation ❤️
├── server.js                    # Entry point of the Auth Service
└── vercel.json                  # Vercel deployment configuration
</pre>

---

## ⚙️ Setup & Installation

```bash
# 1️⃣ Clone the repository
git clone https://github.com/PIYUSH-GIRI23/zipp-auth.git

# 2️⃣ Move into the directory
cd auth

# 3️⃣ Install dependencies
npm install

# 4️⃣ Configure environment variables
cp .env.config .env

# 5️⃣ Start the server (development)
npm run dev

---

🧰 Tech Stack

| Category            | Tools                 |
| ------------------- | --------------------- |
| **Runtime**         | Node.js               |
| **Framework**       | Express.js            |
| **Cache / Session** | Redis                 |
| **Auth**            | JWT, OTP, Passkeys    |
| **Cloud Media**     | Cloudinary            |
| **Validation**      | Custom + Validator.js |
| **Deployment**      | Vercel                |


---

🌐 Connect with Me

<a href="mailto:giri.piyush2003@gmail.com"><img src="https://img.shields.io/badge/Mail-D14836?style=for-the-badge&logo=gmail&logoColor=white" alt="Mail"></a>
<a href="https://github.com/PIYUSH-GIRI23"><img src="https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white" alt="GitHub"></a>
<a href="https://www.linkedin.com/in/piyush-giri-031b71254/"><img src="https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white" alt="LinkedIn"></a>
<a href="https://x.com/GIRIPIYUSH2310"><img src="https://img.shields.io/badge/X-000000?style=for-the-badge&logo=x&logoColor=white" alt="X"></a>
